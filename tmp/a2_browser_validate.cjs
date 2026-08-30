const { spawnSync } = require("node:child_process");
const { readFileSync } = require("node:fs");
const crypto = require("node:crypto");
const { chromium } = require("D:/react-django/Lumen/Lume_Authentication/AuthFlow/react-auth/node_modules/playwright");

const FRONTEND_URL = "https://authflow-staging-68054cd21696.herokuapp.com";
const BACKEND_API_URL = "https://ant-django-auth-staging-a2c075cd4cc0.herokuapp.com/api";
const FRONTEND_HOST = "authflow-staging-68054cd21696.herokuapp.com";
const STAGING_APP = "ant-django-auth-staging";

function decodeJwtPayload(token) {
  const payload = token.split(".")[1];
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

function runHerokuShell(script) {
  const result = spawnSync(
    "heroku",
    ["run", "--no-tty", "--app", STAGING_APP, "python", "manage.py", "shell"],
    {
      input: script,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
      shell: true,
    }
  );

  if (result.status !== 0) {
    throw new Error(
      `Heroku shell failed:\nSTDOUT:\n${result.stdout || ""}\nSTDERR:\n${result.stderr || ""}`
    );
  }

  return result.stdout;
}

function extractJson(text) {
  const matches = text.match(/\{[\s\S]*\}/g);
  if (!matches) {
    throw new Error(`No JSON found in output: ${text}`);
  }
  return JSON.parse(matches[matches.length - 1]);
}

function totp(secret, timestamp = Date.now()) {
  const step = 30;
  const digits = 6;
  const counter = Math.floor(timestamp / 1000 / step);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const key = Buffer.from(secret, "base64");
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, "0");
}

async function seedUsers() {
  const script = readFileSync("tmp/seed_staging_users.py", "utf8");
  return extractJson(runHerokuShell(script));
}

async function getTokens(context) {
  const cookies = await context.cookies(FRONTEND_URL);
  const byName = Object.fromEntries(cookies.map((cookie) => [cookie.name, cookie.value]));
  return {
    accessToken: byName.access_token || null,
    refreshToken: byName.refresh_token || null,
    csrfToken: byName.csrftoken || null,
  };
}

async function setTokenCookie(context, name, value) {
  await context.addCookies([
    {
      name,
      value,
      domain: FRONTEND_HOST,
      path: "/",
      httpOnly: false,
      secure: true,
      sameSite: "None",
    },
  ]);
}

async function setAccessToken(context, token) {
  await setTokenCookie(context, "access_token", token);
}

async function setRefreshToken(context, token) {
  await setTokenCookie(context, "refresh_token", token);
}

async function setAuthTokens(context, accessToken, refreshToken) {
  await Promise.all([
    setAccessToken(context, accessToken),
    setRefreshToken(context, refreshToken),
  ]);
}

async function login(page, email, password) {
  await page.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("Email address").fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function waitForLoggedIn(page) {
  await page.getByRole("button", { name: "Logout" }).waitFor({ timeout: 45000 });
}

async function waitForLoggedOut(page) {
  const loginLink = page.getByRole("link", { name: "Login" });
  const loginButton = page.getByRole("button", { name: "Sign in" });
  await Promise.race([
    loginLink.waitFor({ timeout: 45000 }),
    loginButton.waitFor({ timeout: 45000 }),
  ]);
}

async function fetchJsonInPage(page, url, token, method = "POST", body = undefined) {
  const cookies = await getTokens(page.context());
  return page.evaluate(
    async ({ url, token, method, body, csrfToken }) => {
      const headers = {
        ...(csrfToken ? { "X-CSRFToken": csrfToken } : {}),
        ...(body ? { "Content-Type": "application/json" } : {}),
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      const response = await fetch(url, {
        method,
        headers,
        credentials: "include",
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await response.text();
      let parsed = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch (error) {
        parsed = text;
      }
      return { status: response.status, body: parsed };
    },
    { url, token, method, body, csrfToken: cookies.csrfToken }
  );
}

async function mutateUser(userEmail, mutationScript) {
  const script = `
from django.contrib.auth import get_user_model
from user.models import AuthSession, UserToken
from django.utils import timezone
${mutationScript}
print("done")
`;
  return runHerokuShell(script.replaceAll("${userEmail}", userEmail));
}

async function main() {
  const seed = await seedUsers();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });

  const counters = {
    refresh: 0,
    validation: 0,
  };
  const pageErrors = [];
  const consoleErrors = [];
  const unexpected5xx = [];

  context.on("request", (request) => {
    const url = request.url();
    if (url.includes("/token-refresh/")) {
      counters.refresh += 1;
    }
    if (url.includes("/validate-session/")) {
      counters.validation += 1;
    }
  });

  context.on("response", async (response) => {
    if (response.status() >= 500) {
      unexpected5xx.push({ url: response.url(), status: response.status() });
    }
  });

  const trackedPages = [];
  async function newTrackedPage() {
    const page = await context.newPage();
    trackedPages.push(page);
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        consoleErrors.push(msg.text());
      }
    });
    page.on("pageerror", (error) => {
      pageErrors.push(String(error));
    });
    return page;
  }

  const results = {
    normal_login: null,
    automatic_refresh: null,
    two_tab: null,
    three_tab: null,
    logout: null,
    logout_all: null,
    twofa_login: null,
    replay: null,
    unrelated_session: null,
    inactive_user: null,
    session_expiration: null,
    secret_logging: null,
  };

  // Normal login.
  const page = await newTrackedPage();
  await login(page, seed.normal.email, seed.normal.password);
  await waitForLoggedIn(page);
  let tokens = await getTokens(context);
  const loginAccessPayload = decodeJwtPayload(tokens.accessToken);
  const loginRefreshPayload = decodeJwtPayload(tokens.refreshToken);
  results.normal_login = {
    access_sid: loginAccessPayload.sid,
    refresh_sid: loginRefreshPayload.sid,
    has_access_cookie: Boolean(tokens.accessToken),
    has_refresh_cookie: Boolean(tokens.refreshToken),
  };

  // Automatic refresh + sid preservation.
  const originalRefreshToken = tokens.refreshToken;
  await setAccessToken(context, "invalid.access.token");
  counters.refresh = 0;
  counters.validation = 0;
  await page.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await waitForLoggedIn(page);
  tokens = await getTokens(context);
  const refreshedAccessPayload = decodeJwtPayload(tokens.accessToken);
  const refreshedRefreshPayload = decodeJwtPayload(tokens.refreshToken);
  results.automatic_refresh = {
    refresh_requests: counters.refresh,
    validation_requests: counters.validation,
    access_sid: refreshedAccessPayload.sid,
    refresh_sid: refreshedRefreshPayload.sid,
    refreshed_refresh_changed: tokens.refreshToken !== originalRefreshToken,
  };

  // Two-tab coordination.
  const pageB = await newTrackedPage();
  const pageC = await newTrackedPage();
  await setAccessToken(context, "expired.access.token");
  counters.refresh = 0;
  counters.validation = 0;
  await Promise.all([
    page.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageB.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
  ]);
  await Promise.all([waitForLoggedIn(page), waitForLoggedIn(pageB)]);
  results.two_tab = {
    refresh_requests: counters.refresh,
  };

  // Three-tab coordination.
  await setAccessToken(context, "expired.access.token.2");
  counters.refresh = 0;
  counters.validation = 0;
  await Promise.all([
    page.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageB.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageC.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
  ]);
  await Promise.all([waitForLoggedIn(page), waitForLoggedIn(pageB), waitForLoggedIn(pageC)]);
  results.three_tab = {
    refresh_requests: counters.refresh,
  };

  // Logout revocation.
  const currentTokens = await getTokens(context);
  const logoutAccessToken = currentTokens.accessToken;
  const logoutRefreshToken = currentTokens.refreshToken;
  await page.getByRole("button", { name: "Logout" }).click();
  await waitForLoggedOut(page);
  await setAuthTokens(context, logoutAccessToken, logoutRefreshToken);
  counters.refresh = 0;
  await page.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await waitForLoggedOut(page);
  results.logout = {
    refresh_requests_after_replay_cookie: counters.refresh,
  };

  // Logout-all with two independent sessions.
  const logoutAllContextA = await browser.newContext({ ignoreHTTPSErrors: true });
  const logoutAllContextB = await browser.newContext({ ignoreHTTPSErrors: true });
  const logoutAllPageA = await logoutAllContextA.newPage();
  const logoutAllPageB = await logoutAllContextB.newPage();
  await login(logoutAllPageA, seed.normal.email, seed.normal.password);
  await login(logoutAllPageB, seed.normal.email, seed.normal.password);
  await waitForLoggedIn(logoutAllPageA);
  await waitForLoggedIn(logoutAllPageB);
  const logoutAllTokens = await getTokens(logoutAllContextA);
  const logoutAllResponse = await fetchJsonInPage(
    logoutAllPageA,
    `${BACKEND_API_URL}/logout-all/`,
    logoutAllTokens.accessToken
  );
  await logoutAllPageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await logoutAllPageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  results.logout_all = {
    status: logoutAllResponse.status,
    page_a_logged_out: (await logoutAllPageA.getByRole("link", { name: "Login" }).count()) > 0,
    page_b_logged_out: (await logoutAllPageB.getByRole("link", { name: "Login" }).count()) > 0,
  };

  // 2FA login.
  const twofaContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const twofaPage = await twofaContext.newPage();
  await login(twofaPage, seed.twofa.email, seed.twofa.password);
  await twofaPage.getByText("Enter the Password from your authenticator app").waitFor({
    timeout: 30000,
  });
  const otpInput = twofaPage.locator(".otp-input").first();
  await otpInput.evaluate((el) => el.focus());
  const otpInputs = twofaPage.locator(".otp-input");
  const otpCandidates = [
    totp(seed.twofa.secret),
    totp(seed.twofa.secret, Date.now() - 30000),
    totp(seed.twofa.secret, Date.now() + 30000),
  ];
  let twofaResponse = null;
  let twofaBody = null;
  for (const otp of otpCandidates) {
    await otpInputs.evaluateAll((inputs, otpValue) => {
      inputs.forEach((input, index) => {
        const digit = otpValue[index] || "";
        input.value = digit;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    }, otp);
    const responsePromise = twofaPage.waitForResponse(
      (response) =>
        response.url().includes("/two-factor-login/") || response.url().includes("/verify-otp/")
    );
    await twofaPage.getByRole("button", { name: "Confirm" }).click();
    twofaResponse = await responsePromise;
    twofaBody = twofaResponse.body ? twofaResponse.body : null;
    if (twofaResponse.status === 200) {
      break;
    }
  }
  if (!twofaResponse || twofaResponse.status !== 200) {
    throw new Error(
      `2FA login failed with status ${twofaResponse ? twofaResponse.status : "unknown"} body ${JSON.stringify(twofaBody)}`
    );
  }
  await setAuthTokens(twofaContext, twofaResponse.body.access_token, twofaResponse.body.refresh_token);
  await twofaPage.waitForFunction(() => window.location.pathname === "/", { timeout: 45000 });
  await waitForLoggedIn(twofaPage);
  console.log(JSON.stringify({
    cookie_names: (await twofaContext.cookies()).map((cookie) => cookie.name),
    backend_cookie_names: (await twofaContext.cookies(BACKEND_API_URL)).map((cookie) => cookie.name),
    current_url: twofaPage.url(),
  }, null, 2));
  await browser.close();
  return;
  const twofaTokens = await getTokens(twofaContext);
  const twofaAccessPayload = decodeJwtPayload(twofaTokens.accessToken);
  const twofaRefreshPayload = decodeJwtPayload(twofaTokens.refreshToken);
  results.twofa_login = {
    access_sid: twofaAccessPayload.sid,
    refresh_sid: twofaRefreshPayload.sid,
  };

  // Replay against one session, another session of same user survives.
  const replayContextA = await browser.newContext({ ignoreHTTPSErrors: true });
  const replayContextB = await browser.newContext({ ignoreHTTPSErrors: true });
  const replayPageA = await replayContextA.newPage();
  const replayPageB = await replayContextB.newPage();
  await login(replayPageA, seed.normal.email, seed.normal.password);
  await login(replayPageB, seed.normal.email, seed.normal.password);
  await waitForLoggedIn(replayPageA);
  await waitForLoggedIn(replayPageB);
  const replayTokensA = await getTokens(replayContextA);
  const replayTokensB = await getTokens(replayContextB);
  const replayAccessA = replayTokensA.accessToken;
  const replayRefreshA = replayTokensA.refreshToken;
  await setAccessToken(replayContextA, "expired.access.token.3");
  await replayPageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await waitForLoggedIn(replayPageA);
  const rotatedReplayTokensA = await getTokens(replayContextA);
  const replayAgain = await fetchJsonInPage(
    replayPageA,
    `${BACKEND_API_URL}/token-refresh/`,
    replayRefreshA
  );
  await replayPageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await replayPageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const replayAVisibleLogin = (await replayPageA.getByRole("link", { name: "Login" }).count()) > 0;
  const replayBVisibleLogout = (await replayPageB.getByRole("button", { name: "Logout" }).count()) > 0;
  results.replay = {
    replay_status: replayAgain.status,
    compromised_session_revoked: replayAVisibleLogin,
    unrelated_session_survives: replayBVisibleLogout,
    sid_preserved_after_rotation: decodeJwtPayload(rotatedReplayTokensA.refreshToken).sid === decodeJwtPayload(replayRefreshA).sid,
  };

  // Inactive user.
  const inactiveMutation = `
User = get_user_model()
user = User.objects.get(email="${seed.normal.email}")
user.is_active = False
user.save(update_fields=["is_active"])
print("inactive-user-updated")
`;
  runHerokuShell(`
from django.contrib.auth import get_user_model
${inactiveMutation}
`);
  await replayPageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  results.inactive_user = {
    login_visible_after_deactivation: (await replayPageB.getByRole("link", { name: "Login" }).count()) > 0,
  };

  // Session expiration.
  const sessionExpirationScript = `
from datetime import timedelta
from django.utils import timezone
from user.models import AuthSession
session = AuthSession.objects.get(id="${results.twofa_login.access_sid}")
session.expires_at = timezone.now() - timedelta(minutes=1)
session.save(update_fields=["expires_at"])
print("session-expired")
`;
  runHerokuShell(sessionExpirationScript);
  await twofaPage.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  results.session_expiration = {
    login_visible_after_expiry: (await twofaPage.getByRole("link", { name: "Login" }).count()) > 0,
  };

  // Secret logging review.
  const logSample = spawnSync(
    "heroku",
    ["logs", "--num", "200", "--app", STAGING_APP],
    {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
      shell: true,
    }
  );
  const logText = `${logSample.stdout || ""}\n${logSample.stderr || ""}`;
  results.secret_logging = {
    contains_access_token: logText.includes(results.normal_login.access_sid),
    contains_refresh_token: logText.includes(originalRefreshToken),
    contains_twofa_access_token: logText.includes(twofaTokens.accessToken),
    contains_twofa_refresh_token: logText.includes(twofaTokens.refreshToken),
    contains_authorization_keyword: /authorization/i.test(logText),
    contains_password_keyword: /password/i.test(logText),
    contains_otp_keyword: /otp/i.test(logText),
    contains_mfa_keyword: /mfa/i.test(logText),
  };

  results.browser_errors = {
    console_errors: consoleErrors,
    page_errors: pageErrors,
    unexpected_5xx: unexpected5xx,
  };

  console.log(JSON.stringify(results, null, 2));
  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
