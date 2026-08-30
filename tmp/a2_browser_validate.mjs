import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chromium } from "D:/react-django/Lumen/Lume_Authentication/AuthFlow/react-auth/node_modules/playwright";

const FRONTEND_URL = "https://authflow-staging-68054cd21696.herokuapp.com";
const BACKEND_API_URL = "https://ant-django-auth-staging-a2c075cd4cc0.herokuapp.com/api";

function decodeJwtPayload(token) {
  const payload = token.split(".")[1];
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

function runHerokuShell(script) {
  const result = spawnSync(
    "heroku",
    ["run", "--no-tty", "--app", "ant-django-auth-staging", "python", "manage.py", "shell"],
    {
      input: script,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    }
  );

  if (result.status !== 0) {
    throw new Error(`Heroku shell failed: ${result.stderr || result.stdout}`);
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
  const crypto = require("node:crypto");
  const step = 30;
  const digits = 6;
  const counter = Math.floor(timestamp / 1000 / step);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const key = Buffer.from(secret, "base64");
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, "0");
}

async function seedUsers() {
  const script = readFileSync("tmp/seed_staging_users.py", "utf8");
  return extractJson(runHerokuShell(script));
}

async function createBrowserSession(browser, baseContext, email, password) {
  const page = await baseContext.newPage();
  await page.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForTimeout(1000);
  return page;
}

async function snapshotCookies(context) {
  const cookies = await context.cookies();
  const byName = Object.fromEntries(cookies.map((cookie) => [cookie.name, cookie.value]));
  return {
    accessToken: byName.access_token || null,
    refreshToken: byName.refresh_token || null,
    csrfToken: byName.csrftoken || null,
  };
}

async function ensureLoggedIn(page) {
  await page.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
}

async function setCookie(context, name, value) {
  await context.addCookies([
    {
      name,
      value,
      domain: "authflow-staging-68054cd21696.herokuapp.com",
      path: "/",
      httpOnly: false,
      secure: true,
      sameSite: "None",
    },
  ]);
}

async function clearAndSetAccess(context, token) {
  await setCookie(context, "access_token", token);
}

async function runManagedShell(script) {
  return runHerokuShell(script);
}

async function main() {
  const results = {};
  const seed = await seedUsers();
  results.seeded = {
    normal_email: seed.normal.email,
    twofa_email: seed.twofa.email,
  };

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const requestCounts = {
    refresh: 0,
    validation: 0,
  };
  const responses = [];
  const consoleErrors = [];
  const pageErrors = [];

  context.on("request", (request) => {
    const url = request.url();
    if (url.includes("/token-refresh/")) {
      requestCounts.refresh += 1;
    }
    if (url.includes("/validate-session/")) {
      requestCounts.validation += 1;
    }
  });

  context.on("response", async (response) => {
    const url = response.url();
    const status = response.status();
    if (status >= 500) {
      responses.push({ url, status });
    }
  });

  page.on("console", (msg) => {
    const text = msg.text();
    if (msg.type() === "error") {
      consoleErrors.push(text);
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(String(error));
  });

  // Normal login and automatic refresh.
  await page.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("Email address").fill(seed.normal.email);
  await page.getByLabel("Password").fill(seed.normal.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  const loginCookies = await snapshotCookies(context);
  const loginAccessPayload = decodeJwtPayload(loginCookies.accessToken);
  const loginRefreshPayload = decodeJwtPayload(loginCookies.refreshToken);
  results.normal_login = {
    access_sid: loginAccessPayload.sid,
    refresh_sid: loginRefreshPayload.sid,
    has_access_cookie: Boolean(loginCookies.accessToken),
    has_refresh_cookie: Boolean(loginCookies.refreshToken),
  };

  const invalidAccessToken = "invalid.token.value";
  await clearAndSetAccess(context, invalidAccessToken);
  requestCounts.refresh = 0;
  requestCounts.validation = 0;
  await ensureLoggedIn(page);
  const refreshedCookies = await snapshotCookies(context);
  const refreshedAccessPayload = decodeJwtPayload(refreshedCookies.accessToken);
  const refreshedRefreshPayload = decodeJwtPayload(refreshedCookies.refreshToken);
  results.automatic_refresh = {
    refresh_requests: requestCounts.refresh,
    validation_requests: requestCounts.validation,
    access_sid: refreshedAccessPayload.sid,
    refresh_sid: refreshedRefreshPayload.sid,
    rotated_refresh_changed: refreshedCookies.refreshToken !== loginCookies.refreshToken,
  };

  // Two-tab and three-tab coordination.
  const pageA = page;
  const pageB = await context.newPage();
  const pageC = await context.newPage();
  requestCounts.refresh = 0;
  requestCounts.validation = 0;
  await clearAndSetAccess(context, "expired.access.token");
  await Promise.all([
    pageA.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageB.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
  ]);
  await pageA.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  await pageB.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  results.two_tab = {
    refresh_requests: requestCounts.refresh,
  };

  requestCounts.refresh = 0;
  requestCounts.validation = 0;
  await clearAndSetAccess(context, "expired.access.token.2");
  await Promise.all([
    pageA.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageB.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
    pageC.goto(FRONTEND_URL, { waitUntil: "networkidle" }),
  ]);
  await Promise.all([
    pageA.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 }),
    pageB.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 }),
    pageC.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 }),
  ]);
  results.three_tab = {
    refresh_requests: requestCounts.refresh,
  };

  // Logout and revoked-session access denial.
  const accessBeforeLogout = refreshedCookies.accessToken;
  const refreshBeforeLogout = refreshedCookies.refreshToken;
  await pageA.getByRole("button", { name: "Logout" }).click();
  await pageA.getByRole("link", { name: "Login" }).waitFor({ timeout: 15000 });
  await setCookie(context, "access_token", accessBeforeLogout);
  await setCookie(context, "refresh_token", refreshBeforeLogout);
  requestCounts.refresh = 0;
  await pageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const postLogoutHasLogout = await pageA.getByRole("button", { name: "Logout" }).count();
  results.logout = {
    logout_visible_after_revoke: postLogoutHasLogout,
    refresh_requests_after_replay_cookie: requestCounts.refresh,
  };

  // 2FA login.
  const twofaPage = await context.newPage();
  await twofaPage.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await twofaPage.getByLabel("Email address").fill(seed.twofa.email);
  await twofaPage.getByLabel("Password").fill(seed.twofa.password);
  await twofaPage.getByRole("button", { name: "Sign in" }).click();
  await twofaPage.getByText("Enter the Password from your authenticator app").waitFor({ timeout: 15000 });
  const otp = totp(seed.twofa.secret);
  const otpInputs = twofaPage.locator(".otp-input");
  for (let index = 0; index < 6; index += 1) {
    await otpInputs.nth(index).fill(otp[index]);
  }
  await twofaPage.getByRole("button", { name: "Confirm" }).click();
  await twofaPage.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  const twofaCookies = await snapshotCookies(context);
  const twofaAccessPayload = decodeJwtPayload(twofaCookies.accessToken);
  const twofaRefreshPayload = decodeJwtPayload(twofaCookies.refreshToken);
  results.twofa_login = {
    access_sid: twofaAccessPayload.sid,
    refresh_sid: twofaRefreshPayload.sid,
  };

  // Logout-all via authenticated backend request.
  const sessionUserEmail = seed.normal.email;
  const sessionUserAccess = refreshedCookies.accessToken;
  const logoutAllResponse = await pageA.evaluate(async (args) => {
    const response = await fetch(args.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${args.accessToken}`,
      },
      credentials: "include",
    });
    return { status: response.status };
  }, { url: `${BACKEND_API_URL}/logout-all/`, accessToken: sessionUserAccess });
  await pageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  await pageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  results.logout_all = {
    status: logoutAllResponse.status,
    page_a_logout_visible: await pageA.getByRole("button", { name: "Logout" }).count(),
    page_b_logout_visible: await pageB.getByRole("button", { name: "Logout" }).count(),
  };

  // Fresh normal login for replay/unrelated-session checks.
  const replayPageA = await context.newPage();
  const replayPageB = await context.newPage();
  await replayPageA.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await replayPageA.getByLabel("Email address").fill(seed.normal.email);
  await replayPageA.getByLabel("Password").fill(seed.normal.password);
  await replayPageA.getByRole("button", { name: "Sign in" }).click();
  await replayPageA.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  const sessionA1Cookies = await snapshotCookies(context);
  const sessionA1Refresh = sessionA1Cookies.refreshToken;
  const sessionA1Access = sessionA1Cookies.accessToken;
  await replayPageB.goto(`${FRONTEND_URL}/login`, { waitUntil: "networkidle" });
  await replayPageB.getByLabel("Email address").fill(seed.normal.email);
  await replayPageB.getByLabel("Password").fill(seed.normal.password);
  await replayPageB.getByRole("button", { name: "Sign in" }).click();
  await replayPageB.getByRole("button", { name: "Logout" }).waitFor({ timeout: 15000 });
  const sessionB1Cookies = await snapshotCookies(context);
  const sessionB1Access = sessionB1Cookies.accessToken;

  // Rotate A1 once, then replay it.
  const refreshResponse = await replayPageA.evaluate(async (args) => {
    const response = await fetch(args.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${args.refreshToken}`,
      },
      credentials: "include",
    });
    return { status: response.status, body: await response.json() };
  }, { url: `${BACKEND_API_URL}/token-refresh/`, refreshToken: sessionA1Refresh });
  const replayRefreshToken = sessionA1Cookies.refreshToken;
  results.replay_step_one = {
    refresh_status: refreshResponse.status,
    refresh_sid: decodeJwtPayload(refreshResponse.body.refresh_token).sid,
  };
  const replayAgain = await replayPageA.evaluate(async (args) => {
    const response = await fetch(args.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${args.refreshToken}`,
      },
      credentials: "include",
    });
    return { status: response.status, text: await response.text() };
  }, { url: `${BACKEND_API_URL}/token-refresh/`, refreshToken: replayRefreshToken });
  await replayPageA.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const replayDeniedAfterReplay = await replayPageA.getByRole("button", { name: "Logout" }).count();
  await replayPageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const unrelatedStillValid = await replayPageB.getByRole("button", { name: "Logout" }).count();
  results.replay = {
    replay_status: replayAgain.status,
    replay_denied_after_replay: replayDeniedAfterReplay,
    unrelated_session_logout_visible: unrelatedStillValid,
  };

  // Inactive user check.
  await runManagedShell(`
from django.contrib.auth import get_user_model
from user.models import AuthSession
User = get_user_model()
user = User.objects.get(email="${seed.normal.email}")
user.is_active = False
user.save(update_fields=["is_active"])
AuthSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=None)
print("inactive-updated")
`);
  await replayPageB.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const inactiveLogoutVisible = await replayPageB.getByRole("button", { name: "Logout" }).count();
  results.inactive_user = {
    logout_visible_after_inactive: inactiveLogoutVisible,
  };

  // Session expiration check.
  await runManagedShell(`
from datetime import timedelta
from django.utils import timezone
from user.models import AuthSession
session = AuthSession.objects.get(id="${results.normal_login.access_sid}")
session.expires_at = timezone.now() - timedelta(minutes=1)
session.save(update_fields=["expires_at"])
print("session-expired")
`);
  await page.goto(FRONTEND_URL, { waitUntil: "networkidle" });
  const sessionExpiredLogoutVisible = await page.getByRole("button", { name: "Logout" }).count();
  results.session_expiration = {
    logout_visible_after_expiry: sessionExpiredLogoutVisible,
  };

  // Secret logging review: fetch a bounded log sample and search for our secrets.
  const logSample = spawnSync("heroku", ["logs", "--num", "200", "--app", "ant-django-auth-staging"], {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  const logText = `${logSample.stdout || ""}\n${logSample.stderr || ""}`;
  results.secret_logging = {
    contains_normal_access_token: logText.includes(results.normal_login.access_sid),
    contains_normal_refresh_token: logText.includes(loginCookies.refreshToken),
    contains_twofa_access_token: logText.includes(twofaCookies.accessToken),
    contains_twofa_refresh_token: logText.includes(twofaCookies.refreshToken),
    contains_password_keyword: /password/i.test(logText),
    contains_otp_keyword: /otp/i.test(logText),
    contains_authorization_header: /authorization/i.test(logText),
  };

  results.browser_errors = {
    console_errors,
    page_errors: pageErrors,
    network_errors: responses,
  };

  console.log(JSON.stringify(results, null, 2));
  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
