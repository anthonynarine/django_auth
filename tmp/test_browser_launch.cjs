const { chromium } = require("D:/react-django/Lumen/Lume_Authentication/AuthFlow/react-auth/node_modules/playwright");

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto("https://example.com", { waitUntil: "domcontentloaded" });
  console.log(await page.title());
  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
