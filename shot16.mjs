import { chromium } from "playwright-core";
const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
const page = await browser.newPage({ viewport: { width: 1300, height: 700 }, colorScheme: "dark" });
const errs = []; page.on("pageerror", e => errs.push(e.message));
page.on("dialog", d => d.accept()); // auto-confirm
await page.goto("http://127.0.0.1:8443/");
await page.evaluate(() => localStorage.setItem("mtprov.token", "smoke-admin-token-def45678"));
await page.reload();
await page.waitForSelector("#app:not(.hidden)");
await page.click('nav.tabs button[data-tab="fleet"]');
await page.waitForSelector("#rows tr");
const row = page.locator("#rows tr").first();
console.log("initial has Revoke:", await row.locator('button[data-act="revoke"]').count());
console.log("initial has Remove:", await row.locator('button[data-act="remove"]').count());
// revoke it
await row.locator('button[data-act="revoke"]').click();
await page.waitForTimeout(600);
const row2 = page.locator("#rows tr").first();
console.log("after revoke has Remove:", await row2.locator('button[data-act="remove"]').count());
console.log("after revoke has Revoke:", await row2.locator('button[data-act="revoke"]').count());
const countBefore = await page.locator("#rows tr").count();
// remove it
await row2.locator('button[data-act="remove"]').click();
await page.waitForTimeout(600);
console.log("rows before/after remove:", countBefore, await page.locator("#rows tr").count());
console.log("JS ERRORS:", errs.length ? errs.join("; ") : "none");
await browser.close();
