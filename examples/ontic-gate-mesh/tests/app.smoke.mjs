// Drives dist/index.html in headless Chromium without the Claude runtime (local mode).
// Run: node scripts/build.mjs && node tests/app.smoke.mjs [screenshot-dir]
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let playwright;
try { playwright = require("playwright"); } catch { playwright = require(join(process.env.NODE_PATH || "/usr/local/lib/node_modules", "playwright")); }
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const page_html = readFileSync(join(root, "dist/index.html"), "utf8");
const shell = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"></head><body>${page_html}</body></html>`;
const shots = process.argv[2];

const browser = await playwright.chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const fails = [];
const check = (cond, msg) => { if (!cond) fails.push(msg); else console.log("ok  ", msg); };

for (const vp of [{ width: 1280, height: 900, name: "desktop" }, { width: 390, height: 844, name: "phone" }]) {
  const page = await browser.newPage({ viewport: vp });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.setContent(shell, { waitUntil: "domcontentloaded" });
  const verdict = () => page.locator("#verdict .big").innerText();

  await page.selectOption("#preset", "0"); await page.click("#runBtn"); await page.waitForTimeout(150);
  check((await verdict()) === "BLOCKED" || (await verdict()).toLowerCase() === "blocked", `${vp.name}: scenario 1 is blocked`);
  check((await page.locator("#gates").innerText()).includes("ready requires rights of owned or licensed"), `${vp.name}: ready claim quarantined`);
  await page.selectOption("#preset", "1"); await page.click("#runBtn"); await page.waitForTimeout(150);
  check((await verdict()).toLowerCase() === "pass", `${vp.name}: scenario 2 passes`);
  const gates = await page.locator("#gates").innerText();
  check(/Round 2/i.test(gates) && /O1/.test(gates), `${vp.name}: two adversary rounds with O1 :: ${gates.slice(0, 0)}`);
  check((await page.locator("#window").innerText()).replace(/\s+/g, " ").includes("render"), `${vp.name}: ±3 window shows upstream`);
  check((await page.locator("#drifts").innerText()).includes("+1"), `${vp.name}: adversarial drift +1`);

  await page.click('#advSeg button[data-adv="claude"]');
  await page.selectOption("#preset", "2"); await page.click("#runBtn"); await page.waitForTimeout(150);
  check((await verdict()).toLowerCase() === "fail", `${vp.name}: Claude mode without runtime fails closed`);
  await page.click('#advSeg button[data-adv="rules"]');

  await page.click('#charterSeg button[data-k="oracle-csa"]');
  await page.selectOption("#preset", "0"); await page.click("#runBtn"); await page.waitForTimeout(150);
  check((await page.locator("#gates").innerText()).includes("§1.3(d)"), `${vp.name}: CSA crypto mining blocked citing §1.3(d)`);
  await page.selectOption("#preset", "9"); await page.click("#runBtn"); await page.waitForTimeout(150);
  check((await verdict()).toLowerCase() === "escalate", `${vp.name}: CSA PCI storage escalates`);

  await page.click('#charterSeg button[data-k="video-publish"]');
  await page.selectOption("#preset", "0"); await page.click("#runBtn"); await page.waitForTimeout(100);
  await page.evaluate(() => { location.hash = "chain"; });
  await page.waitForTimeout(100);
  await page.click("#capture"); await page.waitForTimeout(100);
  for (let i = 0; i < 4; i++) { const r = page.locator(`input[data-t="${i}"][data-r="0"]`); if (await r.count()) await r.check(); }
  await page.click("#draftBtn"); await page.click("#exitLitr8"); await page.waitForTimeout(100);
  await page.fill("#specApprover", "Zach"); await page.click("#freeze");
  await page.click("#grant"); await page.waitForTimeout(100);
  const stepsTxt = await page.locator("#steps").innerText();
  check(stepsTxt.includes("edit_deployed"), `${vp.name}: edit_deployed grant refused`);
  await page.click("#runFulrr"); await page.waitForTimeout(400);
  const after = await page.locator("#steps").innerText();
  check(/passed review/i.test(after), `${vp.name}: FulRR passes after repair`);
  await page.click("#promote"); await page.waitForTimeout(100);
  check(/promoted/i.test(await page.locator("#steps").innerText()), `${vp.name}: candidate promoted`);
  if (shots) await page.screenshot({ path: join(shots, `chain-${vp.name}.png`), fullPage: true });

  await page.evaluate(() => { location.hash = "ledger"; }); await page.waitForTimeout(100);
  await page.click("#verifyBtn");
  check((await page.locator("#verifyOut").innerText()).toLowerCase().includes("intact"), `${vp.name}: ledger verifies`);
  await page.click("#tamper");
  check((await page.locator("#verifyOut").innerText()).toLowerCase().includes("broken"), `${vp.name}: tamper test detects the edit`);

  await page.evaluate(() => { location.hash = "mesh"; }); await page.waitForTimeout(100);
  await page.selectOption("#preset", "1"); await page.click("#runBtn"); await page.waitForTimeout(150);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 0, `${vp.name}: no horizontal page scroll (overflow ${overflow}px)`);
  if (shots) await page.screenshot({ path: join(shots, `mesh-${vp.name}.png`), fullPage: true });
  check(errors.length === 0, `${vp.name}: no page errors ${errors.join(" | ")}`);
  await page.close();
}
await browser.close();
if (fails.length) { console.error("FAILED:\n- " + fails.join("\n- ")); process.exit(1); }
console.log("smoke: all checks passed");
