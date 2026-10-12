// Builds dist/index.html: the app page with the engine, charters and presets inlined.
// Run: node scripts/build.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const charter = (dir) => ({
  ontology: JSON.parse(read(`charters/${dir}/ontology.json`)),
  duties: JSON.parse(read(`charters/${dir}/duties.json`)),
  policy: JSON.parse(read(`charters/${dir}/gate-policy.json`)),
});

const charters = {
  "video-publish": { label: "Video publish", about: "The spec's worked example: one video moving from render to publish.", ...charter("video-publish") },
  "oracle-csa": { label: "Oracle CSA", about: "Selected clauses of the Oracle Cloud Services Agreement (v062223) encoded as ordered duties, each citing its section.", ...charter("oracle-csa") },
};
const presets = JSON.parse(read("presets.json"));
const safe = (v) => JSON.stringify(v).replace(/</g, "\\u003c");

let html = read("app/index.html");
html = html.replace("/*__OGM_ENGINE__*/", () => read("engine/ogm.js"));
html = html.replace("/*__CHARTERS__*/null", () => safe(charters));
html = html.replace("/*__PRESETS__*/null", () => safe(presets));
if (html.includes("__OGM_ENGINE__") || html.includes("__CHARTERS__") || html.includes("__PRESETS__")) throw new Error("A placeholder was not replaced.");
mkdirSync(join(root, "dist"), { recursive: true });
writeFileSync(join(root, "dist/index.html"), html);
console.log(`dist/index.html ${(html.length / 1024).toFixed(1)} KiB`);
