import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dataDir = join(__dirname, "..", "data");

function loadJson(name) {
  const p = join(dataDir, name);
  return JSON.parse(readFileSync(p, "utf8"));
}

export function loadDefaultScenarios() {
  return loadJson("scenarios.json");
}

export function loadDefaultRules() {
  return loadJson("rules.json").map((r) => ({
    ...r,
    regex: new RegExp(r.pattern, r.flags || ""),
  }));
}

export function loadDefaultEvalCases() {
  return loadJson("eval_cases.json");
}
