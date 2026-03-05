import { loadDefaultRules, loadDefaultScenarios } from "./resources.mjs";

export const SEVERITY_ORDER = ["minimal", "low", "moderate", "high", "critical"];

export function parseSeverity(value) {
  const v = String(value || "").trim().toLowerCase();
  if (!SEVERITY_ORDER.includes(v)) {
    throw new Error(`invalid severity: ${value}`);
  }
  return v;
}

function severityRank(sev) {
  return SEVERITY_ORDER.indexOf(parseSeverity(sev));
}

function severityFromRisk(risk) {
  if (risk >= 0.90) return "critical";
  if (risk >= 0.75) return "high";
  if (risk >= 0.45) return "moderate";
  if (risk >= 0.20) return "low";
  return "minimal";
}

function sigmoid(x) {
  if (x > 18) return 0.999999;
  if (x < -18) return 0.000001;
  return 1 / (1 + Math.exp(-x));
}

const CONFUSABLE_MAP = new Map([
  ["а", "a"], ["е", "e"], ["о", "o"], ["р", "p"], ["с", "c"], ["у", "y"], ["х", "x"], ["і", "i"], ["ј", "j"],
  ["А", "A"], ["Е", "E"], ["О", "O"], ["Р", "P"], ["С", "C"], ["У", "Y"], ["Х", "X"], ["І", "I"], ["Ј", "J"]
]);

function normalizeText(text) {
  let out = "";
  for (const ch of String(text)) {
    out += CONFUSABLE_MAP.get(ch) ?? ch;
  }
  out = out.replace(/[\u200b-\u200f\ufeff]/g, "");
  return out.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function hasDefensiveContext(text) {
  return /\b(policy|documentation|docs?|tutorial|example|training|drill|audit|hardening|prevent|mitigate|block|remove unauthorized|incident response)\b/i.test(text);
}

function hasOvertMaliciousIntent(text) {
  return /\b(steal|covert(?:ly)?|hidden step|silently|backdoor|payload|bypass|override safeguards|ignore previous|without telling)\b/i.test(text);
}

function chunkText(text, maxChars = 1400) {
  const norm = normalizeText(text);
  const parts = norm.split(/\n\s*\n|(?=^#{1,6}\s)/m).map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return [];
  const out = [];
  let buf = "";
  for (const part of parts) {
    if (!buf) {
      buf = part;
      continue;
    }
    if ((buf.length + 2 + part.length) <= maxChars) {
      buf += `\n\n${part}`;
      continue;
    }
    out.push(buf);
    buf = part;
  }
  if (buf) out.push(buf);
  return out;
}

const STOPWORDS = new Set([
  "the", "and", "for", "that", "with", "this", "from", "into", "your", "then", "they", "them", "are", "was", "were", "you", "but", "all", "any", "can",
  "should", "would", "have", "has", "had", "not", "use", "using", "before", "after", "while", "where", "when", "which", "what", "only", "just", "also",
  "their", "there", "about", "within", "outside", "through", "across", "make", "ensure", "include", "avoid", "without", "inside", "system", "prompt"
]);

function tokenize(text) {
  const t = normalizeText(text).toLowerCase();
  const raw = t.match(/[a-z0-9_.-]+/g) ?? [];
  const tokens = [];
  for (const tok of raw) {
    if (tok.length < 3) continue;
    if (STOPWORDS.has(tok)) continue;
    tokens.push(tok);
  }
  return tokens;
}

function textVector(text) {
  const tokens = tokenize(text);
  const m = new Map();
  for (const tok of tokens) {
    m.set(tok, (m.get(tok) ?? 0) + 1);
  }
  return m;
}

function cosineMap(a, b) {
  if (a.size === 0 || b.size === 0) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (const v of a.values()) na += v * v;
  for (const v of b.values()) nb += v * v;
  const [sm, lg] = a.size < b.size ? [a, b] : [b, a];
  for (const [k, v] of sm.entries()) {
    const w = lg.get(k);
    if (w) dot += v * w;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function scaledSemanticSimilarity(a, b) {
  return Math.min(1, cosineMap(a, b) * 2.25);
}

function noisyOrUpdate(prev, contrib) {
  const c = Math.max(0, Math.min(0.96, contrib));
  return 1 - ((1 - prev) * (1 - c));
}

function topKIndices(values, k) {
  return values
    .map((v, i) => ({ v, i }))
    .sort((a, b) => b.v - a.v)
    .slice(0, k)
    .map((x) => x.i);
}

export class ClawGuardScanner {
  constructor(config = {}) {
    this.config = {
      semanticTopK: 3,
      semanticMinEvidence: 0.35,
      rejectAt: "high",
      ...config,
    };
    this.config.rejectAt = parseSeverity(this.config.rejectAt);
    this.scenarios = loadDefaultScenarios();
    this.rules = loadDefaultRules();
    this.scenarioVectors = this.scenarios.map((s) => textVector(s.description));
  }

  scanText(text, opts = {}) {
    const target = opts.target ?? "<inline>";
    const raw = String(text ?? "");
    const norm = normalizeText(raw);
    const chunks = chunkText(raw);
    const chunksForSemantic = chunks.length > 0 ? chunks : [norm];
    const chunkVectors = chunksForSemantic.map((c) => textVector(c));

    const categoryScores = {};
    const findings = [];
    const ruleHits = [];

    for (let sidx = 0; sidx < this.scenarios.length; sidx += 1) {
      const scenario = this.scenarios[sidx];
      const sims = chunkVectors.map((cv) => scaledSemanticSimilarity(cv, this.scenarioVectors[sidx]));
      const idxs = topKIndices(sims, this.config.semanticTopK);
      for (const cidx of idxs) {
        const sim = sims[cidx];
        const ev = sigmoid((sim - scenario.threshold) / Math.max(scenario.softness, 1e-6));
        if (ev < this.config.semanticMinEvidence) continue;
        const contrib = Math.max(0, Math.min(0.96, scenario.weight * ev));
        const prev = categoryScores[scenario.category] ?? 0;
        categoryScores[scenario.category] = noisyOrUpdate(prev, contrib);
        findings.push({
          scenario_id: scenario.id,
          category: scenario.category,
          similarity: sim,
          evidence: ev,
          weight: scenario.weight,
          chunk_snippet: chunksForSemantic[cidx].slice(0, 280),
        });
      }
    }

    if (/[\u200b-\u200f\ufeff]/.test(raw)) {
      const prev = categoryScores.obfuscation ?? 0;
      categoryScores.obfuscation = noisyOrUpdate(prev, 0.28);
      ruleHits.push({
        rule_id: "zero_width_obfuscation",
        category: "obfuscation",
        weight: 0.28,
        excerpt: "contains zero-width unicode characters",
      });
    }

    for (const rule of this.rules) {
      const m = rule.regex.exec(norm);
      if (!m) continue;
      const prev = categoryScores[rule.category] ?? 0;
      categoryScores[rule.category] = noisyOrUpdate(prev, rule.weight);
      const start = Math.max(0, m.index - 32);
      const end = Math.min(norm.length, m.index + m[0].length + 72);
      ruleHits.push({
        rule_id: rule.id,
        category: rule.category,
        weight: rule.weight,
        excerpt: norm.slice(start, end).replace(/\n/g, " "),
      });
    }

    this.#applyHighConfidenceRulePromotions(categoryScores, ruleHits);
    this.#applySafeIntentAdjustments(categoryScores, norm, ruleHits);

    const conservativeMode = hasDefensiveContext(norm) && !hasOvertMaliciousIntent(norm);
    this.#applyInteractions(categoryScores, conservativeMode);

    let risk = 0;
    for (const value of Object.values(categoryScores)) {
      risk = 1 - ((1 - risk) * (1 - Math.max(0, Math.min(1, value))));
    }

    const severity = severityFromRisk(risk);
    const reject = severityRank(severity) >= severityRank(this.config.rejectAt);

    findings.sort((a, b) => (b.evidence * b.weight) - (a.evidence * a.weight));
    const categorySorted = Object.fromEntries(
      Object.entries(categoryScores).sort((a, b) => b[1] - a[1])
    );

    return {
      target,
      risk: Number(risk.toFixed(6)),
      severity,
      reject,
      category_scores: Object.fromEntries(
        Object.entries(categorySorted).map(([k, v]) => [k, Number(v.toFixed(6))])
      ),
      findings: findings.slice(0, 40).map((f) => ({
        ...f,
        similarity: Number(f.similarity.toFixed(6)),
        evidence: Number(f.evidence.toFixed(6)),
      })),
      rule_hits: ruleHits,
    };
  }

  #applyHighConfidenceRulePromotions(categoryScores, ruleHits) {
    for (const hit of ruleHits) {
      if (!["credential_exfil", "network_exfil", "policy_evasion", "tool_misuse", "data_siphon", "persistence"].includes(hit.category)) {
        continue;
      }
      if (hit.weight >= 0.50) {
        categoryScores[hit.category] = Math.max(categoryScores[hit.category] ?? 0, 0.76);
      } else if (hit.weight >= 0.45) {
        categoryScores[hit.category] = Math.max(categoryScores[hit.category] ?? 0, 0.60);
      }
    }
  }

  #applySafeIntentAdjustments(categoryScores, text, ruleHits) {
    const hasNonPersistenceHard = ruleHits.some((r) =>
      (["credential_exfil", "network_exfil", "policy_evasion"].includes(r.category) && r.weight >= 0.30)
      || (["tool_misuse", "data_siphon"].includes(r.category) && r.weight >= 0.40)
    );
    const hasPersistenceHard = ruleHits.some((r) => r.category === "persistence" && r.weight >= 0.40);
    let hasHardRuleHit = hasNonPersistenceHard || hasPersistenceHard;

    const hasPersistenceLexicalHit = ruleHits.some((r) => r.category === "persistence");
    if (!hasPersistenceLexicalHit && categoryScores.persistence !== undefined) {
      categoryScores.persistence = Math.min(categoryScores.persistence, 0.35);
    }

    const safetyPatterns = [
      /\bdo not\b[\s\S]{0,30}\b(transmit|send|upload|share|exfiltrat|expose|leak|execute)\b/i,
      /\b(do not|never|without)\s+(export|dump|copy|download)\b/i,
      /\b(do not access external services|no external services|no outbound network|do not call external endpoints?)\b/i,
      /\b(never\s+exfiltrat|do not collect secrets|keep all data local|for defensive testing only)\b/i,
      /\b(non[-\s]?secret|non[-\s]?sensitive|redact(?:ed)? secrets?)\b/i,
      /\b(approved internal (?:infrastructure|network|systems?)|internal security review)\b/i,
    ];

    const safetySignals = safetyPatterns.reduce((acc, p) => acc + (p.test(text) ? 1 : 0), 0);
    const defensiveContext = hasDefensiveContext(text);
    const overtMaliciousIntent = hasOvertMaliciousIntent(text);
    const educationalObfuscationContext = /\b(training note|attackers may use|for detection|detect and block|block this pattern|do not execute)\b/i.test(text);
    const persistenceMitigation = /\b(audit|harden|remove|disable|block|prevent)\b[\s\S]{0,60}\b(cron|startup|autostart|persistence|backdoor|scheduled task|launchd|systemd)\b/i.test(text);

    if (persistenceMitigation && hasPersistenceHard && !hasNonPersistenceHard) {
      categoryScores.persistence = Math.min(categoryScores.persistence ?? 0, 0.28);
      hasHardRuleHit = false;
    }

    if (hasHardRuleHit && !(defensiveContext && safetySignals >= 1 && !overtMaliciousIntent)) {
      return;
    }

    if (safetySignals <= 0 && !defensiveContext) {
      return;
    }

    let dampFactor = 0.70;
    if (safetySignals > 1) dampFactor = 0.45;
    if (defensiveContext && safetySignals === 0) dampFactor = 0.75;

    for (const category of ["credential_exfil", "network_exfil", "policy_evasion", "persistence", "data_siphon", "obfuscation"]) {
      if (categoryScores[category] !== undefined) {
        categoryScores[category] *= dampFactor;
      }
    }

    if (educationalObfuscationContext && defensiveContext && !overtMaliciousIntent) {
      const caps = {
        network_exfil: 0.34,
        obfuscation: 0.34,
        credential_exfil: 0.34,
        policy_evasion: 0.30,
        tool_misuse: 0.30,
      };
      for (const [cat, cap] of Object.entries(caps)) {
        if (categoryScores[cat] !== undefined) {
          categoryScores[cat] = Math.min(categoryScores[cat], cap);
        }
      }
    }
  }

  #applyInteractions(categoryScores, conservativeMode) {
    const bump = (cat, amount) => {
      const prev = categoryScores[cat] ?? 0;
      categoryScores[cat] = Math.max(prev, Math.min(1, prev + amount));
    };

    if ((categoryScores.credential_exfil ?? 0) > 0.25 && (categoryScores.network_exfil ?? 0) > 0.25) {
      bump("credential_exfil", 0.24);
      bump("network_exfil", 0.24);
    }

    if (!conservativeMode && (categoryScores.policy_evasion ?? 0) > 0.35 && (categoryScores.tool_misuse ?? 0) > 0.35) {
      bump("policy_evasion", 0.15);
      bump("tool_misuse", 0.15);
    }

    if (!conservativeMode && (categoryScores.policy_evasion ?? 0) > 0.25
      && ((categoryScores.network_exfil ?? 0) > 0.20 || (categoryScores.credential_exfil ?? 0) > 0.20)) {
      bump("policy_evasion", 0.20);
      bump("network_exfil", 0.12);
      bump("credential_exfil", 0.12);
    }

    if (!conservativeMode && (categoryScores.data_siphon ?? 0) > 0.20 && (categoryScores.network_exfil ?? 0) > 0.20) {
      bump("data_siphon", 0.22);
      bump("network_exfil", 0.22);
    }

    if (!conservativeMode && (categoryScores.tool_misuse ?? 0) > 0.30 && (categoryScores.network_exfil ?? 0) > 0.25) {
      bump("tool_misuse", 0.20);
      bump("network_exfil", 0.20);
    }

    if (!conservativeMode && (categoryScores.obfuscation ?? 0) > 0.30
      && ((categoryScores.tool_misuse ?? 0) > 0.25 || (categoryScores.network_exfil ?? 0) > 0.25)) {
      bump("obfuscation", 0.15);
      bump("tool_misuse", 0.10);
      bump("network_exfil", 0.10);
    }

    if ((categoryScores.persistence ?? 0) > 0.25) {
      bump("persistence", 0.25);
    }

    if ((categoryScores.persistence ?? 0) > 0.55 && (categoryScores.network_exfil ?? 0) > 0.35) {
      bump("persistence", 0.25);
      bump("network_exfil", 0.25);
    }
  }
}
