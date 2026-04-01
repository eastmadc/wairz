#!/usr/bin/env node

/**
 * compress-discovery.cjs — Extract structured discovery briefs from agent outputs.
 *
 * Takes raw agent output (markdown) and produces a compressed discovery brief
 * targeted under 500 tokens (~2000 chars). Used by Fleet Commander between waves
 * to auto-inject context into the next wave's agents.
 *
 * Usage:
 *   node scripts/compress-discovery.cjs --input output.md [--output brief.md]
 *   echo "agent output..." | node scripts/compress-discovery.cjs --agent wave1-builder
 *
 * Output format:
 *   ## Agent: {agent-name}
 *   **Status:** complete | partial | failed
 *   **Built:** 1-2 sentences of what was done
 *   **Decisions:** architectural choices (1 line each)
 *   **Discoveries:** things other agents need to know (1 line each)
 *   **Failures:** what broke and why (omitted if none)
 *   **Remaining:** unfinished scope (omitted if none)
 *   **Files:** list of created/modified files (critical paths only)
 */

const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const BRIEFS_DIR = path.join(PROJECT_ROOT, '.planning', 'fleet', 'briefs');
const STATS_FILE = path.join(PROJECT_ROOT, '.planning', 'telemetry', 'compression-stats.jsonl');

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key === '--input') { args.input = val; i++; }
    else if (key === '--output') { args.output = val; i++; }
    else if (key === '--session') { args.session = val; i++; }
    else if (key === '--agent') { args.agent = val; i++; }
    else if (key === '--wave') { args.wave = parseInt(val, 10); i++; }
    else if (key === '--status') { args.status = val; i++; }
  }
  return args;
}

// ── Section Extractors ───────────────────────────────────────────────────────

function extractHandoff(text) {
  const match = text.match(/---\s*HANDOFF\s*---\s*\n([\s\S]*?)(?:\n---|$)/i);
  if (!match) return null;
  return match[1].trim().split('\n')
    .map(l => l.replace(/^[-*]\s*/, '').trim())
    .filter(Boolean);
}

function extractDecisions(text) {
  const decisions = [];
  // Look for "Decision:" or "Decided:" patterns
  const lines = text.split('\n');
  for (const line of lines) {
    if (/\b(decided|decision|chose|chosen|picked)\b/i.test(line) && line.length < 200) {
      decisions.push(line.replace(/^[-*]\s*/, '').trim());
    }
  }
  return decisions.slice(0, 5);
}

function extractFiles(text) {
  const files = new Set();
  const filePatterns = text.match(/(?:src|lib|app|pages|components|api|test|spec)\/[\w\-./]+\.\w+/g);
  if (filePatterns) {
    for (const f of filePatterns) files.add(f);
  }
  return [...files].slice(0, 10);
}

function extractFailures(text) {
  const failures = [];
  const lines = text.split('\n');
  for (const line of lines) {
    if (/\b(failed|error|broke|broken|couldn't|cannot|blocked)\b/i.test(line) && line.length < 200) {
      failures.push(line.replace(/^[-*]\s*/, '').trim());
    }
  }
  return failures.slice(0, 3);
}

// ── Compression ──────────────────────────────────────────────────────────────

function compress(rawText, agentName, status) {
  const handoff = extractHandoff(rawText);
  const decisions = extractDecisions(rawText);
  const files = extractFiles(rawText);
  const failures = extractFailures(rawText);

  const lines = [`## Agent: ${agentName || 'unknown'}`];
  lines.push(`**Status:** ${status || (failures.length > 0 ? 'partial' : 'complete')}`);

  if (handoff && handoff.length > 0) {
    lines.push(`**Built:** ${handoff.slice(0, 2).join('. ')}`);
    if (handoff.length > 2) {
      lines.push(`**Remaining:** ${handoff.slice(2).join('; ')}`);
    }
  }

  if (decisions.length > 0) {
    lines.push('**Decisions:**');
    for (const d of decisions) lines.push(`- ${d}`);
  }

  if (failures.length > 0) {
    lines.push('**Failures:**');
    for (const f of failures) lines.push(`- ${f}`);
  }

  if (files.length > 0) {
    lines.push(`**Files:** ${files.join(', ')}`);
  }

  return lines.join('\n');
}

// ── Main ─────────────────────────────────────────────────────────────────────

function main() {
  const args = parseArgs(process.argv);

  let rawText = '';

  if (args.input) {
    rawText = fs.readFileSync(args.input, 'utf8');
  } else {
    // Read from stdin
    rawText = fs.readFileSync(0, 'utf8');
  }

  const brief = compress(rawText, args.agent, args.status);

  // Log compression stats
  try {
    const dir = path.dirname(STATS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const stat = JSON.stringify({
      timestamp: new Date().toISOString(),
      agent: args.agent || 'unknown',
      inputChars: rawText.length,
      outputChars: brief.length,
      ratio: (brief.length / rawText.length).toFixed(3),
    });
    fs.appendFileSync(STATS_FILE, stat + '\n');
  } catch { /* non-critical */ }

  if (args.output) {
    const outDir = path.dirname(args.output);
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(args.output, brief);
    console.log(`Brief written to ${args.output} (${brief.length} chars)`);
  } else {
    process.stdout.write(brief);
  }
}

main();
