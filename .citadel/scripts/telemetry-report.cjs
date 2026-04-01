#!/usr/bin/env node

/**
 * telemetry-report.cjs — Generate human-readable telemetry summaries.
 *
 * Usage:
 *   node scripts/telemetry-report.cjs                  Full summary
 *   node scripts/telemetry-report.cjs --last 10        Last N runs
 *   node scripts/telemetry-report.cjs --hooks          Hook timing summary
 *   node scripts/telemetry-report.cjs --compression    Discovery compression stats
 *   node scripts/telemetry-report.cjs --tokens         Token economics section
 */

const fs = require('fs');
const path = require('path');
const { readTokenEconomics } = require('./telemetry-stats.js');

const PROJECT_ROOT = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const TELEMETRY_DIR = path.join(PROJECT_ROOT, '.planning', 'telemetry');
const AGENT_LOG = path.join(TELEMETRY_DIR, 'agent-runs.jsonl');
const HOOK_LOG = path.join(TELEMETRY_DIR, 'hook-timing.jsonl');
const COMPRESSION_LOG = path.join(TELEMETRY_DIR, 'compression-stats.jsonl');

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => {
      try { return JSON.parse(line); } catch { return null; }
    })
    .filter(Boolean);
}

function agentReport(limit) {
  const entries = readJsonl(AGENT_LOG);
  const relevant = limit ? entries.slice(-limit) : entries;

  if (relevant.length === 0) {
    console.log('No agent runs recorded yet.');
    return;
  }

  console.log('\n=== Agent Run Summary ===\n');

  // Count by event type
  const counts = {};
  for (const e of relevant) {
    counts[e.event] = (counts[e.event] || 0) + 1;
  }
  for (const [event, count] of Object.entries(counts)) {
    console.log(`  ${event}: ${count}`);
  }

  // Recent runs
  console.log('\n--- Recent Runs ---\n');
  const recent = relevant.filter(e => e.event === 'agent-complete' || e.event === 'agent-fail').slice(-10);
  for (const e of recent) {
    const duration = e.duration_ms ? `${(e.duration_ms / 1000).toFixed(1)}s` : '?';
    console.log(`  ${e.timestamp.slice(0, 16)} | ${e.agent} | ${e.status || e.event} | ${duration}`);
  }

  console.log(`\nTotal entries: ${entries.length}`);
}

function hookReport() {
  const entries = readJsonl(HOOK_LOG);

  if (entries.length === 0) {
    console.log('No hook timing data recorded yet.');
    return;
  }

  console.log('\n=== Hook Timing Summary ===\n');

  // Group by hook
  const byHook = {};
  for (const e of entries) {
    const key = e.hook || 'unknown';
    if (!byHook[key]) byHook[key] = { count: 0, totalMs: 0, metrics: {} };
    byHook[key].count++;
    if (e.duration_ms) byHook[key].totalMs += e.duration_ms;
    if (e.metric) {
      byHook[key].metrics[e.metric] = (byHook[key].metrics[e.metric] || 0) + 1;
    }
  }

  for (const [hook, data] of Object.entries(byHook)) {
    const avg = data.totalMs > 0 ? `avg ${(data.totalMs / data.count).toFixed(0)}ms` : '';
    console.log(`  ${hook}: ${data.count} events ${avg}`);
    for (const [metric, count] of Object.entries(data.metrics)) {
      console.log(`    ${metric}: ${count}`);
    }
  }
}

function compressionReport() {
  const entries = readJsonl(COMPRESSION_LOG);

  if (entries.length === 0) {
    console.log('No compression stats recorded yet.');
    return;
  }

  console.log('\n=== Discovery Compression Stats ===\n');

  let totalInput = 0, totalOutput = 0;
  for (const e of entries) {
    totalInput += e.inputChars || 0;
    totalOutput += e.outputChars || 0;
  }

  const avgRatio = totalInput > 0 ? (totalOutput / totalInput * 100).toFixed(1) : 0;
  console.log(`  Compressions: ${entries.length}`);
  console.log(`  Total input: ${totalInput} chars`);
  console.log(`  Total output: ${totalOutput} chars`);
  console.log(`  Average ratio: ${avgRatio}%`);

  console.log('\n--- Recent ---\n');
  for (const e of entries.slice(-5)) {
    console.log(`  ${e.agent || '?'}: ${e.inputChars} → ${e.outputChars} chars (${(e.ratio * 100).toFixed(1)}%)`);
  }
}

function tokenReport() {
  const econ = readTokenEconomics();
  const LINE = '\u2500'.repeat(30);

  console.log('\nToken Economics (Estimates)');
  console.log(LINE);

  const routing = econ.routing_savings_estimate;
  if (routing) {
    const resolutions = routing.tier0_resolutions + routing.tier1_resolutions + routing.tier2_resolutions;
    const tokens = routing.tokens_saved_estimate;
    console.log(`Routing savings     ~${tokens.toLocaleString()} tokens (${resolutions} Tier 0-2 resolutions)`);
  } else {
    console.log('Routing savings     N/A (tier data not yet tracked in agent-runs.jsonl)');
  }

  const cb = econ.circuit_breaker_saves;
  console.log(`Circuit breaker     ~${cb.tokens_saved_estimate.toLocaleString()} tokens (${cb.total_trips} trips averted)`);

  const qg = econ.quality_gate_saves;
  console.log(`Quality gates       ~${qg.tokens_saved_estimate.toLocaleString()} tokens (${qg.violations_caught} violation${qg.violations_caught !== 1 ? 's' : ''} caught)`);

  console.log(LINE);
  console.log(`Estimated total     ~${econ.total_estimated_savings.toLocaleString()} tokens saved`);
  console.log('* Estimates. Methodology: docs/token-economics-methodology.md');
  console.log('');
}

// ── CLI ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--hooks')) {
  hookReport();
} else if (args.includes('--compression')) {
  compressionReport();
} else if (args.includes('--tokens')) {
  tokenReport();
} else {
  const lastIdx = args.indexOf('--last');
  const limit = lastIdx >= 0 ? parseInt(args[lastIdx + 1], 10) : null;
  agentReport(limit);
  if (args.includes('--tokens')) tokenReport();
}
