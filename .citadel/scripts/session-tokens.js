#!/usr/bin/env node

/**
 * session-tokens.js -- Read real token usage from Claude Code session JSONL files.
 *
 * Claude Code stores per-message token data in:
 *   ~/.claude/projects/{project-slug}/{sessionId}.jsonl
 *   ~/.claude/projects/{project-slug}/{sessionId}/subagents/agent-{id}.jsonl
 *
 * Each assistant message includes:
 *   message.usage.input_tokens
 *   message.usage.output_tokens
 *   message.usage.cache_creation_input_tokens
 *   message.usage.cache_read_input_tokens
 *   message.model (e.g. "claude-opus-4-6")
 *
 * This module sums tokens per session and computes real cost using API pricing.
 *
 * Usage:
 *   const { readSessionTokens, computeCost } = require('./session-tokens');
 *   const tokens = readSessionTokens(sessionId);   // { input, output, cacheCreation, cacheRead, model, messages }
 *   const cost = computeCost(tokens);               // dollar amount
 *
 * CLI:
 *   node scripts/session-tokens.js                  # summarize current/latest session
 *   node scripts/session-tokens.js <sessionId>      # summarize specific session
 *   node scripts/session-tokens.js --all            # summarize all sessions
 *   node scripts/session-tokens.js --today          # summarize today's sessions
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ── Pricing (per million tokens, USD) ────────────────────────────────────────
// Loaded from scripts/pricing.json when available, hardcoded fallback otherwise.
// Update pricing.json when Anthropic changes pricing.

const HARDCODED_PRICING = {
  'claude-opus-4-6':   { input: 5.00,  output: 25.00, cacheCreation: 6.25,  cacheRead: 0.50 },
  'claude-sonnet-4-6': { input: 3.00,  output: 15.00, cacheCreation: 3.75,  cacheRead: 0.30 },
  'claude-haiku-4-5':  { input: 1.00,  output: 5.00,  cacheCreation: 1.25,  cacheRead: 0.10 },
  '_default':          { input: 3.00,  output: 15.00, cacheCreation: 3.75,  cacheRead: 0.30 },
};

function loadPricing() {
  try {
    const pricingPath = path.join(__dirname, 'pricing.json');
    if (fs.existsSync(pricingPath)) {
      const data = JSON.parse(fs.readFileSync(pricingPath, 'utf8'));
      // Merge: external file wins, hardcoded fills gaps
      const merged = { ...HARDCODED_PRICING };
      for (const [key, val] of Object.entries(data)) {
        if (key.startsWith('_') && key !== '_default') continue; // skip metadata fields
        if (val && typeof val === 'object' && typeof val.input === 'number') {
          merged[key] = val;
        }
      }
      return merged;
    }
  } catch { /* fall back to hardcoded */ }
  return HARDCODED_PRICING;
}

const PRICING = loadPricing();

// Model name normalization: session files use full model IDs that may include date suffixes
function normalizeModel(model) {
  if (!model) return '_default';
  const m = model.toLowerCase();
  if (m.includes('opus'))   return 'claude-opus-4-6';
  if (m.includes('sonnet')) return 'claude-sonnet-4-6';
  if (m.includes('haiku'))  return 'claude-haiku-4-5';
  return '_default';
}

function getPricing(model) {
  return PRICING[normalizeModel(model)] || PRICING['_default'];
}

// ── Discover session files ───────────────────────────────────────────────────

function getProjectSlug() {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  // Claude Code encodes the project path as a directory slug.
  // On Windows: C:\Users\foo\project -> C--Users-foo-project
  //   (colon becomes dash, backslashes become dashes, leading slash stripped)
  // On Unix: /home/foo/project -> -home-foo-project
  const normalized = projectDir.replace(/\\/g, '/');
  return normalized.replace(/^\//, '').replace(/:/g, '-').replace(/\//g, '-');
}

function getSessionsDir() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const slug = getProjectSlug();
  return path.join(home, '.claude', 'projects', slug);
}

function listSessionIds(sessionsDir) {
  if (!fs.existsSync(sessionsDir)) return [];
  return fs.readdirSync(sessionsDir)
    .filter(f => f.endsWith('.jsonl') && !f.includes('subagent'))
    .map(f => f.replace('.jsonl', ''))
    .sort();
}

// ── Parse token data from JSONL ──────────────────────────────────────────────

function parseTokensFromFile(filePath) {
  if (!fs.existsSync(filePath)) return null;

  const totals = {
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
    messages: 0,
    models: {},
    first_timestamp: null,
    last_timestamp: null,
  };

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');

  for (const line of lines) {
    if (!line.trim()) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }

    const usage = entry.message?.usage;
    if (!usage) continue;

    totals.input_tokens += usage.input_tokens || 0;
    totals.output_tokens += usage.output_tokens || 0;
    totals.cache_creation_input_tokens += usage.cache_creation_input_tokens || 0;
    totals.cache_read_input_tokens += usage.cache_read_input_tokens || 0;
    totals.messages++;

    const model = entry.message?.model || 'unknown';
    totals.models[model] = (totals.models[model] || 0) + 1;

    if (entry.timestamp) {
      if (!totals.first_timestamp || entry.timestamp < totals.first_timestamp) {
        totals.first_timestamp = entry.timestamp;
      }
      if (!totals.last_timestamp || entry.timestamp > totals.last_timestamp) {
        totals.last_timestamp = entry.timestamp;
      }
    }
  }

  return totals.messages > 0 ? totals : null;
}

/**
 * Read token usage for a specific session, including all subagents.
 *
 * @param {string} sessionId - The session UUID
 * @param {string} [sessionsDir] - Override sessions directory
 * @returns {{ main: object, subagents: object[], combined: object } | null}
 */
function readSessionTokens(sessionId, sessionsDir) {
  const dir = sessionsDir || getSessionsDir();
  const mainFile = path.join(dir, `${sessionId}.jsonl`);

  const main = parseTokensFromFile(mainFile);
  if (!main) return null;

  // Check for subagent sessions
  const subagentDir = path.join(dir, sessionId, 'subagents');
  const subagents = [];

  if (fs.existsSync(subagentDir)) {
    const files = fs.readdirSync(subagentDir).filter(f => f.endsWith('.jsonl'));
    for (const f of files) {
      const tokens = parseTokensFromFile(path.join(subagentDir, f));
      if (tokens) {
        subagents.push({
          agentId: f.replace('.jsonl', ''),
          ...tokens,
        });
      }
    }
  }

  // Combine main + subagents
  const combined = {
    input_tokens: main.input_tokens,
    output_tokens: main.output_tokens,
    cache_creation_input_tokens: main.cache_creation_input_tokens,
    cache_read_input_tokens: main.cache_read_input_tokens,
    messages: main.messages,
    models: { ...main.models },
    first_timestamp: main.first_timestamp,
    last_timestamp: main.last_timestamp,
  };

  for (const sub of subagents) {
    combined.input_tokens += sub.input_tokens;
    combined.output_tokens += sub.output_tokens;
    combined.cache_creation_input_tokens += sub.cache_creation_input_tokens;
    combined.cache_read_input_tokens += sub.cache_read_input_tokens;
    combined.messages += sub.messages;
    for (const [model, count] of Object.entries(sub.models)) {
      combined.models[model] = (combined.models[model] || 0) + count;
    }
    if (sub.first_timestamp && (!combined.first_timestamp || sub.first_timestamp < combined.first_timestamp)) {
      combined.first_timestamp = sub.first_timestamp;
    }
    if (sub.last_timestamp && (!combined.last_timestamp || sub.last_timestamp > combined.last_timestamp)) {
      combined.last_timestamp = sub.last_timestamp;
    }
  }

  return { main, subagents, combined };
}

/**
 * Compute dollar cost from token totals.
 * Uses weighted average pricing when multiple models are used.
 *
 * @param {object} tokens - Token totals with models map
 * @returns {number} Cost in USD
 */
function computeCost(tokens) {
  if (!tokens || tokens.messages === 0) return 0;

  // If single model, straightforward calculation
  const modelNames = Object.keys(tokens.models);
  if (modelNames.length <= 1) {
    const pricing = getPricing(modelNames[0]);
    return computeCostWithPricing(tokens, pricing);
  }

  // Multiple models: compute per-model cost proportionally
  // We don't have per-model token breakdowns, so use the dominant model's pricing
  let dominantModel = modelNames[0];
  let maxCount = 0;
  for (const [model, count] of Object.entries(tokens.models)) {
    if (count > maxCount) { maxCount = count; dominantModel = model; }
  }

  const pricing = getPricing(dominantModel);
  return computeCostWithPricing(tokens, pricing);
}

function computeCostWithPricing(tokens, pricing) {
  const M = 1_000_000;
  const cost =
    (tokens.input_tokens / M) * pricing.input +
    (tokens.output_tokens / M) * pricing.output +
    (tokens.cache_creation_input_tokens / M) * pricing.cacheCreation +
    (tokens.cache_read_input_tokens / M) * pricing.cacheRead;
  return Math.round(cost * 10000) / 10000; // 4 decimal places
}

/**
 * Get the most recent session ID for this project.
 * @returns {string|null}
 */
function getLatestSessionId() {
  const dir = getSessionsDir();
  const ids = listSessionIds(dir);
  if (ids.length === 0) return null;

  // Sort by file modification time to find the most recent
  let latest = null;
  let latestMtime = 0;
  for (const id of ids) {
    try {
      const stat = fs.statSync(path.join(dir, `${id}.jsonl`));
      if (stat.mtimeMs > latestMtime) {
        latestMtime = stat.mtimeMs;
        latest = id;
      }
    } catch { continue; }
  }
  return latest;
}

/**
 * Get the current session ID from environment if available.
 * Falls back to most recent session.
 * @returns {string|null}
 */
function getCurrentSessionId() {
  // Claude Code sets CLAUDE_SESSION_ID in some contexts
  if (process.env.CLAUDE_SESSION_ID) return process.env.CLAUDE_SESSION_ID;
  return getLatestSessionId();
}

/**
 * Read all sessions and compute aggregate stats.
 * @param {object} [opts] - Options
 * @param {string} [opts.since] - ISO date string, only include sessions after this
 * @returns {{ sessions: object[], totals: object }}
 */
function readAllSessions(opts = {}) {
  const dir = getSessionsDir();
  const ids = listSessionIds(dir);
  const sessions = [];
  const totals = {
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
    messages: 0,
    total_cost: 0,
    session_count: 0,
    subagent_count: 0,
  };

  for (const id of ids) {
    // Quick mtime check for --since filter
    if (opts.since) {
      try {
        const stat = fs.statSync(path.join(dir, `${id}.jsonl`));
        if (stat.mtime < new Date(opts.since)) continue;
      } catch { continue; }
    }

    const result = readSessionTokens(id, dir);
    if (!result) continue;

    const cost = computeCost(result.combined);
    const duration = result.combined.first_timestamp && result.combined.last_timestamp
      ? (new Date(result.combined.last_timestamp) - new Date(result.combined.first_timestamp)) / 60000
      : 0;

    sessions.push({
      sessionId: id,
      ...result.combined,
      cost,
      duration_minutes: Math.round(duration),
      subagent_count: result.subagents.length,
    });

    totals.input_tokens += result.combined.input_tokens;
    totals.output_tokens += result.combined.output_tokens;
    totals.cache_creation_input_tokens += result.combined.cache_creation_input_tokens;
    totals.cache_read_input_tokens += result.combined.cache_read_input_tokens;
    totals.messages += result.combined.messages;
    totals.total_cost += cost;
    totals.session_count++;
    totals.subagent_count += result.subagents.length;
  }

  totals.total_cost = Math.round(totals.total_cost * 100) / 100;
  return { sessions, totals };
}

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  PRICING,
  normalizeModel,
  getPricing,
  getSessionsDir,
  listSessionIds,
  readSessionTokens,
  computeCost,
  computeCostWithPricing,
  getLatestSessionId,
  getCurrentSessionId,
  readAllSessions,
};

// ── CLI ──────────────────────────────────────────────────────────────────────

if (require.main === module) {
  const args = process.argv.slice(2);

  function formatTokens(n) {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
  }

  function printSession(label, tokens, cost) {
    console.log(`\n  ${label}`);
    console.log(`  Input:          ${formatTokens(tokens.input_tokens)} tokens`);
    console.log(`  Output:         ${formatTokens(tokens.output_tokens)} tokens`);
    console.log(`  Cache creation: ${formatTokens(tokens.cache_creation_input_tokens)} tokens`);
    console.log(`  Cache read:     ${formatTokens(tokens.cache_read_input_tokens)} tokens`);
    console.log(`  Messages:       ${tokens.messages}`);
    console.log(`  Cost:           $${cost.toFixed(4)}`);
    if (tokens.models) {
      const models = Object.entries(tokens.models).map(([m, c]) => `${m} (${c})`).join(', ');
      console.log(`  Models:         ${models}`);
    }
  }

  if (args.includes('--all') || args.includes('--today')) {
    const opts = args.includes('--today')
      ? { since: new Date().toISOString().slice(0, 10) + 'T00:00:00Z' }
      : {};
    const label = args.includes('--today') ? "Today's" : 'All';

    console.log(`\n${label} Sessions (Claude Code Token Data)`);
    console.log('='.repeat(50));

    const { sessions, totals } = readAllSessions(opts);

    if (sessions.length === 0) {
      console.log('\n  No session data found.');
      process.exit(0);
    }

    // Show last 10 sessions in detail
    const shown = sessions.slice(-10);
    if (sessions.length > 10) {
      console.log(`\n  (Showing last 10 of ${sessions.length} sessions)`);
    }

    for (const s of shown) {
      const date = s.first_timestamp ? new Date(s.first_timestamp).toLocaleString() : 'unknown';
      printSession(
        `${s.sessionId.slice(0, 8)}... (${date}, ${s.duration_minutes}min, ${s.subagent_count} agents)`,
        s, s.cost
      );
    }

    console.log('\n' + '-'.repeat(50));
    console.log(`  Total sessions: ${totals.session_count}`);
    console.log(`  Total agents:   ${totals.subagent_count}`);
    console.log(`  Total messages: ${totals.messages}`);
    console.log(`  Total tokens:   ${formatTokens(totals.input_tokens + totals.output_tokens + totals.cache_creation_input_tokens + totals.cache_read_input_tokens)}`);
    console.log(`  Total cost:     $${totals.total_cost.toFixed(2)}`);
    console.log('');
  } else {
    // Single session
    const sessionId = args[0] || getCurrentSessionId();

    if (!sessionId) {
      console.error('No session found. Pass a session ID or run from a Claude Code project.');
      process.exit(1);
    }

    console.log(`\nSession Token Report`);
    console.log('='.repeat(50));
    console.log(`  Session: ${sessionId}`);

    const result = readSessionTokens(sessionId);
    if (!result) {
      console.error(`  No data found for session ${sessionId}`);
      process.exit(1);
    }

    const cost = computeCost(result.combined);
    printSession('Combined (main + subagents)', result.combined, cost);

    if (result.subagents.length > 0) {
      console.log(`\n  Subagents: ${result.subagents.length}`);
      for (const sub of result.subagents) {
        const subCost = computeCost(sub);
        printSession(`  ${sub.agentId}`, sub, subCost);
      }
    }

    const duration = result.combined.first_timestamp && result.combined.last_timestamp
      ? (new Date(result.combined.last_timestamp) - new Date(result.combined.first_timestamp)) / 60000
      : 0;
    if (duration > 0) {
      console.log(`\n  Duration: ${Math.round(duration)} minutes`);
    }
    console.log('');
  }
}
