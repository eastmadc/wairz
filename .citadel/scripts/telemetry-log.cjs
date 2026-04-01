#!/usr/bin/env node

/**
 * telemetry-log.cjs — Log agent run events to JSONL.
 *
 * Usage:
 *   node scripts/telemetry-log.cjs --event <type> --agent <name> [--session <id>] [--meta <json>]
 *
 * Events: agent-start, agent-complete, agent-fail, campaign-start, campaign-complete,
 *         wave-start, wave-complete, agent-timeout
 */

const fs = require('fs');
const path = require('path');
const { SCHEMA_VERSION, validateAgentRunEvent } = require('./telemetry-schema.js');

const PROJECT_ROOT = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const LOG_FILE = path.join(PROJECT_ROOT, '.planning', 'telemetry', 'agent-runs.jsonl');

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key === '--event') { args.event = val; i++; }
    else if (key === '--agent') { args.agent = val; i++; }
    else if (key === '--session') { args.session = val; i++; }
    else if (key === '--duration') { args.duration = parseInt(val, 10); i++; }
    else if (key === '--status') { args.status = val; i++; }
    else if (key === '--meta') {
      try { args.meta = JSON.parse(val); } catch { args.meta = val; }
      i++;
    }
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv);

  if (!args.event) {
    console.error('Usage: node scripts/telemetry-log.cjs --event <type> --agent <name>');
    process.exit(1);
  }

  const entry = {
    schema: SCHEMA_VERSION,
    timestamp: new Date().toISOString(),
    event: args.event,
    agent: args.agent || 'unknown',
    session: args.session || null,
    duration_ms: args.duration || null,
    status: args.status || null,
    meta: args.meta || null,
  };

  const { valid, errors } = validateAgentRunEvent(entry);
  if (!valid) {
    process.stderr.write(`[telemetry-log] WARNING: invalid event schema — ${errors.join('; ')}\n`);
  }

  const dir = path.dirname(LOG_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');

  if (args.event === 'agent-complete' || args.event === 'campaign-complete') {
    console.log(`Logged: ${args.event} for ${args.agent}`);
  }
}

main();
