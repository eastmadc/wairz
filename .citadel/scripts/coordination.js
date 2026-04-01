#!/usr/bin/env node

/**
 * coordination.js — Multi-instance coordination CLI
 *
 * File-based coordination for multiple Archon/Fleet instances running simultaneously.
 * Prevents scope collisions when parallel agents edit the same files.
 *
 * Usage:
 *   node scripts/coordination.js <command> [options]
 *
 * Commands:
 *   generate-id                          Generate a unique instance ID
 *   register   --id <id>                 Register an active instance
 *   unregister --id <id>                 Remove instance registration
 *   heartbeat  --id <id>                 Update lastSeen timestamp
 *   claim      --id <id> --scope <dirs>  Claim a work scope (comma-separated dirs)
 *              --type <type> --desc <d>  Campaign type and description
 *   release    --id <id>                 Release an instance's claim
 *   check-overlap --scope <dirs>         Check if scope overlaps with active claims
 *   sweep                                Recovery sweep: release claims from dead instances
 *   status                               Show all active instances and claims
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── Paths ────────────────────────────────────────────────────────────────────

const ROOT = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const COORD_DIR = path.join(ROOT, '.planning', 'coordination');
const INSTANCES_DIR = path.join(COORD_DIR, 'instances');
const CLAIMS_DIR = path.join(COORD_DIR, 'claims');

const STALE_INSTANCE_MS = 2 * 60 * 60 * 1000; // 2 hours

// ── Helpers ──────────────────────────────────────────────────────────────────

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function writeJsonAtomic(filePath, data) {
  const tmp = filePath + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, filePath);
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function listJsonFiles(dir) {
  ensureDir(dir);
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json') && !f.startsWith('.'))
    .map(f => ({ name: f, path: path.join(dir, f), data: readJson(path.join(dir, f)) }))
    .filter(f => f.data !== null);
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function scopesOverlap(scopeA, scopeB) {
  for (const a of scopeA) {
    if (a.endsWith('(read-only)')) continue;
    const cleanA = a.replace(/\(read-only\)$/, '').trim();
    for (const b of scopeB) {
      if (b.endsWith('(read-only)')) continue;
      const cleanB = b.replace(/\(read-only\)$/, '').trim();
      // Parent/child overlap
      if (cleanA.startsWith(cleanB) || cleanB.startsWith(cleanA)) return true;
    }
  }
  return false;
}

// ── Commands ─────────────────────────────────────────────────────────────────

function generateId() {
  const id = 'agent-' + crypto.randomBytes(4).toString('hex');
  console.log(id);
  return id;
}

function register(id) {
  ensureDir(INSTANCES_DIR);
  const data = {
    instanceId: id,
    startedAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    status: 'active',
    pid: process.ppid || process.pid,
    campaignSlug: null,
  };
  writeJsonAtomic(path.join(INSTANCES_DIR, `${id}.json`), data);
  console.log(`Registered instance: ${id}`);
}

function unregister(id) {
  const file = path.join(INSTANCES_DIR, `${id}.json`);
  if (fs.existsSync(file)) fs.unlinkSync(file);
  // Also release any claims
  const claimFile = path.join(CLAIMS_DIR, `${id}.json`);
  if (fs.existsSync(claimFile)) fs.unlinkSync(claimFile);
  console.log(`Unregistered instance: ${id}`);
}

function heartbeat(id) {
  const file = path.join(INSTANCES_DIR, `${id}.json`);
  const data = readJson(file);
  if (!data) {
    console.error(`Instance not found: ${id}`);
    process.exit(1);
  }
  data.lastSeen = new Date().toISOString();
  writeJsonAtomic(file, data);
}

function claim(id, scope, type, desc) {
  ensureDir(CLAIMS_DIR);

  // Check for overlaps
  const existingClaims = listJsonFiles(CLAIMS_DIR);
  for (const existing of existingClaims) {
    if (existing.data.instanceId === id) continue;
    if (scopesOverlap(scope, existing.data.scope || [])) {
      console.error(`Scope overlap with ${existing.data.instanceId}: ${existing.data.scope.join(', ')}`);
      process.exit(1);
    }
  }

  const data = {
    instanceId: id,
    type: type || 'unknown',
    scope,
    description: desc || '',
    claimedAt: new Date().toISOString(),
  };
  writeJsonAtomic(path.join(CLAIMS_DIR, `${id}.json`), data);
  console.log(`Claimed scope: ${scope.join(', ')}`);
}

function release(id) {
  const file = path.join(CLAIMS_DIR, `${id}.json`);
  if (fs.existsSync(file)) {
    fs.unlinkSync(file);
    console.log(`Released claim for: ${id}`);
  } else {
    console.log(`No claim found for: ${id}`);
  }
}

function checkOverlap(scope) {
  const existingClaims = listJsonFiles(CLAIMS_DIR);
  for (const existing of existingClaims) {
    if (scopesOverlap(scope, existing.data.scope || [])) {
      console.log(`OVERLAP with ${existing.data.instanceId}: ${existing.data.scope.join(', ')}`);
      process.exit(1);
    }
  }
  console.log('No overlap detected');
}

function sweep() {
  const instances = listJsonFiles(INSTANCES_DIR);
  const now = Date.now();
  let cleaned = 0;

  for (const inst of instances) {
    const lastSeen = new Date(inst.data.lastSeen).getTime();
    const isStale = (now - lastSeen) > STALE_INSTANCE_MS;
    const isDead = inst.data.pid && !isProcessAlive(inst.data.pid);

    if (isStale || isDead) {
      fs.unlinkSync(inst.path);
      const claimFile = path.join(CLAIMS_DIR, inst.name);
      if (fs.existsSync(claimFile)) fs.unlinkSync(claimFile);
      cleaned++;
      console.log(`Swept: ${inst.data.instanceId} (${isDead ? 'dead process' : 'stale'})`);
    }
  }

  console.log(`Sweep complete. Cleaned ${cleaned} instance(s).`);
}

function status() {
  const instances = listJsonFiles(INSTANCES_DIR);
  const claims = listJsonFiles(CLAIMS_DIR);

  console.log('\n=== Active Instances ===');
  if (instances.length === 0) {
    console.log('  (none)');
  } else {
    for (const inst of instances) {
      console.log(`  ${inst.data.instanceId} | status: ${inst.data.status} | since: ${inst.data.startedAt}`);
    }
  }

  console.log('\n=== Active Claims ===');
  if (claims.length === 0) {
    console.log('  (none)');
  } else {
    for (const cl of claims) {
      console.log(`  ${cl.data.instanceId} | scope: ${(cl.data.scope || []).join(', ')} | type: ${cl.data.type}`);
    }
  }
  console.log('');
}

// ── CLI ──────────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = {};
  const argv = process.argv.slice(2);
  args.command = argv[0];

  for (let i = 1; i < argv.length; i++) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key === '--id') { args.id = val; i++; }
    else if (key === '--scope') { args.scope = val.split(',').map(s => s.trim()); i++; }
    else if (key === '--type') { args.type = val; i++; }
    else if (key === '--desc') { args.desc = val; i++; }
  }
  return args;
}

const args = parseArgs();

switch (args.command) {
  case 'generate-id': generateId(); break;
  case 'register': register(args.id); break;
  case 'unregister': unregister(args.id); break;
  case 'heartbeat': heartbeat(args.id); break;
  case 'claim': claim(args.id, args.scope || [], args.type, args.desc); break;
  case 'release': release(args.id); break;
  case 'check-overlap': checkOverlap(args.scope || []); break;
  case 'sweep': sweep(); break;
  case 'status': status(); break;
  default:
    console.log('Usage: node scripts/coordination.js <command> [options]');
    console.log('Commands: generate-id, register, unregister, heartbeat, claim, release, check-overlap, sweep, status');
    process.exit(1);
}
