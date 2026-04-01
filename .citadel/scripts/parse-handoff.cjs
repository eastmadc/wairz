#!/usr/bin/env node

/**
 * parse-handoff.cjs — Extract HANDOFF blocks from agent output.
 *
 * Parses the structured handoff format that agents produce at the end
 * of their work. Used by orchestrators (Archon, Fleet) to update
 * campaign ledgers and fleet session files.
 *
 * Usage:
 *   node scripts/parse-handoff.cjs --input agent-output.md
 *   echo "agent output..." | node scripts/parse-handoff.cjs
 *
 * Output: JSON with { items: string[], raw: string }
 */

const fs = require('fs');

function parseHandoff(text) {
  const match = text.match(/---\s*HANDOFF\s*---\s*\n([\s\S]*?)(?:\n---|\Z)/i);
  if (!match) {
    return { found: false, items: [], raw: '' };
  }

  const raw = match[1].trim();
  const items = raw.split('\n')
    .map(line => line.replace(/^[-*]\s*/, '').trim())
    .filter(Boolean);

  return { found: true, items, raw };
}

function main() {
  const args = process.argv.slice(2);
  let inputFile = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      inputFile = args[i + 1];
      i++;
    }
  }

  let text;
  if (inputFile) {
    text = fs.readFileSync(inputFile, 'utf8');
  } else {
    text = fs.readFileSync(0, 'utf8');
  }

  const result = parseHandoff(text);
  process.stdout.write(JSON.stringify(result, null, 2));
}

main();
