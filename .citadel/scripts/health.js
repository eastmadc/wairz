#!/usr/bin/env node

/**
 * health.js — Output a single JSON health blob to stdout.
 *
 * Usage:
 *   node scripts/health.js
 *
 * Reads from .planning/ and .claude/ to produce a snapshot of harness state.
 * Designed as a heartbeat endpoint for the UI or monitoring scripts.
 * Gracefully degrades when telemetry files are absent.
 */

'use strict';

const {
  readCampaignStats,
  readFleetStats,
  readHooksStats,
  readTelemetryFileStats,
  readCoordinationStats,
  readTokenEconomics,
} = require('./telemetry-stats.js');

function main() {
  const report = {
    timestamp: new Date().toISOString(),
    campaigns: readCampaignStats(),
    fleet: readFleetStats(),
    hooks: readHooksStats(),
    telemetry: readTelemetryFileStats(),
    coordination: readCoordinationStats(),
    token_economics: readTokenEconomics(),
  };

  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

main();
