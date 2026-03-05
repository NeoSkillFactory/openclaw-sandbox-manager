#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const PROFILES_PATH = path.join(__dirname, '..', 'references', 'security-profiles.json');

class SecurityIsolator {
  constructor() {
    this.profiles = this._loadProfiles();
  }

  _loadProfiles() {
    const raw = fs.readFileSync(PROFILES_PATH, 'utf8');
    const data = JSON.parse(raw);
    return data.profiles;
  }

  getProfile(profileName) {
    const profile = this.profiles[profileName];
    if (!profile) {
      const available = Object.keys(this.profiles).join(', ');
      throw new Error(`Unknown security profile "${profileName}". Available: ${available}`);
    }
    return { ...profile };
  }

  listProfiles() {
    return Object.entries(this.profiles).map(([key, profile]) => ({
      name: key,
      description: profile.description,
    }));
  }

  generatePolicy(profileName, overrides = {}) {
    const profile = this.getProfile(profileName);

    if (overrides.network) {
      profile.network = { ...profile.network, ...overrides.network };
    }
    if (overrides.resources) {
      profile.resources = { ...profile.resources, ...overrides.resources };
    }
    if (overrides.filesystem) {
      profile.filesystem = { ...profile.filesystem, ...overrides.filesystem };
    }

    return {
      profileName: profile.name,
      appliedAt: new Date().toISOString(),
      network: profile.network,
      resources: profile.resources,
      filesystem: profile.filesystem,
      rules: this._generateAccessRules(profile),
    };
  }

  _generateAccessRules(profile) {
    const rules = [];

    if (!profile.network.allowOutbound) {
      rules.push({ type: 'network', action: 'deny', direction: 'outbound', target: '*' });
    }
    if (!profile.network.allowInbound) {
      rules.push({ type: 'network', action: 'deny', direction: 'inbound', target: '*' });
    }
    for (const host of (profile.network.allowedHosts || [])) {
      if (host !== '*') {
        rules.push({ type: 'network', action: 'allow', direction: 'outbound', target: host });
      }
    }

    for (const p of (profile.filesystem.denied || [])) {
      rules.push({ type: 'filesystem', action: 'deny', path: p });
    }
    for (const p of (profile.filesystem.readOnly || [])) {
      rules.push({ type: 'filesystem', action: 'readonly', path: p });
    }

    rules.push({
      type: 'resource',
      action: 'limit',
      limits: {
        maxMemoryMB: profile.resources.maxMemoryMB,
        maxCpuPercent: profile.resources.maxCpuPercent,
        maxProcesses: profile.resources.maxProcesses,
        maxOpenFiles: profile.resources.maxOpenFiles,
      },
    });

    return rules;
  }

  validatePolicy(policy) {
    const errors = [];

    if (!policy.network) errors.push('Missing network configuration');
    if (!policy.resources) errors.push('Missing resources configuration');
    if (!policy.filesystem) errors.push('Missing filesystem configuration');

    if (policy.resources) {
      if (policy.resources.maxMemoryMB < 64) {
        errors.push('maxMemoryMB must be at least 64');
      }
      if (policy.resources.maxCpuPercent < 5 || policy.resources.maxCpuPercent > 100) {
        errors.push('maxCpuPercent must be between 5 and 100');
      }
      if (policy.resources.maxProcesses < 1) {
        errors.push('maxProcesses must be at least 1');
      }
    }

    return { valid: errors.length === 0, errors };
  }
}

module.exports = SecurityIsolator;
