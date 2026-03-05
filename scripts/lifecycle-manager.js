#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

class LifecycleManager {
  constructor(sandboxBaseDir) {
    this.sandboxBaseDir = sandboxBaseDir;
  }

  _loadConfig(sandboxId) {
    const configPath = path.join(this.sandboxBaseDir, sandboxId, 'sandbox.json');
    if (!fs.existsSync(configPath)) {
      throw new Error(`Sandbox "${sandboxId}" not found`);
    }
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }

  _saveConfig(sandboxId, config) {
    const configPath = path.join(this.sandboxBaseDir, sandboxId, 'sandbox.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  _writeAuditLog(sandboxId, event, data = {}) {
    const logFile = path.join(this.sandboxBaseDir, sandboxId, 'logs', 'audit.log');
    const logDir = path.dirname(logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    const entry = { timestamp: new Date().toISOString(), event, data };
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  }

  start(sandboxId) {
    const config = this._loadConfig(sandboxId);

    if (config.status === 'running') {
      throw new Error(`Sandbox "${sandboxId}" is already running`);
    }
    if (config.status === 'destroyed') {
      throw new Error(`Sandbox "${sandboxId}" has been destroyed and cannot be started`);
    }

    config.status = 'running';
    config.startedAt = new Date().toISOString();
    this._saveConfig(sandboxId, config);
    this._writeAuditLog(sandboxId, 'sandbox.start', { sandboxId });

    return { sandboxId, status: 'running', startedAt: config.startedAt };
  }

  stop(sandboxId) {
    const config = this._loadConfig(sandboxId);

    if (config.status !== 'running') {
      throw new Error(`Sandbox "${sandboxId}" is not running (current status: ${config.status})`);
    }

    config.status = 'stopped';
    config.stoppedAt = new Date().toISOString();
    this._saveConfig(sandboxId, config);
    this._writeAuditLog(sandboxId, 'sandbox.stop', { sandboxId });

    return { sandboxId, status: 'stopped', stoppedAt: config.stoppedAt };
  }

  destroy(sandboxId) {
    const config = this._loadConfig(sandboxId);

    if (config.status === 'running') {
      this.stop(sandboxId);
    }

    config.status = 'destroyed';
    config.destroyedAt = new Date().toISOString();
    this._saveConfig(sandboxId, config);
    this._writeAuditLog(sandboxId, 'sandbox.destroy', { sandboxId });

    return { sandboxId, status: 'destroyed', destroyedAt: config.destroyedAt };
  }

  status(sandboxId) {
    const config = this._loadConfig(sandboxId);
    return {
      sandboxId: config.id,
      status: config.status,
      template: config.template,
      securityProfile: config.securityProfile,
      createdAt: config.createdAt,
      startedAt: config.startedAt || null,
      stoppedAt: config.stoppedAt || null,
      destroyedAt: config.destroyedAt || null,
    };
  }

  list() {
    if (!fs.existsSync(this.sandboxBaseDir)) {
      return [];
    }

    const entries = fs.readdirSync(this.sandboxBaseDir, { withFileTypes: true });
    const sandboxes = [];

    for (const entry of entries) {
      if (!entry.isDirectory() || !entry.name.startsWith('sb-')) continue;
      const configPath = path.join(this.sandboxBaseDir, entry.name, 'sandbox.json');
      if (!fs.existsSync(configPath)) continue;

      try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        sandboxes.push({
          sandboxId: config.id,
          status: config.status,
          template: config.template,
          createdAt: config.createdAt,
        });
      } catch {
        // Skip corrupted configs
      }
    }

    return sandboxes;
  }

  cleanup(sandboxId) {
    const sandboxDir = path.join(this.sandboxBaseDir, sandboxId);
    if (!fs.existsSync(sandboxDir)) {
      throw new Error(`Sandbox "${sandboxId}" not found`);
    }

    const config = this._loadConfig(sandboxId);
    if (config.status === 'running') {
      throw new Error(`Cannot cleanup running sandbox "${sandboxId}". Stop it first.`);
    }

    fs.rmSync(sandboxDir, { recursive: true, force: true });
    return { sandboxId, cleaned: true };
  }
}

module.exports = LifecycleManager;
