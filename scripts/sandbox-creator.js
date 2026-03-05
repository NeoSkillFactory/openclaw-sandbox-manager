#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const SecurityIsolator = require('./security-isolator');

const TEMPLATES_DIR = path.join(__dirname, '..', 'references', 'sandbox-templates');

class SandboxCreator {
  constructor(sandboxBaseDir) {
    this.sandboxBaseDir = sandboxBaseDir;
    this.isolator = new SecurityIsolator();
  }

  listTemplates() {
    const files = fs.readdirSync(TEMPLATES_DIR).filter(f => f.endsWith('.yml'));
    return files.map(f => {
      const content = fs.readFileSync(path.join(TEMPLATES_DIR, f), 'utf8');
      const name = this._parseYamlField(content, 'name');
      const description = this._parseYamlField(content, 'description');
      return { file: f, name, description };
    });
  }

  loadTemplate(templateName) {
    const filePath = path.join(TEMPLATES_DIR, `${templateName}.yml`);
    if (!fs.existsSync(filePath)) {
      const available = this.listTemplates().map(t => t.name).join(', ');
      throw new Error(`Template "${templateName}" not found. Available: ${available}`);
    }
    const content = fs.readFileSync(filePath, 'utf8');
    return {
      name: this._parseYamlField(content, 'name'),
      description: this._parseYamlField(content, 'description'),
      securityProfile: this._parseYamlField(content, 'securityProfile'),
      raw: content,
    };
  }

  create(templateName, configOverrides = {}) {
    const template = this.loadTemplate(templateName);
    const sandboxId = this._generateId();
    const sandboxDir = path.join(this.sandboxBaseDir, sandboxId);

    fs.mkdirSync(sandboxDir, { recursive: true });
    fs.mkdirSync(path.join(sandboxDir, 'workspace'), { recursive: true });
    fs.mkdirSync(path.join(sandboxDir, 'shared'), { recursive: true });
    fs.mkdirSync(path.join(sandboxDir, 'logs'), { recursive: true });

    const profileName = configOverrides.securityProfile || template.securityProfile;
    const policy = this.isolator.generatePolicy(profileName, configOverrides.policyOverrides || {});

    const validation = this.isolator.validatePolicy(policy);
    if (!validation.valid) {
      fs.rmSync(sandboxDir, { recursive: true, force: true });
      throw new Error(`Invalid security policy: ${validation.errors.join(', ')}`);
    }

    const config = {
      id: sandboxId,
      template: template.name,
      securityProfile: profileName,
      policy,
      createdAt: new Date().toISOString(),
      status: 'created',
      workdir: path.join(sandboxDir, 'workspace'),
      logdir: path.join(sandboxDir, 'logs'),
    };

    const configPath = path.join(sandboxDir, 'sandbox.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    this._writeAuditLog(sandboxDir, 'sandbox.create', { sandboxId, template: template.name, profileName });

    return { sandboxId, sandboxDir, configPath, config };
  }

  _generateId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `sb-${timestamp}-${random}`;
  }

  _parseYamlField(content, field) {
    const regex = new RegExp(`^${field}:\\s*(.+)$`, 'm');
    const match = content.match(regex);
    return match ? match[1].trim().replace(/^["']|["']$/g, '') : '';
  }

  _writeAuditLog(sandboxDir, event, data) {
    const logDir = path.join(sandboxDir, 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
    };
    const logFile = path.join(logDir, 'audit.log');
    const line = JSON.stringify(logEntry) + '\n';
    fs.appendFileSync(logFile, line);
  }
}

module.exports = SandboxCreator;
