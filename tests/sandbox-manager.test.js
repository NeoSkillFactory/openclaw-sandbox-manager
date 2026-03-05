#!/usr/bin/env node
'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const SandboxCreator = require('../scripts/sandbox-creator');
const LifecycleManager = require('../scripts/lifecycle-manager');
const SecurityIsolator = require('../scripts/security-isolator');

const TEST_DIR = path.join(os.tmpdir(), `sandbox-test-${Date.now()}`);
const MANAGER_SCRIPT = path.join(__dirname, '..', 'scripts', 'sandbox-manager.js');

function runCli(...args) {
  return execFileSync('node', [MANAGER_SCRIPT, ...args], {
    env: { ...process.env, SANDBOX_BASE_DIR: TEST_DIR },
    encoding: 'utf8',
    timeout: 10000,
  });
}

describe('SecurityIsolator', () => {
  let isolator;
  before(() => { isolator = new SecurityIsolator(); });

  it('should list all profiles', () => {
    const profiles = isolator.listProfiles();
    assert.ok(profiles.length >= 3);
    const names = profiles.map(p => p.name);
    assert.ok(names.includes('default'));
    assert.ok(names.includes('strict'));
    assert.ok(names.includes('permissive'));
  });

  it('should get a specific profile', () => {
    const profile = isolator.getProfile('default');
    assert.strictEqual(profile.name, 'default');
    assert.ok(profile.network);
    assert.ok(profile.resources);
    assert.ok(profile.filesystem);
  });

  it('should throw for unknown profile', () => {
    assert.throws(() => isolator.getProfile('nonexistent'), /Unknown security profile/);
  });

  it('should generate a valid policy', () => {
    const policy = isolator.generatePolicy('default');
    assert.ok(policy.profileName);
    assert.ok(policy.appliedAt);
    assert.ok(policy.rules.length > 0);
  });

  it('should apply overrides to policy', () => {
    const policy = isolator.generatePolicy('default', {
      resources: { maxMemoryMB: 1024 },
    });
    assert.strictEqual(policy.resources.maxMemoryMB, 1024);
  });

  it('should validate policies correctly', () => {
    const good = isolator.generatePolicy('default');
    assert.ok(isolator.validatePolicy(good).valid);

    const bad = { network: {}, resources: { maxMemoryMB: 10, maxCpuPercent: 200, maxProcesses: 0 }, filesystem: {} };
    const result = isolator.validatePolicy(bad);
    assert.ok(!result.valid);
    assert.ok(result.errors.length > 0);
  });
});

describe('SandboxCreator', () => {
  let creator;
  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    creator = new SandboxCreator(TEST_DIR);
  });

  it('should list templates', () => {
    const templates = creator.listTemplates();
    assert.ok(templates.length >= 3);
    const names = templates.map(t => t.name);
    assert.ok(names.includes('default'));
    assert.ok(names.includes('dev'));
    assert.ok(names.includes('secure'));
  });

  it('should load a template', () => {
    const template = creator.loadTemplate('default');
    assert.strictEqual(template.name, 'default');
    assert.strictEqual(template.securityProfile, 'default');
  });

  it('should throw for unknown template', () => {
    assert.throws(() => creator.loadTemplate('nonexistent'), /not found/);
  });

  it('should create a sandbox', () => {
    const result = creator.create('default');
    assert.ok(result.sandboxId.startsWith('sb-'));
    assert.ok(fs.existsSync(result.sandboxDir));
    assert.ok(fs.existsSync(result.configPath));
    assert.strictEqual(result.config.status, 'created');
    assert.strictEqual(result.config.template, 'default');
  });

  it('should create a sandbox with profile override', () => {
    const result = creator.create('dev', { securityProfile: 'strict' });
    assert.strictEqual(result.config.securityProfile, 'strict');
    assert.strictEqual(result.config.template, 'dev');
  });
});

describe('LifecycleManager', () => {
  let lifecycle;
  let sandboxId;

  before(() => {
    lifecycle = new LifecycleManager(TEST_DIR);
    const creator = new SandboxCreator(TEST_DIR);
    const result = creator.create('default');
    sandboxId = result.sandboxId;
  });

  it('should start a sandbox', () => {
    const result = lifecycle.start(sandboxId);
    assert.strictEqual(result.status, 'running');
    assert.ok(result.startedAt);
  });

  it('should not start an already running sandbox', () => {
    assert.throws(() => lifecycle.start(sandboxId), /already running/);
  });

  it('should get sandbox status', () => {
    const result = lifecycle.status(sandboxId);
    assert.strictEqual(result.status, 'running');
    assert.strictEqual(result.sandboxId, sandboxId);
  });

  it('should stop a sandbox', () => {
    const result = lifecycle.stop(sandboxId);
    assert.strictEqual(result.status, 'stopped');
    assert.ok(result.stoppedAt);
  });

  it('should not stop a non-running sandbox', () => {
    assert.throws(() => lifecycle.stop(sandboxId), /not running/);
  });

  it('should restart a stopped sandbox', () => {
    const result = lifecycle.start(sandboxId);
    assert.strictEqual(result.status, 'running');
  });

  it('should destroy a running sandbox', () => {
    const result = lifecycle.destroy(sandboxId);
    assert.strictEqual(result.status, 'destroyed');
    assert.ok(result.destroyedAt);
  });

  it('should not start a destroyed sandbox', () => {
    assert.throws(() => lifecycle.start(sandboxId), /destroyed/);
  });

  it('should list sandboxes', () => {
    const list = lifecycle.list();
    assert.ok(Array.isArray(list));
    assert.ok(list.length > 0);
  });

  it('should throw for nonexistent sandbox', () => {
    assert.throws(() => lifecycle.status('sb-nonexistent'), /not found/);
  });
});

describe('CLI Integration', () => {
  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  });

  it('should show help', () => {
    const output = runCli('help');
    assert.ok(output.includes('sandbox-manager'));
    assert.ok(output.includes('Commands'));
  });

  it('should list templates', () => {
    const output = runCli('templates');
    assert.ok(output.includes('default'));
    assert.ok(output.includes('dev'));
    assert.ok(output.includes('secure'));
  });

  it('should list profiles', () => {
    const output = runCli('profiles');
    assert.ok(output.includes('default'));
    assert.ok(output.includes('strict'));
    assert.ok(output.includes('permissive'));
  });

  it('should create, start, stop, destroy a sandbox via CLI', () => {
    const createOutput = runCli('create', '--template', 'default');
    assert.ok(createOutput.includes('Sandbox created'));
    const idMatch = createOutput.match(/ID:\s+(sb-\S+)/);
    assert.ok(idMatch, 'Should output sandbox ID');
    const id = idMatch[1];

    const startOutput = runCli('start', id);
    assert.ok(startOutput.includes('started'));

    const statusOutput = runCli('status', id);
    assert.ok(statusOutput.includes('running'));

    const stopOutput = runCli('stop', id);
    assert.ok(stopOutput.includes('stopped'));

    const destroyOutput = runCli('destroy', id);
    assert.ok(destroyOutput.includes('destroyed'));
  });

  it('should list sandboxes', () => {
    const output = runCli('list');
    assert.ok(output.includes('sandbox') || output.includes('No sandboxes') || output.includes('sb-'));
  });

  it('should exit non-zero on unknown command', () => {
    assert.throws(() => runCli('foobar'), (err) => {
      return err.status !== 0;
    });
  });

  after(() => {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });
});
