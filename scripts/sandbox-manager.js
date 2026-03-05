#!/usr/bin/env node
'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const SandboxCreator = require('./sandbox-creator');
const LifecycleManager = require('./lifecycle-manager');
const SecurityIsolator = require('./security-isolator');

const DEFAULT_SANDBOX_DIR = path.join(os.tmpdir(), 'openclaw-sandboxes');

function getSandboxDir() {
  return process.env.SANDBOX_BASE_DIR || DEFAULT_SANDBOX_DIR;
}

function printUsage() {
  console.log(`
openclaw-sandbox-manager - Sandboxed environment management for OpenClaw

Usage:
  sandbox-manager <command> [options]

Commands:
  create [--template <name>] [--profile <name>]   Create a new sandbox
  start <sandbox-id>                               Start a sandbox
  stop <sandbox-id>                                Stop a sandbox
  destroy <sandbox-id>                             Destroy a sandbox
  status <sandbox-id>                              Show sandbox status
  list                                             List all sandboxes
  cleanup <sandbox-id>                             Remove sandbox files
  templates                                        List available templates
  profiles                                         List security profiles
  help                                             Show this help message

Options:
  --template <name>    Sandbox template (default: "default")
  --profile <name>     Security profile override
  --sandbox-dir <dir>  Base directory for sandboxes

Environment:
  SANDBOX_BASE_DIR     Base directory for sandbox storage

Examples:
  sandbox-manager create --template dev
  sandbox-manager start sb-abc123
  sandbox-manager list
  sandbox-manager destroy sb-abc123
`);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const result = { command: null, positional: [], options: {} };

  if (args.length === 0) {
    result.command = 'help';
    return result;
  }

  result.command = args[0];
  let i = 1;

  while (i < args.length) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        result.options[key] = args[i + 1];
        i += 2;
      } else {
        result.options[key] = true;
        i += 1;
      }
    } else {
      result.positional.push(args[i]);
      i += 1;
    }
  }

  return result;
}

function main() {
  const parsed = parseArgs(process.argv);
  const sandboxDir = parsed.options['sandbox-dir'] || getSandboxDir();

  if (!fs.existsSync(sandboxDir)) {
    fs.mkdirSync(sandboxDir, { recursive: true });
  }

  const creator = new SandboxCreator(sandboxDir);
  const lifecycle = new LifecycleManager(sandboxDir);
  const isolator = new SecurityIsolator();

  try {
    switch (parsed.command) {
      case 'create': {
        const template = parsed.options.template || 'default';
        const overrides = {};
        if (parsed.options.profile) {
          overrides.securityProfile = parsed.options.profile;
        }
        const result = creator.create(template, overrides);
        console.log(`Sandbox created successfully.`);
        console.log(`  ID:       ${result.sandboxId}`);
        console.log(`  Dir:      ${result.sandboxDir}`);
        console.log(`  Template: ${result.config.template}`);
        console.log(`  Profile:  ${result.config.securityProfile}`);
        break;
      }

      case 'start': {
        const id = parsed.positional[0];
        if (!id) { console.error('Error: sandbox-id is required'); process.exit(1); }
        const result = lifecycle.start(id);
        console.log(`Sandbox ${result.sandboxId} started at ${result.startedAt}`);
        break;
      }

      case 'stop': {
        const id = parsed.positional[0];
        if (!id) { console.error('Error: sandbox-id is required'); process.exit(1); }
        const result = lifecycle.stop(id);
        console.log(`Sandbox ${result.sandboxId} stopped at ${result.stoppedAt}`);
        break;
      }

      case 'destroy': {
        const id = parsed.positional[0];
        if (!id) { console.error('Error: sandbox-id is required'); process.exit(1); }
        const result = lifecycle.destroy(id);
        console.log(`Sandbox ${result.sandboxId} destroyed at ${result.destroyedAt}`);
        break;
      }

      case 'status': {
        const id = parsed.positional[0];
        if (!id) { console.error('Error: sandbox-id is required'); process.exit(1); }
        const result = lifecycle.status(id);
        console.log(`Sandbox: ${result.sandboxId}`);
        console.log(`  Status:   ${result.status}`);
        console.log(`  Template: ${result.template}`);
        console.log(`  Profile:  ${result.securityProfile}`);
        console.log(`  Created:  ${result.createdAt}`);
        if (result.startedAt) console.log(`  Started:  ${result.startedAt}`);
        if (result.stoppedAt) console.log(`  Stopped:  ${result.stoppedAt}`);
        if (result.destroyedAt) console.log(`  Destroyed: ${result.destroyedAt}`);
        break;
      }

      case 'list': {
        const sandboxes = lifecycle.list();
        if (sandboxes.length === 0) {
          console.log('No sandboxes found.');
        } else {
          console.log(`Found ${sandboxes.length} sandbox(es):\n`);
          for (const sb of sandboxes) {
            console.log(`  ${sb.sandboxId}  [${sb.status}]  template=${sb.template}  created=${sb.createdAt}`);
          }
        }
        break;
      }

      case 'cleanup': {
        const id = parsed.positional[0];
        if (!id) { console.error('Error: sandbox-id is required'); process.exit(1); }
        const result = lifecycle.cleanup(id);
        console.log(`Sandbox ${result.sandboxId} cleaned up.`);
        break;
      }

      case 'templates': {
        const templates = creator.listTemplates();
        console.log('Available templates:\n');
        for (const t of templates) {
          console.log(`  ${t.name} - ${t.description}`);
        }
        break;
      }

      case 'profiles': {
        const profiles = isolator.listProfiles();
        console.log('Available security profiles:\n');
        for (const p of profiles) {
          console.log(`  ${p.name} - ${p.description}`);
        }
        break;
      }

      case 'help':
        printUsage();
        break;

      default:
        console.error(`Unknown command: "${parsed.command}"`);
        printUsage();
        process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();
