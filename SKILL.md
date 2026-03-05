---
name: openclaw-sandbox-manager
description: Automated sandboxed environment creation and management for OpenClaw with security isolation.
version: 1.0.0
author: OpenClaw
triggers:
  - "create a sandbox"
  - "isolate this skill execution"
  - "run in a sandboxed environment"
  - "set up security boundaries"
  - "manage sandbox environments"
  - "configure isolation"
---

# openclaw-sandbox-manager

## 1. One-sentence Description
Automated sandboxed environment creation and management for OpenClaw with security isolation.

## 2. Core Capabilities
- CLI commands: `create`, `start`, `stop`, `destroy`, `list`, `status`
- Security enforcement via runtime policy configuration
- Session isolation using filesystem and process boundaries
- Activity monitoring and audit logging

## 3. Security Considerations
- Filesystem isolation per sandbox
- Process resource limits enforcement
- Network access restriction policies
- Comprehensive audit logging of all sandbox operations

## 4. Testing Procedures
- Unit tests for all CLI commands
- Integration tests for sandbox lifecycle
- Security policy validation tests
