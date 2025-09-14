#!/usr/bin/env node
import { spawn } from 'child_process';

const cmd = process.argv[2] || 'run';

function run(command, args = []) {
  const child = spawn(command, args, {
    stdio: 'inherit',
    env: process.env,
  });
  child.on('exit', (code, signal) => {
    if (signal) process.exit(1);
    process.exit(code ?? 0);
  });
}

switch (cmd) {
  case 'login': {
    // interactive login to produce /data/auth.json
    run('python3', ['login.py', ...process.argv.slice(3)]);
    break;
  }
  case 'run':
  default: {
    run('node', ['app.mjs']);
  }
}

