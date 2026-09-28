#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const extension = fileURLToPath(new URL('./omp-smoke-extension.mjs', import.meta.url));
const child = spawn(process.env.OMP_BIN || 'omp', ['--no-extensions', '-e', extension, '--mode', 'rpc', '--no-skills', '--no-rules', '--no-session', '--no-title'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, JEV_APPROVE_REMOTE: '0', JEV_APPROVE_MODE: 'shadow' },
});
let current;
let report;
let stderr = '';
const prompts = [];
const timer = setTimeout(() => {
  console.error('OMP smoke timed out', { current, stderr });
  child.kill('SIGTERM');
  process.exitCode = 1;
}, 120_000);
child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-16000); });
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
const lines = createInterface({ input: child.stdout });
lines.on('line', line => {
  let frame;
  try { frame = JSON.parse(line); } catch { return; }
  if (frame.type === 'jev_smoke_case') current = frame;
  if (frame.type === 'extension_ui_request' && ['confirm', 'select'].includes(frame.method)) {
    prompts.push({ scenario: current?.name, method: frame.method, title: frame.title });
    const approved = current?.approve !== false;
    const response = frame.method === 'confirm' ? { confirmed: approved } : { value: approved ? 'Approve' : 'Deny' };
    child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, ...response })}\n`);
  }
  if (frame.type === 'jev_smoke_report') {
    report = { ...frame, rpcPrompts: prompts };
    child.stdin.end();
  }
});
child.on('close', (code, signal) => {
  clearTimeout(timer);
  if (!report || !report.ok || code !== 0) {
    console.error(JSON.stringify({ report, code, signal, stderr }, null, 2));
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify(report, null, 2));
  }
});
