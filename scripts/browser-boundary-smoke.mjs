#!/usr/bin/env node
// Runtime boundary smoke: how jev-approve's OMP 18.3.5 host adapter treats
// browser/computer helper boundaries. Exercises the real installed
// ExtensionRunner/ExtensionToolWrapper, the production extension's
// installHostAdapter, and genuine Eval-prelude browser/computer host paths
// against synthetic fixtures only: a loopback 127.0.0.1:9 relay probe (used
// only to detect whether a system Chrome exists offline; nothing is ever
// driven) and an injected in-memory computer controller. No network,
// account or desktop.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const extension = fileURLToPath(new URL('./browser-boundary-extension.mjs', import.meta.url));
const child = spawn(process.env.OMP_BIN || 'omp', ['--no-extensions', '-e', extension, '--mode', 'rpc', '--no-skills', '--no-rules', '--no-session', '--no-title'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, JEV_APPROVE_REMOTE: '0', JEV_APPROVE_MODE: 'enforce' },
});
let report;
let stderr = '';
const prompts = [];
const timer = setTimeout(() => {
  console.error('Browser boundary smoke timed out', stderr.slice(-2000));
  child.kill('SIGTERM');
  process.exitCode = 1;
}, 180_000);
child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8000); });
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
const lines = createInterface({ input: child.stdout });
lines.on('line', line => {
  let frame;
  try { frame = JSON.parse(line); } catch { return; }
  if (frame.type === 'extension_ui_request' && ['confirm', 'select'].includes(frame.method)) {
    prompts.push({ method: frame.method, title: frame.title });
    const response = frame.method === 'confirm' ? { confirmed: true } : { value: 'Approve' };
    child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, ...response })}\n`);
  }
  if (frame.type === 'jev_boundary_report') {
    report = frame;
    child.stdin.end();
  }
});
child.on('close', (code, signal) => {
  clearTimeout(timer);
  if (!report || code !== 0) {
    console.error(JSON.stringify({ error: 'no report from boundary extension', code, signal, stderr }, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log(`browser/computer boundary smoke against installed OMP ${report.ompVersion}`);
  console.log();
  let failures = 0;
  for (const entry of report.entries ?? []) {
    const seen = entry.toolCallSeen === true ? 'tool_call: YES' : entry.toolCallSeen === false ? 'tool_call: no ' : 'tool_call: n/a';
    console.log(`${seen}  ${entry.id}`);
    console.log(`           jev: ${entry.jevDecision ?? '—'}  ${entry.outcome ?? ''}`);
    console.log(`           ${entry.mechanism}`);
    console.log(`           ${entry.note}`);
    if (!entry.exercised) failures++;
    console.log();
  }
  const byId = Object.fromEntries((report.entries ?? []).map(entry => [entry.id, entry]));
  const expectNoToolCall = ['prelude:browser.tabs()', 'prelude:computer.capabilities()'];
  const expectToolCall = ['extension-tool-wrapper-execute', 'tool_call:browser', 'tool_call:computer', 'prelude:eval.container'];
  for (const id of expectNoToolCall) {
    const entry = byId[id];
    if (!entry) { console.error(`MISSING entry ${id}`); failures++; continue; }
    if (entry.toolCallSeen !== false) { console.error(`BOUNDARY VIOLATION: ${id} unexpectedly reached the adapter's tool_call dispatch`); failures++; }
  }
  for (const id of expectToolCall) {
    const entry = byId[id];
    if (!entry) { console.error(`MISSING entry ${id}`); failures++; continue; }
    if (entry.toolCallSeen !== true) { console.error(`BOUNDARY VIOLATION: ${id} did not reach the adapter's tool_call dispatch`); failures++; }
  }
  if (!report.ok && report.limitations?.length) {
    console.log('Not observable in this install:');
    for (const note of report.limitations) console.log(`  - ${note}`);
  }
  if (report.error) { console.error(report.error); failures++; }
  if (failures > 0 || !report.ok) {
    console.error(`browser-boundary smoke: FAIL (${failures} assertion failure(s))`);
    process.exitCode = 1;
  } else {
    console.log('browser-boundary smoke: PASS — prelude browser/computer actions bypass ordinary tool_call (adapter cannot gate them individually); tool_call-emitting entry points are gated, and the opaque Eval container is gated once.');
    console.log(`rpc prompts answered: ${prompts.length}`);
  }
});
