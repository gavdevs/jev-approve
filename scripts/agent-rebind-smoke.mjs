#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { POLICY_VERSION } from '../src/policy.mjs';

// Runtime smoke: a real OMP agent loop issues an actual Eval action whose JS
// payload calls agent() and workpool(). Each spawned child must be rebound
// headless and inherited Jev enforcement must block its unauthorized write.
// Deterministic offline provider; no live API and no network/tool effects
// outside the temporary workspace. RPC prompts are answered programmatically.
const root = await mkdtemp(join(tmpdir(), 'jev-eval-rebind-'));
const frames = [];
const prompts = [];
let stderr = '';
let audit = [];
try {
  await mkdir(join(root, 'work'), { recursive: true });
  await mkdir(join(root, 'protected'));
  await mkdir(join(root, 'agent'));
  await writeFile(join(root, 'policy.json'), JSON.stringify({ readRoots: [join(root, 'work')], protectedPaths: [join(root, 'protected')], auditPath: join(root, 'audit/events.jsonl') }));
  await writeFile(join(root, 'overlay.json'), JSON.stringify({ tools: { approvalMode: 'yolo' }, task: { isolation: { enabled: false }, prewalk: false }, defaultThinkingLevel: 'off', memory: { enabled: false }, advisor: { enabled: false }, autolearn: { enabled: false } }));
  const packagePath = fileURLToPath(new URL('../', import.meta.url));
  const child = spawn(process.env.OMP_BIN || 'omp', ['--cwd', join(root, 'work'), '--config', join(root, 'overlay.json'), '--no-extensions', '-e', packagePath, '-e', fileURLToPath(new URL('./eval-rebind-provider.mjs', import.meta.url)), '--model', 'jev-smoke/offline', '--thinking', 'off', '--mode', 'rpc', '--no-skills', '--no-rules', '--no-lsp', '--no-session', '--no-title', '--tools', 'read,write,eval,task'], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PI_CODING_AGENT_DIR: join(root, 'agent'), JEV_SMOKE_ROOT: root, JEV_APPROVE_CONFIG: join(root, 'policy.json'), JEV_APPROVE_MODE: 'enforce', JEV_APPROVE_REMOTE: '0' },
  });
  const timer = setTimeout(() => child.kill('SIGTERM'), 180000);
  child.stderr.on('data', chunk => { stderr += chunk; });
  let submitted = false;
  createInterface({ input: child.stdout }).on('line', line => {
    let frame;
    try { frame = JSON.parse(line); } catch { return; }
    frames.push(frame);
    if (frame.type === 'ready' && !submitted) {
      submitted = true;
      child.stdin.write(`${JSON.stringify({ id: 'rebind-prompt', type: 'prompt', message: 'Run the offline Eval rebind scenario only in this temporary workspace.' })}\n`);
    }
    if (frame.type === 'extension_ui_request' && frame.method === 'confirm') {
      prompts.push(frame.title);
      child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, confirmed: true })}\n`);
    }
    if (frame.type === 'extension_ui_request' && frame.method === 'select') {
      child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, value: 'Approve' })}\n`);
    }
    if (frame.type === 'prompt_result' && frame.id === 'rebind-prompt') child.stdin.end();
  });
  const [code, signal] = await new Promise((resolve, reject) => { child.on('close', (code, signal) => resolve([code, signal])); child.on('error', reject); });
  clearTimeout(timer);
  assert.equal(code, 0, `OMP exited ${code}/${signal}: ${stderr}`);
  const effects = frames.filter(frame => frame.type === 'jev_effect_probe');
  const sessions = frames.filter(frame => frame.type === 'jev_scope_probe');
  const evalEffect = effects.find(frame => frame.toolCallId === 'parent-eval');
  assert.ok(evalEffect && !evalEffect.isError, `actual Eval action must execute: ${JSON.stringify(evalEffect)}`);
  assert.ok(evalEffect.text.includes('EVAL_AGENT_SPAWNED'), 'Eval payload must actually call agent()');
  assert.ok(evalEffect.text.includes('EVAL_POOL_SPAWNED'), 'Eval payload must actually call workpool()');
  assert.ok(evalEffect.text.includes('Agent child observed its blocked action'), 'agent() child must complete a real turn');
  assert.match(evalEffect.text, /"agents":\[\{"id":"jev-pool-1"/, 'workpool() must run its item on a real keep-alive child');
  const agentChild = sessions.find(frame => frame.agent?.kind === 'sub' && frame.agent?.id === 'jev-agent-child');
  const poolChild = sessions.find(frame => frame.agent?.kind === 'sub' && frame.agent?.id === 'jev-pool-1');
  assert.ok(agentChild && agentChild.hasUI === false, `agent() child must be rebound headless: ${JSON.stringify(agentChild)}`);
  assert.ok(poolChild && poolChild.hasUI === false, `workpool() child must be rebound headless: ${JSON.stringify(poolChild)}`);
  const agentWrite = effects.find(frame => frame.toolCallId === 'agent-child-write');
  const poolWrite = effects.find(frame => frame.toolCallId === 'pool-child-write');
  assert.ok(agentWrite && agentWrite.agent === 'sub' && agentWrite.isError && agentWrite.text.includes('no_interactive_approval'), `agent() child write must be blocked: ${JSON.stringify(agentWrite)}`);
  assert.ok(poolWrite && poolWrite.agent === 'sub' && poolWrite.isError && poolWrite.text.includes('no_interactive_approval'), `workpool() child write must be blocked: ${JSON.stringify(poolWrite)}`);
  await assert.rejects(access(join(root, 'work/agent-child-must-not-exist.txt')), { code: 'ENOENT' });
  await assert.rejects(access(join(root, 'work/pool-child-must-not-exist.txt')), { code: 'ENOENT' });
  audit = (await readFile(join(root, 'audit/events.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(audit.every(row => row.policyVersion === POLICY_VERSION), 'Every real tool decision must use the current loaded policy');
  assert.ok(audit.filter(row => row.rules.includes('no_interactive_approval')).length >= 2, 'Both child writes must be recorded as headless blocks');
  assert.equal(prompts.length, audit.filter(row => row.rules.includes('manual_exact_invocation')).length, 'Every manual approval must correspond to an actual confirmation');
  console.log(JSON.stringify({ ok: true, policyVersion: POLICY_VERSION, actualEvalAction: true, evalPayloadSpawnedAgent: true, evalPayloadSpawnedWorkpool: true, agentChildReboundHeadless: true, workpoolChildReboundHeadless: true, agentChildWriteBlocked: true, workpoolChildWriteBlocked: true, rpcConfirmations: prompts.length, sessions, effects, auditDecisions: audit.map(row => ({ decision: row.decision, rules: row.rules })) }, null, 2));
} catch (error) {
  console.error(JSON.stringify({ error: error.stack, stderr, auditDecisions: audit.map(row => ({ decision: row.decision, rules: row.rules })), frames: frames.filter(frame => ['response', 'prompt_result', 'extension_error', 'jev_scope_probe', 'jev_effect_probe', 'message_end'].includes(frame.type)) }, null, 2));
  process.exitCode = 1;
} finally { await rm(root, { recursive: true, force: true }); }
