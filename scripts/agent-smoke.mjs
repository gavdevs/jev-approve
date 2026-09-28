#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { POLICY_VERSION } from '../src/policy.mjs';

// Live mode exercises the production Jev transport; the agent provider remains
// deterministic so no uncontrolled model-generated actions can execute.
const { values: { live, discovery } } = parseArgs({ options: { live: { type: 'boolean', default: false }, discovery: { type: 'boolean', default: false } } });
if (live) {
  assert.ok(process.env.TYPESAFE_API_KEY, '--live requires TYPESAFE_API_KEY');
  assert.equal(process.env.JEV_APPROVE_REMOTE, '1', '--live requires explicit JEV_APPROVE_REMOTE=1');
}
const root = await mkdtemp(join(tmpdir(), 'jev-agent-smoke-'));
const frames = [];
const prompts = [];
let stderr = '';
let audit = [];
try {
  await mkdir(join(root, 'work/.omp/agents'), { recursive: true });
  await mkdir(join(root, 'protected'));
  await mkdir(join(root, 'agent'));
  await writeFile(join(root, 'work/source.txt'), 'actual built-in read');
  await writeFile(join(root, 'work/.omp/agents/jev-smoke-child.md'), '---\nname: jev-smoke-child\ndescription: Offline acceptance fixture\nmodel: jev-smoke/offline\nthinking: off\ntools: read, write\n---\nPerform the offline fixture action.\n');
  await writeFile(join(root, 'policy.json'), JSON.stringify({ readRoots: live ? [] : [join(root, 'work')], protectedPaths: [join(root, 'protected')], auditPath: join(root, 'audit/events.jsonl') }));
  await writeFile(join(root, 'overlay.json'), JSON.stringify({ tools: { approvalMode: 'yolo' }, async: { enabled: false }, task: { isolation: { enabled: false }, agentModelOverrides: { 'jev-smoke-child': 'jev-smoke/offline' }, prewalk: false }, defaultThinkingLevel: 'off', memory: { enabled: false }, advisor: { enabled: false }, autolearn: { enabled: false } }));
  const packagePath = fileURLToPath(new URL('../', import.meta.url));
  if (discovery) await writeFile(join(root, 'work/.omp/config.yml'), JSON.stringify({ extensions: [packagePath] }));
  const activation = discovery ? [] : ['--no-extensions', '-e', packagePath];
  const child = spawn(process.env.OMP_BIN || 'omp', ['--cwd', join(root, 'work'), '--config', join(root, 'overlay.json'), ...activation, '-e', fileURLToPath(new URL('./offline-provider.mjs', import.meta.url)), '--model', 'jev-smoke/offline', '--thinking', 'off', '--mode', 'rpc', '--no-skills', '--no-rules', '--no-lsp', '--no-session', '--no-title', '--tools', 'read,write,task'], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PI_CODING_AGENT_DIR: join(root, 'agent'), JEV_SMOKE_ROOT: root, JEV_APPROVE_CONFIG: join(root, 'policy.json'), JEV_APPROVE_MODE: 'enforce', JEV_APPROVE_REMOTE: live ? '1' : '0' },
  });
  const timer = setTimeout(() => child.kill('SIGTERM'), 60000);
  child.stderr.on('data', chunk => { stderr += chunk; });
  let submitted = false;
  createInterface({ input: child.stdout }).on('line', line => {
    let frame;
    try { frame = JSON.parse(line); } catch { return; }
    frames.push(frame);
    if (frame.type === 'ready' && !submitted) {
      submitted = true;
      child.stdin.write(`${JSON.stringify({ id: 'smoke-prompt', type: 'prompt', message: '/jev-scope' })}\n`);
    }
    if (frame.type === 'extension_ui_request' && frame.method === 'input') {
      const scope = live
        ? `Read ${join(root, 'work/source.txt')}. Create ${join(root, 'work/approved.txt')} with exactly actual built-in write. Spawn the smoke child to check that its unapproved write is blocked. Authorize no other file changes.`
        : 'Run the offline acceptance scenario only in this temporary workspace.';
      child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, value: scope })}\n`);
    }
    if (frame.type === 'extension_ui_request' && frame.method === 'confirm') {
      prompts.push(frame.title);
      child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, confirmed: true })}\n`);
    }
    if (frame.type === 'extension_ui_request' && frame.method === 'select') {
      child.stdin.write(`${JSON.stringify({ type: 'extension_ui_response', id: frame.id, value: 'Approve' })}\n`);
    }
    if ((frame.type === 'prompt_result' && frame.id === 'smoke-prompt') ||
      (frame.type === 'agent_end' && frames.some(item => item.type === 'jev_effect_probe' && item.toolCallId === 'parent-task'))) child.stdin.end();
  });
  const [code, signal] = await new Promise((resolve, reject) => { child.on('close', (code, signal) => resolve([code, signal])); child.on('error', reject); });
  clearTimeout(timer);
  assert.equal(code, 0, `OMP exited ${code}/${signal}: ${stderr}`);
  assert.equal(await readFile(join(root, 'work/approved.txt'), 'utf8'), 'actual built-in write');
  await assert.rejects(access(join(root, 'protected/must-not-exist.txt')), { code: 'ENOENT' });
  await assert.rejects(access(join(root, 'work/child-must-not-exist.txt')), { code: 'ENOENT' });
  const effects = frames.filter(frame => frame.type === 'jev_effect_probe');
  assert.ok(effects.some(frame => frame.toolCallId === 'parent-read' && frame.text.includes('actual built-in read') && !frame.isError));
  assert.ok(effects.some(frame => frame.toolCallId === 'parent-protected' && frame.isError && frame.text.includes('protected_mutation')));
  assert.ok(frames.some(frame => frame.type === 'jev_scope_probe' && frame.agent.kind === 'sub' && frame.hasUI === false), 'actual task must create a headless child and rebind fixture factory');
  assert.ok(effects.some(frame => frame.agent === 'sub' && frame.toolCallId === 'child-write' && frame.isError && frame.text.includes('no_interactive_approval')), 'inherited Jev must block actual child write');
  audit = (await readFile(join(root, 'audit/events.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(audit.some(row => row.rules.includes('no_interactive_approval')));
  assert.equal(frames.filter(frame => frame.type === 'extension_ui_request' && frame.method === 'input').length, 1, '/jev-scope must collect actual UI-observed instructions');
  assert.ok(audit.every(row => row.policyVersion === POLICY_VERSION), 'Every real tool decision must use the current loaded policy');
  // Live probabilities are measurements, not deterministic test expectations.
  // The labelled evaluator reports unnecessary asks; this smoke verifies that
  // real prompts and effects agree with the decisions actually returned.
  if (live) assert.equal(audit.filter(row => row.probabilities).length, 4, 'All four contextual actions must receive valid live judgments');
  assert.equal(prompts.length, audit.filter(row => row.rules.includes('manual_exact_invocation')).length, 'Every manual approval must correspond to an actual confirmation');
  console.log(JSON.stringify({ ok: true, liveJev: live, activation: discovery ? 'project-config' : 'explicit-package', policyVersion: POLICY_VERSION, automaticContextualAllows: audit.filter(row => row.rules.includes('authorized_low_hazard')).length, packageManifestLoaded: true, actualScopeDialog: true, actualAgentLoop: true, actualBuiltinReadWrite: true, actualTaskSpawn: true, inheritedExtensionBlockedChild: true, rpcConfirmations: prompts.length, effects, auditDecisions: audit.map(row => ({ decision: row.decision, rules: row.rules, ...(row.probabilities ? { probabilities: row.probabilities } : {}) })) }, null, 2));
} catch (error) {
  console.error(JSON.stringify({ error: error.stack, stderr, auditDecisions: audit.map(row => ({ decision: row.decision, rules: row.rules, probabilities: row.probabilities })), frames: frames.filter(frame => ['response', 'prompt_result', 'extension_error', 'jev_scope_probe', 'jev_effect_probe', 'message_end'].includes(frame.type)) }, null, 2));
  process.exitCode = 1;
} finally { await rm(root, { recursive: true, force: true }); }
