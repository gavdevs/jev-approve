import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEngine } from '../src/engine.mjs';
import { loadConfig } from '../src/config.mjs';
import { installHostAdapter, SUPPORTED_OMP } from '../src/host.mjs';

const emit = frame => process.stdout.write(`${JSON.stringify(frame)}\n`);
const absent = async path => { await assert.rejects(access(path), { code: 'ENOENT' }); };

export default function smokeExtension(pi) {
  let started = false;
  pi.on('session_start', (_event, outer) => {
    if (started) return;
    started = true;
    // Return from startup before requesting RPC UI: its input loop must be running.
    setTimeout(() => run(pi, outer).catch(error => emit({ type: 'jev_smoke_report', ok: false, error: error.stack })), 0);
  });
}

async function run(pi, outer) {
  const sdk = pi.pi;
  assert.equal(sdk.VERSION, SUPPORTED_OMP);
  for (const key of ['ExtensionRunner', 'ExtensionToolWrapper', 'loadExtensions', 'loadExtensionFromFactory', 'Settings', 'SessionManager']) assert.ok(sdk[key], key);
  assert.equal(outer.hasUI, true, 'RPC must expose extension UI');
  const root = await mkdtemp(join(tmpdir(), 'jev-omp-smoke-'));
  const results = [];
  const runners = [];
  let activeCase;
  try {
    const files = join(root, 'files');
    const protectedDir = join(root, 'protected');
    await mkdir(files);
    await mkdir(protectedDir);
    const source = join(files, 'source.txt');
    await writeFile(source, 'scoped smoke content');
    let count = 0;
    async function setup({ mode = 'enforce', headless = false, native = {}, rewrite, mutate, child = false, unsupported = false, duplicate = false } = {}) {
      const configPath = join(root, `config-${++count}.json`);
      await writeFile(configPath, JSON.stringify({ readRoots: [files], protectedPaths: [protectedDir], auditPath: join(root, 'audit', `${count}.jsonl`), approvalTimeoutMs: 10000 }));
      const config = await loadConfig({ JEV_APPROVE_CONFIG: configPath, JEV_APPROVE_MODE: mode, JEV_APPROVE_REMOTE: '0' }, files);
      const records = [];
      const engine = createEngine(config, { audit: async (_path, record) => records.push(record), judgeImpl: async () => { throw new Error('Offline smoke must not call Jev'); } });
      const loaded = await sdk.loadExtensions([], files, pi.events);
      assert.deepEqual(loaded.errors, []);
      const factory = inner => {
        if (rewrite) inner.on('tool_call', rewrite);
        const api = unsupported ? { pi: { ...inner.pi, VERSION: 'unsupported-test-version' }, on: inner.on.bind(inner) } : inner;
        assert.equal(installHostAdapter(api, engine.evaluate, mode), !unsupported);
        if (duplicate) assert.equal(installHostAdapter(inner, engine.evaluate, mode), true);
      };
      const extension = await sdk.loadExtensionFromFactory(factory, files, pi.events, loaded.runtime, `jev-smoke-${count}`);
      const settings = sdk.Settings.isolated({ 'tools.approvalMode': 'yolo', 'eval.js': true, 'eval.py': false, 'eval.autoProvision': false, 'eval.autoBackground.enabled': false, ...Object.fromEntries(Object.entries(native).map(([name, value]) => [`tools.approval.${name}`, value])) });
      const session = sdk.SessionManager.inMemory(files);
      const runner = new sdk.ExtensionRunner([extension], loaded.runtime, files, session, outer.modelRegistry, undefined, settings, undefined, undefined, child ? { kind: 'sub', name: 'smoke-child' } : { kind: 'main' });
      const dialogs = [];
      const ui = { ...outer.ui,
        confirm: async (...args) => { dialogs.push('jev'); mutate?.(); return outer.ui.confirm(...args); },
        select: async (...args) => { dialogs.push('native'); mutate?.(); return outer.ui.select(...args); },
      };
      runner.initialize({}, { getModel: () => outer.model, isIdle: () => true, abort() {}, hasPendingMessages: () => false, shutdown() {}, getContextUsage: () => undefined, getSystemPrompt: () => [] }, undefined, headless ? undefined : ui, 'rpc');
      runners.push(runner);
      const executions = [];
      const tool = name => new sdk.ExtensionToolWrapper({
        name, label: name, description: 'Offline temporary-file smoke tool',
        parameters: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path'] },
        execute: async (_id, input) => {
          executions.push(structuredClone(input));
          if (name === 'read') return { content: [{ type: 'text', text: await readFile(input.path, 'utf8') }] };
          await writeFile(input.path, input.content);
          return { content: [{ type: 'text', text: 'written' }] };
        },
      }, runner);
      return { runner, settings, session, tool, records, dialogs, executions, call: (name, input) => tool(name).execute(`smoke-${count}-${activeCase}`, input, new AbortController().signal) };
    }
    async function scenario(name, approve, body) {
      activeCase = name;
      emit({ type: 'jev_smoke_case', name, approve });
      await body();
      results.push(name);
    }
    await scenario('scoped-read-allow', true, async () => {
      const host = await setup();
      assert.equal((await host.call('read', { path: source })).content[0].text, 'scoped smoke content');
      assert.deepEqual(host.dialogs, []);
      assert.equal(host.records.at(-1).decision, 'allow');
    });
    await scenario('ask-approved', true, async () => {
      const host = await setup(); const path = join(files, 'approved.txt');
      await host.call('write', { path, content: 'approved' });
      assert.equal(await readFile(path, 'utf8'), 'approved');
      assert.deepEqual(host.dialogs, ['jev']);
    });
    await scenario('ask-denied', false, async () => {
      const host = await setup(); const path = join(files, 'denied.txt');
      await assert.rejects(host.call('write', { path, content: 'denied' }), /Jev:/);
      await absent(path); assert.deepEqual(host.dialogs, ['jev']);
    });
    await scenario('protected-write-block', true, async () => {
      const host = await setup(); const path = join(protectedDir, 'blocked.txt');
      await assert.rejects(host.call('write', { path, content: 'blocked' }), /Jev:/);
      await absent(path); assert.deepEqual(host.dialogs, []); assert.equal(host.executions.length, 0);
    });
    await scenario('headless-ask-block', true, async () => {
      const host = await setup({ headless: true }); const path = join(files, 'headless.txt');
      await assert.rejects(host.call('write', { path, content: 'blocked' }), /no_interactive_approval/);
      await absent(path); assert.deepEqual(host.dialogs, []);
    });
    await scenario('shadow-no-intervention', false, async () => {
      const host = await setup({ mode: 'shadow' }); const path = join(protectedDir, 'shadow.txt');
      await host.call('write', { path, content: 'shadow executed' });
      assert.equal(await readFile(path, 'utf8'), 'shadow executed'); assert.deepEqual(host.dialogs, []);
      assert.equal(host.records.at(-1).decision, 'block');
    });
    await scenario('shadow-native-prompt-still-denies', false, async () => {
      const host = await setup({ mode: 'shadow', native: { write: 'prompt' } });
      const path = join(files, 'shadow-native-denied.txt');
      await assert.rejects(host.call('write', { path, content: 'must not execute' }), /denied/i);
      await absent(path);
      assert.deepEqual(host.dialogs, ['native']);
    });
    await scenario('native-policy-deny', true, async () => {
      const host = await setup({ native: { write: 'deny' } }); const path = join(files, 'native-deny.txt');
      await assert.rejects(host.call('write', { path, content: 'blocked' }));
      await absent(path); assert.deepEqual(host.dialogs, []); assert.equal(host.records.length, 0);
    });
    await scenario('native-prompt-preserved', true, async () => {
      const host = await setup({ native: { write: 'prompt' } }); const path = join(files, 'native-approved.txt');
      await host.call('write', { path, content: 'both gates approved' });
      assert.deepEqual(host.dialogs, ['native', 'jev']); assert.equal(await readFile(path, 'utf8'), 'both gates approved');
    });
    await scenario('native-prompt-denied', false, async () => {
      const host = await setup({ native: { write: 'prompt' } }); const path = join(files, 'native-ui-denied.txt');
      await assert.rejects(host.call('write', { path, content: 'blocked' }), /denied/i);
      await absent(path); assert.deepEqual(host.dialogs, ['native']); assert.equal(host.records.length, 0);
    });
    await scenario('earlier-handler-final-rewrite', true, async () => {
      const path = join(protectedDir, 'rewritten.txt');
      const host = await setup({ rewrite: () => ({ input: { path, content: 'blocked final input' } }) });
      await assert.rejects(host.call('write', { path: join(files, 'original.txt'), content: 'safe initial input' }), /Jev:/);
      await absent(path); await absent(join(files, 'original.txt')); assert.deepEqual(host.dialogs, []);
    });
    await scenario('retained-input-mutation-isolated', true, async () => {
      const path = join(files, 'detached.txt'); const bad = join(protectedDir, 'mutated.txt');
      const retained = { path, content: 'original detached bytes' };
      const host = await setup({ native: { write: 'prompt' }, rewrite: () => ({ input: retained }), mutate: () => { retained.path = bad; retained.content = 'mutated bytes'; } });
      await host.call('write', { path, content: 'initial' });
      assert.equal(await readFile(path, 'utf8'), 'original detached bytes'); await absent(bad);
      assert.equal(host.executions[0].path, path);
    });
    await scenario('native-policy-changed-during-confirmation', true, async () => {
      let host;
      host = await setup({ mutate: () => { host.runner.settings = sdk.Settings.isolated({ 'tools.approval.write': 'deny' }); } });
      const path = join(files, 'changed-native-policy.txt');
      await assert.rejects(host.call('write', { path, content: 'must not execute' }), /native_policy_changed/);
      await absent(path);
    });
    await scenario('unsupported-host-blocks-enforcement', true, async () => {
      const host = await setup({ unsupported: true });
      await assert.rejects(host.call('read', { path: source }), /unsupported_host/);
      assert.equal(host.executions.length, 0);
    });
    await scenario('duplicate-gates-block-enforcement', true, async () => {
      const host = await setup({ duplicate: true });
      await assert.rejects(host.call('read', { path: source }), /duplicate_gate_installation/);
      assert.equal(host.executions.length, 0);
    });
    await scenario('rebound-child-factory-headless-ask', true, async () => {
      const host = await setup({ child: true }); const path = join(files, 'child.txt');
      await assert.rejects(host.call('write', { path, content: 'blocked child' }), /no_interactive_approval/);
      await absent(path); assert.deepEqual(host.dialogs, []);
    });
    await scenario('actual-eval-nested-read-and-direct-effect', true, async () => {
      assert.equal(typeof sdk.EvalTool, 'function', 'Installed SDK must export actual EvalTool');
      const host = await setup();
      const directPath = join(protectedDir, 'opaque-eval-effect.txt');
      const evalSession = {
        cwd: files, hasUI: true, settings: host.settings, sessionManager: host.session,
        toolRegistry: new Map([['read', host.tool('read')]]),
        getToolForEvalBridge: name => name === 'read' ? host.tool('read') : undefined,
        getEvalSessionId: () => `jev-smoke-${host.session.getSessionId()}`,
        getSessionFile: () => undefined, getSessionSpawns: () => false,
        getActiveModel: () => outer.model,
      };
      const browserPrelude = sdk.createBrowserPrelude(evalSession);
      evalSession.getEvalPreludes = () => [browserPrelude];
      const evalTool = new sdk.ExtensionToolWrapper(new sdk.EvalTool(evalSession), host.runner);
      const result = await evalTool.execute('actual-eval', {
        language: 'js', timeout: 20, reset: true,
        code: `const result = await tool.read({path: ${JSON.stringify(source)}}); print(JSON.stringify(result)); print('browser-prelude-tabs', JSON.stringify(await browser.tabs())); await Bun.write(${JSON.stringify(directPath)}, 'opaque side effect');`,
      }, new AbortController().signal);
      assert.notEqual(result.isError, true, JSON.stringify(result));
      assert.match(JSON.stringify(result.content), /scoped smoke content/);
      assert.match(JSON.stringify(result.content), /browser-prelude-tabs/);
      assert.equal(await readFile(directPath, 'utf8'), 'opaque side effect');
      assert.deepEqual(host.dialogs, ['jev']);
      assert.equal(host.records.length, 2, 'Eval and nested read are judged; actual browser.tabs and raw Bun.write are not');
      assert.equal(host.executions.length, 1);
    });
    emit({ type: 'jev_smoke_report', ok: true, ompVersion: sdk.VERSION, passed: results,
      boundaries: { realInstalledRunner: true, realInstalledWrapper: true, realRpcDialogs: true, realTemporaryFileEffects: true, realAgentLoop: false, actualEval: true, actualBrowserPrelude: true, actualSubagentSpawn: false },
      limitations: ['Tools are controlled file-effect implementations behind actual OMP wrappers, not built-in read/write implementations.', 'Child coverage rebinds an inline factory to a genuine isolated sub-kind runner; it does not spawn a task/subagent.', 'Actual Eval uses the real JS backend, nested tool.read and actual browser.tabs prelude. Browser DOM actions and computer helpers are not exercised.'] });
  } finally {
    for (const runner of runners) runner.disposeFileFallbacks();
    await rm(root, { recursive: true, force: true });
  }
}
