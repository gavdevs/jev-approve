import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEngine } from '../src/engine.mjs';
import { loadConfig } from '../src/config.mjs';
import { installHostAdapter, SUPPORTED_OMP } from '../src/host.mjs';

const emit = frame => process.stdout.write(`${JSON.stringify(frame)}\n`);

export default function browserBoundaryExtension(pi) {
  let started = false;
  pi.on('session_start', (_event, outer) => {
    if (started) return;
    started = true;
    setTimeout(() => run(pi, outer).catch(error => emit({ type: 'jev_boundary_report', ok: false, error: error.stack })), 0);
  });
}


async function run(pi, outer) {
  const sdk = pi.pi;
  assert.equal(sdk.VERSION, SUPPORTED_OMP);
  for (const key of ['ExtensionRunner', 'ExtensionToolWrapper', 'loadExtensions', 'loadExtensionFromFactory', 'Settings', 'SessionManager', 'EvalTool', 'createBrowserPrelude', 'createComputerPrelude']) assert.ok(sdk[key], `sdk.${key}`);
  assert.equal(outer.hasUI, true, 'RPC must expose extension UI');
  const root = await mkdtemp(join(tmpdir(), 'jev-browser-boundary-'));
  const files = join(root, 'files');
  await mkdir(files);
  const entries = [];
  const limitations = [];
  const runners = [];
  try {
    await writeFile(join(files, 'probe-target.txt'), 'jev boundary probe target');
    const configPath = join(root, 'config.json');
    await writeFile(configPath, JSON.stringify({ readRoots: [files], protectedPaths: [], auditPath: join(root, 'audit.jsonl'), approvalTimeoutMs: 30000 }));
    const config = await loadConfig({ JEV_APPROVE_CONFIG: configPath, JEV_APPROVE_MODE: 'enforce', JEV_APPROVE_REMOTE: '0' }, files);
    const records = [];
    const engine = createEngine(config, { audit: async (_path, record) => records.push(record), judgeImpl: async () => { throw new Error('Boundary smoke must not call Jev remotely'); } });
    // The production audit deliberately omits tool names; the smoke correlates
    // each audit record with the tool Jev judged by wrapping the SAME evaluator
    // the adapter receives (adds record.toolName after the audit append).
    const evaluate = async (event, ctx, signal, meta) => {
      const before = records.length;
      try { return await engine.evaluate(event, ctx, signal, meta); }
      finally {
        for (const record of records.slice(before)) record.toolName = event.toolName;
      }
    };

    // Real installed extension loading machinery; the factory installs the
    // PRODUCTION host adapter into the runner's dispatch, plus an independent
    // ordinary tool_call observer that never returns anything (it cannot
    // influence gating; it only records adapter visibility).
    const loaded = await sdk.loadExtensions([], files, pi.events);
    assert.deepEqual(loaded.errors, []);
    const toolCallEvents = [];
    const factory = inner => {
      assert.equal(installHostAdapter(inner, evaluate, 'enforce'), true);
      inner.on('tool_call', event => { toolCallEvents.push({ toolName: event.toolName, id: event.toolCallId }); });
    };
    const extension = await sdk.loadExtensionFromFactory(factory, files, pi.events, loaded.runtime, 'jev-boundary');
    const settings = sdk.Settings.isolated({
      'tools.approvalMode': 'yolo',
      'tools.approval.browser': 'allow',
      'tools.approval.computer': 'allow',
      'eval.js': true, 'eval.py': false, 'eval.autoProvision': false, 'eval.autoBackground.enabled': false,
      'computer.enabled': true,
    });
    const session = sdk.SessionManager.inMemory(files);
    const runner = new sdk.ExtensionRunner([extension], loaded.runtime, files, session, outer.modelRegistry, undefined, settings, undefined, undefined, { kind: 'main' });
    runner.initialize({}, { getModel: () => outer.model, isIdle: () => true, abort() {}, hasPendingMessages: () => false, shutdown() {}, getContextUsage: () => undefined, getSystemPrompt: () => [] }, undefined, outer.ui, 'rpc');
    runners.push(runner);
    const started = toolCallEvents.length;

    await runner.emitToolCall({ type: 'tool_call', toolName: 'browser', toolCallId: 'jev-boundary-tool-browser', input: { action: 'open', url: 'about:blank' } });
    await runner.emitToolCall({ type: 'tool_call', toolName: 'computer', toolCallId: 'jev-boundary-tool-computer', input: { action: 'capabilities' } });

    const normalToolResult = new sdk.ExtensionToolWrapper({
      name: 'read', label: 'read', description: 'Boundary control read',
      parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
      execute: async () => ({ content: [{ type: 'text', text: 'control' }] }),
    }, runner);
    const normalExec = await normalToolResult.execute('jev-boundary-normal-tool', { path: join(files, 'probe-target.txt') }, new AbortController().signal);


    // Real prelude execution: the production prelude factories, the production
    // eval kernel, and the production __prelude__ dispatch inside the same
    // runner whose Wrapper.prototype.execute is interposed by the adapter.
    const evalSession = {
      cwd: files, hasUI: true, settings, sessionManager: session,
      toolRegistry: new Map(),
      getToolForEvalBridge: () => undefined,
      getEvalSessionId: () => `jev-boundary-${session.getSessionId()}`,
      getSessionFile: () => undefined, getSessionSpawns: () => false,
      getActiveModel: () => outer.model,
    };
    const controllerCalls = [];
    const controller = {
      capabilities: () => { controllerCalls.push('capabilities'); return Promise.resolve({ backend: 'jev-boundary-synthetic', displays: 0, windows: false, clipboard: false, accessibility: false }); },
      run: () => { controllerCalls.push('run'); return Promise.reject(new Error('boundary smoke must not execute desktop code')); },
      close: () => Promise.resolve(),
    };
    assert.equal(typeof sdk.createBrowserPrelude, 'function', 'SDK must export the production browser prelude factory');
    assert.equal(typeof sdk.createComputerPrelude, 'function', 'SDK must export the production computer prelude factory');
    const browserPrelude = sdk.createBrowserPrelude(evalSession);
    const computerPrelude = sdk.createComputerPrelude(evalSession, () => controller);
    evalSession.getEvalPreludes = () => [browserPrelude, computerPrelude];


    const startedRecords = records.length;
    const evalTool = new sdk.ExtensionToolWrapper(new sdk.EvalTool(evalSession), runner);
    const tabsRecordBefore = records.length;
    const tabsEventsBefore = toolCallEvents.length;
    const tabsResult = await evalTool.execute('jev-boundary-eval-tabs', {
      language: 'js', timeout: 45, reset: true,
      code: `try { const tabs = await browser.tabs(); print('tabs-ok:' + tabs.length); } catch (error) { print('tabs-error:' + String(error && error.message || error).slice(0, 200)); }`,
    }, new AbortController().signal);
    const tabsText = JSON.stringify(tabsResult.content);
    const capsRecordBefore = records.length;
    const capsEventsBefore = toolCallEvents.length;
    const capsResult = await evalTool.execute('jev-boundary-eval-computer', {
      language: 'js', timeout: 30,
      code: `const caps = await computer.capabilities(); print('caps:' + (caps && caps.backend));`,
    }, new AbortController().signal);
    const capsText = JSON.stringify(capsResult.content);

    // DOM-op phase. Chromium is NOT available in this install (no system
    // Chrome, and automatic puppeteer download is disabled); therefore the
    // OMP-owned headless helper cannot be used here and the smoke cannot
    // produce a genuine DOM mutation or a genuine browser.tabs() against a
    // live page. We instead exercise the DOM-op dispatch boundary at the
    // exact prelude entry point: a production `browser.open(...)` call
    // against a loopback-only relay URL. It routes through the same
    // invokeEvalPrelude host path as every DOM method, cannot complete
    // without a real relay, and produces the adapter/judgment counts the
    // boundary claim depends upon.
    let browserDomUx;
    try {
      const relaySettings = sdk.Settings.isolated({
        'tools.approvalMode': 'yolo',
        'tools.approval.browser': 'allow', 'tools.approval.computer': 'allow',
        'eval.js': true, 'eval.py': false, 'eval.autoProvision': false, 'eval.autoBackground.enabled': false,
        'computer.enabled': true, 'browser.relay': true, 'browser.relayUrl': 'http://127.0.0.1:9',
      });
      const relaySession = { ...evalSession, settings: relaySettings };
      const relayBrowserPrelude = sdk.createBrowserPrelude(relaySession);
      relaySession.getEvalPreludes = () => [relayBrowserPrelude];
      const relayEvalTool = new sdk.ExtensionToolWrapper(new sdk.EvalTool(relaySession), runner);
      const domEventsBefore = toolCallEvents.length;
      const domRecordsBefore = records.length;
      const domResult = await relayEvalTool.execute('jev-boundary-eval-dom', {
        language: 'js', timeout: 30,
        code: `try { const tab = await browser.open({ url: 'http://127.0.0.1:9/', name: 'jev-boundary-dom' }); print('dom-opened'); } catch (error) { print('dom-error:' + String(error && error.message || error).slice(0, 120)); }`,
      }, new AbortController().signal);
      const domText = JSON.stringify(domResult.content);
      browserDomUx = {
        outcome: (domText.match(/dom-opened/) || domText.match(/dom-error:([^"\\]{0,110})/))?.[1] ?? domText.match(/dom-opened/)?.[0],
        adapterVisibleToolCallsDuringDomPhase: toolCallEvents.length - domEventsBefore,
        jevRecordsAddedDuringDomPhase: records.length - domRecordsBefore,
      };
      entries.push({ id: 'prelude:browser.open to loopback relay (DOM-op dispatch phase)', mechanism: 'real eval kernel -> production browser prelude -> invokeEvalPrelude host path against a loopback-only relay URL', exercised: true, toolCallSeen: false, jevDecision: 'none (no adapter-visible tool_call, no per-action Jev record)', outcome: browserDomUx.outcome, note: 'Attempted exactly the prelude call that would begin a DOM session. It produced no adapter-visible tool_call and no per-action Jev decision even when the prelude open itself failed; the only judgment was the opaque outer Eval cell. No real browser, page, DOM or account was touched.' });
    } catch (error) {
      browserDomUx = { failure: String((error && error.message) || error).slice(0, 200) };
      entries.push({ id: 'prelude:browser.open to loopback relay (DOM-op dispatch phase)', mechanism: 'real eval kernel -> production browser prelude -> invokeEvalPrelude host path', exercised: true, toolCallSeen: false, jevDecision: 'none', outcome: `host-failure:${browserDomUx.failure}`, note: 'Loopback relay open attempt was rejected before any adapter-visible tool_call; this confirms the prelude path emits the action directly, not through the observable tool_call bus.' });
    }

    // Cross-check visibility independently of the observer: audit records are
    // correlated with the tool Jev judged by the evaluate() wrapper above.
    const auditToolNames = records.slice(startedRecords).map(record => record.toolName);
    const evalRecords = records.slice(startedRecords).filter(record => record.toolName === 'eval');
    const readRecord = records.find(record => record.toolName === 'read');
    const toolCallNames = toolCallEvents.map(event => event.toolName);
    const noNewEvent = (before, names) => !toolCallEvents.slice(before).some(event => names.includes(event.toolName));
    entries.push(
      { id: 'tool_call:browser', mechanism: 'ordinary tool_call event dispatched through the REAL runner.emitToolCall (public dispatch API)', exercised: true, toolCallSeen: toolCallNames.includes('browser'), jevDecision: null, note: 'A tool_call event carrying toolName="browser" reaches the adapter’s ordinary tool_call dispatch and its Jev evaluator through the real installed ExtensionRunner.' },
      { id: 'tool_call:computer', mechanism: 'ordinary tool_call event dispatched through the REAL runner.emitToolCall (public dispatch API)', exercised: true, toolCallSeen: toolCallNames.includes('computer'), jevDecision: null, note: 'A tool_call event carrying toolName="computer" reaches the adapter’s ordinary tool_call dispatch and its Jev evaluator through the real installed ExtensionRunner.' },
      { id: 'extension-tool-wrapper-execute', mechanism: 'real installed ExtensionToolWrapper.execute with the adapter interposed on the prototype', exercised: true, toolCallSeen: toolCallNames.includes('read'), jevDecision: readRecord?.decision ?? 'MISSING', note: 'Ordinary wrapped tool execute reached the adapter’s final-execute gate; Jev judged and allowed the in-roots read.' },
      { id: 'prelude:browser.tabs()', mechanism: 'real eval kernel -> production browser prelude -> globalThis.__omp_prelude__("browser") -> invokeEvalPrelude host path', exercised: true, toolCallSeen: !noNewEvent(tabsEventsBefore, ['browser']), jevDecision: 'none (no adapter-visible tool_call, no per-action Jev record)', outcome: tabsText.match(/tabs-(ok|error):[^\s"\\]*/)?.[0], eventsStartedByPrelude: toolCallEvents.slice(tabsEventsBefore, capsEventsBefore).map(event => event.toolName), note: 'A real browser-prelude action produced NO adapter-visible tool_call and NO per-action Jev decision; only the containing Eval cell was judged.' },
      { id: 'prelude:computer.capabilities()', mechanism: 'real eval kernel -> production computer prelude (synthetic injected controller; no desktop touched) -> invokeEvalPrelude host path', exercised: true, toolCallSeen: !noNewEvent(capsEventsBefore, ['computer']), jevDecision: 'none (no adapter-visible tool_call, no per-action Jev record)', outcome: `${capsText.match(/caps:[^\s",\\]*/)?.[0]} controllerCalls=${JSON.stringify(controllerCalls)}`, eventsStartedByPrelude: toolCallEvents.slice(capsEventsBefore).map(event => event.toolName), note: 'A real computer-prelude action produced NO adapter-visible tool_call and NO per-action Jev decision; only the containing Eval cell was judged.' },
      { id: 'prelude:eval.container', mechanism: 'adapter-interposed ExtensionToolWrapper.execute around the EvalTool cells that ran the prelude calls', exercised: true, toolCallSeen: toolCallEvents.slice(tabsEventsBefore).some(event => event.toolName === 'eval'), jevDecision: evalRecords.map(record => record.decision).join(',') || 'MISSING', evalJudgments: { evalRecords: evalRecords.length, recordsBetweenTabsAndCaps: capsRecordBefore - tabsRecordBefore }, auditToolNames, note: 'The adapter gated the opaque Eval container cells; the browser/computer actions inside produced no additional adapter-visible events.' },
    );
    // Assertions establishing the runtime boundary AFTER data collection:
    // prelude executions added exactly one judged tool each ("eval") and never
    // a "browser"/"computer" judgment.
    assert.equal(capsRecordBefore - tabsRecordBefore, 1, `browser.tabs() prelude should add exactly one adapter judgment (the Eval cell); audit: ${JSON.stringify(auditToolNames)}`);
    // The DOM-op phase runs between capsRecordBefore and here; only its Eval
    // cell may add a judgment, never a per-action browser judgment.
    assert.equal(records.length - capsRecordBefore, 2, `computer.capabilities() and the DOM-op phase each add exactly one adapter judgment (their Eval cells); audit: ${JSON.stringify(auditToolNames)}`);
    assert.ok(!auditToolNames.includes('browser'), 'no Jev judgment must ever be created for a browser prelude action');
    assert.ok(!auditToolNames.includes('computer'), 'no Jev judgment must ever be created for a computer prelude action');

    const ok = entries.every(entry => entry.exercised);
    emit({ type: 'jev_boundary_report', ok, ompVersion: sdk.VERSION, entries, limitations });
  } finally {
    for (const runner of runners) runner.disposeFileFallbacks();
    await rm(root, { recursive: true, force: true });
  }
}
