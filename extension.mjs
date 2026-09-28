import { loadConfig } from './src/config.mjs';
import { createEngine } from './src/engine.mjs';
import { installHostAdapter, SUPPORTED_OMP } from './src/host.mjs';
import { POLICY_VERSION } from './src/policy.mjs';

export default async function jevApprove(pi) {
  let config;
  try { config = await loadConfig(); }
  catch {
    // A load exception would merely disable the extension in OMP. Register a
    // fail-closed hook instead when enforcement was requested or mode is invalid.
    const observational = (process.env.JEV_APPROVE_MODE ?? 'shadow') === 'shadow';
    pi.on('tool_call', () => observational ? undefined : { block: true, reason: 'Jev: invalid_configuration' });
    pi.on('session_start', (_event, ctx) => ctx.ui.notify(`Jev: invalid_configuration; ${observational ? 'shadow is observational, not protection' : 'all intercepted tool calls blocked'}.`, 'warning'));
    return;
  }
  const secrets = Object.entries(process.env)
    .filter(([name, value]) => value && /key|token|secret|password|credential|cookie|authorization/i.test(name))
    .map(([, value]) => value);
  // Opt-in learning capture: enabled only when an operator points the sink at
  // a writable JSONL path and runs a dedicated feedback session. Never active
  // under normal use; no production manifest ships the variable.
  let captureOutcome = null;
  if (typeof process.env.JEV_LEARN_SINK === 'string' && process.env.JEV_LEARN_SINK.startsWith('/')) {
    const sink = process.env.JEV_LEARN_SINK;
    const { appendFile, mkdir } = await import('node:fs/promises');
    const { dirname } = await import('node:path');
    await mkdir(dirname(sink), { recursive: true });
    await appendFile(sink, `${JSON.stringify({ capturedAt: Date.now(), type: 'sink_ready' })}\n`, 'utf8');
    captureOutcome = async payload => {
      await appendFile(sink, `${JSON.stringify({ capturedAt: Date.now(), type: 'capture', ...payload })}\n`, 'utf8');
    };
  }
  const engine = createEngine(config, { apiKey: process.env.TYPESAFE_API_KEY, secrets, captureOutcome });
  const supported = installHostAdapter(pi, engine.evaluate, config.mode);
  pi.on('session_start', (_event, ctx) => {
    engine.clear();
    ctx.ui.setStatus('jev-approve', `Jev policy ${POLICY_VERSION} ${config.mode === 'shadow' ? 'SHADOW (observational)' : 'ENFORCE'} | remote ${config.remote ? 'ON' : 'OFF'}`);
    ctx.ui.notify(`Jev policy ${POLICY_VERSION} ${config.mode}: ${config.mode === 'shadow' ? 'observational only, NOT protection' : 'additional approval gate; native policy remains authoritative'}. Remote TypeSafe ${config.remote ? 'enabled: sanitized context may leave this machine' : 'disabled'}.${supported ? '' : ` Unsupported host; requires OMP ${SUPPORTED_OMP}.`}`, 'warning');
  });
  for (const name of ['session_switch', 'session_branch', 'session_tree', 'session_compact']) pi.on(name, () => engine.clear());
  // Input events may already be transformed, queued or consumed; transcript user
  // attribution can also be extension-generated. None is an authorization receipt.
  pi.on('input', () => engine.clear());
  pi.on('before_agent_start', event => engine.observePrompt(event.prompt));
  pi.on('agent_end', () => engine.clear());
  pi.registerCommand('jev-scope', {
    description: 'Enter and start a task with explicit user-authorized scope. No persistent or blanket approval.',
    handler: async (_args, ctx) => {
      if (!ctx.hasUI || ctx.agent?.kind === 'sub' || !ctx.isIdle()) return;
      const origin = [ctx.sessionManager.getSessionId(), ctx.sessionManager.getLeafId(), ctx.sessionManager.getCwd()];
      const text = await ctx.ui.input('Jev: enter the task, permitted targets and exclusions. This is scope evidence, not blanket approval.');
      const current = [ctx.sessionManager.getSessionId(), ctx.sessionManager.getLeafId(), ctx.sessionManager.getCwd()];
      if (text === undefined || !ctx.isIdle() || origin.some((value, index) => value !== current[index])) return;
      engine.authorize(text, { source: 'operator./jev-scope.ui-input', sessionId: origin[0], branch: origin[1], cwd: origin[2] });
      ctx.ui.notify('Jev scope replaced. Exact-action confirmation is still required for opaque effects; no verdicts are cached.', 'info');
      pi.sendUserMessage(text);
    },
  });
  pi.registerCommand('jev-status', {
    description: 'Show observational/enforcement mode, outbound consent, session counters and recent decisions.',
    handler: async (_args, ctx) => {
      const counters = engine.stats();
      const top = Object.entries(counters.byRule).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([rule, count]) => `${rule}:${count}`).join(' ') || 'none';
      let tail = 'no local audit rows';
      try {
        const { readFile } = await import('node:fs/promises');
        const lines = (await readFile(config.auditPath, 'utf8')).trim().split('\n').filter(Boolean)
          .map(line => { try { return JSON.parse(line); } catch { return null; } }).filter(Boolean)
          .filter(row => row && typeof row.decision === 'string');
        tail = lines.slice(-3).map(row => `${row.decision}(${[...(row.rules ?? [])].slice(0, 3).join('+') || 'no-rules'})`).join('  ') || 'no local audit rows';
      } catch { /* Missing/corrupt audit should never break status. */ }
      ctx.ui.notify(`Jev policy ${POLICY_VERSION} ${config.mode}; remote ${config.remote ? 'ON' : 'OFF'}; pinned host ${SUPPORTED_OMP}; ${supported ? 'final-input adapter active' : 'unsupported host'}. Session: ${counters.total} judged (${counters.automaticAllows} automatic allow, ${counters.allows - counters.automaticAllows} manual allow, ${counters.asks} ask, ${counters.blocks} block). Top rules: ${top}. Recent: ${tail}. Audit: ${config.auditPath}. Shadow is not protection.`, 'info');
    },
  });
}
