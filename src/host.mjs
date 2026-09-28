// Version-pinned host interposition, NOT a supported OMP extension API.
// Ordinary tool_call hooks cannot see accumulated input revisions in 18.3.5.
const SLOT = Symbol.for('jev-approve.omp-18.3.5.execution.v1');
export const SUPPORTED_OMP = '18.3.5';
function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function bindings(runner, state) {
  return runner.extensions.flatMap(extension => (extension.handlers.get('tool_call') ?? [])
    .map(handler => state.evaluators.get(handler)).filter(Boolean));
}
export function installHostAdapter(pi, evaluate, mode) {
  const marker = () => mode === 'enforce' ? { block: true, reason: 'Jev: unsupported_host' } : undefined;
  const Runner = pi.pi?.ExtensionRunner;
  const Wrapper = pi.pi?.ExtensionToolWrapper;
  if (pi.pi?.VERSION !== SUPPORTED_OMP || typeof Runner?.prototype?.emitToolCall !== 'function' || typeof Wrapper?.prototype?.execute !== 'function') {
    pi.on('tool_call', marker);
    return false;
  }
  const prototype = Runner.prototype;
  let state = prototype[SLOT];
  if (!state) {
    const emit = prototype.emitToolCall;
    const execute = Wrapper.prototype.execute;
    state = { evaluators: new WeakMap() };
    Object.defineProperty(prototype, SLOT, { value: state });
    prototype.emitToolCall = async function(event, signal) {
      const result = await emit.call(this, event, signal);
      if (result?.block || !bindings(this, state).some(binding => binding.mode === 'enforce')) return result;
      // Detach returned replacements from other handlers before native UI awaits.
      // No replacement for synthetic computer input (host ignores it anyway).
      if (event.toolName === 'computer' || result?.input === undefined) return result;
      return { ...result, input: freeze(structuredClone(result.input)) };
    };
    Wrapper.prototype.execute = async function(id, args, signal, onUpdate, executionContext) {
      const active = bindings(this.runner, state);
      if (!active.length) return execute.call(this, id, args, signal, onUpdate, executionContext);
      const enforce = active.some(binding => binding.mode === 'enforce');
      if (enforce && active.length !== 1) throw new Error('Jev: duplicate_gate_installation');
      const nativeTool = this.tool;
      const runner = this.runner;
      const settingsForCall = () => executionContext?.settings ?? runner.sessionSettings;
      const settingsBefore = settingsForCall();
      const revisionBefore = enforce ? settingsBefore?.revision : undefined;
      const autoApproveBefore = executionContext?.autoApprove;
      const receiver = Object.create(this);
      const tool = Object.create(nativeTool);
      tool.execute = async function(callId, finalArgs, abort, update, context) {
        let input = finalArgs;
        for (const binding of active) {
          const ctx = runner.createContext();
          Object.defineProperty(ctx, 'cwd', { get: () => runner.cwd });
          let result;
          try {
            result = await binding.evaluate({ type: 'tool_call', toolName: nativeTool.name, toolCallId: callId, input }, ctx, abort, undefined);
          } catch {
            if (binding.mode === 'enforce') throw new Error('Jev: internal_failure');
          }
          if (binding.mode === 'enforce') {
            if (result?.block) throw new Error(result.reason || 'Jev: blocked');
            if (!result || result.input === undefined) throw new Error('Jev: missing_execution_binding');
            input = result.input;
          }
        }
        if (enforce && abort?.aborted) throw new Error('Jev: cancelled');
        if (enforce && (settingsForCall() !== settingsBefore || settingsBefore?.revision !== revisionBefore ||
          executionContext?.autoApprove !== autoApproveBefore)) throw new Error('Jev: native_policy_changed');
        return nativeTool.execute.call(nativeTool, callId, input, abort, update, context);
      };
      receiver.tool = tool;
      // Keep every native deny, prompt, safety check and result hook intact.
      return execute.call(receiver, id, enforce ? freeze(structuredClone(args)) : args, signal, onUpdate, executionContext);
    };
    state.emit = prototype.emitToolCall;
    state.execute = Wrapper.prototype.execute;
  }
  if (prototype.emitToolCall !== state.emit || Wrapper.prototype.execute !== state.execute) {
    pi.on('tool_call', marker);
    return false;
  }
  const activeMarker = () => mode === 'enforce' &&
    (prototype.emitToolCall !== state.emit || Wrapper.prototype.execute !== state.execute)
    ? { block: true, reason: 'Jev: host_adapter_changed' } : undefined;
  state.evaluators.set(activeMarker, { evaluate, mode });
  pi.on('tool_call', activeMarker);
  return true;
}
