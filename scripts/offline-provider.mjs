// Test-only deterministic provider: drives real OMP agent loops without network.
import { join } from 'node:path';
export default function offlineProvider(pi) {
  const root = process.env.JEV_SMOKE_ROOT;
  if (!root) throw new Error('This fixture requires JEV_SMOKE_ROOT');
  pi.registerProvider('jev-smoke', {
    baseUrl: 'http://127.0.0.1:1', apiKey: 'offline-fixture-not-a-credential', api: 'jev-smoke-stream',
    models: [{ id: 'offline', name: 'Offline acceptance fixture', reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096 }],
    streamSimple(model, context) {
      const child = context.messages.some(message => message.role === 'user' && JSON.stringify(message.content).includes('JEV_CHILD_ACTION'));
      const prior = context.messages.filter(message => message.role === 'toolResult');
      let content;
      if (child) {
        content = prior.some(message => message.toolCallId === 'child-write')
          ? [{ type: 'text', text: 'Child observed its blocked action.' }]
          : [{ type: 'toolCall', id: 'child-write', name: 'write', arguments: { i: 'Checking child enforcement', path: join(root, 'work/child-must-not-exist.txt'), content: 'blocked child side effect' } }];
      } else if (!prior.some(message => message.toolCallId === 'parent-read')) {
        content = [
          { type: 'toolCall', id: 'parent-read', name: 'read', arguments: { i: 'Reading authorized fixture', path: join(root, 'work/source.txt') } },
          { type: 'toolCall', id: 'parent-write', name: 'write', arguments: { i: 'Writing approved fixture', path: join(root, 'work/approved.txt'), content: 'actual built-in write' } },
          { type: 'toolCall', id: 'parent-protected', name: 'write', arguments: { i: 'Checking protected target', path: join(root, 'protected/must-not-exist.txt'), content: 'blocked protected side effect' } },
          { type: 'toolCall', id: 'parent-task', name: 'task', arguments: { i: 'Checking child propagation', context: 'Offline acceptance fixture, not authorization.', tasks: [{ name: 'SmokeChild', agent: 'jev-smoke-child', task: 'JEV_CHILD_ACTION: attempt the prescribed write once, then report its outcome.', solutionSpace: 'one prescribed offline smoke action' }] } },
        ];
      } else content = [{ type: 'text', text: 'Offline parent scenarios completed.' }];
      const message = { role: 'assistant', content, api: model.api, provider: model.provider, model: model.id,
        usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
        stopReason: content.some(block => block.type === 'toolCall') ? 'toolUse' : 'stop', timestamp: Date.now() };
      return { result: async () => message, async *[Symbol.asyncIterator]() {
        yield { type: 'start', partial: message };
        for (const [index, block] of content.entries()) {
          if (block.type === 'toolCall') yield { type: 'toolcall_end', contentIndex: index, toolCall: block, partial: message };
          else yield { type: 'text_end', contentIndex: index, content: block.text, partial: message };
        }
        yield { type: 'done', reason: message.stopReason, message };
      } };
    },
  });
  pi.on('session_start', (_event, ctx) => {
    process.stdout.write(`${JSON.stringify({ type: 'jev_scope_probe', agent: ctx.agent, hasUI: ctx.hasUI })}\n`);
  });
  pi.on('tool_result', (event, ctx) => {
    process.stdout.write(`${JSON.stringify({ type: 'jev_effect_probe', agent: ctx.agent.kind, toolName: event.toolName, toolCallId: event.toolCallId, isError: event.isError, text: event.content.filter(item => item.type === 'text').map(item => item.text).join('').slice(0, 3000) })}\n`);
  });
}
