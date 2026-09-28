// Test-only deterministic provider: drives a real OMP agent loop whose Eval
// payload calls agent()/workpool(); each child attempts one unauthorized write.
import { join } from 'node:path';
export default function evalRebindProvider(pi) {
  const root = process.env.JEV_SMOKE_ROOT;
  if (!root) throw new Error('This fixture requires JEV_SMOKE_ROOT');
  pi.registerProvider('jev-smoke', {
    baseUrl: 'http://127.0.0.1:1', apiKey: 'offline-fixture-not-a-credential', api: 'jev-smoke-stream',
    models: [{ id: 'offline', name: 'Offline acceptance fixture', reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096 }],
    streamSimple(model, context) {
      const userText = context.messages.filter(message => message.role === 'user').map(message => JSON.stringify(message.content)).join('');
      const prior = context.messages.filter(message => message.role === 'toolResult');
      let content;
      if (userText.includes('JEV_AGENT_CHILD')) {
        content = prior.some(message => message.toolCallId === 'agent-child-write')
          ? [{ type: 'text', text: 'Agent child observed its blocked action.' }]
          : [{ type: 'toolCall', id: 'agent-child-write', name: 'write', arguments: { i: 'Checking agent() child enforcement', path: join(root, 'work/agent-child-must-not-exist.txt'), content: 'blocked agent child side effect' } }];
      } else if (userText.includes('JEV_POOL_CHILD')) {
        content = prior.some(message => message.toolCallId === 'pool-child-write')
          ? [{ type: 'text', text: 'Pool child observed its blocked action.' }]
          : [{ type: 'toolCall', id: 'pool-child-write', name: 'write', arguments: { i: 'Checking workpool() child enforcement', path: join(root, 'work/pool-child-must-not-exist.txt'), content: 'blocked pool child side effect' } }];
      } else if (!prior.some(message => message.toolCallId === 'parent-eval')) {
        const code = `
const handle = agent('JEV_AGENT_CHILD: attempt the prescribed write once, then report its outcome.', { label: 'jev-agent-child' });
print('EVAL_AGENT_SPAWNED', String(typeof handle));
print('EVAL_AGENT_RESULT', JSON.stringify(await handle.wait(60)));
const pool = await workpool({ name: 'jev-pool' });
pool.push('JEV_POOL_CHILD: attempt the prescribed write once, then report its outcome.');
let poolStatus = null;
for (let i = 0; i < 120; i++) {
  poolStatus = await pool.status();
  if (poolStatus && poolStatus.items.queued === 0 && poolStatus.items.running === 0) break;
  await new Promise(resolve => setTimeout(resolve, 500));
}
print('EVAL_POOL_SPAWNED', JSON.stringify(poolStatus));
await pool.close();
`;
        content = [{ type: 'toolCall', id: 'parent-eval', name: 'eval', arguments: { i: 'Running the Eval child-rebinding scenario', language: 'js', timeout: 120, reset: true, code } }];
      } else content = [{ type: 'text', text: 'Offline rebind scenario completed.' }];
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
