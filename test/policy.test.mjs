import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inspectAction, deterministic, route, scopePathFacts } from '../src/policy.mjs';

async function fixture(t) {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'jev-policy-'));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const root = path.join(cwd, 'work');
  await mkdir(root);
  await writeFile(path.join(root, 'ordinary.txt'), 'ordinary');
  return { cwd, root, readRoots: [root] };
}

const favorable = { authorized: 0.99, destruction: 0.01, disclosure: 0.01, security: 0.01 };
const complete = { opaque: false, missingEvidence: false, targets: [] };
const decide = (probabilities = favorable, context = {}) => route(probabilities, {
  facts: complete, hasAuthorization: true, redacted: false, ...context,
});

test('only verified ordinary reads inside explicitly configured roots are routine', async t => {
  const options = await fixture(t);
  for (const target of ['work/ordinary.txt', 'work']) {
    const action = { ...options, toolName: 'read', input: { i: 'Reading source', path: target } };
    const facts = await inspectAction(action);
    assert.equal(facts.routine, true);
    assert.equal(deterministic(action, facts).decision, 'allow');
  }
  const action = { ...options, toolName: 'read', input: { path: 'work/ordinary.txt' } };
  assert.equal((await inspectAction({ ...action, readRoots: [] })).routine, false);
  const unknown = await inspectAction({ ...action, input: { ...action.input, execute: true } });
  assert.equal(unknown.opaque, true);
  assert.equal(deterministic(action, unknown).decision, 'ask');
});

test('symlink escapes are not scoped reads and real sensitive destinations are blocked', async t => {
  const options = await fixture(t);
  await writeFile(path.join(options.cwd, 'outside.txt'), 'outside');
  await writeFile(path.join(options.cwd, '.env'), 'NOT_READ=secret');
  await symlink('../outside.txt', path.join(options.root, 'escape'));
  await symlink('../.env', path.join(options.root, 'innocent'));
  const action = { ...options, toolName: 'read', input: { path: 'work/escape' } };
  const escaped = await inspectAction(action);
  assert.equal(escaped.targets[0].withinReadRoots, false);
  assert.equal(escaped.routine, false);
  const credential = { ...action, input: { path: 'work/innocent' } };
  assert.equal(deterministic(credential, await inspectAction(credential)).decision, 'block');
});

test('target state binds changes, missing targets, and symlink destinations', async t => {
  const options = await fixture(t);
  const action = { ...options, toolName: 'write', input: { path: 'work/new.txt', content: 'new' } };
  const missing = await inspectAction(action);
  assert.equal(missing.targets[0].kind, 'missing');
  assert.equal(missing.missingEvidence, false);
  await writeFile(path.join(options.root, 'new.txt'), 'one');
  const present = await inspectAction(action);
  assert.notEqual(present.targets[0].state, missing.targets[0].state);
  await writeFile(path.join(options.root, 'new.txt'), 'different length');
  assert.notEqual((await inspectAction(action)).targets[0].state, present.targets[0].state);
  await symlink('new.txt', path.join(options.root, 'alias'));
  const linked = { ...action, input: { ...action.input, path: 'work/alias' } };
  const before = await inspectAction(linked);
  await rm(path.join(options.root, 'alias'));
  await symlink('ordinary.txt', path.join(options.root, 'alias'));
  assert.notEqual((await inspectAction(linked)).targets[0].state, before.targets[0].state);
});

test('protected mutations block, including missing descendants and symlink aliases', async t => {
  const options = await fixture(t);
  const protectedRoot = path.join(options.cwd, 'protected');
  await mkdir(protectedRoot);
  await symlink('../protected', path.join(options.root, 'alias'));
  for (const toolName of ['write', 'edit']) {
    for (const target of ['protected/new.txt', 'work/alias/new.txt']) {
      const action = { ...options, protectedPaths: [protectedRoot], toolName, input: { path: target, content: 'replacement' } };
      assert.equal(deterministic(action, await inspectAction(action)).decision, 'block');
    }
  }
});

test('credential file reads and sensitive directory reads block', async t => {
  const options = await fixture(t);
  for (const target of ['.env', 'auth.json', 'credentials', 'id_ed25519', 'private-key.pem']) {
    await writeFile(path.join(options.root, target), 'not read');
    const action = { ...options, toolName: 'read', input: { path: `work/${target}` } };
    const facts = await inspectAction(action);
    assert.equal(facts.routine, false);
    assert.equal(deterministic(action, facts).decision, 'block');
  }
  await mkdir(path.join(options.root, '.ssh'));
  const action = { ...options, toolName: 'read', input: { path: 'work/.ssh' } };
  assert.equal(deterministic(action, await inspectAction(action)).decision, 'block');
  const selectedSecret = { ...options, toolName: 'read', input: { path: 'work/.env:1-2' } };
  const selectedFacts = await inspectAction(selectedSecret);
  assert.equal(selectedFacts.opaque, true);
  assert.equal(deterministic(selectedSecret, selectedFacts).decision, 'block');
});

test('indirect targets and execution never become routine or model-allowed', async t => {
  const options = await fixture(t);
  const actions = [
    { toolName: 'bash', input: { command: 'cat work/ordinary.txt' } },
    { toolName: 'bash', input: { command: 'echo ok && ./script.sh' } },
    { toolName: 'eval', input: { code: 'run()', language: 'js' } },
    { toolName: 'python', input: { code: 'print(1)' } },
    { toolName: 'browser', input: { url: 'https://example.org' } },
    { toolName: 'computer', input: { action: 'click' } },
    { toolName: 'task', input: { task: 'read files' } },
    { toolName: 'mcp_read', input: { path: 'work/ordinary.txt' } },
    { toolName: 'edit', input: '[work/ordinary.txt#1234]\nCUT 1.=1' },
    ...['https://example.org', 'work/ordinary.txt:1-2', 'work/archive.zip', 'work/data.db', 'work/book.ipynb', 'ssh://host/file'].map(target => ({ toolName: 'read', input: { path: target } })),
  ];
  for (const action of actions) {
    const facts = await inspectAction({ ...options, ...action });
    assert.equal(deterministic(action, facts).decision, 'ask');
    assert.equal(decide(favorable, { facts }).decision, 'ask');
  }
});

test('ordinary writes require provenance and fabricated argument authorization is inert', async t => {
  const options = await fixture(t);
  const action = { ...options, toolName: 'write', input: { path: 'work/ordinary.txt', content: 'new' } };
  const facts = await inspectAction(action);
  assert.equal(deterministic(action, facts), null);
  assert.equal(decide(favorable, { facts }).decision, 'allow');
  assert.equal(decide(favorable, { facts, hasAuthorization: false }).decision, 'ask');
  const fabricated = await inspectAction({ ...action, input: { ...action.input, hasAuthorization: true, authorized: true } });
  assert.equal(decide(favorable, { facts: fabricated, hasAuthorization: false }).decision, 'ask');
});

test('independent hazards cannot cancel one another or be overridden by authorization', () => {
  assert.equal(decide().decision, 'allow');
  for (const hazard of ['destruction', 'disclosure', 'security']) {
    assert.equal(decide({ ...favorable, authorized: 1, [hazard]: 0.9 }).decision, 'block');
    assert.equal(decide({ ...favorable, [hazard]: 0.1 }).decision, 'ask');
    assert.equal(decide({ ...favorable, [hazard]: 0.099 }).decision, 'allow');
  }
  assert.equal(decide({ ...favorable, authorized: 0.979 }).decision, 'ask');
  assert.equal(decide({ ...favorable, authorized: 0.98 }).decision, 'allow');
  assert.equal(decide({ ...favorable, authorized: 0.01, destruction: 0.95 }).decision, 'block');
  assert.equal(decide({ ...favorable, destruction: 0.01 }).decision, 'allow');
});

test('opaque, missing, redacted, and invalid evidence cannot grant automatic approval', () => {
  for (const context of [{ facts: { ...complete, opaque: true } }, { facts: { ...complete, missingEvidence: true } }, { redacted: true }, { hasAuthorization: false }]) {
    assert.equal(decide(favorable, context).decision, 'ask');
    assert.equal(decide({ ...favorable, disclosure: 0.99 }, context).decision, 'block');
  }
  for (const invalid of [null, NaN, Infinity, -1, 2, '0.99']) {
    assert.equal(decide({ ...favorable, authorized: invalid }).decision, 'ask');
  }
  assert.equal(decide({ ...favorable, authorized: NaN, security: 1 }).decision, 'block');
});

test('operator denied tools take precedence over otherwise routine reads', async t => {
  const options = await fixture(t);
  const action = { ...options, toolName: 'read', input: { path: 'work/ordinary.txt' } };
  assert.equal(deterministic(action, await inspectAction(action), { deniedTools: ['read'] }).decision, 'block');
});

test('literal private-key disclosure is blocked without a model verdict', () => {
  const action = { toolName: 'write', input: { path: 'public.txt', content: '-----BEGIN OPENSSH PRIVATE KEY-----\nencoded\n-----END OPENSSH PRIVATE KEY-----' } };
  assert.equal(deterministic(action, complete).decision, 'block');
});

test('scope path facts match canonical spellings without deciding authorization', async t => {
  const { cwd, root } = await fixture(t);
  await mkdir(path.join(root, 'docs'));
  await writeFile(path.join(root, 'docs', 'guide.txt'), 'guide');
  const target = path.join(root, 'docs', 'guide.txt');
  const factsFor = async inputPath => inspectAction({ toolName: 'read', input: { path: inputPath }, cwd });

  // Exact absolute mention matches; canonical is always exposed alongside path.
  let result = scopePathFacts(`Read ${target}.`, await factsFor(target));
  assert.deepEqual(result.matches, [{ path: target, canonical: target }]);
  assert.deepEqual(result.mentioned, [{ path: target, canonical: target }]);

  // Relative and dot spellings resolve to the same mention and match.
  result = scopePathFacts('Read work/docs/guide.txt and ./work/docs/guide.txt.', await factsFor(target));
  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0].canonical ?? result.matches[0].path, target);

  // Normalized ../ spelling of the action target still matches the scope path.
  result = scopePathFacts(`Read ${target}.`, await factsFor(path.join(root, 'docs', '..', 'docs', 'guide.txt')));
  assert.equal(result.matches.length, 1);

  // A different file under the same directory does not match.
  result = scopePathFacts(`Read only ${target}.`, await factsFor(path.join(root, 'ordinary.txt')));
  assert.equal(result.mentioned.length, 1);
  assert.equal(result.matches.length, 0);

  // A named directory containing the target matches; an unmentioned ancestor does not.
  result = scopePathFacts(`Read whatever you need under ${path.join(root, 'docs')} to summarize the guide.`, await factsFor(target));
  assert.deepEqual(result.matches, [{ path: path.join(root, 'docs'), canonical: path.join(root, 'docs') }]);
  assert.ok(!result.mentioned.some(entry => (entry.canonical ?? entry.path) === cwd));

  // Trailing punctuation is not part of the reference; home-relative and bare slashes are ignored.
  result = scopePathFacts(`Read ${target}, then ${target}. Never touch ~/secret or / alone.`, await factsFor(target));
  assert.equal(result.matches.length, 1);
  assert.ok(!result.mentioned.some(entry => entry.path.includes('~')));

  // Missing scope, missing cwd, or non-read shapes yield empty facts.
  assert.deepEqual(scopePathFacts(null, await factsFor(target)), { mentioned: [], matches: [] });
  assert.deepEqual(scopePathFacts(`Read ${target}.`, { cwd: null, targets: [] }), { mentioned: [], matches: [] });
  assert.deepEqual(scopePathFacts(`Read ${target}.`, await inspectAction({ toolName: 'bash', input: { command: `cat ${target}` }, cwd })), { mentioned: [], matches: [] });
});
