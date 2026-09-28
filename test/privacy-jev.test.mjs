import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { sanitize, canonical, fingerprint } from '../src/privacy.mjs';
import { judge, MODEL } from '../src/jev.mjs';

const apiKey = 'local-only-api-credential-fixture';
const probabilities = { authorized: 0.99, destruction: 0.03, disclosure: 0.1, security: 0.02 };
const validResponse = () => ({
  model: MODEL,
  answers: Object.fromEntries(Object.entries(probabilities).map(([name, noul]) => [name, { type: 'noul', noul }])),
  usage: { input_tokens: 100, output_tokens: 20 },
});
const jsonResponse = (value) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const fixedError = (code) => (error) => {
  assert.equal(error.code, code);
  assert.equal(error.cause, undefined);
  assert.equal(error.message.includes(apiKey), false);
  assert.equal(error.message.includes('server-secret'), false);
  return true;
};
async function server(t, handler) {
  const instance = createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  t.after(() => {
    instance.closeAllConnections();
    return new Promise((resolve) => instance.close(resolve));
  });
  return `http://127.0.0.1:${instance.address().port}`;
}

test('secrets discovered late disappear from earlier instructions, keys, paths, and nested copies', () => {
  const secret = 'buried-private-value-791';
  const input = {
    userAuthorization: { source: 'interactive', text: `Inspect /work/${secret}/notes` },
    action: { input: { [secret]: `copy ${secret}`, nested: [secret] }, cwd: `/work/${secret}` },
    facts: { targets: [{ path: `/work/${secret}` }] },
    credentials: { password: secret },
  };
  const result = sanitize(input);
  assert.equal(result.redacted, true);
  assert.equal(JSON.stringify(result.value).includes(secret), false);
  assert.equal(result.value.userAuthorization.source, 'interactive');
  assert.equal(input.credentials.password, secret);
});

test('all environment values and caller-supplied secrets are hidden across the payload', () => {
  const result = sanitize({
    message: 'custom-env-value custom-supplied-value numeric 473821',
    env: { CUSTOM: 'custom-env-value' },
    pin: 473821,
    copiedNumber: 473821,
  }, ['custom-supplied-value']);
  const serialized = JSON.stringify(result.value);
  for (const secret of ['custom-env-value', 'custom-supplied-value', '473821']) assert.equal(serialized.includes(secret), false);
  assert.equal(result.redacted, true);
});

test('TYPESAFE_API_KEY is automatically removed from arbitrary text and keys', () => {
  const previous = process.env.TYPESAFE_API_KEY;
  process.env.TYPESAFE_API_KEY = 'environment-fixture-key-428';
  try {
    const result = sanitize({ ['environment-fixture-key-428']: 'use environment-fixture-key-428' });
    assert.equal(JSON.stringify(result.value).includes('environment-fixture-key-428'), false);
    assert.equal(result.redacted, true);
  } finally {
    if (previous === undefined) delete process.env.TYPESAFE_API_KEY;
    else process.env.TYPESAFE_API_KEY = previous;
  }
});

test('ambient PWD preserves working-directory evidence without exempting password fields', () => {
  const previous = process.env.PWD;
  process.env.PWD = '/tmp/jev-public-workspace';
  try {
    const result = sanitize({ action: { cwd: process.env.PWD } });
    assert.equal(result.value.action.cwd, process.env.PWD);
    assert.equal(result.redacted, false);
    const password = sanitize({ pwd: 'private-password-fixture', copied: 'private-password-fixture' });
    assert.equal(password.value.pwd, '[REDACTED]');
    assert.equal(password.value.copied, '[REDACTED]');
    assert.equal(password.redacted, true);
  } finally {
    if (previous === undefined) delete process.env.PWD;
    else process.env.PWD = previous;
  }
});

test('text credentials are removed from their source and copied ordinary fields', () => {
  const fixtures = [
    ['run --password "a password with spaces"', 'a password with spaces'],
    ['run --api-key=assignment-secret-488', 'assignment-secret-488'],
    ['export DB_PASSWORD=shell-secret-199', 'shell-secret-199'],
    ['{"password":"json-embedded-secret-176"}', 'json-embedded-secret-176'],
    ['Authorization: Bearer opaque-header-token-583', 'opaque-header-token-583'],
    ['Authorization: Basic dXNlcjpwYXNzd29yZA==', 'dXNlcjpwYXNzd29yZA=='],
    ['Cookie: first=cookie-fixture-one; second=cookie-fixture-two', 'cookie-fixture-two'],
    ['https://username-fixture:encoded%2fsecret@example.com/path', 'encoded/secret'],
    ['https://example.com/?access_token=query%2fsecret&view=all', 'query/secret'],
    ['https://example.com/?api_key=space+secret', 'space secret'],
    ['-----BEGIN PRIVATE KEY-----\nPRIVATEKEYFIXTURE\n-----END PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----\nPRIVATEKEYFIXTURE\n-----END PRIVATE KEY-----'],
    ['-----BEGIN PRIVATE KEY-----\nCOPIEDPEMBODYFIXTURE\n-----END PRIVATE KEY-----', 'COPIEDPEMBODYFIXTURE'],
    ['ghp_abcdefghijklmNOPQRSTUVWXYZ1234', 'ghp_abcdefghijklmNOPQRSTUVWXYZ1234'],
    ['sk-proj-abcdefghijklmnopqrstuvwxyz1234', 'sk-proj-abcdefghijklmnopqrstuvwxyz1234'],
    ['AKIAABCDEFGHIJKLMNOP', 'AKIAABCDEFGHIJKLMNOP'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturefixture', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturefixture'],
  ];
  for (const [text, secret] of fixtures) {
    const result = sanitize({ before: secret, text, [secret]: 'target' });
    assert.equal(result.redacted, true, text);
    const serialized = JSON.stringify(result.value);
    assert.equal(serialized.includes(secret), false, text);
    assert.equal(serialized.includes(encodeURIComponent(secret)), false, text);
  }
});

test('sensitive aliases are rediscovered and getters/cycles do not leak or execute', () => {
  const shared = { entry: 'shared-alias-secret' };
  const input = { first: shared, credentials: shared };
  input.self = input;
  Object.defineProperty(input, 'getter', { enumerable: true, get() { throw new Error('must not execute'); } });
  const result = sanitize(input);
  assert.equal(result.redacted, true);
  assert.equal(JSON.stringify(result.value).includes('shared-alias-secret'), false);
  assert.equal(result.value.getter, '[REDACTED]');
  assert.equal(result.value.self, '[REDACTED]');
});

test('ordinary trusted provenance remains usable and prototype keys remain inert', () => {
  const input = JSON.parse('{"userAuthorization":{"text":"Inspect the source tree","source":"interactive"},"__proto__":{"polluted":true}}');
  const result = sanitize(input);
  assert.equal(result.redacted, false);
  assert.equal(result.value.userAuthorization.text, 'Inspect the source tree');
  assert.equal(Object.getPrototypeOf(result.value), null);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.hasOwn(result.value, '__proto__'), true);
});

test('natural-language authorization is preserved while whitespace password flags are redacted', () => {
  const state = {
    trustedPolicy: 'Never disclose credentials to other services. Keep secret values local and require authorization before modifying files.',
    userAuthorization: { source: 'interactive', text: 'Update the password field documentation and explain token expiration.' },
  };
  const plain = sanitize(state);
  assert.equal(plain.redacted, false);
  assert.equal(canonical(plain.value), canonical(state));
  const flagged = sanitize({
    ...state,
    action: { command: 'client --quiet --password \"flag-secret-fixture\"' },
    copied: 'flag-secret-fixture',
  });
  assert.equal(flagged.redacted, true);
  assert.equal(JSON.stringify(flagged.value).includes('flag-secret-fixture'), false);
  assert.equal(flagged.value.userAuthorization.text, state.userAuthorization.text);
});

test('action identities ignore object insertion order but bind exact secrets, arrays, and instance key', () => {
  const key = Buffer.alloc(32, 11);
  const input = { toolName: 'write', input: { password: 'alpha', path: 'a' }, args: [1, 2] };
  const reordered = { args: [1, 2], input: { path: 'a', password: 'alpha' }, toolName: 'write' };
  assert.equal(canonical(input), canonical(reordered));
  const identity = fingerprint(input, key);
  assert.equal(identity, fingerprint(reordered, key));
  assert.notEqual(identity, fingerprint({ ...input, input: { ...input.input, password: 'beta' } }, key));
  assert.notEqual(identity, fingerprint({ ...input, args: [2, 1] }, key));
  assert.notEqual(identity, fingerprint(input, Buffer.alloc(32, 12)));
  assert.match(identity, /^[a-f0-9]{64}$/);
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => canonical(cyclic));
  assert.throws(() => canonical({ input: undefined }));
});

test('one real HTTP request returns independent probabilities and excludes secrets from body', async (t) => {
  let calls = 0;
  let received;
  let auth;
  const url = await server(t, async (request, response) => {
    calls++;
    auth = request.headers.authorization;
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks).toString());
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(validResponse()));
  });
  const result = await judge({
    userAuthorization: { source: 'interactive', text: `Inspect notes ${apiKey}` },
    action: { toolName: 'read', input: { path: '/work/notes', password: 'copied-secret-151' } },
    untrustedEvidence: `copied-secret-151 ${apiKey}`,
  }, {
    apiKey,
    fetchImpl: (endpoint, init) => {
      assert.equal(endpoint, 'https://api.typesafe.ai/v1/systemone');
      assert.equal(init.redirect, 'error');
      return fetch(url, init);
    },
  });
  assert.deepEqual(result, { probabilities, model: MODEL });
  assert.equal(calls, 1);
  assert.equal(auth, `Bearer ${apiKey}`);
  const body = JSON.stringify(received);
  assert.equal(body.includes(apiKey), false);
  assert.equal(body.includes('copied-secret-151'), false);
  assert.equal(received.userAuthorization, undefined);
  assert.equal(received.state.userAuthorization.source, 'interactive');
});

test('missing credentials never start a request', async () => {
  let calls = 0;
  await assert.rejects(judge({}, { apiKey: ' ', fetchImpl: () => { calls++; } }), fixedError('missing_credentials'));
  assert.equal(calls, 0);
});

test('HTTP errors are fixed and never retried; redirects never reach their destination', async (t) => {
  let calls = 0;
  let destinations = 0;
  const url = await server(t, (request, response) => {
    calls++;
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: '/destination' });
      response.end();
    } else if (request.url === '/destination') {
      destinations++;
      response.end('server-secret');
    } else {
      response.writeHead(503, { 'Content-Type': 'text/plain' });
      response.end(`server-secret ${apiKey}`);
    }
  });
  for (const path of ['/failure', '/redirect']) {
    await assert.rejects(judge({}, { apiKey, fetchImpl: (_, init) => fetch(url + path, init) }), fixedError('service_unavailable'));
  }
  assert.equal(calls, 2);
  assert.equal(destinations, 0);
});

test('untrusted transport errors cannot forge safe error codes or expose payloads', async () => {
  await assert.rejects(judge({}, {
    apiKey,
    fetchImpl: async () => { throw Object.assign(new Error(`server-secret ${apiKey}`), { code: 'invalid_response' }); },
  }), fixedError('service_unavailable'));
});

test('malformed, incomplete, mistyped, nonfinite, out-of-range and unpinned responses fail closed', async () => {
  const mutations = [
    (value) => { delete value.model; },
    (value) => { value.model = 'jev-latest'; },
    (value) => { value.model = 'jev-1.14.0'; },
    (value) => { delete value.answers.security; },
    (value) => { value.answers.extra = { type: 'noul', noul: 0 }; },
    (value) => { value.answers.authorized.type = 'score'; },
    (value) => { value.answers.authorized.noul = '0.99'; },
    (value) => { value.answers.authorized.noul = true; },
    (value) => { value.answers.authorized.noul = null; },
    (value) => { value.answers.destruction.noul = -0.01; },
    (value) => { value.answers.disclosure.noul = 1.01; },
    (value) => { value.answers = []; },
  ];
  for (const mutate of mutations) {
    const value = validResponse(); mutate(value);
    await assert.rejects(judge({}, { apiKey, fetchImpl: async () => jsonResponse(value) }), fixedError('invalid_response'));
  }
  for (const raw of ['{server-secret', 'null', JSON.stringify(validResponse()).replace('0.99', '1e999')]) {
    await assert.rejects(judge({}, { apiKey, fetchImpl: async () => new Response(raw, { headers: { 'Content-Type': 'application/json' } }) }), fixedError('invalid_response'));
  }
});

test('stream limits apply without Content-Length and declared oversized bodies fail closed', async () => {
  for (const headers of [{}, { 'Content-Length': '9999999' }]) {
    await assert.rejects(judge({}, {
      apiKey,
      fetchImpl: async () => new Response(' '.repeat(65 * 1024), { headers: { 'Content-Type': 'application/json', ...headers } }),
    }), fixedError('invalid_response'));
  }
});

test('deadline bounds both uncooperative fetch and a hanging response body', async () => {
  let signal;
  await assert.rejects(judge({}, {
    apiKey, timeoutMs: 25,
    fetchImpl: (_, init) => { signal = init.signal; return new Promise(() => {}); },
  }), fixedError('timeout'));
  assert.equal(signal.aborted, true);
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  await assert.rejects(judge({}, {
    apiKey, timeoutMs: 25,
    fetchImpl: async () => new Response(body, { headers: { 'Content-Type': 'application/json' } }),
  }), fixedError('timeout'));
  assert.equal(cancelled, true);
});
