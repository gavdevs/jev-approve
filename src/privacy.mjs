import { createHmac } from 'node:crypto';

const MASK = '[REDACTED]';
const sensitiveName = (name) => {
  const normalized = name.replace(/[^a-z0-9]/gi, '').toLowerCase();
  return /password|passwd|passphrase|secret|token|apikey|privatekey|cookie|credential|accesskey|signingkey|encryptionkey|databaseurl|connectionstring/.test(normalized)
    || /^(key|pwd|auth|pin|authorization|proxyauthorization)$/.test(normalized);
};
const environmentName = (name) => /^(env|environment|environmentvariables)$/i.test(name);
const tokenPatterns = [
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,
  /\b(?:Bearer|Basic)\s+([^\s,;"'<>]+)/gi,
  /\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
];
const assignmentPattern = /(?:^|[\s,;{?&"'])(?:--)?((?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|cookie|credential|access[_-]?key|signing[_-]?key|encryption[_-]?key|database[_-]?url|connection[_-]?string)[A-Za-z0-9_.-]*|key|pwd|auth|pin|authorization)["']?\s*(?:=|:)\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;&}\]"']+))/gi;
const flagPattern = /(?:^|\s)--([A-Za-z][A-Za-z0-9_-]*)[ \t]+(?:"([^"\r\n]*)"|'([^'\r\n]*)'|((?!--)[^\s,;&}\]"']+))/g;
const urlPattern = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi;

function decoded(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

// Discovery precedes rewriting: a credential in a late field must also disappear
// from earlier instructions, arbitrary object keys, and target paths.
export function sanitize(value, secrets = []) {
  let redacted = false;
  const known = new Set();
  const add = (secret) => {
    if ((typeof secret === 'string' || typeof secret === 'number') && String(secret)) {
      const text = String(secret);
      known.add(text);
      known.add(encodeURIComponent(text));
      known.add(encodeURIComponent(text).replace(/%[A-F0-9]{2}/g, (part) => part.toLowerCase()));
      known.add(new URLSearchParams({ value: text }).toString().slice(6));
    }
  };
  const discoverText = (text) => {
    for (const pattern of tokenPatterns) {
      for (const match of text.matchAll(pattern)) {
        add(match[1] ?? match[0]);
        if (match[0].startsWith('-----BEGIN ')) {
          const body = match[0].replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').trim();
          add(body);
          for (const line of body.split(/\r?\n/)) add(line.trim());
        }
      }
    }
    for (const pattern of [assignmentPattern, flagPattern]) {
      for (const match of text.matchAll(pattern)) {
        if (sensitiveName(match[1])) {
          const secret = match[2] ?? match[3] ?? match[4];
          add(secret);
          add(decoded(secret));
        }
      }
    }
    for (const match of text.matchAll(/(?:^|[\r\n"'])\s*(?:Cookie|Set-Cookie)\s*:\s*([^\r\n"']+)/gi)) {
      add(match[1]);
      for (const part of match[1].split(';')) {
        const separator = part.indexOf('=');
        if (separator !== -1) add(part.slice(separator + 1).trim());
      }
    }
    for (const match of text.matchAll(urlPattern)) {
      try {
        const url = new URL(match[0]);
        if (url.username || url.password) {
          add(url.username);
          add(url.password);
          add(decoded(url.username));
          add(decoded(url.password));
        }
        for (const [key, secret] of url.searchParams) {
          if (sensitiveName(key)) add(secret);
        }
      } catch { /* Invalid URLs still pass through assignment/token discovery. */ }
    }
  };
  try {
    for (const secret of secrets) add(secret);
    for (const [name, secret] of Object.entries(process.env)) {
      // POSIX PWD is the working directory, not the password-field alias "pwd".
      if (name !== 'PWD' && sensitiveName(name)) add(secret);
    }
    const visited = new WeakMap();
    const discover = (item, sensitive = false) => {
      if (typeof item === 'string') {
        if (sensitive) add(item);
        discoverText(item);
        return;
      }
      if (typeof item === 'number') {
        if (sensitive) add(item);
        return;
      }
      if (item === null || typeof item !== 'object') return;
      // Revisit shared objects when reached through a sensitive field later.
      if (visited.has(item) && (visited.get(item) || !sensitive)) return;
      visited.set(item, sensitive);
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(item))) {
        if (!descriptor.enumerable) continue;
        discoverText(key);
        if (sensitive) add(key);
        if ('value' in descriptor) {
          discover(descriptor.value, sensitive || sensitiveName(key) || environmentName(key));
        }
      }
    };
    discover(value);
    const alternatives = [...known].sort((a, b) => b.length - a.length)
      .map((secret) => secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const knownPattern = alternatives.length ? new RegExp(alternatives.join('|'), 'g') : null;
    const cleanText = (text) => {
      if (!knownPattern) return text;
      return text.replace(knownPattern, () => { redacted = true; return MASK; });
    };
    const ancestors = new WeakSet();
    const clean = (item, depth = 0) => {
      if (typeof item === 'string') return cleanText(item);
      if (typeof item === 'number' && Number.isFinite(item)) {
        if (known.has(String(item))) { redacted = true; return MASK; }
        return item;
      }
      if (item === null || typeof item === 'boolean') return item;
      if (typeof item !== 'object' || depth > 100 || ancestors.has(item)) {
        redacted = true;
        return MASK;
      }
      const prototype = Object.getPrototypeOf(item);
      if (!Array.isArray(item) && prototype !== Object.prototype && prototype !== null) {
        redacted = true;
        return MASK;
      }
      ancestors.add(item);
      const result = Array.isArray(item) ? [] : Object.create(null);
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(item))) {
        if (!descriptor.enumerable) continue;
        const safeKey = cleanText(key);
        const hidden = sensitiveName(key) || environmentName(key) || !('value' in descriptor);
        if (hidden) redacted = true;
        Object.defineProperty(result, safeKey, {
          value: hidden ? MASK : clean(descriptor.value, depth + 1),
          enumerable: true, configurable: true, writable: true,
        });
      }
      ancestors.delete(item);
      return result;
    };
    return { value: clean(value), redacted };
  } catch {
    // Proxies, extreme recursion, and unusual non-JSON values fail closed.
    return { value: MASK, redacted: true };
  }
}

// Canonicalization is deliberately local and does not redact: distinct exact
// invocations must never share an approval because their secrets were removed.
export function canonical(value) {
  const ancestors = new WeakSet();
  const encode = (item) => {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item);
    if (typeof item !== 'object' || ancestors.has(item)) throw new Error('Invalid action snapshot');
    const prototype = Object.getPrototypeOf(item);
    if (!Array.isArray(item) && prototype !== Object.prototype && prototype !== null) throw new Error('Invalid action snapshot');
    ancestors.add(item);
    let result;
    if (Array.isArray(item)) {
      result = '[' + Array.from({ length: item.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(item, index);
        if (!descriptor || !('value' in descriptor)) throw new Error('Invalid action snapshot');
        return encode(descriptor.value);
      }).join(',') + ']';
    } else {
      result = '{' + Object.keys(item).sort().map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!('value' in descriptor)) throw new Error('Invalid action snapshot');
        return JSON.stringify(key) + ':' + encode(descriptor.value);
      }).join(',') + '}';
    }
    ancestors.delete(item);
    return result;
  };
  return encode(value);
}

export function fingerprint(value, key) {
  return createHmac('sha256', key).update(canonical(value)).digest('hex');
}
