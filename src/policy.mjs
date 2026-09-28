import { createHash } from 'node:crypto';
import { lstat, realpath, stat } from 'node:fs/promises';
import path from 'node:path';

export const POLICY_VERSION = '2';

const READ_KEYS = new Set(['i', 'path']);
const WRITE_KEYS = new Set(['i', 'path', 'content']);
const MUTATIONS = new Set(['write', 'edit']);
const SENSITIVE = /^(?:\.env(?:\..*)?|\.ssh|\.aws|\.gnupg|\.kube|auth\.json|credentials(?:\..*)?|secrets?(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.*\.(?:pem|key|p12|pfx)|.*(?:private[-_]?key).*)$/i;
const CONTAINERS = /\.(?:zip|jar|apk|whl|tar|gz|tgz|bz2|xz|rar|7z|iso|cab|deb|rpm|cpio|ar|lzh|arj|asar|sqlite\d*|db|ipynb)$/i;
function inside(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function plainPath(value) {
  return typeof value === 'string' && value.length > 0 && !/[\0\r\n:*?\[\]#]/.test(value)
    && !value.startsWith('~') && !CONTAINERS.test(value);
}


function sensitive(value) {
  return value.split(/[\\/]/).some(part => SENSITIVE.test(part));
}

function metadata(value) {
  return ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']
    .map(key => String(value[key]));
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// Resolve missing targets through their nearest existing ancestor, including symlinks.
async function locate(target) {
  const remainder = [];
  let ancestor = target;
  for (;;) {
    try {
      const link = await lstat(ancestor, { bigint: true });
      const resolved = await realpath(ancestor);
      const actual = await stat(ancestor, { bigint: true });
      if (remainder.length && !actual.isDirectory()) throw new Error('invalid_parent');
      return {
        realPath: path.join(resolved, ...remainder),
        state: digest([ancestor, resolved, remainder, metadata(link), metadata(actual)]),
        kind: remainder.length ? 'missing' : actual.isFile() ? 'file' : actual.isDirectory() ? 'directory' : 'other',
      };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      // A dangling symlink is not an ordinary absent target.
      try {
        await lstat(ancestor);
        throw new Error('unresolved_link');
      } catch (linkError) {
        if (linkError.code !== 'ENOENT') throw linkError;
      }
      const parent = path.dirname(ancestor);
      if (parent === ancestor) throw error;
      remainder.unshift(path.basename(ancestor));
      ancestor = parent;
    }
  }
}

async function roots(values, cwd, mustExist) {
  const result = [];
  for (const value of values ?? []) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) continue;
    const absolute = path.resolve(cwd, value);
    try {
      const found = await locate(absolute);
      if (!mustExist || found.kind === 'directory' || found.kind === 'file') {
        result.push({ path: absolute, realPath: found.realPath });
      }
    } catch {
      if (!mustExist) result.push({ path: absolute, realPath: absolute });
    }
  }
  return result;
}

export async function inspectAction({ toolName, input, cwd, protectedPaths = [], readRoots = [] }) {
  const facts = { cwd: null, targets: [], opaque: true, routine: false, missingEvidence: true };
  try {
    if (typeof cwd !== 'string' || !path.isAbsolute(cwd)) return facts;
    facts.cwd = await realpath(cwd);
    if (!(await stat(facts.cwd)).isDirectory()) return facts;
  } catch {
    return facts;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) return facts;
  // Selectors never qualify for routine allow, but cannot hide a sensitive or
  // protected local target from deterministic prohibitions.
  const targetPath = typeof input.path === 'string' && !input.path.includes('://') ? input.path.split(':', 1)[0] : input.path;
  if (!plainPath(targetPath)) return facts;
  const absolute = path.resolve(facts.cwd, targetPath);
  const target = { path: absolute, realPath: null, state: null, kind: 'unknown', withinReadRoots: false, protected: false, sensitive: sensitive(absolute) };
  facts.targets.push(target);
  const protectedRoots = await roots(protectedPaths, facts.cwd, false);
  target.protected = protectedRoots.some(root => inside(absolute, root.path) || inside(root.path, absolute));
  try {
    Object.assign(target, await locate(absolute));
    target.sensitive ||= sensitive(target.realPath);
    target.protected ||= protectedRoots.some(root => inside(target.realPath, root.realPath) || inside(root.realPath, target.realPath));
    const allowedRoots = await roots(readRoots, facts.cwd, true);
    target.withinReadRoots = allowedRoots.some(root => inside(absolute, root.path) && inside(target.realPath, root.realPath));
  } catch {
    return facts;
  }
  const keys = Object.keys(input);
  if (toolName === 'read' && targetPath === input.path && keys.every(key => READ_KEYS.has(key))) {
    facts.opaque = false;
    facts.missingEvidence = !['file', 'directory'].includes(target.kind);
    facts.routine = !facts.missingEvidence && target.withinReadRoots && !target.sensitive;
  } else if (toolName === 'write' && targetPath === input.path && keys.every(key => WRITE_KEYS.has(key)) && typeof input.content === 'string') {
    facts.opaque = false;
    facts.missingEvidence = !['file', 'missing'].includes(target.kind);
  }
  return facts;
}

export function deterministic({ toolName, input }, facts, { deniedTools = [] } = {}) {
  if (deniedTools.includes(toolName)) return { decision: 'block', rules: ['denied_tool'] };
  if (toolName === 'write' && typeof input?.content === 'string'
    && /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(input.content)) {
    return { decision: 'block', rules: ['credential_disclosure'] };
  }
  if (toolName === 'read' && facts.targets.some(target => target.sensitive)) {
    return { decision: 'block', rules: ['credential_read'] };
  }
  if (MUTATIONS.has(toolName) && facts.targets.some(target => target.protected)) {
    return { decision: 'block', rules: ['protected_mutation'] };
  }
  if (toolName === 'read' && facts.routine && !facts.opaque && !facts.missingEvidence) {
    return { decision: 'allow', rules: ['routine_scoped_read'] };
  }
  if (facts.opaque || facts.missingEvidence) {
    return { decision: 'ask', rules: [facts.opaque ? 'opaque_effects' : 'missing_evidence'] };
  }
  return null;
}
const PATH_REFERENCE = /(?:^|[\s"'`(=])(?<reference>\.{0,2}\/(?:[^\s"'`);]+)|~?\/(?:[^\s"'`);]+))/g;

// Extract deterministic, host-computable path facts from trusted scope text.
// These never decide anything by themselves; they give the model canonical
// evidence instead of relying on lexical path inference inside judgment.
export function scopePathFacts(scopeText, facts) {
  if (typeof scopeText !== 'string' || !scopeText || !facts?.cwd || !Array.isArray(facts.targets) || facts.targets.length !== 1) {
    return { mentioned: [], matches: [] };
  }
  const target = facts.targets[0];
  const forms = new Set([target.path]);
  const normalized = typeof target.path === 'string' ? path.normalize(target.path) : null;
  if (normalized) forms.add(normalized);
  if (target.realPath) forms.add(target.realPath);
  const mentioned = scopePathsMentioned(scopeText, facts.cwd);
  const matches = mentioned.filter(({ path: raw, canonical }) =>
    forms.has(raw) || forms.has(canonical) || inside(canonical, normalized ?? canonical) || (normalized && inside(normalized, canonical)));
  return { mentioned, matches };
}

// All absolute/canonical path references in trusted scope text, deduplicated.
// Pure extraction; no authorization inference. Returns {path, canonical}.
function scopePathsMentioned(scopeText, cwd) {
  const mentioned = new Map();
  if (typeof scopeText !== 'string' || !scopeText || typeof cwd !== 'string' || !path.isAbsolute(cwd)) return [];
  for (const match of scopeText.matchAll(PATH_REFERENCE)) {
    let reference = match.groups.reference.replace(/[.,;:!?]+$/, '');
    if (!reference || reference === '/' || reference === './' || reference === '../') continue;
    if (reference.startsWith('~') || reference.includes('\\') || /[\u0000-\u001f]/.test(reference)) continue;
    if (!path.isAbsolute(reference)) reference = path.resolve(cwd, reference);
    const canonical = path.resolve(reference);
    if (!mentioned.has(canonical)) mentioned.set(canonical, { path: reference, canonical });
  }
  return [...mentioned.values()].map(({ path: raw, canonical }) => ({ path: raw, canonical }));
}


export function route(probabilities, { facts, hasAuthorization, redacted }) {
  const hazards = ['destruction', 'disclosure', 'security'];
  const valid = name => typeof probabilities?.[name] === 'number' && Number.isFinite(probabilities[name])
    && probabilities[name] >= 0 && probabilities[name] <= 1;
  const high = hazards.filter(name => valid(name) && probabilities[name] >= 0.9);
  if (high.length) return { decision: 'block', rules: high.map(name => `high_${name}`) };
  const rules = [];
  if (!['authorized', ...hazards].every(valid)) rules.push('invalid_probabilities');
  for (const name of hazards) {
    if (valid(name) && probabilities[name] >= 0.1) rules.push(`uncertain_${name}`);
  }
  if (!hasAuthorization) rules.push('missing_authorization');
  if (!valid('authorized') || probabilities.authorized < 0.98) rules.push('uncertain_authorization');
  if (!facts || facts.opaque) rules.push('opaque_effects');
  if (!facts || facts.missingEvidence) rules.push('missing_evidence');
  if (redacted) rules.push('redacted_evidence');
  return rules.length ? { decision: 'ask', rules } : { decision: 'allow', rules: ['authorized_low_hazard'] };
}
