import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';

export const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export async function loadConfig(env = process.env, cwd = process.cwd()) {
  const mode = env.JEV_APPROVE_MODE ?? 'shadow';
  if (!['shadow', 'enforce'].includes(mode)) throw new Error('invalid_configuration');
  const configPath = env.JEV_APPROVE_CONFIG;
  if (configPath && !isAbsolute(configPath)) throw new Error('invalid_configuration');
  const text = configPath ? await readFile(configPath, 'utf8') : '{}';
  const data = JSON.parse(text);
  const keys = ['readRoots', 'deniedTools', 'protectedPaths', 'timeoutMs', 'approvalTimeoutMs', 'auditPath'];
  if (!data || Array.isArray(data) || typeof data !== 'object' || Object.keys(data).some(k => !keys.includes(k))) throw new Error('invalid_configuration');
  for (const key of ['readRoots', 'deniedTools', 'protectedPaths']) {
    if (data[key] !== undefined && (!Array.isArray(data[key]) || data[key].some(v => typeof v !== 'string' || !v))) throw new Error('invalid_configuration');
  }
  for (const key of ['readRoots', 'protectedPaths']) {
    if ((data[key] ?? []).some(v => !isAbsolute(v))) throw new Error('invalid_configuration');
  }
  for (const key of ['timeoutMs', 'approvalTimeoutMs']) {
    if (data[key] !== undefined && (!Number.isSafeInteger(data[key]) || data[key] < 100 || data[key] > 60000)) throw new Error('invalid_configuration');
  }
  if (data.auditPath !== undefined && (typeof data.auditPath !== 'string' || !isAbsolute(data.auditPath))) throw new Error('invalid_configuration');
  const readRoots = [];
  for (const root of data.readRoots ?? []) {
    const path = await realpath(root);
    if (!(await stat(path)).isDirectory()) throw new Error('invalid_configuration');
    readRoots.push(path);
  }
  const auditPath = data.auditPath ?? resolve(cwd, '.jev-approve/audit.jsonl');
  const config = {
    mode, remote: env.JEV_APPROVE_REMOTE === '1', configPath,
    configDigest: createHash('sha256').update(text).digest('hex'),
    readRoots, deniedTools: data.deniedTools ?? [],
    protectedPaths: [PACKAGE_ROOT, resolve(homedir(), '.omp'), resolve(homedir(), '.prime'),
      resolve(cwd, '.omp'), ...(env.PI_CODING_AGENT_DIR ? [resolve(env.PI_CODING_AGENT_DIR)] : []),
      ...(configPath ? [configPath] : []), dirname(auditPath), ...(data.protectedPaths ?? [])],
    timeoutMs: data.timeoutMs ?? 8000, approvalTimeoutMs: data.approvalTimeoutMs ?? 60000, auditPath,
  };
  for (const value of Object.values(config)) if (Array.isArray(value)) Object.freeze(value);
  return Object.freeze(config);
}

export async function configurationUnchanged(config) {
  if (!config.configPath) return true;
  try {
    const text = await readFile(config.configPath, 'utf8');
    return createHash('sha256').update(text).digest('hex') === config.configDigest;
  } catch { return false; }
}
