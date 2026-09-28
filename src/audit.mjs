import { constants } from 'node:fs';
import { mkdir, open, realpath } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';

export async function appendAudit(path, record) {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // Linux fd-relative opening pins the parent directory across pathname changes.
  // Fail closed on hosts without /proc rather than use a racy pathname fallback.
  const directory = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const anchor = `/proc/self/fd/${directory.fd}`;
    if (await realpath(anchor) !== resolve(dir)) throw new Error('audit_unavailable');
    const file = await open(`${anchor}/${basename(path)}`, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    try {
      const info = await file.stat();
      if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077) !== 0) throw new Error('audit_unavailable');
      await file.writeFile(`${JSON.stringify(record)}\n`);
    } finally { await file.close(); }
  } finally { await directory.close(); }
}
