#!/usr/bin/env node
'use strict';

// Read-only kernel self-probe for a disposable Linux audit container. This does
// not start a container, load the upstream skill, or authorize target execution.
const fs = require('node:fs');
const { TextDecoder } = require('node:util');

const MAX_BYTES = 128 * 1024;
const INPUTS = Object.freeze({
  status: '/proc/self/status',
  uidMap: '/proc/self/uid_map',
  gidMap: '/proc/self/gid_map',
  mountinfo: '/proc/self/mountinfo',
  network: '/proc/net/dev',
  memory: '/sys/fs/cgroup/memory.max',
  swap: '/sys/fs/cgroup/memory.swap.max',
  cpu: '/sys/fs/cgroup/cpu.max',
  pids: '/sys/fs/cgroup/pids.max',
  apparmor: '/proc/self/attr/current',
});
const EXPLICIT_ENV = Object.freeze({
  HOME: '/scratch/home',
  TMPDIR: '/tmp',
  PATH: '/usr/local/bin:/usr/bin:/bin',
  LANG: 'C.UTF-8',
});
function getField(status, key) {
  const lines = status.split('\n').filter(line => line.startsWith(key + ':'));
  return lines.length === 1 ? lines[0].slice(key.length + 1).trim() : null;
}
function parseMap(text) {
  const lines = text.trim().split(/\n/).filter(Boolean);
  if (!lines.length || lines.length > 5) return null;
  const result = [];
  for (const line of lines) {
    const pieces = line.trim().split(/\s+/);
    if (pieces.length !== 3 || pieces.some(p => !/^\d+$/.test(p))) return null;
    const values = pieces.map(Number);
    if (values.some(x => !Number.isSafeInteger(x)) || values[2] <= 0) return null;
    result.push(values);
  }
  return result;
}
function mappedWithoutHostRoot(text, id) {
  const ranges = parseMap(text);
  if (!ranges) return false;
  if (ranges.some(([inside, outside, length]) => outside === 0 ||
      outside + length > 4294967296 || inside + length > 4294967296)) return false;
  return ranges.some(([inside, , length]) => id >= inside && id < inside + length);
}
function parseMounts(text) {
  const result = [];
  for (const line of text.trim().split('\n')) {
    const pivot = line.indexOf(' - ');
    if (pivot < 0) return null;
    const lhs = line.slice(0, pivot).split(' ');
    const rhs = line.slice(pivot + 3).split(' ');
    if (lhs.length < 6 || rhs.length < 3) return null;
    // Reject escaped/special mountpoints, which cannot satisfy these literal paths.
    result.push({mount:lhs[4], options:lhs[5].split(','), optional:lhs.slice(6),
      fsType:rhs[0], superOpts:rhs.slice(2).join(' ').split(',')});
  }
  return result;
}
function checkMounts(text) {
  const mounts = parseMounts(text);
  if (!mounts) return false;
  const expected = ['/', '/source', '/scratch', '/tmp'];
  for (const name of expected) {
    if (mounts.filter(x => x.mount === name).length !== 1) return false;
  }
  const byName = Object.fromEntries(mounts.filter(x => expected.includes(x.mount))
    .map(x => [x.mount, x]));
  // A writable root can hide an additional host bind at an unrelated path.
  // A process-only probe cannot identify the host source of a bind, so accept
  // only documented container-system mountpoints, and still require host checks.
  const systemMounts = new Map([
    ['/proc', {type:'proc', required:['nosuid','nodev','noexec']}],
    ['/sys', {type:'sysfs', required:['ro']}],
    ['/sys/fs/cgroup', {type:'cgroup2', required:['ro']}],
    ['/dev', {type:'tmpfs', required:['nosuid']}],
    ['/dev/pts', {type:'devpts', required:['nosuid','noexec']}],
    ['/dev/shm', {type:'tmpfs', required:['nosuid','nodev','noexec']}],
    ['/dev/mqueue', {type:'mqueue', required:['nosuid','nodev','noexec']}],
    ['/etc/hostname', {required:['ro']}],
    ['/etc/hosts', {required:['ro']}],
    ['/etc/resolv.conf', {required:['ro']}],
  ]);
  if (mounts.some(m => {
    // Shared/slave mounts can receive propagation from a separate namespace.
    // Nothing under this evidence-only audit profile should propagate mounts.
    if (m.optional.some(x => /^(shared|master|propagate_from):/.test(x))) return true;
    if (m.mount.includes('\\') || !m.mount.startsWith('/')) return true;
    if (expected.includes(m.mount)) return false;
    const rule = systemMounts.get(m.mount);
    return !rule || (rule.type && m.fsType !== rule.type) ||
      !rule.required.every(flag => m.options.includes(flag));
  })) return false;
  if (!byName['/'].options.includes('ro') || !byName['/source'].options.includes('ro')) return false;
  if (byName['/source'].optional.some(x => /^(shared|master|propagate_from):/.test(x))) return false;
  for (const name of ['/scratch', '/tmp']) {
    const mount = byName[name];
    if (mount.fsType !== 'tmpfs' ||
        !['rw', 'nosuid', 'nodev', 'noexec'].every(v => mount.options.includes(v))) return false;
  }
  // A read-only parent bind does not guarantee all submounts are read-only.
  // Fail closed even when a nested mount claims to be read-only.
  if (mounts.some(m => ['/source','/scratch','/tmp'].some(dir => m.mount.startsWith(dir + '/')))) return false;
  return true;
}
function checkNetwork(text) {
  const lines = text.trim().split('\n');
  if (lines.length < 3) return false;
  const names = lines.slice(2).map(line => line.split(':')[0].trim());
  return names.length === 1 && names[0] === 'lo';
}
function getLimit(s) {
  return /^\d+$/.test(s.trim()) ? Number(s.trim()) : NaN;
}
function checkQuota(cpu) {
  const parts = cpu.trim().split(/\s+/);
  if (parts.length !== 2) return false;
  const [quota, period] = parts.map(getLimit);
  return Number.isSafeInteger(quota) && Number.isSafeInteger(period) &&
    quota > 0 && period > 0 && quota <= period;
}
function checkEnv(env) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return false;
  const keys = Object.keys(env);
  return keys.length === Object.keys(EXPLICIT_ENV).length &&
    keys.every(key => Object.hasOwn(EXPLICIT_ENV, key) && env[key] === EXPLICIT_ENV[key]);
}
function evaluate(records, env) {
  const failures = [];
  const demand = (ok, reason) => { if (!ok) failures.push(reason); };
  if (!records || typeof records !== 'object' ||
      Object.keys(INPUTS).some(name => typeof records[name] !== 'string')) {
    return {ok:false,failures:['missing or invalid kernel observation']};
  }
  const status = records.status;
  const uid = getField(status, 'Uid');
  const gid = getField(status, 'Gid');
  const ids = (line) => line && /^\d+(?:\s+\d+){3}$/.test(line) ? line.split(/\s+/).map(Number) : [];
  const uids = ids(uid), gids = ids(gid);
  demand(uids.length === 4 && uids.every(x => x > 0 && x === uids[0]), 'process UID must be an explicit non-root unchanging ID');
  demand(gids.length === 4 && gids.every(x => x > 0 && x === gids[0]), 'process GID must be an explicit non-root unchanging ID');
  demand(getField(status, 'TracerPid') === '0', 'probe must not be traced or ptrace-supervised');
  demand(getField(status, 'Groups') === '', 'probe must not have supplementary groups');
  demand(getField(status, 'NoNewPrivs') === '1', 'no-new-privileges must be enforced');
  demand(getField(status, 'Seccomp') === '2', 'process must have a kernel seccomp filter');
  demand(/^\d+$/.test(getField(status, 'Seccomp_filters') || '') &&
    Number(getField(status, 'Seccomp_filters')) >= 1, 'seccomp filter count must be positive');
  for (const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']) {
    const value = getField(status,key);
    demand(typeof value === 'string' && /^[0-9a-fA-F]+$/.test(value) && /^0+$/.test(value),
      key + ' must contain zero capabilities');
  }
  demand(uids.length === 4 && mappedWithoutHostRoot(records.uidMap, uids[0]), 'user namespace must map process ID away from host root');
  demand(gids.length === 4 && mappedWithoutHostRoot(records.gidMap, gids[0]), 'group namespace must map process ID away from host root');
  demand(checkMounts(records.mountinfo), 'critical mounts must have read-only/noexec flags and no nested source mounts');
  demand(checkNetwork(records.network), 'network interfaces must contain only loopback');
  const memory = getLimit(records.memory), pids = getLimit(records.pids), swap = getLimit(records.swap);
  demand(Number.isSafeInteger(memory) && memory >= 64*1024*1024 && memory <= 512*1024*1024,
    'cgroup-v2 memory limit must be 64..512 MiB');
  demand(Number.isSafeInteger(pids) && pids >= 1 && pids <= 32, 'cgroup-v2 PID limit must be 1..32');
  demand(swap === 0, 'cgroup-v2 swap allowance must be zero');
  demand(checkQuota(records.cpu), 'cgroup-v2 CPU quota must be limited to at most 1 CPU');
  demand(typeof records.apparmor === 'string' && /\(enforce\)\s*$/.test(records.apparmor) &&
    !/unconfined|complain/i.test(records.apparmor), 'AppArmor process policy must be enforced');
  demand(checkEnv(env), 'process environment must contain only approved variables');
  return {ok:failures.length===0, failures};
}
function readBoundedBytes(file) {
  const flags = fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW;
  if (process.platform !== 'linux' || !Number.isInteger(fs.constants.O_NOFOLLOW) ||
      !Number.isInteger(fs.constants.O_NONBLOCK)) throw new Error('unsupported platform');
  const fd = fs.openSync(file, flags);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error('non-regular kernel observation');
    if (stat.size > MAX_BYTES) throw new Error('kernel observation exceeds bound');
    const bytes = Buffer.alloc(MAX_BYTES+1);
    let offset = 0;
    while (offset < bytes.length) {
      const n = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (!n) break;
      offset += n;
    }
    if (offset > MAX_BYTES) throw new Error('kernel observation exceeds bound');
    const after=fs.fstatSync(fd);
    // Ordinary probe files have stable inode/size/metadata. Procfs virtual
    // observations commonly report a size of zero and cannot use this check.
    // Reject changed source bytes before using them for integrity comparison.
    if (stat.size > 0 &&
        (after.dev !== stat.dev || after.ino !== stat.ino ||
         after.size !== stat.size || after.mtimeMs !== stat.mtimeMs ||
         after.ctimeMs !== stat.ctimeMs || offset !== stat.size)) {
      throw new Error('regular observation changed during bounded read');
    }
    // Return the exact original bytes, including a possible UTF-8 BOM.
    // Hashing decoded text could omit these bytes and mask source changes.
    return bytes.subarray(0,offset);
  } finally { fs.closeSync(fd); }
}
function readBounded(file) {
  return new TextDecoder('utf-8',{fatal:true}).decode(readBoundedBytes(file));
}
function capture() {
  const records = {};
  for (const [name, file] of Object.entries(INPUTS)) records[name] = readBounded(file);
  return records;
}
function main(argv) {
  if (argv.length===1 && argv[0]==='--help') {
    process.stdout.write('Read-only Linux kernel self-probe for a separate disposable audit container; usage: node runtime-probe.cjs\n');
    return 0;
  }
  // Optional finite witness window holds ONLY this first-party self-probe,
  // never starts an agent, and does not write a handshake or spawn subprocesses.
  const witnessWindow = argv.length === 1 && argv[0] === '--witness-window=90';
  if (argv.length !== 0 && !witnessWindow) {
    process.stderr.write('BLOCKED: only the exact 90-second host witness window is accepted; no files or commands\n');
    return 2;
  }
  try {
    const verdict = evaluate(capture(), process.env);
    if (!verdict.ok) {
      for (const reason of verdict.failures) process.stderr.write('BLOCKED: ' + reason + '\n');
      return 1;
    }
    process.stdout.write('KERNEL SELF-PROBE MATCH ONLY: measured safeguards passed. Independent host-side attestation, image/source provenance and disposable-environment review remain mandatory; no audit execution authorized.\n');
    return 0;
  } catch (error) {
    process.stderr.write('BLOCKED: kernel observation unavailable or malformed; no audit authorization\n');
    return 1;
  }
}
if (require.main===module) {
  const args=process.argv.slice(2);
  const result=main(args);
  process.exitCode=result;
  if (result === 0 && args.length === 1 && args[0] === '--witness-window=90') {
    // A host witness can observe this already-validated, non-target process.
    // Expiry is a failure, not an implicit approval. Node holds only a timer.
    setTimeout(() => { process.exitCode=1; }, 90_000);
  }
}
module.exports = {INPUTS,EXPLICIT_ENV,getField,parseMap,mappedWithoutHostRoot,parseMounts,checkMounts,checkNetwork,checkQuota,checkEnv,evaluate,readBounded,readBoundedBytes,capture,main};
