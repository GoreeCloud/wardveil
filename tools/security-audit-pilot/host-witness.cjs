#!/usr/bin/env node
'use strict';

// Host-side, READ-ONLY evidence check. This program never invokes Docker,
// starts a container, executes an audit, or changes host/container state.
// Its verdict is a narrow observation, never permission to launch an agent.
const fs = require('node:fs');
const path = require('node:path');
const {readInspectFile, evaluateContainerConfig} = require('./check-container-policy.cjs');
const {readBounded, getField, mappedWithoutHostRoot, checkMounts, checkNetwork, checkQuota} = require('./runtime-probe.cjs');

const NS_TYPES = Object.freeze(['user','pid','mnt','net','ipc','uts','cgroup']);
const MAX_MEMORY = 512 * 1024 * 1024;
const APPROVED_COMMAND = '/opt/wardveil/runtime-probe.cjs';
const APPROVED_WITNESS_ARGUMENT = '--witness-window=90';
const APPROVED_BIN = '/usr/bin/node';

function parseStartTicks(stat) {
  if (typeof stat !== 'string') return null;
  const offset = stat.lastIndexOf(') ');
  if (offset < 0 || !/^\d+ \(/.test(stat)) return null;
  // After ") " the first field is #3; starttime is field #22.
  const fields = stat.slice(offset + 2).trim().split(/\s+/);
  return fields.length >= 20 && /^\d+$/.test(fields[19]) ? fields[19] : null;
}
function cgroupRelativePath(text, id) {
  if (typeof text !== 'string' || typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)) return null;
  const lines = text.trim().split('\n');
  if (lines.length !== 1) return null;
  const m = /^0::(\/[a-zA-Z0-9._\/-]+)$/.exec(lines[0]);
  if (!m || m[1] === '/' || m[1].includes('//') ||
      m[1].split('/').some(part => part === '..' || part === '.')) return null;
  // Match an entire 64-hex container ID as a cgroup path component or
  // Docker's full docker-<id>.scope name. A 12-character prefix or an
  // embedded substring is not sufficient to bind an observed process.
  const segments = m[1].split('/').filter(Boolean);
  if (!segments.some(segment => segment === id || segment === 'docker-' + id + '.scope')) return null;
  return m[1];
}
function matchesProbeCommandLine(data) {
  if (typeof data !== 'string') return false;
  const actual = data.split('\0');
  if (actual[actual.length-1] !== '') return false;
  actual.pop();
  return actual.length === 3 && actual[0] === APPROVED_BIN &&
    actual[1] === APPROVED_COMMAND && actual[2] === APPROVED_WITNESS_ARGUMENT;
}
function isNamespaceRef(value, namespace) {
  return typeof value === 'string' &&
    new RegExp('^' + namespace + ':\\[[0-9]+\\]$').test(value);
}
function safeSnapshot(inspect, expected) {
  if (!Array.isArray(inspect) || inspect.length !== 1) return {ok:false,errors:['expected exactly one Docker container inspection']};
  const doc = inspect[0];
  const e = [];
  const check = (yes, msg) => {if (!yes) e.push(msg);};
  check(expected && /^[0-9a-f]{64}$/.test(expected.id || ''), 'expected ID must be a full container digest');
  check(doc && typeof doc === 'object' && doc.Id === expected.id, 'container ID must match explicit approved target');
  if (!doc || typeof doc !== 'object') return {ok:false,errors:e};
  const st = doc.State || {};
  const pid = st.Pid;
  check(st.Status === 'running' && st.Running === true && st.Restarting === false &&
    st.Paused === false && st.Dead === false &&
    Number.isSafeInteger(pid) && pid > 1 && doc.RestartCount === 0,
    'the expected first-start probe process must still be running');
  check(doc.Path === APPROVED_BIN && Array.isArray(doc.Args) &&
    doc.Args.length === 2 && doc.Args[0] === APPROVED_COMMAND &&
    doc.Args[1] === APPROVED_WITNESS_ARGUMENT,
    'running process must be the reviewed first-party probe command');
  check(Array.isArray(doc.ExecIDs) ? doc.ExecIDs.length === 0 : doc.ExecIDs == null,
    'container must not have additional exec processes');
  // Reuse all static configuration checks. Only the runtime status fields are
  // adapted AFTER checking the running state above; settings remain unchanged.
  const configView = {...doc, State:{...st,Status:'created',Running:false,Pid:0,
    Restarting:false,Paused:false,Dead:false}, RestartCount:doc.RestartCount};
  let policy;
  try { policy = evaluateContainerConfig([configView],
    {image:expected.image,source:expected.source}); }
  catch { policy = {ok:false,errors:['invalid expected image or source']}; }
  check(policy.ok, 'active container config differs from restrictive pre-start policy');
  return {ok:e.length===0,errors:e,pid};
}
function safeHostWitness(inspect, observed, expected) {
  const s = safeSnapshot(inspect,expected);
  if (!s.ok) return {ok:false,errors:s.errors};
  const errs = [];
  const check=(yes,msg)=>{if(!yes)errs.push(msg);};
  const pid=s.pid;
  check(observed && observed.pid === pid, 'host witness PID must match Docker inspection');
  if (!observed || typeof observed !== 'object') return {ok:false,errors:errs};
  check(observed.startBefore != null && observed.startBefore === observed.startAfter &&
    /^\d+$/.test(observed.startBefore || ''), 'PID start time must remain stable during witness capture');
  check(observed.comm === 'node', 'host-observed process name must be node');
  check(observed.exe === APPROVED_BIN,
    'host-observed executable must match approved Node binary without deletion or redirection');
  check(matchesProbeCommandLine(observed.cmdline),
    'host-observed process argv must equal the exact first-party witness command');
  check(typeof observed.cgroup === 'string' &&
    !!cgroupRelativePath(observed.cgroup,expected.id),
    'host cgroup must include container ID and use cgroup v2');
  for (const ns of NS_TYPES) {
    const h=observed.hostNamespaces && observed.hostNamespaces[ns];
    const c=observed.containerNamespaces && observed.containerNamespaces[ns];
    check(isNamespaceRef(h,ns) && isNamespaceRef(c,ns) && h !== c,
      ns + ' namespace must be distinct from host PID1');
  }
  const status=observed.status || '';
  // Inspect the kernel's own process IDs, not only the daemon-supplied PID.
  const kernelPid=getField(status,'Pid');
  const nsPid=getField(status,'NSpid');
  check(kernelPid === String(pid),
    'host-observed kernel PID must match inspected container PID');
  const pidChain=typeof nsPid === 'string' && /^\d+(?:\s+\d+)*$/.test(nsPid) ?
    nsPid.split(/\s+/).map(Number) : [];
  check(pidChain.length >= 2 && pidChain[0] === pid &&
    pidChain[pidChain.length-1] === 1 &&
    pidChain.every(Number.isSafeInteger),
    'probe must be PID 1 in an isolated child PID namespace');
  const uid=getField(status,'Uid'),gid=getField(status,'Gid');
  const parseIds=line=>typeof line==='string'&&/^\d+(?:\s+\d+){3}$/.test(line) ?
    line.split(/\s+/).map(Number) : [];
  const uids=parseIds(uid), gids=parseIds(gid);
  check(uids.length===4 && uids.every(n=>n>0&&n===uids[0]) &&
    mappedWithoutHostRoot(observed.uidMap || '',uids[0]),
    'host-observed UID must be nonroot and remapped');
  check(gids.length===4 && gids.every(n=>n>0&&n===gids[0]) &&
    mappedWithoutHostRoot(observed.gidMap || '',gids[0]),
    'host-observed GID must be nonroot and remapped');
  check(getField(status,'NoNewPrivs')==='1' && getField(status,'Seccomp')==='2' &&
    Number(getField(status,'Seccomp_filters'))>=1,
    'host-observed process must have no_new_privs and active seccomp filters');
  for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']){
    check(/^0+$/.test(getField(status,key)||'!'),
      key+' must have no process capabilities');
  }
  check(checkMounts(observed.mountinfo||''), 'host-observed mounts must match the approved restrictive profile');
  check(checkNetwork(observed.network||''), 'host-observed network interfaces must be loopback-only');
  check(typeof observed.apparmor==='string' &&
    /\(enforce\)\s*$/.test(observed.apparmor) &&
    !/unconfined|complain/i.test(observed.apparmor),
    'host-observed AppArmor policy must be enforcing');
  const limit=s=>typeof s==='string'&&/^\d+$/.test(s.trim())?Number(s.trim()):NaN;
  const m=limit(observed.memory),p=limit(observed.pids),sw=limit(observed.swap);
  check(Number.isSafeInteger(m)&&m>=64*1024*1024&&m<=MAX_MEMORY,'actual cgroup memory limit must be finite and <=512 MiB');
  check(Number.isSafeInteger(p)&&p>0&&p<=32,'actual cgroup PID limit must be <=32');
  check(sw===0,'actual cgroup swap allowance must be zero');
  check(checkQuota(observed.cpu||''),'actual cgroup CPU quota must be <=1 CPU');
  return {ok:errs.length===0,errors:errs};
}
function captureFromHost(inspect, expected) {
  const p = safeSnapshot(inspect,expected);
  if (!p.ok) throw new Error('running container inspection does not meet pre-start policy');
  const pid = p.pid;
  const proc='/proc/'+pid;
  const startBefore=parseStartTicks(readBounded(proc+'/stat'));
  if (!startBefore) throw new Error('invalid process start time');
  const hostNamespaces={},containerNamespaces={};
  for (const ns of NS_TYPES) {
    hostNamespaces[ns]=fs.readlinkSync('/proc/1/ns/'+ns);
    containerNamespaces[ns]=fs.readlinkSync(proc+'/ns/'+ns);
  }
  const cgroup=readBounded(proc+'/cgroup');
  const rel=cgroupRelativePath(cgroup,expected.id);
  if(!rel) throw new Error('container cgroup identity not established');
  const dir=path.resolve('/sys/fs/cgroup', '.'+rel);
  if (!dir.startsWith('/sys/fs/cgroup/')) throw new Error('unsafe cgroup path');
  const readCg=name=>readBounded(path.join(dir,name));
  const witness={
    pid,startBefore,comm:readBounded(proc+'/comm').trim(),
    exe:fs.readlinkSync(proc+'/exe'),
    cmdline:readBounded(proc+'/cmdline'),
    cgroup,hostNamespaces,containerNamespaces,
    status:readBounded(proc+'/status'),
    uidMap:readBounded(proc+'/uid_map'),
    gidMap:readBounded(proc+'/gid_map'),
    mountinfo:readBounded(proc+'/mountinfo'),
    network:readBounded(proc+'/net/dev'),
    apparmor:readBounded(proc+'/attr/current'),
    memory:readCg('memory.max'),
    swap:readCg('memory.swap.max'),
    cpu:readCg('cpu.max'),
    pids:readCg('pids.max'),
  };
  witness.startAfter=parseStartTicks(readBounded(proc+'/stat'));
  return witness;
}
function main(argv) {
  if(argv.length===1 && argv[0]==='--help'){
    process.stdout.write('Read-only host witness: node host-witness.cjs /absolute/inspect.json --id <64hex> --image <name>@sha256:<64hex> --source /srv/wardveil-audit-pilot/source/<name>\n');
    return 0;
  }
  if(argv.length!==7 || !path.isAbsolute(argv[0]) || argv[1]!=='--id' ||
     argv[3]!=='--image' || argv[5]!=='--source') {
    process.stderr.write('BLOCKED: explicit inspect file, container ID, pinned image and source are required\n');
    return 2;
  }
  try {
    const expected={id:argv[2],image:argv[4],source:argv[6]};
    const inspect=readInspectFile(argv[0]);
    const observed=captureFromHost(inspect,expected);
    const verdict=safeHostWitness(inspect,observed,expected);
    if(!verdict.ok){
      for(const why of verdict.errors) process.stderr.write('BLOCKED: '+why+'\n');
      return 1;
    }
    process.stdout.write('HOST KERNEL WITNESS MATCH ONLY: recorded namespace and cgroup constraints match the inspect snapshot. This is not provenance proof, host authorization, audit sandbox certification or permission to run an agent.\n');
    return 0;
  }catch {
    process.stderr.write('BLOCKED: trusted host observations or expected container identity unavailable\n');
    return 1;
  }
}
if(require.main===module)process.exitCode=main(process.argv.slice(2));
module.exports={NS_TYPES,parseStartTicks,cgroupRelativePath,matchesProbeCommandLine,safeSnapshot,safeHostWitness,captureFromHost,main};
