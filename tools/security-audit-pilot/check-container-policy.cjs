#!/usr/bin/env node
'use strict';

// Offline, fail-closed CONFIGURATION CHECK ONLY. Never creates/starts/executes a container.
// A matching config is not proof of runtime isolation or permission to run an audit.
const fs = require('node:fs');
const path = require('node:path');
const {TextDecoder} = require('node:util');

const MAX_BYTES = 128 * 1024;
const MAX_MEMORY = 512 * 1024 * 1024;
const MAX_NANOCPUS = 1_000_000_000;
const MAX_PIDS = 32;
const EXPECTED_ENVS = Object.freeze({
  HOME: '/scratch/home',
  TMPDIR: '/tmp',
  PATH: '/usr/local/bin:/usr/bin:/bin',
  LANG: 'C.UTF-8',
});
const SAFE_SOURCE_PREFIX = '/srv/wardveil-audit-pilot/source/';
// Only the reviewed first-party self-probe may run on the container's first start.
// Matching these paths does NOT prove the image bytes or probe integrity.
const EXPECTED_ENTRYPOINT = '/usr/bin/node';
const EXPECTED_COMMAND = '/opt/wardveil/runtime-probe.cjs';
const EXPECTED_WITNESS_ARGUMENT = '--witness-window=90';

function isPlainObject(obj) {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj) &&
    (Object.getPrototypeOf(obj) === Object.prototype || Object.getPrototypeOf(obj) === null);
}
function finiteIntegerIn(value, min, max) {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}
function validExpected(expected) {
  if (!isPlainObject(expected) || typeof expected.image !== 'string' ||
      !/^[-\w./]+@sha256:[a-f0-9]{64}$/.test(expected.image)) {
    throw new Error('expected image must be an explicitly pinned image@sha256 digest');
  }
  if (typeof expected.imageId !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(expected.imageId)) {
    throw new Error('expected resolved image ID must be a separately reviewed sha256 digest');
  }
  const src = expected.source;
  if (typeof src !== 'string' || !src.startsWith(SAFE_SOURCE_PREFIX) ||
      path.posix.normalize(src) !== src || src.includes('//') ||
      src.split('/').some(p => p === '..' || p === '.') || src.endsWith('/')) {
    throw new Error('expected source must be a canonical absolute directory under /srv/wardveil-audit-pilot/source/');
  }
}
function evaluateContainerConfig(input, expected) {
  validExpected(expected);
  const errors = [];
  const requireField = (condition, message) => { if (!condition) errors.push(message); };
  const doc = Array.isArray(input) && input.length === 1 ? input[0] : input;
  if (!isPlainObject(doc)) return {ok:false,errors:['inspect input must be one container object']};
  const host = isPlainObject(doc.HostConfig) ? doc.HostConfig : {};
  const config = isPlainObject(doc.Config) ? doc.Config : {};
  const state = isPlainObject(doc.State) ? doc.State : {};
  const network = isPlainObject(doc.NetworkSettings) ? doc.NetworkSettings : {};
  const mounts = doc.Mounts;

  requireField(state.Running === false && state.Status === 'created' &&
    state.Pid === 0 && state.Restarting === false && state.Paused === false &&
    state.Dead === false && doc.RestartCount === 0 &&
    (doc.ExecIDs == null || (Array.isArray(doc.ExecIDs) && doc.ExecIDs.length === 0)),
    'container must be created, never started, and have no executing or restarted process');
  requireField(host.NetworkMode === 'none', 'external networking must be disabled at runtime configuration');
  requireField(host.Privileged === false && host.ReadonlyRootfs === true, 'root filesystem must be read-only and container unprivileged');
  requireField(Array.isArray(host.CapDrop) && host.CapDrop.map(v => String(v).toUpperCase()).includes('ALL') &&
    Array.isArray(host.CapAdd) && host.CapAdd.length === 0, 'all Linux capabilities must be dropped; no additions');
  requireField(Array.isArray(host.SecurityOpt) && host.SecurityOpt.length === 1 &&
    host.SecurityOpt[0] === 'no-new-privileges:true',
    'require exact no-new-privileges security option; prohibit all other overrides');
  requireField(typeof doc.AppArmorProfile === 'string' && doc.AppArmorProfile !== '' &&
    doc.AppArmorProfile !== 'unconfined', 'require active non-unconfined AppArmor profile');
  requireField(host.PidMode === '' || host.PidMode === 'private', 'PID namespace must be private');
  requireField(host.IpcMode === 'private', 'IPC namespace must be private');
  requireField(host.UTSMode === '' || host.UTSMode === 'private', 'UTS namespace must not be shared with host');
  requireField(host.CgroupnsMode === 'private', 'cgroup namespace must be private');
  // Docker supports empty (daemon policy) or 'host' here; 'private' is not a Docker --userns value.
  // Empty does NOT prove daemon remapping: require separate host-level userns/rootless evidence.
  requireField(host.UsernsMode === '', 'must inherit Docker daemon user namespace policy, never --userns=host');
  requireField(typeof config.User === 'string' && /^[1-9]\d{0,8}:[1-9]\d{0,8}$/.test(config.User),
    'container must use explicit non-root numeric UID:GID');
  requireField(finiteIntegerIn(host.PidsLimit,1,MAX_PIDS), 'PID limit must be 1..32');
  requireField(finiteIntegerIn(host.Memory,64*1024*1024,MAX_MEMORY), 'memory limit must be 64..512 MiB');
  requireField(finiteIntegerIn(host.MemorySwap,host.Memory,host.Memory), 'swap cannot exceed memory limit');
  requireField(finiteIntegerIn(host.NanoCpus,1,MAX_NANOCPUS), 'CPU budget must not exceed 1 CPU');
  requireField(host.OomKillDisable !== true, 'OOM killer must remain enabled');
  requireField(host.Init === false && (host.Runtime === '' || host.Runtime === 'runc') &&
    (host.Isolation === '' || host.Isolation === 'default') &&
    (host.CgroupParent == null || host.CgroupParent === '') &&
    (host.Ulimits == null || (Array.isArray(host.Ulimits) && host.Ulimits.length === 0)),
    'no init wrapper, custom runtime, cgroup parent, or ulimit overrides');
  requireField(config.Image === expected.image, 'container image digest must equal approved digest');
  requireField(Array.isArray(config.Entrypoint) &&
    config.Entrypoint.length === 1 && config.Entrypoint[0] === EXPECTED_ENTRYPOINT &&
    Array.isArray(config.Cmd) && config.Cmd.length === 2 &&
    config.Cmd[0] === EXPECTED_COMMAND && config.Cmd[1] === EXPECTED_WITNESS_ARGUMENT &&
    doc.Path === EXPECTED_ENTRYPOINT && Array.isArray(doc.Args) &&
    doc.Args.length === 2 && doc.Args[0] === EXPECTED_COMMAND &&
    doc.Args[1] === EXPECTED_WITNESS_ARGUMENT,
    'first start may run only the reviewed first-party kernel self-probe');
  requireField(config.Tty === false && config.OpenStdin === false &&
    config.StdinOnce === false && config.AttachStdin === false,
    'interactive terminal or inherited stdin is not allowed');
  requireField(doc.Image === expected.imageId,
    'resolved image ID must exactly match the separately approved local image ID');
  requireField(config.WorkingDir === '/scratch', 'working directory must be scratch');
  requireField(Array.isArray(config.Env) && config.Env.length === Object.keys(EXPECTED_ENVS).length &&
    config.Env.every(x => typeof x === 'string' && /^(HOME|TMPDIR|PATH|LANG)=/.test(x)) &&
    Object.entries(EXPECTED_ENVS).every(([k,v]) => config.Env.includes(k+'='+v)),
    'environment must contain only the four exact safe variables');
  requireField(isPlainObject(host.Tmpfs) && Object.keys(host.Tmpfs).length === 2 &&
    tmpfsSafe(host.Tmpfs['/scratch'],64*1024*1024) &&
    tmpfsSafe(host.Tmpfs['/tmp'],32*1024*1024),
    '/scratch and /tmp must be bounded nosuid,nodev,noexec tmpfs');
  requireField(Array.isArray(mounts) && mounts.length === 1 && isPlainObject(mounts[0]) &&
    mounts[0].Type === 'bind' && mounts[0].Source === expected.source &&
    mounts[0].Destination === '/source' && mounts[0].RW === false &&
    typeof mounts[0].Mode === 'string' && mounts[0].Mode.split(',').includes('ro') &&
    (mounts[0].Propagation === 'rprivate' || mounts[0].Propagation === 'private'),
    'exactly one approved read-only source bind mount; no extra host mounts');
  // Inspect both declared mount intent and realized Mounts. The latter alone
  // may not reflect deferred/hidden mount configuration in every engine.
  requireField(Array.isArray(host.Mounts) && host.Mounts.length === 1 &&
    isPlainObject(host.Mounts[0]) && host.Mounts[0].Type === 'bind' &&
    host.Mounts[0].Source === expected.source && host.Mounts[0].Target === '/source' &&
    host.Mounts[0].ReadOnly === true &&
    isPlainObject(host.Mounts[0].BindOptions) &&
    host.Mounts[0].BindOptions.Propagation === 'rprivate',
    'declared mount must be only the approved read-only private source bind');
  requireField(!host.Binds || (Array.isArray(host.Binds) && host.Binds.length === 0), 'no legacy bind mounts');
  requireField(!host.Devices || (Array.isArray(host.Devices) && host.Devices.length === 0), 'no host devices');
  requireField(!host.DeviceRequests || (Array.isArray(host.DeviceRequests) && host.DeviceRequests.length === 0), 'no GPU or device requests');
  requireField(!host.VolumesFrom || (Array.isArray(host.VolumesFrom) && host.VolumesFrom.length === 0), 'no borrowed container volumes');
  requireField(!host.Links || (Array.isArray(host.Links) && host.Links.length === 0), 'no container network links');
  requireField(isPlainObject(host.LogConfig) && host.LogConfig.Type === 'none',
    'prevent persistent host-side container log capture');
  requireField(isPlainObject(host.RestartPolicy) && host.RestartPolicy.Name === 'no' &&
    host.AutoRemove === false,
    'no automatic restart or removal of the first-party witness container');
  requireField(config.Healthcheck == null ||
    (isPlainObject(config.Healthcheck) && Array.isArray(config.Healthcheck.Test) &&
    config.Healthcheck.Test.length === 1 && config.Healthcheck.Test[0] === 'NONE'),
    'image healthcheck must not execute automatically');
  requireField(config.Volumes == null || (isPlainObject(config.Volumes) && Object.keys(config.Volumes).length === 0),
    'image must not declare hidden anonymous volumes');
  requireField(host.Sysctls == null || (isPlainObject(host.Sysctls) && Object.keys(host.Sysctls).length === 0),
    'no container sysctl overrides');
  requireField(host.DeviceCgroupRules == null || (Array.isArray(host.DeviceCgroupRules) && host.DeviceCgroupRules.length === 0),
    'no device cgroup bypass rules');
  requireField(host.GroupAdd == null || (Array.isArray(host.GroupAdd) && host.GroupAdd.length === 0),
    'no supplemental groups');
  requireField(['Dns','DnsOptions','DnsSearch','ExtraHosts'].every(key =>
    host[key] == null || (Array.isArray(host[key]) && host[key].length === 0)),
    'no host DNS or additional host mappings');
  requireField(network.Networks == null || (isPlainObject(network.Networks) &&
    Object.keys(network.Networks).every(key => key === 'none')),
    'network inspection must not show other attached networks');
  requireField(host.PublishAllPorts === false && isPlainObject(host.PortBindings) &&
    Object.keys(host.PortBindings).length === 0 && (network.Ports == null ||
      (isPlainObject(network.Ports) && Object.keys(network.Ports).length === 0)),
    'no published ports or port bindings');
  requireField(host.PidMode !== 'host' && host.IpcMode !== 'host' && host.CgroupnsMode !== 'host' && host.UsernsMode !== 'host',
    'no host namespaces');
  return {ok:errors.length===0,errors};
}
function tmpfsSafe(raw,maxSize) {
  if (typeof raw !== 'string') return false;
  const tokens=raw.split(',').map(s => s.trim());
  const required=['rw','nosuid','nodev','noexec','size='+maxSize];
  return tokens.length===required.length && required.every(x => tokens.includes(x));
}
function readInspectFile(file) {
  const flags=fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
  if(process.platform !== 'linux' || !path.isAbsolute(file) ||
     !Number.isInteger(fs.constants.O_NOFOLLOW) || !fs.constants.O_NOFOLLOW ||
     !Number.isInteger(fs.constants.O_NONBLOCK) || !fs.constants.O_NONBLOCK ||
     !Number.isInteger(fs.constants.O_DIRECTORY) || !fs.constants.O_DIRECTORY ||
     !fs.existsSync('/proc/self/fd')) {
    throw new Error('Linux descriptor-safe absolute input path required');
  }
  const parts=file.slice(path.parse(file).root.length).split(path.sep);
  if(parts.length<1 || parts.some(part=>!part||part==='.'||part==='..')) {
    throw new Error('noncanonical input path');
  }
  // Open every ancestor relative to an already-pinned directory descriptor.
  // A parent-path symlink cannot swap in another file between lookup and read.
  let dirFd=fs.openSync(path.parse(file).root,flags|fs.constants.O_DIRECTORY);
  try {
    for(const part of parts.slice(0,-1)){
      const child=fs.openSync('/proc/self/fd/'+dirFd+'/'+part,flags|fs.constants.O_DIRECTORY);
      fs.closeSync(dirFd);
      dirFd=child;
    }
    const fd=fs.openSync('/proc/self/fd/'+dirFd+'/'+parts[parts.length-1],flags);
    try{
      const first=fs.fstatSync(fd);
      if(!first.isFile() || first.size>MAX_BYTES) {
        throw new Error('inspect input must be bounded ordinary file');
      }
      const data=Buffer.alloc(first.size);
      let n=0;
      while(n<data.length){
        const k=fs.readSync(fd,data,n,data.length-n,null);
        if(!k) throw new Error('inspect input short read');
        n+=k;
      }
      const after=fs.fstatSync(fd);
      if(first.size!==after.size || first.mtimeMs!==after.mtimeMs ||
         first.ctimeMs!==after.ctimeMs || first.ino!==after.ino ||
         first.dev!==after.dev) {
        throw new Error('inspect input changed during read');
      }
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
    } finally {fs.closeSync(fd);}
  } finally {fs.closeSync(dirFd);}
}
function main(args) {
  if (args.length===1 && args[0]==='--help') {
    process.stdout.write('Static, offline gate only: node check-container-policy.cjs /absolute/inspect.json --image name@sha256:<64hex> --image-id sha256:<64hex> --source /srv/wardveil-audit-pilot/source/<name>\n');
    return 0;
  }
  if(args.length!==7 || !path.isAbsolute(args[0]) || args[1]!=='--image' ||
     args[3]!=='--image-id' || args[5]!=='--source') {
    process.stderr.write('BLOCKED: inspect JSON, pinned image reference, approved local image ID and approved source path required\n');
    return 2;
  }
  try {
    const obj=readInspectFile(args[0]);
    const verdict=evaluateContainerConfig(obj,{image:args[2],imageId:args[4],source:args[6]});
    if(!verdict.ok) {
      // No raw inspection data, secrets, or environment values are echoed.
      for(const why of verdict.errors) process.stderr.write('BLOCKED: '+why+'\n');
      return 1;
    }
    process.stdout.write('STATIC POLICY MATCH ONLY: created container settings satisfy the restrictive profile. This is NOT runtime isolation proof or authorization to start/execute any audit.\n');
    return 0;
  }catch(error){
    process.stderr.write('BLOCKED: malformed or unsafe inspection input; verify file and expected arguments locally\n');
    return 1;
  }
}
if(require.main===module) process.exitCode=main(process.argv.slice(2));
module.exports={MAX_BYTES,EXPECTED_ENVS,SAFE_SOURCE_PREFIX,EXPECTED_ENTRYPOINT,EXPECTED_COMMAND,EXPECTED_WITNESS_ARGUMENT,validExpected,evaluateContainerConfig,tmpfsSafe,readInspectFile,main};
