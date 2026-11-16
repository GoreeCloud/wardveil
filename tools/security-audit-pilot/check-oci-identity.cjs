#!/usr/bin/env node
'use strict';

// Offline OCI identity gate for a separately reviewed, first-party probe.
// This does not generate, install, execute or edit an OCI bundle or container.
// A passing spec is NOT proof that the runtime honored it.
const {
  EXPECTED_ENTRYPOINT, EXPECTED_COMMAND, EXPECTED_WITNESS_ARGUMENT,
  EXPECTED_ENVS, readInspectFile,
} = require('./check-container-policy.cjs');

const {parseUniqueJson}=require('./unique-json.cjs');
const REQUIRED_NAMESPACES = Object.freeze([
  'user','pid','mount','network','ipc','uts','cgroup',
]);
const EXPECTED_UID = 65534;
const EXPECTED_GID = 65534;

function plain(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    (Object.getPrototypeOf(x) === Object.prototype ||
     Object.getPrototypeOf(x) === null);
}
function validMap(entries) {
  if (!Array.isArray(entries) || entries.length !== 1 || !plain(entries[0])) return false;
  const m = entries[0];
  return m.containerID === 0 && Number.isSafeInteger(m.hostID) && m.hostID > 0 &&
    Number.isSafeInteger(m.size) && m.size >= 65535 && m.size <= 65536 &&
    m.hostID + m.size <= 4294967296;
}
function evaluateOciIdentity(spec) {
  const errors = [];
  const requireField = (ok,message) => { if (!ok) errors.push(message); };
  if (!plain(spec)) return {ok:false,errors:['OCI spec must be one object']};
  const proc=plain(spec.process)?spec.process:{};
  const user=plain(proc.user)?proc.user:{};
  const caps=plain(proc.capabilities)?proc.capabilities:{};
  const linux=plain(spec.linux)?spec.linux:{};
  const root=plain(spec.root)?spec.root:{};
  // Review only one concrete OCI schema revision, not arbitrary future 1.x
  // versions whose security-sensitive field semantics may have changed.
  requireField(spec.ociVersion === '1.1.0',
    'explicit reviewed OCI spec version 1.1.0 required');
  requireField(plain(user) &&
    Object.keys(user).every(key=>['uid','gid','additionalGids'].includes(key)),
    'unreviewed OCI process user extensions prohibited');
  requireField(user.uid===EXPECTED_UID && user.gid===EXPECTED_GID,
    'numeric unprivileged process UID/GID must match the reviewed profile');
  // This is intentionally stricter than Docker. Moby's getUser normally
  // includes the primary GID in AdditionalGids. Do not reinterpret it as
  // permission to weaken the zero supplementary-groups runtime rule.
  requireField(Array.isArray(user.additionalGids) && user.additionalGids.length===0,
    'OCI process user.additionalGids must be an explicitly empty array');
  requireField(plain(proc) &&
    Object.keys(proc).every(key=>[
      'user','noNewPrivileges','terminal','args','cwd','env','apparmorProfile','capabilities',
    ].includes(key)), 'unreviewed OCI process extensions prohibited');
  requireField(proc.noNewPrivileges===true,
    'no-new-privileges must be explicitly enabled in OCI process');
  requireField(proc.terminal===false,
    'interactive terminal is prohibited');
  requireField(Array.isArray(proc.args) &&
    proc.args.length===3 && proc.args[0]===EXPECTED_ENTRYPOINT &&
    proc.args[1]===EXPECTED_COMMAND &&
    proc.args[2]===EXPECTED_WITNESS_ARGUMENT,
    'the initial process must be the reviewed first-party Node probe only');
  requireField(proc.cwd==='/scratch', 'working directory must be /scratch');
  const expectedEnv=Object.entries(EXPECTED_ENVS).map(([key,val])=>key+'='+val);
  requireField(Array.isArray(proc.env) && proc.env.length===expectedEnv.length &&
    expectedEnv.every(e=>proc.env.includes(e)),
    'process environment must contain exactly the four approved entries');
  requireField(typeof proc.apparmorProfile==='string' &&
    proc.apparmorProfile.length>0 &&
    !/unconfined|complain/i.test(proc.apparmorProfile),
    'OCI process must request a non-unconfined AppArmor profile');
  requireField(plain(caps) &&
    Object.keys(caps).every(key=>
      ['bounding','effective','permitted','inheritable','ambient'].includes(key)),
    'unreviewed OCI capability extensions prohibited');
  for (const name of ['bounding','effective','permitted','inheritable','ambient']) {
    requireField(Array.isArray(caps[name]) && caps[name].length===0,
      'OCI '+name+' capabilities must be explicitly empty');
  }
  requireField(root.readonly===true, 'OCI root must be read-only');
  const ns=linux.namespaces;
  requireField(Array.isArray(ns) && ns.length===REQUIRED_NAMESPACES.length &&
    ns.every(n=>plain(n) && REQUIRED_NAMESPACES.includes(n.type) &&
      Object.keys(n).every(key=>key==='type'||key==='path') &&
      (n.path===undefined || n.path==='')) &&
    REQUIRED_NAMESPACES.every(type=>ns.filter(n=>n.type===type).length===1),
    'all seven OCI namespaces must be private, unique and without host paths');
  requireField(validMap(linux.uidMappings) && validMap(linux.gidMappings),
    'user and group namespace mappings must exclude outside root and cover UID/GID 65534');
  requireField(plain(linux.seccomp) &&
    typeof linux.seccomp.defaultAction==='string' &&
    linux.seccomp.defaultAction!=='SCMP_ACT_ALLOW' &&
    /^SCMP_ACT_(?:ERRNO|KILL|KILL_PROCESS|TRAP)$/.test(linux.seccomp.defaultAction),
    'OCI seccomp must explicitly default-deny (filter semantics require independent review)');
  return {ok:errors.length===0,errors};
}
function main(argv) {
  if(argv.length===1 && argv[0]==='--help') {
    process.stdout.write('Read-only OCI identity gate: node check-oci-identity.cjs /absolute/path/to/config.json\n');
    return 0;
  }
  if(argv.length!==1) {
    process.stderr.write('BLOCKED: exactly one absolute OCI config.json path required\n');
    return 2;
  }
  try {
    const verdict=evaluateOciIdentity(readInspectFile(argv[0],parseUniqueJson));
    if(!verdict.ok) {
      for(const why of verdict.errors) process.stderr.write('BLOCKED: '+why+'\n');
      return 1;
    }
    process.stdout.write('OCI STATIC IDENTITY MATCH ONLY: no extra groups requested; runtime enforcement and provenance NOT verified.\n');
    return 0;
  } catch (_) {
    process.stderr.write('BLOCKED: malformed, oversized or unsafe OCI input\n');
    return 1;
  }
}
if(require.main===module) process.exitCode=main(process.argv.slice(2));
module.exports={REQUIRED_NAMESPACES,EXPECTED_UID,EXPECTED_GID,validMap,evaluateOciIdentity,main};
