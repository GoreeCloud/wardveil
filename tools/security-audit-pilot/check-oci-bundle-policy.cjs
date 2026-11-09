#!/usr/bin/env node
'use strict';

// Strict, read-only policy for a proposed FIRST-PARTY OCI bundle.
// No container creation, image extraction, runtime invocation, mount, or writes.
// This is not a certified OCI/runtime policy nor a deployment authorization.
const {SAFE_SOURCE_PREFIX,readInspectFile}=require('./check-container-policy.cjs');
const {evaluateOciIdentity}=require('./check-oci-identity.cjs');

const MAX_MEMORY=512*1024*1024;
const MIN_MEMORY=64*1024*1024;
const RESERVED_MOUNTS=Object.freeze(['/proc','/sys/fs/cgroup','/source','/scratch','/tmp']);
const DENIED_SYSCALLS=new Set([
  'mount','umount','umount2','pivot_root','chroot','setns','unshare',
  // clone/clone3 with unreviewed flags could create nested namespaces.
  // An executable that genuinely needs threads requires a separately
  // reviewed argument-filtered profile; never allow an unfiltered syscall.
  'clone','clone3','io_uring_setup','io_uring_enter','io_uring_register',
  'userfaultfd','fanotify_init','fsopen','fsconfig','fsmount',
  'open_tree','move_mount','mount_setattr',
  'ptrace','bpf','perf_event_open','keyctl','add_key','request_key',
  'init_module','finit_module','delete_module','kexec_load','kexec_file_load',
  'reboot','swapon','swapoff','open_by_handle_at','process_vm_writev',
]);
// This is a proposed PRE-EXECUTION identity/security profile, not a working
// Node syscall recipe. A default-deny profile with an open-ended "anything
// not known to be bad" allowance is NOT reviewable or safe. The permitted
// syscall names are explicitly enumerated and require a separate independent
// audit before this bundle can be used on an actual runtime.
const REVIEWED_SYSCALLS=new Set([
  'read','write','close','exit','exit_group','futex','mmap','munmap',
  'openat','newfstatat','brk','mprotect','rt_sigaction','rt_sigprocmask',
  'rt_sigreturn','clock_gettime','getrandom','getpid','gettid',
  'getuid','geteuid','getgid','getegid','lseek','pread64','fstat',
  'readlinkat','statx','uname','arch_prctl','prlimit64','rseq',
  'set_robust_list','sched_yield','epoll_create1','epoll_ctl',
  'epoll_pwait','eventfd2','pipe2','fcntl','dup','dup2','dup3',
  'nanosleep',
]);
const PLAIN=(v)=>v!==null && typeof v==='object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v)===Object.prototype || Object.getPrototypeOf(v)===null);
const EMPTY=(v)=>v===undefined || (PLAIN(v)&&Object.keys(v).length===0);
const EMPTY_ARRAY=(v)=>v===undefined || (Array.isArray(v)&&v.length===0);
const POS=(v)=>Number.isSafeInteger(v)&&v>0;
const keysOnly=(obj,names)=>PLAIN(obj)&&Object.keys(obj).every(k=>names.includes(k));
function optionsMatch(actual,required){
  if(!Array.isArray(actual)||actual.length!==required.length||
     actual.some(v=>typeof v!=='string')) return false;
  const set=new Set(actual);
  return set.size===required.length && required.every(k=>set.has(k));
}
function cleanSource(src){
  return typeof src==='string' && src.startsWith(SAFE_SOURCE_PREFIX) &&
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(src.slice(SAFE_SOURCE_PREFIX.length));
}
const MOUNT_POLICIES=Object.freeze({
  '/proc':{type:'proc',source:'proc',options:['ro','nosuid','nodev','noexec']},
  '/sys/fs/cgroup':{type:'cgroup2',source:'cgroup',options:['ro','nosuid','nodev','noexec']},
  '/scratch':{type:'tmpfs',source:'tmpfs',options:['rw','nosuid','nodev','noexec','size=67108864','mode=0700']},
  '/tmp':{type:'tmpfs',source:'tmpfs',options:['rw','nosuid','nodev','noexec','size=33554432','mode=0700']},
  '/source':{type:'bind',source:null,options:['rbind','ro','nosuid','nodev','noexec','rprivate']},
});
function validMounts(mounts){
  if(!Array.isArray(mounts)||mounts.length!==RESERVED_MOUNTS.length) return false;
  const seen=new Set();
  for(const mount of mounts){
    if(!keysOnly(mount,['destination','type','source','options']) ||
       !RESERVED_MOUNTS.includes(mount.destination) ||
       seen.has(mount.destination)) return false;
    seen.add(mount.destination);
    const p=MOUNT_POLICIES[mount.destination];
    if(mount.type!==p.type || !optionsMatch(mount.options,p.options)) return false;
    if(mount.destination==='/source'? !cleanSource(mount.source):mount.source!==p.source) return false;
  }
  return seen.size===RESERVED_MOUNTS.length;
}
function validSeccomp(sec){
  if(!keysOnly(sec,['defaultAction','syscalls','architectures']) ||
     sec.defaultAction!=='SCMP_ACT_ERRNO' ||
     !Array.isArray(sec.architectures) ||
     !optionsMatch(sec.architectures,['SCMP_ARCH_X86_64']) ||
     !Array.isArray(sec.syscalls) || sec.syscalls.length===0 ||
     sec.syscalls.length>128) return false;
  const observed=new Set();
  for(const rule of sec.syscalls){
    if(!keysOnly(rule,['names','action']) ||
       rule.action!=='SCMP_ACT_ALLOW' ||
       !Array.isArray(rule.names)||rule.names.length<1||rule.names.length>64) return false;
    for(const name of rule.names){
      if(typeof name!=='string' || !/^[a-z0-9_]{2,40}$/.test(name) ||
         DENIED_SYSCALLS.has(name)||!REVIEWED_SYSCALLS.has(name)||
         observed.has(name)) return false;
      observed.add(name);
    }
  }
  return true;
}
function validResources(resources){
  if(!keysOnly(resources,['memory','cpu','pids','devices'])) return false;
  const mem=resources.memory,cpu=resources.cpu,pids=resources.pids,devices=resources.devices;
  if(!keysOnly(mem,['limit','swap']) ||
     !Number.isSafeInteger(mem.limit) ||
     mem.limit<MIN_MEMORY||mem.limit>MAX_MEMORY ||
     mem.swap!==mem.limit) return false;
  if(!keysOnly(cpu,['quota','period'])||!POS(cpu.quota)||!POS(cpu.period)||
     cpu.period<1000||cpu.period>1000000||cpu.quota>cpu.period) return false;
  if(!keysOnly(pids,['limit'])||!POS(pids.limit)||pids.limit>32) return false;
  if(!Array.isArray(devices)||devices.length!==1||
     !keysOnly(devices[0],['allow','access']) ||
     devices[0].allow!==false||devices[0].access!=='rwm') return false;
  return true;
}
function evaluateOciBundle(spec){
  const errors=[];
  const demand=(ok,msg)=>{if(!ok)errors.push(msg)};
  const identity=evaluateOciIdentity(spec);
  if(!identity.ok) errors.push(...identity.errors.map(x=>'identity: '+x));
  if(!PLAIN(spec)) return {ok:false,errors};
  demand(keysOnly(spec,[
    'ociVersion','process','root','mounts','linux','hostname','hooks','annotations',
  ]),'unexpected top-level OCI extension prohibited');
  const linux=PLAIN(spec.linux)?spec.linux:{};
  const root=PLAIN(spec.root)?spec.root:{};
  // The only supported root is an unambiguous directory inside the bundle.
  // It must be independently inspected for immutability and symlinks.
  demand(keysOnly(root,['path','readonly'])&&root.path==='rootfs'&&root.readonly===true,
    'root must be relative rootfs with readonly=true and no extensions');
  demand(validMounts(spec.mounts),
    'exact five reviewed mounts and their conservative options required');
  demand(EMPTY(spec.hooks),'OCI hooks are prohibited, even lifecycle hooks');
  demand(EMPTY(spec.annotations),'custom OCI annotations prohibited');
  demand(spec.hostname==='wardveil-audit-probe',
    'fixed first-party hostname required');
  demand(keysOnly(linux,[
    'namespaces','uidMappings','gidMappings','seccomp','resources','sysctl',
    'devices','netDevices','rootfsPropagation','cgroupsPath',
    'maskedPaths','readonlyPaths',
  ]),'unreviewed OCI Linux extensions prohibited');
  demand(linux.rootfsPropagation==='rprivate',
    'mount propagation must be explicitly recursive private');
  demand(EMPTY(linux.sysctl),'kernel sysctl changes prohibited');
  demand(EMPTY(linux.netDevices),'network device injection prohibited');
  demand(EMPTY_ARRAY(linux.devices),'extra Linux device nodes prohibited');
  demand(Array.isArray(linux.maskedPaths)&&
    optionsMatch(linux.maskedPaths,['/proc/kcore','/proc/keys','/proc/timer_list',
      '/proc/scsi','/sys/firmware']),
    'exact reviewed kernel-information masks required');
  demand(Array.isArray(linux.readonlyPaths)&&
    optionsMatch(linux.readonlyPaths,['/proc/sys','/proc/sysrq-trigger']),
    'exact reviewed read-only kernel paths required');
  demand(typeof linux.cgroupsPath==='string' &&
    /^wardveil-audit\/[a-z0-9](?:[a-z0-9-]{6,62}[a-z0-9])?$/.test(linux.cgroupsPath),
    'isolated named cgroup path required');
  demand(validResources(linux.resources),
    'bounded CPU/memory/swap/PID and device deny-only cgroup resources required');
  demand(validSeccomp(linux.seccomp),
    'seccomp must default deny with explicit reviewed syscall syntax; no dangerous syscall allowances');
  // Even a passing static config does not establish that the runtime applies
  // mounts recursively readonly, blocks egress, enforces AppArmor or honors
  // cgroups; those need independent actual kernel observation.
  return {ok:errors.length===0,errors};
}
function main(argv){
  if(argv.length===1&&argv[0]==='--help'){
    process.stdout.write('Read-only proposed OCI bundle gate: node check-oci-bundle-policy.cjs /absolute/path/to/config.json\n');
    return 0;
  }
  if(argv.length!==1){
    process.stderr.write('BLOCKED: one absolute OCI config.json path required\n');
    return 2;
  }
  try{
    const verdict=evaluateOciBundle(readInspectFile(argv[0]));
    if(!verdict.ok){
      for(const msg of verdict.errors)process.stderr.write('BLOCKED: '+msg+'\n');
      return 1;
    }
    process.stdout.write('OCI STATIC BUNDLE POLICY MATCH ONLY: actual runtime/host isolation and provenance NOT verified.\n');
    return 0;
  }catch(_){
    process.stderr.write('BLOCKED: unsafe or invalid OCI bundle evidence input\n');
    return 1;
  }
}
if(require.main===module) process.exitCode=main(process.argv.slice(2));
module.exports={RESERVED_MOUNTS,DENIED_SYSCALLS,REVIEWED_SYSCALLS,validMounts,validSeccomp,validResources,evaluateOciBundle,main};
