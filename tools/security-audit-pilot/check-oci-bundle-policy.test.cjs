'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {test}=require('node:test');
const {EXPECTED_ENVS,SAFE_SOURCE_PREFIX}=require('./check-container-policy.cjs');
const {REQUIRED_NAMESPACES}=require('./check-oci-identity.cjs');
const {validMounts,validSeccomp,validResources,evaluateOciBundle}=require('./check-oci-bundle-policy.cjs');
function good(){
  return {
    ociVersion:'1.1.0',
    hostname:'wardveil-audit-probe',
    process:{
      user:{uid:65534,gid:65534,additionalGids:[]},
      noNewPrivileges:true,terminal:false,
      args:['/usr/bin/node','/opt/wardveil/runtime-probe.cjs','--witness-window=90'],
      cwd:'/scratch',
      env:Object.entries(EXPECTED_ENVS).map(([k,v])=>k+'='+v),
      apparmorProfile:'reviewed-firstparty-profile',
      capabilities:Object.fromEntries(
        ['bounding','effective','permitted','inheritable','ambient'].map(k=>[k,[]])),
    },
    root:{path:'rootfs',readonly:true},
    mounts:[
      {destination:'/proc',type:'proc',source:'proc',options:['ro','nosuid','nodev','noexec']},
      {destination:'/sys/fs/cgroup',type:'cgroup2',source:'cgroup',options:['ro','nosuid','nodev','noexec']},
      {destination:'/source',type:'bind',source:SAFE_SOURCE_PREFIX+'firstparty-fixture',
        options:['rbind','ro','nosuid','nodev','noexec','rprivate']},
      {destination:'/scratch',type:'tmpfs',source:'tmpfs',
        options:['rw','nosuid','nodev','noexec','size=67108864','mode=0700']},
      {destination:'/tmp',type:'tmpfs',source:'tmpfs',
        options:['rw','nosuid','nodev','noexec','size=33554432','mode=0700']},
    ],
    linux:{
      namespaces:REQUIRED_NAMESPACES.map(type=>({type})),
      uidMappings:[{containerID:0,hostID:231072,size:65536}],
      gidMappings:[{containerID:0,hostID:231072,size:65536}],
      seccomp:{defaultAction:'SCMP_ACT_ERRNO',architectures:['SCMP_ARCH_X86_64'],
        syscalls:[{names:['read','write','close','exit','exit_group','futex','mmap','munmap','openat','newfstatat'],action:'SCMP_ACT_ALLOW'}]},
      resources:{
        memory:{limit:268435456,swap:268435456},
        cpu:{quota:50000,period:100000},
        pids:{limit:24},
        devices:[{allow:false,access:'rwm'}],
      },
      rootfsPropagation:'rprivate',cgroupsPath:'wardveil-audit/firstparty-1234',
      maskedPaths:['/proc/kcore','/proc/keys','/proc/timer_list','/proc/scsi','/sys/firmware'],
      readonlyPaths:['/proc/sys','/proc/sysrq-trigger'],
      devices:[],netDevices:{},sysctl:{},
    },
  };
}
function rejects(label,modify){
  test('OCI bundle refuses '+label,()=>{
    const doc=good();
    modify(doc);
    const r=evaluateOciBundle(doc);
    assert.equal(r.ok,false,label);
    assert.ok(r.errors.length>0);
    assert.ok(r.errors.every(e=>!e.includes('231072')));
  });
}
test('reviewed-looking OCI proposal is a static match, NOT approval to run',()=>{
  assert.deepEqual(evaluateOciBundle(good()),{ok:true,errors:[]});
});
test('bundle evaluator fails closed on malformed data without throwing',()=>{
  for (const x of [null,undefined,[],false,0,'oci',{}]){
    assert.equal(evaluateOciBundle(x).ok,false);
  }
});
rejects('nonempty supplementary groups',x=>x.process.user.additionalGids=[65534]);
rejects('unprivileged process swapped for root',x=>x.process.user.uid=0);
rejects('unexpected startup command',x=>x.process.args.push('bash'));
rejects('root path absolute',x=>x.root.path='/tmp/rootfs');
rejects('top-level Windows platform extension',x=>x.windows={});
rejects('top-level VM runtime extension',x=>x.vm={hypervisor:{path:'/usr/bin/unknown'}});
rejects('top-level unknown lifecycle extension',x=>x.extraLifecycle={});
rejects('unreviewed process flags',x=>x.process.ioPriority={class:'IOPRIO_CLASS_RT'});

rejects('root parent traversal',x=>x.root.path='../rootfs');
rejects('root unexpectedly writable',x=>x.root.readonly=false);
rejects('root extension',x=>x.root.maskedPaths=[]);
rejects('missing proc mount',x=>x.mounts=x.mounts.filter(m=>m.destination!=='/proc'));
rejects('duplicate proc mount',x=>x.mounts[1]={...x.mounts[0]});
rejects('additional host filesystem mount',x=>x.mounts.push({destination:'/home',type:'bind',source:'/home',options:['ro']}));
rejects('source from owner HOME',x=>x.mounts[2].source='/home/owner/repo');
rejects('source directory with traversal',x=>x.mounts[2].source=SAFE_SOURCE_PREFIX+'../secrets');
rejects('source path containing nested directory',x=>x.mounts[2].source=SAFE_SOURCE_PREFIX+'abc/subdir');
rejects('source path symlink alias string',x=>x.mounts[2].source=SAFE_SOURCE_PREFIX+'.hidden');
rejects('source mount writable',x=>x.mounts[2].options[1]='rw');
rejects('source without recursive bind',x=>x.mounts[2].options[0]='bind');
rejects('source propagation shared',x=>x.mounts[2].options[5]='rshared');
rejects('source mount executable',x=>x.mounts[2].options[4]='exec');
rejects('source mount with duplicate flags',x=>x.mounts[2].options[1]='rbind');
rejects('source mount with host path field',x=>x.mounts[2].uidMappings=[]);
rejects('scratch tmpfs executable',x=>x.mounts[3].options[3]='exec');
rejects('oversized scratch tmpfs',x=>x.mounts[3].options[4]='size=9999999999');
rejects('scratch tmpfs world-writable',x=>x.mounts[3].options[5]='mode=0777');
rejects('cgroup hierarchy writable',x=>x.mounts[1].options[0]='rw');
rejects('incorrect proc type',x=>x.mounts[0].type='bind');
rejects('Lifecycle prestart hook',x=>x.hooks={prestart:[{path:'/bin/sh',args:['sh']}]});
rejects('Lifecycle poststop hook',x=>x.hooks={poststop:[{path:'/usr/bin/cleanup'}]});
rejects('unknown OCI annotation',x=>x.annotations={'evil.example/hook':'true'});
rejects('unknown Linux extension',x=>x.linux.intelRdt={});
rejects('shared rootfs propagation',x=>x.linux.rootfsPropagation='shared');
rejects('absent rootfs propagation',x=>delete x.linux.rootfsPropagation);
rejects('additional sysctl',x=>x.linux.sysctl={'kernel.hostname':'owner'});
rejects('injected network device',x=>x.linux.netDevices={eth0:{name:'eth0'}});
rejects('injected Linux device',x=>x.linux.devices.push({path:'/dev/kvm',type:'c',major:10,minor:232}));
rejects('unsafe cgroup path',x=>x.linux.cgroupsPath='../system.slice');
rejects('absolute cgroup path',x=>x.linux.cgroupsPath='/sys/fs/cgroup/owner');
rejects('missing kernel mask',x=>x.linux.maskedPaths.pop());
rejects('unreviewed kernel mask',x=>x.linux.maskedPaths[0]='/tmp');
rejects('missing proc readonly path',x=>x.linux.readonlyPaths=[]);
rejects('unbounded memory',x=>x.linux.resources.memory.limit=1073741824);
rejects('too-small memory limit',x=>x.linux.resources.memory.limit=1024);
rejects('swap allocation',x=>x.linux.resources.memory.swap=536870912);
rejects('swap unbounded',x=>x.linux.resources.memory.swap=-1);
rejects('CPU quota unlimited',x=>x.linux.resources.cpu.quota=-1);
rejects('CPU quota above one',x=>x.linux.resources.cpu.quota=120000);
rejects('CPU quota missing',x=>delete x.linux.resources.cpu.quota);
rejects('CPU period unrealistic',x=>x.linux.resources.cpu.period=0);
rejects('PIDs unbounded',x=>x.linux.resources.pids.limit=-1);
rejects('PIDs over limit',x=>x.linux.resources.pids.limit=33);
rejects('allowing cgroup device access',x=>x.linux.resources.devices[0].allow=true);
rejects('device control missing',x=>delete x.linux.resources.devices);
rejects('unified cgroup override',x=>x.linux.resources.unified={'memory.max':'max'});
rejects('system OOM killer disabled',x=>x.linux.resources.memory.disableOOMKiller=true);
rejects('extra CPU realtime privilege',x=>x.linux.resources.cpu.realtimeRuntime=10000);
rejects('seccomp default permissive',x=>x.linux.seccomp.defaultAction='SCMP_ACT_ALLOW');
rejects('seccomp notify on permitted rules',x=>x.linux.seccomp.syscalls[0].action='SCMP_ACT_NOTIFY');
rejects('seccomp with no actual syscall rules',x=>x.linux.seccomp.syscalls=[]);
rejects('seccomp allowed mount syscall',x=>x.linux.seccomp.syscalls[0].names.push('mount'));
rejects('seccomp allowed ptrace',x=>x.linux.seccomp.syscalls[0].names=['ptrace']);
rejects('seccomp allowed namespace switching',x=>x.linux.seccomp.syscalls[0].names=['setns']);
rejects('seccomp allowed bpf',x=>x.linux.seccomp.syscalls[0].names=['bpf']);
rejects('seccomp allowed arbitrary syscalls',x=>x.linux.seccomp.syscalls[0].names=['*']);
rejects('seccomp duplicate syscall',x=>x.linux.seccomp.syscalls[0].names.push('read'));
rejects('seccomp listener path',x=>x.linux.seccomp.listenerPath='/tmp/owner.sock');
rejects('seccomp flags including speculative bypass',x=>x.linux.seccomp.flags=['SECCOMP_FILTER_FLAG_SPEC_ALLOW']);
rejects('seccomp architecture mismatch',x=>x.linux.seccomp.architectures=['SCMP_ARCH_X86']);
test('read-only candidate CLI refuses symlinks, invalid JSON and oversized OCI data',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-oci-bundle-'));
  try{
    const file=path.join(dir,'config.json');
    const alias=path.join(dir,'alias.json');
    fs.writeFileSync(file,JSON.stringify(good()));
    const call=(p)=>spawnSync(process.execPath,[path.join(__dirname,'check-oci-bundle-policy.cjs'),p],{encoding:'utf8'});
    const goodRun=call(file);
    assert.equal(goodRun.status,0,goodRun.stderr);
    assert.match(goodRun.stdout,/STATIC BUNDLE POLICY MATCH ONLY/);
    assert.doesNotMatch(goodRun.stdout,/approved|safe to run|certified/i);
    fs.symlinkSync(file,alias);
    assert.notEqual(call(alias).status,0);
    fs.writeFileSync(file,'invalid json');
    assert.notEqual(call(file).status,0);
    fs.writeFileSync(file,'{}'.padEnd(150000,' '));
    assert.notEqual(call(file).status,0);
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
});
test('bundle helpers are conservative on hostile values',()=>{
  assert.equal(validMounts([{destination:'/proc'}]),false);
  assert.equal(validResources({memory:{limit:99999999}}),false);
  assert.equal(validSeccomp({defaultAction:'SCMP_ACT_ALLOW'}),false);
});
