'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {test}=require('node:test');
const {SAFE_SOURCE_PREFIX,EXPECTED_ENVS}=require('./check-container-policy.cjs');
const {REQUIRED_NAMESPACES}=require('./check-oci-identity.cjs');
const {canonicalAbsolute,validatePaths,verifyLinkedEvidence}=require('./check-oci-evidence.cjs');

const pin=b=>crypto.createHash('sha256').update(b).digest('hex');
function goodConfig(){
  return {
    ociVersion:'1.1.0',hostname:'wardveil-audit-probe',
    process:{
      user:{uid:65534,gid:65534,additionalGids:[]},
      noNewPrivileges:true,terminal:false,
      args:['/usr/bin/node','/opt/wardveil/runtime-probe.cjs','--witness-window=90'],
      cwd:'/scratch',env:Object.entries(EXPECTED_ENVS).map(([k,v])=>k+'='+v),
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
      resources:{memory:{limit:268435456,swap:268435456},
        cpu:{quota:50000,period:100000},pids:{limit:24},
        devices:[{allow:false,access:'rwm'}]},
      rootfsPropagation:'rprivate',cgroupsPath:'wardveil-audit/firstparty-1234',
      maskedPaths:['/proc/kcore','/proc/keys','/proc/timer_list','/proc/scsi','/sys/firmware'],
      readonlyPaths:['/proc/sys','/proc/sysrq-trigger'],
      devices:[],netDevices:{},sysctl:{},
    },
  };
}
function fixture(){
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-oci-linked-'));
  const bundle=path.join(temp,'bundle');
  const root=path.join(bundle,'rootfs');
  const trusted=path.join(temp,'trusted');
  fs.mkdirSync(path.join(root,'usr','bin'),{recursive:true,mode:0o755});
  fs.mkdirSync(path.join(root,'opt','wardveil'),{recursive:true,mode:0o755});
  fs.mkdirSync(trusted,{mode:0o755});
  const files=[
    {path:'opt/wardveil/runtime-probe.cjs',mode:'0444',bytes:Buffer.from('/* inert tested script only */\n')},
    {path:'usr/bin/node',mode:'0555',bytes:Buffer.from('inert binary fixture\n')},
  ];
  for(const f of files){
    fs.writeFileSync(path.join(root,f.path),f.bytes);
    fs.chmodSync(path.join(root,f.path),parseInt(f.mode,8));
  }
  const manifest={format:'wardveil-oci-rootfs-v1',
    files:files.map(f=>({path:f.path,mode:f.mode,size:f.bytes.length,sha256:pin(f.bytes)}))};
  const config=goodConfig();
  const configPath=path.join(bundle,'config.json');
  const manifestPath=path.join(trusted,'manifest.json');
  const x={temp,bundle,root,trusted,config,manifest,configPath,manifestPath};
  saveConfig(x);saveManifest(x);
  return x;
}
function saveConfig(x){const raw=Buffer.from(JSON.stringify(x.config));fs.writeFileSync(x.configPath,raw);x.configPin=pin(raw);}
function saveManifest(x){const raw=Buffer.from(JSON.stringify(x.manifest));fs.writeFileSync(x.manifestPath,raw);x.manifestPin=pin(raw);}
function withFixture(fn){
  const x=fixture();
  try{return fn(x)}finally{fs.rmSync(x.temp,{recursive:true,force:true})}
}
function verify(x){return verifyLinkedEvidence(x.configPath,x.manifestPath,x.configPin,x.manifestPin);}
function cli(x,config=x.configPath,manifest=x.manifestPath,configPin=x.configPin,manifestPin=x.manifestPin){
  return spawnSync(process.execPath,[path.join(__dirname,'check-oci-evidence.cjs'),
    config,manifest,'--config-sha256',configPin,'--manifest-sha256',manifestPin],
    {encoding:'utf8'});
}
function blocked(name,fn){
  test('linked evidence refuses '+name,()=>withFixture(x=>{fn(x);assert.throws(()=>verify(x));}));
}
test('exact externally pinned OCI config/manifest and matching bundle rootfs produce static match only',()=>withFixture(x=>{
  const r=verify(x);
  assert.deepEqual(r,{ok:true,files:2,bytes:
    Buffer.byteLength('/* inert tested script only */\n')+
    Buffer.byteLength('inert binary fixture\n')});
  const run=cli(x);
  assert.equal(run.status,0,run.stderr);
  assert.match(run.stdout,/OCI LINKED STATIC EVIDENCE MATCH ONLY/);
  assert.doesNotMatch(run.stdout,/certified|runtime verified|approved to run/i);
}));
test('only canonical config.json path derives the exact sibling rootfs directory',()=>{
  assert.equal(canonicalAbsolute('/tmp/test/bundle/config.json'),true);
  for(const p of ['relative','/','/tmp/../bundle/config.json','/tmp//bundle/config.json',
    '/tmp/bundle/./config.json','/tmp/bundle/config.json/','/tmp/bundle/\0bad',
    '/tmp/bundle\\config.json'])assert.equal(canonicalAbsolute(p),false,p);
  assert.equal(validatePaths('/tmp/bundle/config.json','/tmp/reviewer/manifest.json'),
    '/tmp/bundle/rootfs');
  assert.throws(()=>validatePaths('/tmp/bundle/config.json','/tmp/bundle/manifest.json'));
  assert.throws(()=>validatePaths('/tmp/bundle/settings.json','/tmp/reviewer/manifest.json'));
});
blocked('different trusted config hash',x=>x.configPin='0'.repeat(64));
blocked('different independently reviewed manifest hash',x=>x.manifestPin='0'.repeat(64));
blocked('unreviewed process primary and additional group',x=>{
  x.config.process.user.additionalGids=[65534];saveConfig(x);
});
blocked('unreviewed permissive OCI seccomp default',x=>{
  x.config.linux.seccomp.defaultAction='SCMP_ACT_ALLOW';saveConfig(x);
});
blocked('source mount unexpectedly writable',x=>{
  x.config.mounts.find(m=>m.destination==='/source').options[1]='rw';saveConfig(x);
});
blocked('config root path does not name exact sibling rootfs',x=>{
  x.config.root.path='other';saveConfig(x);
});
blocked('unreviewed config filename',x=>{
  const other=path.join(x.bundle,'other.json');
  fs.renameSync(x.configPath,other);x.configPath=other;
});
blocked('manifest moved inside candidate bundle',x=>{
  const other=path.join(x.bundle,'manifest.json');
  fs.renameSync(x.manifestPath,other);x.manifestPath=other;
});
blocked('missing required first-party Node binary',x=>{
  fs.unlinkSync(path.join(x.root,'usr/bin/node'));
});
blocked('rootfs binary content changed after manifest pin',x=>{
  const file=path.join(x.root,'usr/bin/node');
  fs.chmodSync(file,0o644);fs.writeFileSync(file,'another inert binary\n');fs.chmodSync(file,0o555);
});
blocked('unexpected extra rootfs file',x=>{
  fs.writeFileSync(path.join(x.root,'unexpected'),'unreviewed');
});
blocked('symlinked bundle config ancestor',x=>{
  const alias=path.join(x.temp,'alias');
  fs.symlinkSync(x.bundle,alias);
  x.configPath=path.join(alias,'config.json');
});
blocked('unexpected lifecycle hook even when independently pinned',x=>{
  x.config.hooks={prestart:[{path:'/bin/sh'}]};saveConfig(x);
});
blocked('changed manifest file size even when digest repinned',x=>{
  x.manifest.files[0].size+=1;saveManifest(x);
});
test('CLI rejects source BOM change when only unmodified JSON digest was approved',()=>withFixture(x=>{
  const raw=fs.readFileSync(x.configPath);
  fs.writeFileSync(x.configPath,Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),raw]));
  const r=cli(x);
  assert.notEqual(r.status,0);
  assert.match(r.stderr,/BLOCKED/);
}));
test('CLI requires two pinned hashes with exact argument order',()=>withFixture(x=>{
  const fail=spawnSync(process.execPath,[path.join(__dirname,'check-oci-evidence.cjs'),
    x.configPath,x.manifestPath],{encoding:'utf8'});
  assert.notEqual(fail.status,0);
  assert.match(fail.stderr,/BLOCKED/);
}));
