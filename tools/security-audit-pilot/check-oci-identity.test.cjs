'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const {spawnSync}=require('node:child_process');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {EXPECTED_ENVS}=require('./check-container-policy.cjs');
const {REQUIRED_NAMESPACES,EXPECTED_UID,EXPECTED_GID,validMap,evaluateOciIdentity}=require('./check-oci-identity.cjs');

function good() {
  const capabilities=Object.fromEntries(
    ['bounding','effective','permitted','inheritable','ambient'].map(k=>[k,[]]));
  return {
    ociVersion:'1.1.0',
    process:{
      user:{uid:EXPECTED_UID,gid:EXPECTED_GID,additionalGids:[]},
      noNewPrivileges:true,terminal:false,
      args:['/usr/bin/node','/opt/wardveil/runtime-probe.cjs','--witness-window=90'],
      cwd:'/scratch',
      env:Object.entries(EXPECTED_ENVS).map(([k,v])=>k+'='+v),
      apparmorProfile:'reviewed-firstparty-profile',capabilities,
    },
    root:{path:'rootfs',readonly:true},
    linux:{
      namespaces:REQUIRED_NAMESPACES.map(type=>({type})),
      uidMappings:[{containerID:0,hostID:231072,size:65536}],
      gidMappings:[{containerID:0,hostID:231072,size:65536}],
      seccomp:{defaultAction:'SCMP_ACT_ERRNO',syscalls:[]},
    },
  };
}
function bad(name,mutate) {
  test('rejects '+name,()=>{
    const s=good();
    mutate(s);
    const result=evaluateOciIdentity(s);
    assert.equal(result.ok,false,name);
    assert.ok(result.errors.length>0);
    assert.ok(result.errors.every(e=>!e.includes('231072')));
  });
}
test('a deliberately empty OCI additionalGids list is an offline identity match, not attestation',()=>{
  const result=evaluateOciIdentity(good());
  assert.deepEqual(result,{ok:true,errors:[]});
});
test('invalid documents are rejected without throwing',()=>{
  for(const spec of [null,undefined,[],false,0,'config']) {
    assert.equal(evaluateOciIdentity(spec).ok,false);
  }
});
bad('missing additionalGids',x=>delete x.process.user.additionalGids);
bad('Moby-style primary GID inserted into AdditionalGids',x=>x.process.user.additionalGids=[65534]);
bad('Docker group-add extra group',x=>x.process.user.additionalGids=[65534,0]);
bad('unmapped supplementary group',x=>x.process.user.additionalGids=[999999]);
bad('null additionalGids',x=>x.process.user.additionalGids=null);
bad('string additionalGids',x=>x.process.user.additionalGids='');
bad('root user',x=>x.process.user.uid=0);
bad('root primary group',x=>x.process.user.gid=0);
bad('string UID',x=>x.process.user.uid='65534');
bad('missing process',x=>delete x.process);
bad('missing process user',x=>delete x.process.user);
bad('disabled no new privileges',x=>x.process.noNewPrivileges=false);
bad('extra startup argument',x=>x.process.args.push('--shell'));
bad('substituted executable',x=>x.process.args[0]='/bin/sh');
bad('wrong program argument',x=>x.process.args[1]='/tmp/probe.cjs');
bad('wrong process working directory',x=>x.process.cwd='/');
bad('inherited secret environment',x=>x.process.env.push('SECRET=unknown'));
bad('unexpected duplicate environment',x=>x.process.env.push(x.process.env[0]));
bad('non-enforced AppArmor profile',x=>x.process.apparmorProfile='unconfined');
bad('absent AppArmor profile',x=>delete x.process.apparmorProfile);
bad('tty permitted',x=>x.process.terminal=true);
bad('added permitted capability',x=>x.process.capabilities.permitted.push('CAP_SYS_ADMIN'));
bad('missing capabilities field',x=>delete x.process.capabilities.ambient);
bad('writable OCI root',x=>x.root.readonly=false);
bad('shared host network namespace',x=>x.linux.namespaces.find(n=>n.type==='network').path='/proc/1/ns/net');
bad('missing user namespace',x=>x.linux.namespaces=x.linux.namespaces.filter(n=>n.type!=='user'));
bad('duplicate PID namespace',x=>x.linux.namespaces[0]={type:'pid'});
bad('unexpected unknown namespace',x=>x.linux.namespaces[0]={type:'time'});
bad('host root mapped at start',x=>x.linux.uidMappings[0].hostID=0);
bad('GID host root mapped at start',x=>x.linux.gidMappings[0].hostID=0);
bad('user mapping excludes probe process',x=>x.linux.uidMappings[0].size=65534);
bad('group mapping excludes probe process',x=>x.linux.gidMappings[0].size=65534);
bad('mapping overflows 32-bit group space',x=>x.linux.gidMappings[0].hostID=4294967295);
bad('several UID mapping segments',x=>x.linux.uidMappings.push({containerID:65536,hostID:300000,size:1}));
bad('no seccomp',x=>delete x.linux.seccomp);
bad('permissive seccomp',x=>x.linux.seccomp.defaultAction='SCMP_ACT_ALLOW');
bad('unrecognized seccomp action',x=>x.linux.seccomp.defaultAction='bogus');
bad('OCI version missing',x=>delete x.ociVersion);
bad('unreviewed OCI spec version',x=>x.ociVersion='1.99.0');
bad('unreviewed process user umask extension',x=>x.process.user.umask=0);
bad('unreviewed process scheduler extension',x=>x.process.scheduler={policy:'SCHED_FIFO'});
bad('unreviewed process selinuxLabel extension',x=>x.process.selinuxLabel='untrusted');
bad('unreviewed capability extension',x=>x.process.capabilities.debug=['CAP_SYS_ADMIN']);
bad('unreviewed namespace extension',x=>x.linux.namespaces[0].extra='host');

test('the disposable Docker smoke cannot silently waive zero supplementary groups',()=>{
  const workflow=fs.readFileSync(path.join(__dirname,'..','..','.github',
    'workflows','wardveil-firstparty-runtime-smoke.yml'),'utf8');
  assert.ok(workflow.includes('if field(status,"Groups")!="" { fail("supplementary group membership") }'));
  assert.ok(workflow.includes('--user 65534:65534 --pids-limit 24'));
  assert.ok(workflow.includes('--cap-drop ALL --security-opt no-new-privileges:true'));
  assert.ok(workflow.includes('--userns-remap=default'));
  assert.ok(workflow.includes('HOST GROUP EVIDENCE: primary GID also assigned as supplementary'));
  assert.ok(!workflow.includes('--group-add '));
  assert.ok(workflow.includes("github.event.number == 24"));
  assert.ok(workflow.includes('docker --host "$socket"'));
});
test('OCI identity checker never runs a process or opens a network socket',()=>{
  const src=fs.readFileSync(path.join(__dirname,'check-oci-identity.cjs'),'utf8');
  assert.doesNotMatch(src,/\brequire\(['"]node:(?:child_process|net|http|https|dgram|vm)['"]\)/);
  assert.doesNotMatch(src,/\b(?:spawn|exec|fork)\s*\(/);
  assert.doesNotMatch(src,/\b(?:fetch|WebSocket)\s*\(/);
});
test('validMap covers exact expected bounds',()=>{
  assert.equal(validMap([{containerID:0,hostID:1,size:65535}]),true);
  assert.equal(validMap([{containerID:0,hostID:1,size:65536}]),true);
  assert.equal(validMap([{containerID:0,hostID:0,size:65536}]),false);
  assert.equal(validMap([{containerID:0,hostID:1,size:65534}]),false);
});
test('read-only CLI accepts only normal, bounded and no-follow OCI JSON',()=>{
  const folder=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-oci-identity-'));
  try {
    const file=path.join(folder,'config.json');
    fs.writeFileSync(file,JSON.stringify(good()));
    const run=(p)=>spawnSync(process.execPath,[path.join(__dirname,'check-oci-identity.cjs'),p],{encoding:'utf8'});
    let r=run(file);
    assert.equal(r.status,0,r.stderr);
    assert.match(r.stdout,/OCI STATIC IDENTITY MATCH ONLY/);
    assert.doesNotMatch(r.stdout,/certified|sandbox verified/i);
    const symlink=path.join(folder,'alias.json');
    fs.symlinkSync(file,symlink);
    r=run(symlink);
    assert.notEqual(r.status,0);
    assert.match(r.stderr,/BLOCKED/);
    fs.writeFileSync(file,'{ invalid');
    assert.notEqual(run(file).status,0);
    fs.writeFileSync(file,'{}');
    assert.notEqual(run(file).status,0);
    fs.writeFileSync(file,JSON.stringify(good())+' '.repeat(140000));
    assert.notEqual(run(file).status,0);
  }finally{fs.rmSync(folder,{recursive:true,force:true});}
});
