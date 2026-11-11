'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {test}=require('node:test');
const {validateManifest,relativeFile,verifyRootfs}=require('./check-oci-rootfs.cjs');
function fixture(){
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-oci-rootfs-'));
  const root=path.join(temp,'rootfs');
  fs.mkdirSync(path.join(root,'usr','bin'),{recursive:true,mode:0o755});
  fs.mkdirSync(path.join(root,'opt','wardveil'),{recursive:true,mode:0o755});
  const entries=[
    {path:'opt/wardveil/runtime-probe.cjs',value:Buffer.from('/* first-party fixture only */\n'),mode:'0444'},
    {path:'usr/bin/node',value:Buffer.from('first-party inert binary fixture\n'),mode:'0555'},
  ];
  for(const x of entries){
    fs.writeFileSync(path.join(root,x.path),x.value);
    fs.chmodSync(path.join(root,x.path),Number.parseInt(x.mode,8));
  }
  const manifest={
    format:'wardveil-oci-rootfs-v1',
    files:entries.map(x=>({
      path:x.path,sha256:crypto.createHash('sha256').update(x.value).digest('hex'),
      size:x.value.length,mode:x.mode,
    })),
  };
  return{temp,root,manifest};
}
function withFixture(fn){
  const x=fixture();
  try{return fn(x)}finally{fs.rmSync(x.temp,{recursive:true,force:true})}
}
function cli(root,manifestPath,sha){
  return spawnSync(process.execPath,[path.join(__dirname,'check-oci-rootfs.cjs'),
    root,manifestPath,'--manifest-sha256',sha],{encoding:'utf8'});
}
function bad(name,fn){
  test('rootfs refuses '+name,()=>withFixture(x=>{
    fn(x);
    assert.throws(()=>verifyRootfs(x.root,x.manifest));
  }));
}
test('exact inert two-file fixture and digest match passes as static bytes only',()=>withFixture(x=>{
  assert.deepEqual(verifyRootfs(x.root,x.manifest),
    {ok:true,files:2,bytes:Buffer.byteLength('/* first-party fixture only */\n')+
      Buffer.byteLength('first-party inert binary fixture\n')});
}));
test('manifest validation rejects absent or unknown files',()=>{
  assert.throws(()=>validateManifest({format:'wardveil-oci-rootfs-v1',files:[]}));
  assert.throws(()=>validateManifest(null));
  assert.throws(()=>validateManifest({format:'test',files:[]}));
});
test('relative file policy rejects aliases and out-of-scope paths',()=>{
  for(const p of ['usr/bin/node','opt/wardveil/runtime-probe.cjs','lib/a.so'])assert.equal(relativeFile(p),true);
  for(const p of ['/usr/bin/node','../usr/bin/node','usr//bin/node','usr/../bin/node',
    'usr/./bin/node','usr\\bin\\node','home/secrets','opt/wardveil','/etc/shadow',
    'usr/bin/node/','lib/.','lib64/..'])assert.equal(relativeFile(p),false,p);
});
bad('modified script contents with identical size',x=>{
  const p=path.join(x.root,'opt','wardveil','runtime-probe.cjs');
  fs.chmodSync(p,0o644);
  const data=fs.readFileSync(p);data[3]=data[3]===0x41?0x42:0x41;
  fs.writeFileSync(p,data);
  fs.chmodSync(p,0o444);
});
bad('unexpected unlisted root file',x=>fs.writeFileSync(path.join(x.root,'extra'),'hidden'));
bad('unexpected unlisted nested directory',x=>fs.mkdirSync(path.join(x.root,'usr','local')));
bad('missing reviewed first-party binary',x=>fs.unlinkSync(path.join(x.root,'usr/bin/node')));
bad('symlinked final first-party binary',x=>{
  const p=path.join(x.root,'usr/bin/node');
  fs.unlinkSync(p);
  fs.symlinkSync('/bin/sh',p);
});
bad('symlinked first-party directory',x=>{
  fs.rmSync(path.join(x.root,'opt'),{recursive:true});
  fs.symlinkSync(path.join(x.root,'usr'),path.join(x.root,'opt'));
});
bad('extra hardlinked first-party executable',x=>{
  fs.linkSync(path.join(x.root,'usr/bin/node'),path.join(x.temp,'other'));
});
bad('writable first-party script mode',x=>{
  fs.chmodSync(path.join(x.root,'opt/wardveil/runtime-probe.cjs'),0o644);
});
bad('writable rootfs directory',x=>fs.chmodSync(x.root,0o777));
bad('writable nested directory',x=>fs.chmodSync(path.join(x.root,'usr'),0o777));
bad('setgid root directory',x=>fs.chmodSync(x.root,0o2755));
bad('sticky nested directory',x=>fs.chmodSync(path.join(x.root,'usr'),0o1755));
bad('setuid nested directory',x=>fs.chmodSync(path.join(x.root,'opt'),0o4755));
bad('no-traverse root directory',x=>fs.chmodSync(x.root,0o700));
bad('unreviewed mode on nested directory',x=>fs.chmodSync(path.join(x.root,'opt'),0o711));
bad('different expected manifest digest',x=>x.manifest.files[1].sha256='0'.repeat(64));
bad('unreviewed manifest file mode',x=>x.manifest.files[1].mode='0777');
bad('out-of-order manifest file list',x=>x.manifest.files.reverse());
bad('same path repeated in manifest',x=>x.manifest.files[1].path=x.manifest.files[0].path);
bad('wrong reviewed manifest file byte size',x=>x.manifest.files[0].size+=1);
bad('unknown manifest entry key',x=>x.manifest.files[0].uid=0);
bad('unknown top-level manifest key',x=>x.manifest.config='unsafe');
bad('additional malicious manifest file path',x=>x.manifest.files.push({
  path:'usr/bin/../secrets',size:3,sha256:'0'.repeat(64),mode:'0444'
}));
test('CLI requires a separately pinned manifest digest',()=>withFixture(x=>{
  const manifest=path.join(x.temp,'manifest.json');
  const raw=JSON.stringify(x.manifest);
  fs.writeFileSync(manifest,raw);
  const sha=crypto.createHash('sha256').update(raw).digest('hex');
  const ok=cli(x.root,manifest,sha);
  assert.equal(ok.status,0,ok.stderr);
  assert.match(ok.stdout,/ROOTFS STATIC BYTE MATCH ONLY/);
  assert.doesNotMatch(ok.stdout,/verified runtime|certified/i);
  const wrong=cli(x.root,manifest,'0'.repeat(64));
  assert.notEqual(wrong.status,0);
  assert.match(wrong.stderr,/BLOCKED/);
  const noSha=spawnSync(process.execPath,[path.join(__dirname,'check-oci-rootfs.cjs'),
    x.root,manifest],{encoding:'utf8'});
  assert.notEqual(noSha.status,0);
  assert.match(noSha.stderr,/BLOCKED/);
}));
test('CLI refuses symlinked manifest file and parent directory',()=>withFixture(x=>{
  const src=path.join(x.temp,'manifest.json'),alias=path.join(x.temp,'alias.json');
  const data=JSON.stringify(x.manifest);
  fs.writeFileSync(src,data);fs.symlinkSync(src,alias);
  const sha=crypto.createHash('sha256').update(data).digest('hex');
  assert.notEqual(cli(x.root,alias,sha).status,0);
  const dir=path.join(x.temp,'aliasdir');
  fs.symlinkSync(x.temp,dir);
  assert.notEqual(cli(x.root,path.join(dir,'manifest.json'),sha).status,0);
}));
test('CLI rejects ambiguous duplicate manifest keys even with valid digest',()=>withFixture(x=>{
  const file=path.join(x.temp,'dup.json');
  const raw=JSON.stringify(x.manifest).replace(
    '"format":"wardveil-oci-rootfs-v1"',
    '"format":"wardveil-oci-rootfs-v1","format":"wardveil-oci-rootfs-v1"');
  fs.writeFileSync(file,raw);
  const sha=crypto.createHash('sha256').update(raw).digest('hex');
  const r=cli(x.root,file,sha);
  assert.notEqual(r.status,0);
  assert.match(r.stderr,/BLOCKED/);
}));
test('CLI rejects unlisted file even if manifest digest is correct',()=>withFixture(x=>{
  const file=path.join(x.temp,'manifest.json');
  const raw=JSON.stringify(x.manifest);
  fs.writeFileSync(file,raw);
  fs.writeFileSync(path.join(x.root,'unlisted'),'bad');
  const sha=crypto.createHash('sha256').update(raw).digest('hex');
  assert.notEqual(cli(x.root,file,sha).status,0);
}));
