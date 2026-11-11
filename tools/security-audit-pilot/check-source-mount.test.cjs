'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {approvedSource,canonicalAbsolute,verifySourceTree,MAX_ENTRIES}=require('./check-source-mount.cjs');
const mount=(id,p)=>id+' 1 8:1 / '+p+' ro - ext4 /dev/a ro\n';
function make(){
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-source-'));
  const src=path.join(tmp,'approved');
  fs.mkdirSync(src);
  fs.mkdirSync(path.join(src,'src'),{mode:0o755});
  fs.writeFileSync(path.join(src,'src','fixture.cjs'),'/* inert first-party fixture */\n');
  fs.chmodSync(path.join(src,'src','fixture.cjs'),0o444);
  return {tmp,src};
}
function withSource(fn){
  const x=make();
  try{return fn(x)}
  finally{
    // Restore only fixture-owned temporary directory modes for removal.
    for(const p of [x.src,path.join(x.src,'src')]){
      try{fs.chmodSync(p,0o755)}catch(_){}
    }
    fs.rmSync(x.tmp,{recursive:true,force:true});
  }
}
test('approved source is exactly one canonical subdirectory under fixed pilot root',()=>{
  assert.equal(approvedSource('/srv/wardveil-audit-pilot/source/firstparty-smoke'),true);
  for(const x of ['/home/user/repo','/srv/wardveil-audit-pilot/source/',
    '/srv/wardveil-audit-pilot/source/a/b','/srv/wardveil-audit-pilot/source/../secret',
    '/srv/wardveil-audit-pilot/source/.hidden','/srv/wardveil-audit-pilot/source/a/',
    '/srv/wardveil-audit-pilot/source/a_b','/srv/wardveil-audit-pilot/source/A',
    '/srv/wardveil-audit-pilot/source/a//b']){
    assert.equal(approvedSource(x),false,x);
  }
});
test('source path rejects ambiguous Unicode, traversal and invalid absolute forms',()=>{
  assert.equal(canonicalAbsolute('/tmp/approved'),true);
  for(const x of ['relative','/','/tmp/../src','/tmp/./src','/tmp//src','/tmp/src/',
    '/tmp/src\0bad','/tmp/x\\y','/tmp/space\nsrc'])assert.equal(canonicalAbsolute(x),false,x);
});
test('read-only tree rejects neither legitimate inert files nor clean directories',()=>withSource(x=>{
  assert.deepEqual(verifySourceTree(x.src),{
    ok:true,files:1,dirs:1,bytes:Buffer.byteLength('/* inert first-party fixture */\n'),
  });
}));
test('clean source with two children and allowed readonly modes passes',()=>withSource(x=>{
  fs.writeFileSync(path.join(x.src,'README.md'),'inert');
  fs.chmodSync(path.join(x.src,'README.md'),0o555);
  assert.equal(verifySourceTree(x.src).files,2);
}));
function reject(label,change){
  test('source preflight refuses '+label,()=>withSource(x=>{
    change(x);
    assert.throws(()=>verifySourceTree(x.src));
  }));
}
reject('source filesystem symlink',x=>{
  fs.symlinkSync('/etc/passwd',path.join(x.src,'src','shadow'));
});
reject('untrusted ancestor symlink',x=>{
  fs.symlinkSync(x.src,path.join(x.tmp,'alias'));
  x.src=path.join(x.tmp,'alias');
});
reject('hidden .env file',x=>fs.writeFileSync(path.join(x.src,'.env'),'NOT A REAL SECRET'));
reject('private key-like basename',x=>fs.writeFileSync(path.join(x.src,'private.key'),'fixture'));
reject('credential filename',x=>fs.writeFileSync(path.join(x.src,'credential.json'),'inert'));
reject('unlisted executable file mode 0777',x=>{
  const p=path.join(x.src,'src','fixture.cjs');fs.chmodSync(p,0o777);
});
reject('group-writable source file',x=>{
  const p=path.join(x.src,'src','fixture.cjs');fs.chmodSync(p,0o664);
});
reject('group-writable source directory',x=>{
  fs.chmodSync(path.join(x.src,'src'),0o775);
});
reject('setgid source directory',x=>fs.chmodSync(x.src,0o2755));
reject('sticky source directory',x=>fs.chmodSync(x.src,0o1755));
reject('source file hardlink',x=>{
  fs.linkSync(path.join(x.src,'src','fixture.cjs'),path.join(x.tmp,'hardlink.cjs'));
});
reject('unlisted empty source tree',x=>fs.rmSync(path.join(x.src,'src'),{recursive:true,force:true}));
reject('file larger than approved size',x=>{
  const p=path.join(x.src,'src','fixture.cjs');fs.chmodSync(p,0o644);
  fs.truncateSync(p,16*1024*1024+1);fs.chmodSync(p,0o444);
});
reject('source file path is actually a directory link',x=>{
  const p=path.join(x.src,'src','fixture.cjs');fs.unlinkSync(p);
  fs.symlinkSync(x.src,p);
});
test('nested and stacked mounts fail even with readable inert source',()=>withSource(x=>{
  assert.throws(()=>verifySourceTree(x.src,()=>mount(1,'/')+mount(2,x.src+'/src')),
    /mount over or beneath/);
  assert.throws(()=>verifySourceTree(x.src,()=>mount(1,'/')+mount(2,x.src)+mount(3,x.src)),
    /stacked/);
}));
test('changed root mount identity during two snapshots fails closed',()=>withSource(x=>{
  let turn=0;
  assert.throws(()=>verifySourceTree(x.src,()=>{
    turn++;return mount(1,'/')+mount(turn===1?2:3,x.src);
  }),/mount identity changed/);
}));
test('neighboring lexical mount prefix cannot masquerade as nested source',()=>withSource(x=>{
  const neighbor=x.src+'-neighbor';
  const r=verifySourceTree(x.src,()=>mount(1,'/')+mount(2,neighbor));
  assert.equal(r.ok,true);
}));
test('source directory entry count limit remains bounded',()=>{
  assert.equal(MAX_ENTRIES,1024);
});
test('CLI rejects unapproved user or owner source without reading it',()=>withSource(x=>{
  const r=spawnSync(process.execPath,
    [path.join(__dirname,'check-source-mount.cjs'),'--source',x.src],{encoding:'utf8'});
  assert.notEqual(r.status,0);
  assert.match(r.stderr,/BLOCKED/);
}));
