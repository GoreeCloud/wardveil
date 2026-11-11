'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const {spawnSync} = require('node:child_process');
const {UPSTREAM,FILES,gitBlobID,verifySnapshot} = require('./preflight.cjs');

const supported = process.platform === 'linux' && Number.isInteger(fs.constants.O_NOFOLLOW) && Number.isInteger(fs.constants.O_NONBLOCK);
const fakeBytes = Buffer.from('read-only test fixture\n');
const sampleManifest = [['skills/security-audit/SKILL.md',gitBlobID(fakeBytes),fakeBytes.length]];
function withFixture(fn) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-preflight-'));
  try {
    fs.mkdirSync(path.join(root,'skills/security-audit'),{recursive:true});
    fs.writeFileSync(path.join(root,'skills/security-audit/SKILL.md'),fakeBytes);
    return fn(root);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
}
test('provenance pin and complete manifest are fixed',()=>{
  assert.equal(UPSTREAM.commit,'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8');
  assert.equal(FILES.length,22);
  assert.equal(new Set(FILES.map(x=>x[0])).size,22);
});
test('blob hashing uses real Git blob framing',()=>{
  assert.equal(gitBlobID(Buffer.from('test content\n')),'d670460b4b4aece5915caf5c68d12f560a9fe3e4');
});
test('accepts exact, read-only fixture', {skip:!supported},()=>withFixture(root=>{
  assert.equal(verifySnapshot(root,sampleManifest),1);
}));
test('rejects changed content even with equal size',{skip:!supported},()=>withFixture(root=>{
  const changed=Buffer.from(fakeBytes); changed[0]=changed[0]===65?66:65;
  fs.writeFileSync(path.join(root,'skills/security-audit/SKILL.md'),changed);
  assert.throws(()=>verifySnapshot(root,sampleManifest),/content hash mismatch/);
}));
test('rejects unexpected file',{skip:!supported},()=>withFixture(root=>{
  fs.writeFileSync(path.join(root,'extra.sh'),'anything');
  assert.throws(()=>verifySnapshot(root,sampleManifest),/unexpected file/);
}));
test('rejects symlink file',{skip:!supported},()=>withFixture(root=>{
  const file=path.join(root,'skills/security-audit/SKILL.md');
  fs.rmSync(file);
  fs.symlinkSync('/etc/passwd',file);
  assert.throws(()=>verifySnapshot(root,sampleManifest),/symlink prohibited/);
}));
test('rejects symlinked intermediate directory',{skip:!supported},()=>withFixture(root=>{
  const directory=path.join(root,'skills/security-audit');
  fs.rmSync(directory,{recursive:true});
  fs.symlinkSync('/etc',directory);
  assert.throws(()=>verifySnapshot(root,sampleManifest),/symlink prohibited/);
}));
test('rejects symlinked ancestor of root',{skip:!supported},()=>withFixture(root=>{
  const parent=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-parent-'));
  try {
    const link=path.join(parent,'link');
    fs.symlinkSync(path.dirname(root),link);
    assert.throws(()=>verifySnapshot(path.join(link,path.basename(root)),sampleManifest),/symlink or non-directory ancestor/);
  } finally { fs.rmSync(parent,{recursive:true,force:true}); }
}));
test('rejects a symlink as the requested snapshot root',{skip:!supported},()=>withFixture(root=>{
  const link=root+'.link';
  try {
    fs.symlinkSync(root,link);
    assert.throws(()=>verifySnapshot(link,sampleManifest),/symlink or non-directory ancestor/);
  } finally { if (fs.existsSync(link)) fs.unlinkSync(link); }
}));
test('never follows a FIFO or device-like extra entry',{skip:!supported},()=>withFixture(root=>{
  const fifo=path.join(root,'extra.fifo');
  const made=spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:2000});
  if (made.error) throw made.error;
  assert.equal(made.status,0,made.stderr);
  assert.throws(()=>verifySnapshot(root,sampleManifest),/nonregular entry/);
}));
test('rejects unexpected nested directory',{skip:!supported},()=>withFixture(root=>{
  fs.mkdirSync(path.join(root,'skills/security-audit/other'));
  assert.throws(()=>verifySnapshot(root,sampleManifest),/unexpected directory/);
}));
test('rejects unexpected symlinked git metadata',{skip:!supported},()=>withFixture(root=>{
  fs.symlinkSync('/etc',path.join(root,'.git'));
  assert.throws(()=>verifySnapshot(root,sampleManifest),/unsafe git metadata/);
}));
test('rejects missing file',{skip:!supported},()=>withFixture(root=>{
  fs.rmSync(path.join(root,'skills/security-audit/SKILL.md'));
  assert.throws(()=>verifySnapshot(root,sampleManifest),/missing file/);
}));
test('rejects unsafe manifest traversal',{skip:!supported},()=>withFixture(root=>{
  assert.throws(()=>verifySnapshot(root,[['../outside','0'.repeat(40),1]]),/invalid manifest path/);
}));
test('CLI cannot be invoked without one absolute path',()=>{
  const p=path.join(__dirname,'preflight.cjs');
  for (const args of [[],['.'],['/tmp','/var']]) {
    const r=spawnSync(process.execPath,[p,...args],{encoding:'utf8',timeout:2000});
    assert.equal(r.status,2);
  }
});
