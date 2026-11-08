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
  fs.writeFileSync(path.join(root,'skills/security-audit/SKILL.md'),'evil-only test fixture\n');
  assert.throws(()=>verifySnapshot(root,sampleManifest),/size mismatch|content hash mismatch/);
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
