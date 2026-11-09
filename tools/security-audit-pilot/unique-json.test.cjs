'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {test}=require('node:test');
const {parseUniqueJson}=require('./unique-json.cjs');

test('duplicate-safe OCI parser accepts ordinary formatted JSON without changing its meaning',()=>{
  for(const s of [
    '{"root":{"readonly":true},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO"}}}',
    '{\n "root": { "path": "rootfs", "readonly": true },\n "mounts": [1, {"source":"/tmp"}]\n}',
    '{"name":"alpha","literal":"\\\\u0061", "array": ["hello", null, 2.5, false]}',
    '[{"a":1},{"a":2}]',
    'null','true','[]','{}',
  ]) assert.deepEqual(parseUniqueJson(s),JSON.parse(s));
});
test('duplicate-safe OCI parser rejects repeated top-level and nested keys',()=>{
  for(const s of [
    '{"linux":{},"linux":{"resources":{}}}',
    '{"process":{"user":{"uid":65534,"uid":0}}}',
    '{"mounts":[{"destination":"/source","destination":"/host"}]}',
    '{"linux":{"resources":{"cpu":{"quota":50000,"period":100000,"quota":-1}}}}',
    '{"annotations":{"x":"safe","x":"unsafe"}}',
    '{"a":1,"a":2}',
  ]) assert.throws(()=>parseUniqueJson(s),/duplicate JSON object member/);
});
test('duplicate names normalized through JSON escape sequences are rejected',()=>{
  for(const s of [
    '{"user":1,"\\u0075ser":2}',
    '{"a":1,"\\u0061":2}',
    '{"\\uD83D\\uDE80":1,"🚀":2}',
    '{"nested":{"\\u0061":1,"a":2}}',
  ]) assert.throws(()=>parseUniqueJson(s),/duplicate JSON object member/);
});
test('same member names in separate JSON objects are permitted',()=>{
  const s='{"one":{"key":1},"two":{"key":2},"array":[{"key":3},{"key":4}]}';
  assert.deepEqual(parseUniqueJson(s),JSON.parse(s));
});
test('OCI parser bounds nesting, input size and grammar ambiguity',()=>{
  assert.throws(()=>parseUniqueJson('['.repeat(65)+'0'+']'.repeat(65)),/excessive JSON structure/);
  assert.throws(()=>parseUniqueJson(' '.repeat(131073)),/bounded UTF-8/);
  for(const v of [null,undefined,{},42,true]) assert.throws(()=>parseUniqueJson(v));
  for(const s of ['{"a":1,}','{"a":1','{"a" 1}','{"a":"unterminated}',
    '{"bad":"\\z"}','[1,,2]']) assert.throws(()=>parseUniqueJson(s));
});
test('OCI CLIs reject duplicate members from the original bounded file bytes',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-oci-json-'));
  try {
    const p=path.join(dir,'config.json');
    fs.writeFileSync(p,'{"process":{"user":{"uid":65534,"uid":0}}}');
    for(const tool of ['check-oci-identity.cjs','check-oci-bundle-policy.cjs']) {
      const r=spawnSync(process.execPath,[path.join(__dirname,tool),p],{encoding:'utf8'});
      assert.notEqual(r.status,0,tool);
      assert.match(r.stderr,/BLOCKED/);
      assert.doesNotMatch(r.stderr,/65534|uid.*0/);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
