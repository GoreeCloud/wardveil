'use strict';

// Regression tripwire for the first-party read-only audit evidence
// programs. Source pattern checks are defense-in-depth, not a sandbox or a
// comprehensive malware/source-code audit.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');

const SOURCES = Object.freeze({
  'preflight.cjs': ['node:fs','node:path','node:crypto'],
  'check-container-policy.cjs': ['node:fs','node:path','node:util'],
  'check-oci-identity.cjs': ['./check-container-policy.cjs','./unique-json.cjs'],
  'check-oci-bundle-policy.cjs': ['./check-container-policy.cjs','./check-oci-identity.cjs','./unique-json.cjs'],
  'unique-json.cjs': [],
  'check-oci-rootfs.cjs': ['node:fs','node:path','node:crypto','./check-container-policy.cjs','./unique-json.cjs','./mount-boundary.cjs'],
  'mount-boundary.cjs': ['node:fs'],
  'check-source-mount.cjs': ['node:fs','./check-container-policy.cjs','./mount-boundary.cjs'],
  'check-oci-evidence.cjs': ['node:crypto','node:path','./check-container-policy.cjs','./unique-json.cjs','./check-oci-bundle-policy.cjs','./check-oci-rootfs.cjs'],
  'runtime-probe.cjs': ['node:fs','node:util'],
  'host-witness.cjs': ['node:fs','node:path','node:crypto','./check-container-policy.cjs','./runtime-probe.cjs'],
});
const FORBIDDEN = Object.freeze([
  /\b(?:eval|Function)\s*\(/,
  /(?<!\.)\bexec\s*\(|\b(?:execFile|execSync|execFileSync|spawn|spawnSync|fork)\s*\(/,
  /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|writeSync|writev|writevSync|ftruncate|ftruncateSync|truncate|truncateSync|copyFile|copyFileSync|symlink|symlinkSync|link|linkSync|createWriteStream|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|rename|renameSync|mkdir|mkdirSync|chmod|chmodSync|chown|chownSync)\s*\(/,
  /\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b/,
  /\[\s*['"](?:writeFile|writeFileSync|appendFile|appendFileSync|writeSync|writev|writevSync|truncate|truncateSync|unlink|unlinkSync|rename|renameSync|mkdir|mkdirSync|rm|rmSync|copyFile|copyFileSync|symlink|symlinkSync)['"]\s*\]\s*\(/,
  /\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/,
  /\b(?:setInterval|setImmediate)\s*\(/,
  /\b(?:process\.chdir|process\.kill|process\.abort)\s*\(/,
  /\b(?:import)\s*\(/,
  /\b(?:require)\s*\(\s*[^'" \t]/,
]);
function checkReadOnlySource(source, allowImports) {
  if (typeof source !== 'string' || !Array.isArray(allowImports)) return false;
  // Every callsite using require() must be one of these statically declared
  // imports. This rejects transitive third-party dependencies and unreviewed
  // node builtins, including networking, process control and worker APIs.
  const imports = [...source.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g)]
    .map(m=>m[1]);
  const calls = (source.match(/\brequire\s*\(/g)||[]).length;
  if (calls !== imports.length || imports.length !== allowImports.length ||
      imports.some((name,i)=>name!==allowImports[i])) return false;
  if (/\b(?:await\s+import\s*\(|new\s+(?:Worker|Function|WebSocket)\s*\()/.test(source)) return false;
  if (FORBIDDEN.some(re=>re.test(source))) return false;
  // The exact import allowlist above rejects unreviewed Node networking and
  // process-control modules. Do not pattern-match those names in string
  // literals: a legitimate provenance URL is not a network API invocation.
  return true;
}
for (const [name,allow] of Object.entries(SOURCES)) {
  test(name + ' keeps the reviewed module and read-only API profile',()=>{
    const content=fs.readFileSync(path.join(__dirname,name),'utf8');
    assert.equal(checkReadOnlySource(content,allow),true,name);
  });
}
test('tripwire rejects unreviewed import and direct system/network APIs',()=>{
  const good="const fs=require('node:fs');\n";
  assert.equal(checkReadOnlySource(good,['node:fs']),true);
  assert.equal(checkReadOnlySource(good+"const m=/x/.exec('x');",['node:fs']),true);
  for (const bad of [
    good+"const cp=require('node:child_process');",
    good+"spawnSync('sh',['-c','exit 0']);",
    good+"exec('sh');",
    good+"fs.writeFileSync('/tmp/x','data');",
    good+"fs.writeSync(4,'secret');",
    good+"fs['writeFileSync']('/tmp/x','data');",
    good+"fs.openSync('/tmp/x',fs.constants.O_WRONLY);",
    good+"fs.symlinkSync('/secret','/tmp/link');",
    good+"fetch('https://example.invalid');",
    good+"eval('2+2');",
    good+"const vm=require('node:vm');",
    good+"import('node:fs');",
    good+"setInterval(()=>{},1000);",
  ]) assert.equal(checkReadOnlySource(bad,['node:fs']),false,bad.slice(0,90));
});
