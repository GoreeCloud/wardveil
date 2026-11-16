#!/usr/bin/env node
'use strict';
// Offline, read-only LINKED evidence check for a proposed OCI first-party bundle.
// Exact config.json and rootfs manifest SHA-256 pins must come from a separate,
// trusted review. Passing NEVER authorizes an OCI runtime or agent execution.
const crypto=require('node:crypto');
const path=require('node:path');
const {readInspectFile}=require('./check-container-policy.cjs');
const {parseUniqueJson}=require('./unique-json.cjs');
const {evaluateOciBundle}=require('./check-oci-bundle-policy.cjs');
const {verifyRootfs}=require('./check-oci-rootfs.cjs');

const PIN=/^[a-f0-9]{64}$/;
function canonicalAbsolute(p){
  return typeof p==='string'&&p.startsWith('/')&&p.length<=1024&&p!=='/'&&
    !p.includes('\0')&&!p.includes('\\')&&!p.includes('//')&&
    !p.endsWith('/')&&!p.split('/').some(x=>x==='.'||x==='..'||/[\r\n\t]/.test(x));
}
function validatePaths(configPath,manifestPath){
  if(!canonicalAbsolute(configPath)||!canonicalAbsolute(manifestPath)||
     path.basename(configPath)!=='config.json')
    throw Error('reviewed canonical config and manifest paths required');
  const parent=path.dirname(configPath);
  if(parent==='/'||manifestPath===parent||manifestPath.startsWith(parent+'/'))
    throw Error('manifest must reside outside the untrusted OCI bundle');
  return path.join(parent,'rootfs');
}
function readPinnedJson(file,hash){
  if(typeof hash!=='string'||!PIN.test(hash))
    throw Error('out-of-band lowercase SHA-256 pin required');
  let actual=null;
  const obj=readInspectFile(file,(text,raw)=>{
    actual=crypto.createHash('sha256').update(raw).digest('hex');
    return parseUniqueJson(text);
  });
  if(actual!==hash)throw Error('reviewed content digest mismatch');
  return obj;
}
function verifyLinkedEvidence(configPath,manifestPath,configPin,manifestPin){
  const root=validatePaths(configPath,manifestPath);
  const config=readPinnedJson(configPath,configPin);
  const policy=evaluateOciBundle(config);
  if(!policy.ok)throw Error('OCI identity or policy mismatch');
  const manifest=readPinnedJson(manifestPath,manifestPin);
  // The rootfs is intentionally derived from the same config.json parent.
  // A caller cannot provide an unrelated --rootfs pathname to make three
  // separate green checks appear to describe one bundle.
  const result=verifyRootfs(root,manifest);
  if(!result.ok)throw Error('rootfs evidence mismatch');
  return {ok:true,files:result.files,bytes:result.bytes};
}
function main(argv){
  if(argv.length===1&&argv[0]==='--help'){
    process.stdout.write('Read-only linked OCI evidence: node check-oci-evidence.cjs /absolute/bundle/config.json /absolute/trusted/manifest.json --config-sha256 <hex> --manifest-sha256 <hex>\n');
    return 0;
  }
  if(argv.length!==6||argv[2]!=='--config-sha256'||argv[4]!=='--manifest-sha256'){
    process.stderr.write('BLOCKED: exact two source paths and separately reviewed config/manifest pins required\n');
    return 2;
  }
  try{
    const r=verifyLinkedEvidence(argv[0],argv[1],argv[3],argv[5]);
    process.stdout.write('OCI LINKED STATIC EVIDENCE MATCH ONLY: '+r.files+
      ' reviewed rootfs files; no runtime/host/source ownership or continuous isolation verified.\n');
    return 0;
  }catch(_){
    process.stderr.write('BLOCKED: OCI config, manifest and rootfs do not form one pinned static evidence set\n');
    return 1;
  }
}
if(require.main===module)process.exitCode=main(process.argv.slice(2));
module.exports={canonicalAbsolute,validatePaths,readPinnedJson,verifyLinkedEvidence,main};