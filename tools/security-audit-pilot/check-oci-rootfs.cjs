#!/usr/bin/env node
'use strict';
// Read-only, Linux-only exact-file integrity review for a proposed OCI rootfs.
// Manifest digest must come from a separately trusted review; a self-computed
// digest from an untrusted manifest is NOT provenance or runtime attestation.
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {readInspectFile}=require('./check-container-policy.cjs');
const {parseUniqueJson}=require('./unique-json.cjs');
const {checkRootfsMountBoundary,readKernelMountinfo}=require('./mount-boundary.cjs');

const MAX_FILES=512,MAX_BYTES=512*1024*1024,MAX_SINGLE=128*1024*1024,MAX_ENTRIES=8192;
const REQUIRED_FILES=['opt/wardveil/runtime-probe.cjs','usr/bin/node'];
const DIR_FLAGS=fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|
  fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
const FILE_FLAGS=fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
const HEX=/^[a-f0-9]{64}$/;
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null)}
function sameStat(a,b){return a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode&&
  a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs}
function safeDirectory(st,rootDev){
  // Directory ownership is not attested by this gate. Even so, reject
  // sticky, setgid, setuid and other unreviewed mode configurations.
  return st.isDirectory()&&st.dev===rootDev&&
    [0o555,0o755].includes(st.mode&0o7777);
}
function partsOf(p){
  if(typeof p!=='string'||!p.startsWith('/')||p==='/'||
     p.includes('//')||p.endsWith('/')||p.includes('\0'))throw Error('noncanonical absolute path');
  const parts=p.slice(1).split('/');
  if(parts.some(x=>!x||x==='.'||x==='..'))throw Error('unsafe path component');
  return parts;
}
function relativeFile(p){
  if(typeof p!=='string'||p.length>256||p.startsWith('/')||p.includes('\\')||
     !/^[a-zA-Z0-9._/-]+$/.test(p))return false;
  const a=p.split('/');
  if(a.length<2||a.length>12||a.some(x=>!x||x==='.'||x==='..'))return false;
  return p.startsWith('usr/')||p.startsWith('opt/wardveil/')||
    p.startsWith('lib/')||p.startsWith('lib64/');
}
function validateManifest(m){
  if(!plain(m)||Object.keys(m).some(k=>!['format','files'].includes(k))||
     m.format!=='wardveil-oci-rootfs-v1'||!Array.isArray(m.files)||
     m.files.length<2||m.files.length>MAX_FILES)throw Error('invalid rootfs manifest');
  let previous='',total=0;
  const files=new Map(),dirs=new Set();
  for(const entry of m.files){
    if(!plain(entry)||Object.keys(entry).length!==4||
       ['path','size','sha256','mode'].some(k=>!Object.hasOwn(entry,k))||
       !relativeFile(entry.path)||!(entry.path>previous)||
       !Number.isSafeInteger(entry.size)||entry.size<1||entry.size>MAX_SINGLE||
       typeof entry.sha256!=='string'||!HEX.test(entry.sha256)||
       !['0444','0555'].includes(entry.mode))throw Error('unreviewed rootfs entry');
    previous=entry.path;
    total+=entry.size;
    if(total>MAX_BYTES)throw Error('rootfs manifest exceeds aggregate limit');
    files.set(entry.path,entry);
    const segments=entry.path.split('/');
    for(let i=1;i<segments.length;i++)dirs.add(segments.slice(0,i).join('/'));
  }
  if(REQUIRED_FILES.some(p=>!files.has(p)))throw Error('required first-party files absent');
  if(files.get('usr/bin/node').mode!=='0555'||
     files.get('opt/wardveil/runtime-probe.cjs').mode!=='0444')
    throw Error('first-party process file modes mismatch');
  return {files,dirs,total};
}
function openPinnedDirectory(absolute){
  if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW||!fs.constants.O_DIRECTORY||
     !fs.existsSync('/proc/self/fd'))throw Error('Linux descriptor-safe mode required');
  const parts=partsOf(absolute);
  let fd=fs.openSync('/',DIR_FLAGS);
  try{
    for(const p of parts){
      const child=fs.openSync('/proc/self/fd/'+fd+'/'+p,DIR_FLAGS);
      fs.closeSync(fd);
      fd=child;
    }
    const s=fs.fstatSync(fd);
    if(!safeDirectory(s,s.dev))throw Error('rootfs directory must have reviewed read/traverse permissions');
    return fd;
  }catch(e){fs.closeSync(fd);throw e}
}
function verifyRootfs(rootfs,manifest){
  const expected=validateManifest(manifest);
  // Snapshot mount topology BEFORE opening the proposed rootfs and after
  // reading the complete file tree. A nested bind mount (even one whose
  // contents match the manifest) is not accepted as original image bytes.
  const startRootMount=checkRootfsMountBoundary(rootfs,readKernelMountinfo());
  let rootFd=openPinnedDirectory(rootfs);
  const rootBefore=fs.fstatSync(rootFd);
  let filesSeen=0,entriesSeen=0,totalRead=0;
  const found=new Set();
  function walk(dirFd,rel,depth){
    if(depth>12)throw Error('rootfs walk depth exceeded');
    const before=fs.fstatSync(dirFd);
    if(!safeDirectory(before,rootBefore.dev))throw Error('unreviewed directory, device or special mode bits');
    const list=fs.readdirSync('/proc/self/fd/'+dirFd);
    for(const name of list){
      if(++entriesSeen>MAX_ENTRIES||!name||name==='.'||name==='..'||name.includes('/'))
        throw Error('unreviewed rootfs entry name or count');
      const sub=rel?rel+'/'+name:name;
      if(expected.dirs.has(sub)){
        const child=fs.openSync('/proc/self/fd/'+dirFd+'/'+name,DIR_FLAGS);
        try{walk(child,sub,depth+1)}finally{fs.closeSync(child)}
        continue;
      }
      const pin=expected.files.get(sub);
      if(!pin)throw Error('extra or unexpected rootfs path');
      const file=fs.openSync('/proc/self/fd/'+dirFd+'/'+name,FILE_FLAGS);
      try{
        const st=fs.fstatSync(file);
        if(!st.isFile()||st.dev!==rootBefore.dev||st.nlink!==1||st.size!==pin.size||
           (st.mode&0o7777)!==Number.parseInt(pin.mode,8))
          throw Error('nonregular, linked, oversized or differently permissioned file');
        const hash=crypto.createHash('sha256');
        const buf=Buffer.allocUnsafe(65536);
        let n=0;
        while(n<st.size){
          const got=fs.readSync(file,buf,0,Math.min(buf.length,st.size-n),null);
          if(!got)throw Error('rootfs short file read');
          n+=got;totalRead+=got;
          if(totalRead>MAX_BYTES)throw Error('aggregate rootfs bound exceeded');
          hash.update(buf.subarray(0,got));
        }
        if(!sameStat(st,fs.fstatSync(file))||hash.digest('hex')!==pin.sha256)
          throw Error('rootfs content changed or review digest mismatch');
        filesSeen++;found.add(sub);
      }finally{fs.closeSync(file)}
    }
    if(!sameStat(before,fs.fstatSync(dirFd)))throw Error('rootfs directory mutated during walk');
  }
  try{
    walk(rootFd,'',0);
    if(filesSeen!==expected.files.size||found.size!==expected.files.size||
       !sameStat(rootBefore,fs.fstatSync(rootFd)))throw Error('rootfs file set inconsistent');
    const endRootMount=checkRootfsMountBoundary(rootfs,readKernelMountinfo());
    if(endRootMount!==startRootMount)throw Error('rootfs mount identity changed during inspection');
    return {ok:true,files:filesSeen,bytes:totalRead};
  }finally{fs.closeSync(rootFd)}
}
function main(argv){
  if(argv.length===1&&argv[0]==='--help'){
    process.stdout.write('Read-only rootfs check: node check-oci-rootfs.cjs /absolute/rootfs /absolute/manifest.json --manifest-sha256 <64-lowercase-hex>\n');
    return 0;
  }
  if(argv.length!==4||argv[2]!=='--manifest-sha256'||!HEX.test(argv[3])){
    process.stderr.write('BLOCKED: reviewed manifest digest and exact arguments required\n');
    return 2;
  }
  try{
    let observed=null;
    const manifest=readInspectFile(argv[1],txt=>{
      observed=crypto.createHash('sha256').update(Buffer.from(txt,'utf8')).digest('hex');
      return parseUniqueJson(txt);
    });
    if(observed!==argv[3])throw Error('out-of-band manifest digest mismatch');
    const verdict=verifyRootfs(argv[0],manifest);
    process.stdout.write('ROOTFS STATIC BYTE MATCH ONLY: '+verdict.files+' reviewed files; runtime, LSM and host isolation NOT verified.\n');
    return 0;
  }catch(_){
    process.stderr.write('BLOCKED: unreviewed or unsafe rootfs files, manifest or path\n');
    return 1;
  }
}
if(require.main===module)process.exitCode=main(process.argv.slice(2));
module.exports={MAX_FILES,MAX_BYTES,validateManifest,relativeFile,verifyRootfs,main};
