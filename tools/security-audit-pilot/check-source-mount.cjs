#!/usr/bin/env node
'use strict';
// Standalone, read-only source-bind PRE-EXECUTION inspection. Does not claim
// source authorship, uninterrupted immutability, or actual container isolation.
const fs=require('node:fs');
const {SAFE_SOURCE_PREFIX}=require('./check-container-policy.cjs');
const {readKernelMountinfo,checkRootfsMountBoundary}=require('./mount-boundary.cjs');
const MAX_ENTRIES=1024,MAX_FILE=16*1024*1024,MAX_TOTAL=128*1024*1024,MAX_DEPTH=8;
const DIR_FLAGS=fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|
  fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
const FILE_FLAGS=fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK;
const NAME=/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
function approvedSource(src){
  return typeof src==='string' && src.startsWith(SAFE_SOURCE_PREFIX) &&
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(src.slice(SAFE_SOURCE_PREFIX.length));
}
function canonicalAbsolute(src){
  return typeof src==='string'&&src.startsWith('/')&&src!=='/'&&
    src.length<=1024&&!src.includes('//')&&!src.endsWith('/')&&
    !src.includes('\\')&&!src.includes('\0')&&
    src.split('/').every(p=>p!=='.'&&p!=='..'&&
      !/[\r\n\t]/.test(p));
}
function same(a,b){
  return a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode&&
    a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;
}
function directoryOK(st,dev){
  return st.isDirectory() && st.dev===dev &&
    [0o555,0o755].includes(st.mode&0o7777);
}
function verifySourceTree(source,mountSource=readKernelMountinfo){
  if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW||
     !fs.constants.O_DIRECTORY||!fs.existsSync('/proc/self/fd')||
     !canonicalAbsolute(source)||typeof mountSource!=='function')
    throw Error('Linux descriptor-safe canonical source directory required');
  const startMount=checkRootfsMountBoundary(source,mountSource());
  let fd=fs.openSync('/',DIR_FLAGS);
  let files=0,dirs=0,bytes=0,entries=0;
  const seenNames=new Set();
  const sourceParts=source.slice(1).split('/');
  try{
    for(const part of sourceParts){
      const child=fs.openSync('/proc/self/fd/'+fd+'/'+part,DIR_FLAGS);
      fs.closeSync(fd);
      fd=child;
    }
    const origin=fs.fstatSync(fd);
    if(!directoryOK(origin,origin.dev))throw Error('unreviewed source-root directory mode');
    const scan=(dir,depth,relative)=>{
      if(depth>MAX_DEPTH)throw Error('source tree depth exceeded');
      const before=fs.fstatSync(dir);
      if(!directoryOK(before,origin.dev))throw Error('unsafe or cross-device directory');
      const list=fs.readdirSync('/proc/self/fd/'+dir);
      if(list.length>MAX_ENTRIES)throw Error('source directory too large');
      for(const name of list){
        if(++entries>MAX_ENTRIES||!NAME.test(name)||name.startsWith('.')||
           /(?:^|[._-])(?:secret|credential|password|private|token)(?:[._-]|$)/i.test(name))
          throw Error('unreviewed source object name or excessive entries');
        const rel=relative?relative+'/'+name:name;
        if(seenNames.has(rel))throw Error('duplicate source entry');
        seenNames.add(rel);
        const child=fs.openSync('/proc/self/fd/'+dir+'/'+name,FILE_FLAGS);
        try{
          const stat=fs.fstatSync(child);
          if(stat.isDirectory()){
            if(!directoryOK(stat,origin.dev))throw Error('unsafe source directory');
            dirs++;
            scan(child,depth+1,rel);
          }else{
            if(!stat.isFile()||stat.dev!==origin.dev||stat.nlink!==1||
               ![0o444,0o555].includes(stat.mode&0o7777)||
               stat.size<0||stat.size>MAX_FILE)
              throw Error('unsafe, mutable, linked or nonregular source file');
            // A metadata-only preflight does not hash file content; a
            // separately reviewed source manifest remains mandatory.
            files++;bytes+=stat.size;
            if(bytes>MAX_TOTAL)throw Error('source file aggregate size exceeded');
          }
          if(!same(stat,fs.fstatSync(child)))throw Error('source inode changed');
        }finally{fs.closeSync(child)}
      }
      if(!same(before,fs.fstatSync(dir)))throw Error('source directory changed');
    };
    scan(fd,0,'');
    if(files<1||!same(origin,fs.fstatSync(fd)))throw Error('empty or unstable source tree');
    if(startMount!==checkRootfsMountBoundary(source,mountSource()))
      throw Error('source mount identity changed');
    return {ok:true,files,dirs,bytes};
  }finally{fs.closeSync(fd)}
}
function main(argv){
  if(argv.length===1&&argv[0]==='--help'){
    process.stdout.write('Read-only source preflight: node check-source-mount.cjs --source /srv/wardveil-audit-pilot/source/<approved-label>\n');
    return 0;
  }
  if(argv.length!==2||argv[0]!=='--source'||!approvedSource(argv[1])){
    process.stderr.write('BLOCKED: exact approved source mount path required\n');return 2;
  }
  try{
    const result=verifySourceTree(argv[1]);
    process.stdout.write('SOURCE STATIC MOUNT-PATH MATCH ONLY: '+result.files+
      ' ordinary files checked; content provenance, runtime mounts and egress NOT verified.\n');
    return 0;
  }catch(_){
    process.stderr.write('BLOCKED: unreviewed source inode, mount, mode or tree\n');return 1;
  }
}
if(require.main===module)process.exitCode=main(process.argv.slice(2));
module.exports={approvedSource,canonicalAbsolute,verifySourceTree,main,MAX_ENTRIES,MAX_TOTAL};
