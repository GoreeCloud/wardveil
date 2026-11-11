'use strict';
// Linux mountinfo is a point-in-time observation, not an execution-time LSM
// attestation. Refuse stacked and nested bind mounts inside a reviewed rootfs.
// The scanner reads only /proc/self/mountinfo; it makes no mounts or changes.
const fs=require('node:fs');
const MAX_MOUNTINFO_BYTES=1024*1024;
const MAX_MOUNT_ENTRIES=8192;
const FLAGS=fs.constants.O_RDONLY|fs.constants.O_NONBLOCK|fs.constants.O_NOFOLLOW;
function decodeKernelMountpoint(encoded){
  if(typeof encoded!=='string'||!encoded.startsWith('/')||encoded.length>4096)
    throw Error('invalid kernel mountpoint');
  // Reject unknown raw backslash escapes even when another valid escape
  // appears in the same path; mixed encodings must never pass review.
  if(encoded.replace(/\\(?:040|011|012|134)/g,'').includes('\\'))
    throw Error('unrecognized mountpoint escape');
  const path=encoded.replace(/\\([0-7]{3})/g,(_,oct)=>{
    if(!['040','011','012','134'].includes(oct))
      throw Error('unreviewed kernel mountpoint escape');
    return String.fromCharCode(parseInt(oct,8));
  });
  if(path.includes('\0')||path.includes('\r')||path.includes('\n')||
     path.includes('\t'))throw Error('mountpoint control character');
  return path;
}
function parseMountpoints(raw){
  if(typeof raw!=='string'||raw.length<1||raw.length>MAX_MOUNTINFO_BYTES)
    throw Error('unsafe mountinfo length');
  const lines=raw.endsWith('\n')?raw.slice(0,-1).split('\n'):raw.split('\n');
  if(lines.length<1||lines.length>MAX_MOUNT_ENTRIES)throw Error('mountinfo entry limit');
  return lines.map(line=>{
    const boundary=line.indexOf(' - ');
    if(boundary<0)throw Error('invalid mountinfo record');
    const fields=line.slice(0,boundary).split(' ');
    if(fields.length<6||!(/^[1-9]\d*$/.test(fields[0]))||
       !(/^[0-9]+$/.test(fields[1])))throw Error('invalid mountinfo header');
    return {id:fields[0],point:decodeKernelMountpoint(fields[4])};
  });
}
function checkRootfsMountBoundary(root,raw){
  if(typeof root!=='string'||!root.startsWith('/')||root==='/'||
     root.includes('\0')||root.includes('//')||root.endsWith('/')||
     root.split('/').some(x=>x==='.'||x==='..'))
    throw Error('noncanonical rootfs path');
  let rootMountId=null;
  for(const {point,id} of parseMountpoints(raw)){
    if(point===root){
      if(rootMountId!==null)throw Error('stacked rootfs mounts');
      rootMountId=id;
    }else if(point.startsWith(root+'/')){
      throw Error('mount over or beneath reviewed rootfs path');
    }
  }
  return rootMountId;
}
function readKernelMountinfo(){
  if(process.platform!=='linux'||!fs.constants.O_NOFOLLOW)
    throw Error('Linux proc mountinfo required');
  const fd=fs.openSync('/proc/self/mountinfo',FLAGS);
  try{
    let n=0;
    const chunks=[];
    const buf=Buffer.alloc(16384);
    while(true){
      const got=fs.readSync(fd,buf,0,buf.length,null);
      if(!got)break;
      n+=got;
      if(n>MAX_MOUNTINFO_BYTES)throw Error('kernel mountinfo too large');
      chunks.push(Buffer.from(buf.subarray(0,got)));
    }
    const bytes=Buffer.concat(chunks);
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  }finally{fs.closeSync(fd)}
}
module.exports={MAX_MOUNTINFO_BYTES,MAX_MOUNT_ENTRIES,decodeKernelMountpoint,
  parseMountpoints,checkRootfsMountBoundary,readKernelMountinfo};