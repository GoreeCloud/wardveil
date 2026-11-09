'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {EXPLICIT_ENV,parseMap,checkMounts,checkNetwork,evaluate,readBounded,readBoundedBytes,main} = require('./runtime-probe.cjs');
const mount = (n,mp,opts,kind,src,superopts='rw') =>
  [n,1,'0:'+n,'/',mp,opts,'-',kind,src,superopts].join(' ');
function good() {
  return {
    status: ['Name:\tnode','Uid:\t65534\t65534\t65534\t65534',
      'Gid:\t65534\t65534\t65534\t65534','Groups:\t','TracerPid:\t0','NoNewPrivs:\t1','Seccomp:\t2',
      'Seccomp_filters:\t1','CapInh:\t0000000000000000','CapPrm:\t0000000000000000',
      'CapEff:\t0000000000000000','CapBnd:\t0000000000000000',
      'CapAmb:\t0000000000000000'].join('\n')+'\n',
    uidMap:'0 100000 65536\n',gidMap:'0 200000 65536\n',
    mountinfo: [
      mount(1,'/','ro,relatime','overlay','overlay'),
      mount(2,'/source','ro,relatime','ext4','/dev/sda','ro'),
      mount(3,'/scratch','rw,nosuid,nodev,noexec,relatime','tmpfs','tmpfs','rw,size=67108864'),
      mount(4,'/tmp','rw,nosuid,nodev,noexec,relatime','tmpfs','tmpfs','rw,size=33554432'),
      mount(5,'/proc','rw,nosuid,nodev,noexec','proc','proc'),
    ].join('\n'),
    network:'Inter-|   Receive                                                |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n',
    memory:String(256*1024*1024),swap:'0\n',cpu:'50000 100000\n',pids:'24\n',apparmor:'docker-default (enforce)\n',
  };
}
function bad(label,modify) {test('rejects '+label,()=>{
  const rec=good(); const env={...EXPLICIT_ENV}; modify(rec,env);
  const out=evaluate(rec,env);
  assert.equal(out.ok,false,label); assert.ok(out.failures.length>0);
});}
test('valid synthetic kernel readings only establish measured control matches',()=>{
  const r=evaluate(good(), {...EXPLICIT_ENV}); assert.deepEqual(r,{ok:true,failures:[]});
});
test('does not accept incomplete records',()=>{
  for(const x of [null,{},[],{status:'a'}]) assert.equal(evaluate(x,EXPLICIT_ENV).ok,false);
});
test('parseMap requires numeric, bounded mapping records',()=>{
  assert.equal(parseMap('0 100000 65536\n').length,1);
  for(const x of ['','x 1 2','0 -1 3','0 1 0','0 2 3 4']) assert.equal(parseMap(x),null);
});
bad('root effective UID',r=>{r.status=r.status.replaceAll('65534','0');});
bad('identity UID mismatch',r=>{r.status=r.status.replace('65534\t65534\t65534\t65534','65534\t0\t65534\t65534');});
bad('host-root UID mapping',r=>{r.uidMap='0 0 4294967295';});
bad('UID not mapped',r=>{r.uidMap='0 100000 65533';});
bad('host-root GID mapping',r=>{r.gidMap='0 0 4294967295';});
bad('missing user namespace mapping',r=>{r.uidMap='';});
bad('attached ptrace tracer',r=>{r.status=r.status.replace('TracerPid:\t0','TracerPid:\t99');});
bad('missing tracer evidence',r=>{r.status=r.status.replace('TracerPid:\t0','');});
bad('unexpected supplementary group',r=>{r.status=r.status.replace('Groups:\t','Groups:\t0 20');});
bad('missing supplementary-group evidence',r=>{r.status=r.status.replace('Groups:\t','');});
bad('no-new-privileges disabled',r=>{r.status=r.status.replace('NoNewPrivs:\t1','NoNewPrivs:\t0');});
bad('seccomp not active',r=>{r.status=r.status.replace('Seccomp:\t2','Seccomp:\t0');});
bad('zero seccomp filter count',r=>{r.status=r.status.replace('Seccomp_filters:\t1','Seccomp_filters:\t0');});
bad('missing seccomp filter count',r=>{r.status=r.status.replace('Seccomp_filters:\t1','');});
for(const cap of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']) bad(cap+' effective bit',r=>{
  r.status=r.status.replace(cap+':\t0000000000000000',cap+':\t0000000000000001');
});
bad('writable root filesystem',r=>{r.mountinfo=r.mountinfo.replace('/ ro,relatime','/ rw,relatime');});
bad('writable source',r=>{r.mountinfo=r.mountinfo.replace('/source ro,relatime','/source rw,relatime');});
bad('shared source mount propagation',r=>{r.mountinfo=r.mountinfo.replace('/source ro,relatime - ','/source ro,relatime shared:14 - ');});
bad('slave scratch mount propagation',r=>{r.mountinfo=r.mountinfo.replace('/scratch rw,nosuid,nodev,noexec,relatime - ','/scratch rw,nosuid,nodev,noexec,relatime master:12 - ');});
bad('shared system proc propagation',r=>{r.mountinfo=r.mountinfo.replace('/proc rw,nosuid,nodev,noexec - ','/proc rw,nosuid,nodev,noexec shared:7 - ');});
bad('missing scratch noexec',r=>{r.mountinfo=r.mountinfo.replace('/scratch rw,nosuid,nodev,noexec,relatime','/scratch rw,nosuid,nodev,relatime');});
bad('source submount',r=>{r.mountinfo+='\n'+mount(6,'/source/host-private','rw,relatime','ext4','/dev/sdc');});
bad('unapproved host bind at unrelated mountpoint',r=>{r.mountinfo+='\n'+mount(6,'/host','ro,relatime','ext4','/dev/sda','ro');});
bad('unapproved mount under dev',r=>{r.mountinfo+='\n'+mount(6,'/dev/secret','ro,relatime','ext4','/dev/sda','ro');});
bad('unapproved mount under proc',r=>{r.mountinfo+='\n'+mount(6,'/proc/mount-leak','ro,relatime','tmpfs','tmpfs','ro');});
bad('unapproved mount under etc',r=>{r.mountinfo+='\n'+mount(6,'/etc/shadow','ro,relatime','ext4','/dev/sda','ro');});
bad('writable Docker hosts bind',r=>{r.mountinfo+='\n'+mount(6,'/etc/hosts','rw,relatime','ext4','/dev/sda','rw');});
bad('unsafe proc mount flags',r=>{r.mountinfo=r.mountinfo.replace('/proc rw,nosuid,nodev,noexec','/proc rw,nosuid,nodev');});
bad('sysfs writable mount',r=>{r.mountinfo+='\n'+mount(6,'/sys','rw,relatime','sysfs','sysfs','rw');});
bad('escaped mount path rejected',r=>{r.mountinfo+='\n'+mount(6,'/escape\\\\040directory','ro,relatime','ext4','/dev/sdb','ro');});

bad('scratch submount',r=>{r.mountinfo+='\n'+mount(6,'/scratch/secrets','rw,relatime','ext4','/dev/sdc');});
bad('duplicate source mount',r=>{r.mountinfo+='\n'+mount(7,'/source','ro,relatime','ext4','/dev/sdc');});
bad('missing source mount',r=>{r.mountinfo=r.mountinfo.split('\n').filter(x=>!x.includes('/source ')).join('\n');});
bad('unexpected ethernet interface',r=>{r.network+=' eth0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n';});
bad('unlimited memory',r=>{r.memory='max';});
bad('excess memory',r=>{r.memory=String(1024*1024*1024);});
bad('swap enabled',r=>{r.swap='1024';});
bad('unlimited pids',r=>{r.pids='max';});
bad('no CPU quota',r=>{r.cpu='max 100000';});
bad('excess CPU quota',r=>{r.cpu='200000 100000';});
bad('AppArmor disabled',r=>{r.apparmor='unconfined';});
bad('AppArmor complain mode',r=>{r.apparmor='docker-default (complain)';});
bad('extra environment secret',(r,e)=>{e.ACCESS_TOKEN='synthetic';});
bad('host home',(r,e)=>{e.HOME='/home/user';});
test('CLI rejects unsupported or unbounded witness windows',()=>{
  assert.equal(main(['--witness-window=3600']),2);
});
test('CLI rejects any command-line arguments',()=>{
  assert.equal(main(['--config','unsafe']),2);
});
test('bounded read rejects symlink and huge file',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-runtime-'));
  try {
    const real=path.join(dir,'real.txt');fs.writeFileSync(real,'sample');
    assert.equal(readBounded(real),'sample');
    const link=path.join(dir,'link');fs.symlinkSync(real,link);
    assert.throws(()=>readBounded(link));
    fs.writeFileSync(real,'x'.repeat(128*1024+1));
    assert.throws(()=>readBounded(real));
    const fifo=path.join(dir,'fifo');
    const cmd=spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:2000});
    assert.equal(cmd.status,0,cmd.stderr);
    assert.throws(()=>readBounded(fifo));
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('byte-preserving reader includes a UTF-8 BOM exactly',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-probe-raw-'));
  try {
    const name=path.join(dir,'probe.cjs');
    const raw=Buffer.from([0xef,0xbb,0xbf,0x61,0x62,0x63]);
    fs.writeFileSync(name,raw);
    assert.deepEqual(readBoundedBytes(name),raw);
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('raw byte reader preserves non-UTF8 content while text reader rejects it',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-probe-binary-'));
  try {
    const name=path.join(dir,'probe.cjs');
    const raw=Buffer.from([0xff,0x80,0x00,0x61]);
    fs.writeFileSync(name,raw);
    assert.deepEqual(readBoundedBytes(name),raw);
    assert.throws(()=>readBounded(name));
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('bounded raw reader detects ordinary file growth during read',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-probe-grow-'));
  const file=path.join(dir,'probe.cjs');
  const original=fs.readSync;
  try {
    fs.writeFileSync(file,'known source bytes');
    let modified=false;
    fs.readSync=function(fd, ...args) {
      const n=original.call(fs,fd,...args);
      if (!modified) {
        modified=true;
        fs.appendFileSync(file,' injected');
      }
      return n;
    };
    assert.throws(()=>readBoundedBytes(file),/changed during bounded read/);
    assert.equal(modified,true);
  } finally {
    fs.readSync=original;
    fs.rmSync(dir,{recursive:true,force:true});
  }
});
test('bounded raw reader rejects same-size file replacement during read',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-probe-change-'));
  const file=path.join(dir,'probe.cjs');
  const original=fs.readSync;
  try {
    fs.writeFileSync(file,'known source bytes');
    let modified=false;
    fs.readSync=function(fd, ...args) {
      const n=original.call(fs,fd,...args);
      if (!modified) {
        modified=true;
        fs.writeFileSync(file,'other source bytes');
        fs.utimesSync(file,new Date('2000-01-01T00:00:00Z'),new Date('2000-01-01T00:00:00Z'));
      }
      return n;
    };
    assert.throws(()=>readBoundedBytes(file),/changed during bounded read/);
    assert.equal(modified,true);
  } finally {
    fs.readSync=original;
    fs.rmSync(dir,{recursive:true,force:true});
  }
});
test('mount reader rejects unparseable records',()=>{
  assert.equal(checkMounts('garbage'),false);
  assert.equal(checkNetwork(''),false);
});
