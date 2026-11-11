'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const {decodeKernelMountpoint,parseMountpoints,checkRootfsMountBoundary,
  readKernelMountinfo}=require('./mount-boundary.cjs');

const root='/tmp/wardveil-rootfs-test/rootfs';
const mount=(id,point,parent=1)=>id+' '+parent+' 8:1 / '+point+
  ' ro,relatime - ext4 /dev/sda ro\n';
test('rootfs mount parser accepts ordinary distinct mountpoints',()=>{
  const text=mount(1,'/')+mount(2,'/proc')+mount(3,'/tmp')+
    mount(4,root+'-neighbor')+mount(5,root+'-neighbor/opt');
  assert.equal(checkRootfsMountBoundary(root,text),null);
  assert.deepEqual(parseMountpoints(mount(2,'/tmp')),[{id:'2',point:'/tmp'}]);
});
test('root mount may be a single separately visible filesystem',()=>{
  const text=mount(1,'/')+mount(2,root);
  assert.equal(checkRootfsMountBoundary(root,text),'2');
});
test('rootfs mount parser rejects direct nested bind mounts',()=>{
  for(const sub of ['usr','opt','opt/wardveil','opt/wardveil/runtime-probe.cjs',
    'lib/node.so','usr/bin/node','proc','source','.hidden']){
    assert.throws(()=>checkRootfsMountBoundary(root,mount(1,'/')+mount(2,root+'/'+sub)),
      /mount over or beneath reviewed rootfs path/);
  }
});
test('rootfs mount parser rejects stacked mounts on reviewed root itself',()=>{
  assert.throws(()=>checkRootfsMountBoundary(root,
    mount(1,'/')+mount(2,root)+mount(3,root)),/stacked rootfs mounts/);
});
test('rootfs mount parser rejects escaped mountpoint paths',()=>{
  const disguised='/tmp/wardveil-rootfs-test/rootfs\\040alias';
  assert.equal(decodeKernelMountpoint(disguised),root+' alias');
  assert.throws(()=>checkRootfsMountBoundary(root,mount(1,'/')+
    mount(2,root+'/opt\\040wardveil')));
  const control='/tmp/wardveil-rootfs-test/rootfs\\012sub';
  assert.throws(()=>checkRootfsMountBoundary(root,mount(1,'/')+mount(2,control)));
  for(const p of ['\\000','\\999','/tmp\\','relative','/tmp\\134\\000']){
    assert.throws(()=>decodeKernelMountpoint(p));
  }
});
test('rootfs mount parser refuses malformed or excessive kernel data',()=>{
  for(const raw of ['',false,{},'abc','x - y\n',
    '0 1 8:1 / / ro - ext4 /dev/a ro\n',
    mount(1,'/')+'bad\n',' '.repeat(1048577)]) {
    assert.throws(()=>parseMountpoints(raw));
  }
});
test('noncanonical rootfs prefixes cannot bypass mount boundary matching',()=>{
  for(const p of ['/', '', 'relative','/tmp/../rootfs','/tmp//rootfs',
    '/tmp/./rootfs','/tmp/rootfs/','/tmp/abc\0def']) {
    assert.throws(()=>checkRootfsMountBoundary(p,mount(1,'/')));
  }
});
test('read-only real host mountinfo is parseable and has no empty mountpoint',()=>{
  const raw=readKernelMountinfo();
  const entries=parseMountpoints(raw);
  assert.ok(entries.length>0);
  assert.ok(entries.every(x=>x.point.startsWith('/')&&/^\d+$/.test(x.id)));
});
