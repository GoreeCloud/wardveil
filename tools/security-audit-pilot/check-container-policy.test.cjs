'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {evaluateContainerConfig,readInspectFile,main}=require('./check-container-policy.cjs');
const image='wardveil-audit@sha256:'+'a'.repeat(64);
const source='/srv/wardveil-audit-pilot/source/test-target';
const expected={image,source};
function good(){return {
  State:{Status:'created',Running:false},AppArmorProfile:'docker-default',
  Config:{User:'65534:65534',Image:image,WorkingDir:'/scratch',Env:['HOME=/scratch/home','TMPDIR=/tmp','PATH=/usr/local/bin:/usr/bin:/bin','LANG=C.UTF-8']},
  HostConfig:{NetworkMode:'none',Privileged:false,ReadonlyRootfs:true,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges:true'],
    PidMode:'',IpcMode:'private',CgroupnsMode:'private',UsernsMode:'',PidsLimit:24,Memory:256*1024*1024,MemorySwap:256*1024*1024,NanoCpus:500000000,
    OomKillDisable:false,Tmpfs:{'/scratch':'rw,nosuid,nodev,noexec,size=67108864','/tmp':'rw,nosuid,nodev,noexec,size=33554432'},
    Mounts:[{Type:'bind',Source:source,Target:'/source',ReadOnly:true,BindOptions:{Propagation:'rprivate'}}],
    UTSMode:'',Binds:[],Devices:[],DeviceRequests:[],VolumesFrom:[],Links:[],PublishAllPorts:false,PortBindings:{},
    LogConfig:{Type:'none'},RestartPolicy:{Name:'no'}},
  Mounts:[{Type:'bind',Source:source,Destination:'/source',RW:false,Mode:'ro',Propagation:'rprivate'}],
  NetworkSettings:{Ports:{}}
};}
function invalid(name,mutate){test('rejects '+name,()=>{const obj=good();mutate(obj);const verdict=evaluateContainerConfig(obj,expected);assert.equal(verdict.ok,false,name);assert.ok(verdict.errors.length>0);});}
test('a restrictive created-container inspection matches static policy',()=>{const verdict=evaluateContainerConfig(good(),expected);assert.equal(verdict.ok,true,verdict.errors.join('; '));});
test('single-element docker inspect array supported',()=>assert.equal(evaluateContainerConfig([good()],expected).ok,true));
test('no false approval for malformed input',()=>{for(const value of [[],[good(),good()],null,{},'bad'])assert.equal(evaluateContainerConfig(value,expected).ok,false);});
invalid('already running container',obj=>{obj.State.Status='running';obj.State.Running=true;});
invalid('external network',obj=>{obj.HostConfig.NetworkMode='bridge';});
invalid('privileged container',obj=>{obj.HostConfig.Privileged=true;});
invalid('writable root filesystem',obj=>{obj.HostConfig.ReadonlyRootfs=false;});
invalid('persisted container logs',obj=>{obj.HostConfig.LogConfig.Type='json-file';});
invalid('automatic restart',obj=>{obj.HostConfig.RestartPolicy.Name='always';});
invalid('automatic image healthcheck',obj=>{obj.Config.Healthcheck={Test:['CMD','sh','-c','true']};});
invalid('hidden image volumes',obj=>{obj.Config.Volumes={'/private':{}};});
invalid('sysctl override',obj=>{obj.HostConfig.Sysctls={'net.ipv4.ip_forward':'1'};});
invalid('device cgroup override',obj=>{obj.HostConfig.DeviceCgroupRules=['c 1:3 rwm'];});
invalid('capability additions',obj=>{obj.HostConfig.CapAdd=['SYS_ADMIN'];});
invalid('missing cap drop',obj=>{obj.HostConfig.CapDrop=[];});
invalid('unconfined profile',obj=>{obj.AppArmorProfile='unconfined';});
invalid('disabled no-new-privileges',obj=>{obj.HostConfig.SecurityOpt=[];});
invalid('host PID namespace',obj=>{obj.HostConfig.PidMode='host';});
invalid('host UTS namespace',obj=>{obj.HostConfig.UTSMode='host';});
invalid('hidden declared mount',obj=>{obj.HostConfig.Mounts.push({Type:'bind',Source:'/home',Target:'/private',ReadOnly:false});});
invalid('mismatched declared source bind',obj=>{obj.HostConfig.Mounts[0].Source='/home/owner';});
invalid('unsafe source mount propagation',obj=>{obj.HostConfig.Mounts[0].BindOptions.Propagation='rshared';});
invalid('host IPC namespace',obj=>{obj.HostConfig.IpcMode='host';});
invalid('host user namespace',obj=>{obj.HostConfig.UsernsMode='host';});
invalid('root user',obj=>{obj.Config.User='0:0';});
invalid('unlimited PIDs',obj=>{obj.HostConfig.PidsLimit=0;});
invalid('unlimited memory',obj=>{obj.HostConfig.Memory=0;});
invalid('excess swap',obj=>{obj.HostConfig.MemorySwap=500*1024*1024;});
invalid('unlimited CPU',obj=>{obj.HostConfig.NanoCpus=0;});
invalid('disabled OOM killer',obj=>{obj.HostConfig.OomKillDisable=true;});
invalid('mismatched image digest',obj=>{obj.Config.Image='untrusted@sha256:'+'b'.repeat(64);});
invalid('host HOME variable',obj=>{obj.Config.Env[0]='HOME=/home/operator';});
invalid('extra credential variable',obj=>{obj.Config.Env.push('SECRET_TOKEN=not-a-secret');});
invalid('missing noexec scratch',obj=>{obj.HostConfig.Tmpfs['/scratch']='rw,nosuid,nodev,size=67108864';});
invalid('scratch mounted from host',obj=>{obj.Mounts.push({Type:'bind',Source:'/home/user',Destination:'/scratch',RW:true,Mode:'rw'});});
invalid('source write permission',obj=>{obj.Mounts[0].RW=true;});
invalid('source mounted from wrong location',obj=>{obj.Mounts[0].Source='/root';});
invalid('host device exposure',obj=>{obj.HostConfig.Devices=[{PathOnHost:'/dev/kvm'}];});
invalid('GPU device request',obj=>{obj.HostConfig.DeviceRequests=[{}];});
invalid('published port',obj=>{obj.HostConfig.PortBindings={'80/tcp':[{}]};});
invalid('attached network',obj=>{obj.NetworkSettings.Networks={bridge:{}};});
invalid('additional DNS resolver',obj=>{obj.HostConfig.Dns=['8.8.8.8'];});
invalid('supplemental groups',obj=>{obj.HostConfig.GroupAdd=['0'];});
invalid('additional legacy bind',obj=>{obj.HostConfig.Binds=['/:/host:ro'];});
test('expected image must be pinned; expected source must be safe',()=>{
 for(const changed of [{image:'wardveil-audit:latest',source},{image,source:'/home/operator/repo'},
  {image,source:'/srv/wardveil-audit-pilot/source/../secrets'}]){
  assert.throws(()=>evaluateContainerConfig(good(),changed));
 }
});
test('CLI requires explicit source and immutable image',()=>{assert.equal(main([]),2);});
test('safe bounded file read and malformed JSON rejection',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-policy-'));
 const file=path.join(dir,'inspect.json');
 try{fs.writeFileSync(file,JSON.stringify([good()]));assert.equal(evaluateContainerConfig(readInspectFile(file),expected).ok,true);
   assert.equal(main([file,'--image',image,'--source',source]),0);
   fs.writeFileSync(file,'this is not json');assert.equal(main([file,'--image',image,'--source',source]),1);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('read rejects symlink and FIFO without blocking',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-policy-'));
 try{
  const actual=path.join(dir,'real.json');fs.writeFileSync(actual,'{}');
  const symlink=path.join(dir,'link.json');fs.symlinkSync(actual,symlink);
  assert.throws(()=>readInspectFile(symlink));
  const fifo=path.join(dir,'fifo.json');
  const result=spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:2000});assert.equal(result.status,0,result.stderr);
  assert.throws(()=>readInspectFile(fifo));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('read rejects oversized input without echoing its content',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'wardveil-policy-'));
 try{const file=path.join(dir,'huge.json');fs.writeFileSync(file,'x'.repeat(128*1024+1));assert.throws(()=>readInspectFile(file));}
 finally{fs.rmSync(dir,{recursive:true,force:true});}
});
