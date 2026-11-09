'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {safeHostWitness,parseStartTicks,cgroupRelativePath,main} = require('./host-witness.cjs');
const id = 'a'.repeat(64);
const image = 'wardveil-audit@sha256:'+'b'.repeat(64);
const source = '/srv/wardveil-audit-pilot/source/public-fixture';
const expected = {id,image,source};
const entry = '/usr/bin/node';
const cmd = '/opt/wardveil/runtime-probe.cjs';
const witnessArg = '--witness-window=90';
function inspect() {
  return [{
    Id:id,Image:'sha256:'+'c'.repeat(64),Path:entry,Args:[cmd,witnessArg],ExecIDs:[],RestartCount:0,
    State:{Status:'running',Running:true,Pid:34567,Restarting:false,Paused:false,Dead:false},
    AppArmorProfile:'docker-default',
    Config:{Image:image,User:'65534:65534',WorkingDir:'/scratch',Entrypoint:[entry],Cmd:[cmd,witnessArg],
      Tty:false,OpenStdin:false,StdinOnce:false,AttachStdin:false,
      Env:['HOME=/scratch/home','TMPDIR=/tmp','PATH=/usr/local/bin:/usr/bin:/bin','LANG=C.UTF-8']},
    HostConfig:{
      NetworkMode:'none',Privileged:false,ReadonlyRootfs:true,CapDrop:['ALL'],CapAdd:[],
      SecurityOpt:['no-new-privileges:true'],PidMode:'',IpcMode:'private',UTSMode:'',CgroupnsMode:'private',UsernsMode:'',
      PidsLimit:24,Memory:256*1024*1024,MemorySwap:256*1024*1024,NanoCpus:500000000,
      OomKillDisable:false,Init:false,Runtime:'runc',Isolation:'default',CgroupParent:'',Ulimits:[],
      Tmpfs:{'/scratch':'rw,nosuid,nodev,noexec,size=67108864',
        '/tmp':'rw,nosuid,nodev,noexec,size=33554432'},
      Mounts:[{Type:'bind',Source:source,Target:'/source',ReadOnly:true,
        BindOptions:{Propagation:'rprivate'}}],
      Binds:[],Devices:[],DeviceRequests:[],VolumesFrom:[],Links:[],GroupAdd:[],
      PublishAllPorts:false,PortBindings:{},LogConfig:{Type:'none'},RestartPolicy:{Name:'no'},
    },
    Mounts:[{Type:'bind',Source:source,Destination:'/source',RW:false,Mode:'ro',Propagation:'rprivate'}],
    NetworkSettings:{Ports:{},Networks:{none:{}}},
  }];
}
const ns=['user','pid','mnt','net','ipc','uts','cgroup'];
const mount=(i,p,o,type,dev,superOpt='rw')=>
  [i,1,'0:'+i,'/',p,o,'-',type,dev,superOpt].join(' ');
function observed() {
  const hostNamespaces={},containerNamespaces={};
  ns.forEach((type,i)=>{hostNamespaces[type]=type+':['+(100+i)+']';
    containerNamespaces[type]=type+':['+(200+i)+']';});
  return {
    pid:34567,startBefore:'123456',startAfter:'123456',comm:'node',
    hostNamespaces,containerNamespaces,
    cgroup:'0::/system.slice/docker-'+id+'.scope',
    status:['Name:\tnode','Uid:\t65534\t65534\t65534\t65534',
      'Gid:\t65534\t65534\t65534\t65534','NoNewPrivs:\t1',
      'Seccomp:\t2','Seccomp_filters:\t1',
      ...['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].map(x=>x+':\t0000000000000000')].join('\n')+'\n',
    uidMap:'0 100000 65536\n',gidMap:'0 200000 65536\n',
    mountinfo:[
      mount(1,'/','ro,relatime','overlay','overlay'),
      mount(2,'/source','ro,relatime','ext4','/dev/sda','ro'),
      mount(3,'/scratch','rw,nosuid,nodev,noexec,relatime','tmpfs','tmpfs','rw,size=67108864'),
      mount(4,'/tmp','rw,nosuid,nodev,noexec,relatime','tmpfs','tmpfs','rw,size=33554432'),
      mount(5,'/proc','rw,nosuid,nodev,noexec','proc','proc')
    ].join('\n'),
    network:'Inter-| Receive | Transmit\n face |bytes packets errs drop|bytes packets errs drop\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n',
    apparmor:'docker-default (enforce)\n',memory:String(256*1024*1024),
    pids:'24',swap:'0',cpu:'50000 100000',
  };
}
test('matching host and Docker metadata returns evidence match, not audit authorization',()=>{
  const result=safeHostWitness(inspect(), observed(), expected);
  assert.equal(result.ok,true,result.errors.join('; '));
});
function reject(name, edit){
  test('rejects '+name,()=>{
    const data=inspect(), witness=observed(), wanted={...expected};
    edit(data,witness,wanted);
    const result=safeHostWitness(data,witness,wanted);
    assert.equal(result.ok,false,name);
    assert.ok(result.errors.length>0);
  });
}
reject('wrong container ID',(d,w,e)=>{e.id='f'.repeat(64);});
reject('running wrong process',(d)=>{d[0].Path='/bin/sh';});
reject('different startup command',(d)=>{d[0].Config.Cmd=['/tmp/untrusted.cjs'];});
reject('unapproved witness duration',(d)=>{d[0].Args[1]='--witness-window=3600';});
reject('same host user namespace',(d,w)=>{w.containerNamespaces.user=w.hostNamespaces.user;});
reject('same host network namespace',(d,w)=>{w.containerNamespaces.net=w.hostNamespaces.net;});
reject('same host PID namespace',(d,w)=>{w.containerNamespaces.pid=w.hostNamespaces.pid;});
reject('same host cgroup namespace',(d,w)=>{w.containerNamespaces.cgroup=w.hostNamespaces.cgroup;});
reject('incorrect host namespace type',(d,w)=>{w.containerNamespaces.user='net:[200]';});
reject('mismatched process PID',(d,w)=>{w.pid=1;});
reject('PID reuse/start time changed',(d,w)=>{w.startAfter='123457';});
reject('wrong process name',(d,w)=>{w.comm='bash';});
reject('no cgroup identifier binding',(d,w)=>{w.cgroup='0::/system.slice/unrelated.scope';});
reject('cgroup v1 record',(d,w)=>{w.cgroup='12:pids:/docker/'+id;});
reject('host-root mapping',(d,w)=>{w.uidMap='0 0 65536';});
reject('zero effective UID',(d,w)=>{w.status=w.status.replaceAll('65534','0');});
reject('disabled seccomp',(d,w)=>{w.status=w.status.replace('Seccomp:\t2','Seccomp:\t0');});
reject('nonzero capabilities',(d,w)=>{w.status=w.status.replace('CapBnd:\t0000000000000000','CapBnd:\t0000000000000001');});
reject('unapproved host bind',(d,w)=>{w.mountinfo+='\n'+mount(6,'/host','ro','ext4','/dev/sdb','ro');});
reject('network interface exposure',(d,w)=>{w.network+=' eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n';});
reject('disabled AppArmor',(d,w)=>{w.apparmor='unconfined';});
reject('unlimited CPU',(d,w)=>{w.cpu='max 100000';});
reject('unlimited memory',(d,w)=>{w.memory='max';});
reject('unlimited PIDs',(d,w)=>{w.pids='max';});
reject('swap enabled',(d,w)=>{w.swap='10000';});
reject('unapproved additional exec process',(d)=>{d[0].ExecIDs=['unknown'];});
reject('already restarted container',(d)=>{d[0].RestartCount=1;});
reject('halted container',(d)=>{d[0].State.Running=false;d[0].State.Status='exited';});
test('cgroup identity requires single bounded v2 container path',()=>{
  assert.equal(cgroupRelativePath('0::/system.slice/docker-'+id+'.scope',id),'/system.slice/docker-'+id+'.scope');
  for(const bad of ['1:cpu:/docker/'+id,'0::/../docker/'+id,'0::/docker/'+id+'\n0::/foo', '0::/']){
    assert.equal(cgroupRelativePath(bad,id),null,bad);
  }
});
test('proc stat parser extracts process start ticks without executing target',()=>{
  const after=['S',...Array.from({length:19},(_,i)=>String(i===18?12345:1))].join(' ');
  assert.equal(parseStartTicks('34567 (node) '+after),'12345');
  assert.equal(parseStartTicks('garbage'),null);
});
test('CLI does not accept commands or run Docker without explicit target',()=>{
  assert.equal(main([]),2);
  assert.equal(main(['/tmp/x','--id','bad']),2);
});
