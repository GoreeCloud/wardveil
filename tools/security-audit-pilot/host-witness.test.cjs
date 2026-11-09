'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {safeHostWitness,parseStartTicks,cgroupRelativePath,matchesProbeCommandLine,main} = require('./host-witness.cjs');
const id = 'a'.repeat(64);
const image = 'wardveil-audit@sha256:'+'b'.repeat(64);
const source = '/srv/wardveil-audit-pilot/source/public-fixture';
const imageId='sha256:'+'c'.repeat(64);
const probeSha256='sha256:'+'1'.repeat(64);
const expected = {id,image,imageId,probeSha256,source};
const entry = '/usr/bin/node';
const cmd = '/opt/wardveil/runtime-probe.cjs';
const witnessArg = '--witness-window=90';
function inspect() {
  return [{
    Id:id,Image:imageId,Path:entry,Args:[cmd,witnessArg],ExecIDs:[],RestartCount:0,
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
      PublishAllPorts:false,PortBindings:{},LogConfig:{Type:'none'},RestartPolicy:{Name:'no'},AutoRemove:false,
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
    exe:entry,exeAfter:entry,probeSha256,probeSha256After:probeSha256,
    cmdline:[entry,cmd,witnessArg,''].join('\0'),
    cmdlineAfter:[entry,cmd,witnessArg,''].join('\0'),
    hostNamespaces,containerNamespaces,
    cgroup:'0::/system.slice/docker-'+id+'.scope',
    cgroupAfter:'0::/system.slice/docker-'+id+'.scope',
    status:['Name:\tnode','Pid:\t34567','NSpid:\t34567\t1','Uid:\t65534\t65534\t65534\t65534',
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
test('missing or malformed approved metadata fails closed without an exception',()=>{
  for(const value of [null,undefined,[],{},'invalid']) {
    const result=safeHostWitness(inspect(),observed(),value);
    assert.equal(result.ok,false);
    assert.ok(result.errors.length>0);
  }
});
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
reject('well-formed wrong local image ID',(d)=>{d[0].Image='sha256:'+'d'.repeat(64);});
reject('host expected image ID missing',(d,w,e)=>{delete e.imageId;});
reject('host expected image ID disagrees',(d,w,e)=>{e.imageId='sha256:'+'e'.repeat(64);});
reject('unapproved but well-formed probe hash',(d,w,e)=>{e.probeSha256='sha256:'+'2'.repeat(64);});
reject('missing reviewed probe hash',(d,w,e)=>{delete e.probeSha256;});
reject('host-viewed probe file differs',(d,w)=>{w.probeSha256='sha256:'+'2'.repeat(64);});
reject('unapproved witness duration',(d)=>{d[0].Args[1]='--witness-window=3600';});
reject('same host user namespace',(d,w)=>{w.containerNamespaces.user=w.hostNamespaces.user;});
reject('same host network namespace',(d,w)=>{w.containerNamespaces.net=w.hostNamespaces.net;});
reject('same host PID namespace',(d,w)=>{w.containerNamespaces.pid=w.hostNamespaces.pid;});
reject('same host cgroup namespace',(d,w)=>{w.containerNamespaces.cgroup=w.hostNamespaces.cgroup;});
reject('incorrect host namespace type',(d,w)=>{w.containerNamespaces.user='net:[200]';});
reject('mismatched process PID',(d,w)=>{w.pid=1;});
reject('PID reuse/start time changed',(d,w)=>{w.startAfter='123457';});
reject('wrong process name',(d,w)=>{w.comm='bash';});
reject('host process binary changed',(d,w)=>{w.exe='/usr/bin/python3';});
reject('host process executable deleted',(d,w)=>{w.exe='/usr/bin/node (deleted)';});
reject('process executable changed during witness',(d,w)=>{w.exeAfter='/usr/bin/python3';});
reject('missing process executable reread',(d,w)=>{delete w.exeAfter;});
reject('command line changed during witness',(d,w)=>{w.cmdlineAfter=[entry,'/tmp/altered.cjs',witnessArg,''].join('\0');});
reject('missing command line reread',(d,w)=>{delete w.cmdlineAfter;});
reject('first-party script changed during witness',(d,w)=>{w.probeSha256After='sha256:'+'2'.repeat(64);});
reject('missing first-party script hash reread',(d,w)=>{delete w.probeSha256After;});
reject('host kernel PID mismatch',(d,w)=>{w.status=w.status.replace('Pid:\t34567','Pid:\t34568');});
reject('host process not PID 1 inside namespace',(d,w)=>{w.status=w.status.replace('NSpid:\t34567\t1','NSpid:\t34567\t2');});
reject('missing NSpid evidence',(d,w)=>{w.status=w.status.replace('NSpid:\t34567\t1','');});
reject('unapproved host-observed process arguments',(d,w)=>{w.cmdline=[entry,'/tmp/other.cjs',witnessArg,''].join('\0');});
reject('unapproved extra host-observed arguments',(d,w)=>{w.cmdline=[entry,cmd,witnessArg,'--unexpected',''].join('\0');});
reject('truncated proc cmdline',(d,w)=>{w.cmdline=[entry,cmd,witnessArg].join('\0');});
reject('no cgroup identifier binding',(d,w)=>{w.cgroup='0::/system.slice/unrelated.scope';});
reject('migrated process cgroup during witness',(d,w)=>{w.cgroupAfter='0::/system.slice/unrelated.scope';});
reject('missing cgroup reread',(d,w)=>{delete w.cgroupAfter;});
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
reject('automatic container cleanup',d=>{d[0].HostConfig.AutoRemove=true;});
reject('halted container',(d)=>{d[0].State.Running=false;d[0].State.Status='exited';});
test('exact proc argv parser refuses missing NUL or executable changes',()=>{
 assert.equal(matchesProbeCommandLine([entry,cmd,witnessArg,''].join('\0')),true);
 for(const bad of ['', [entry,cmd,witnessArg].join('\0'),['node',cmd,witnessArg,''].join('\0'),
  [entry,cmd,'--witness-window=3600',''].join('\0'),[entry,cmd,witnessArg,'hidden',''].join('\0')]){
  assert.equal(matchesProbeCommandLine(bad),false);
 }
});
test('cgroup identity requires single bounded v2 container path',()=>{
  assert.equal(cgroupRelativePath('0::/system.slice/docker-'+id+'.scope',id),'/system.slice/docker-'+id+'.scope');
  for(const bad of ['1:cpu:/docker/'+id,'0::/../docker/'+id,'0::/docker/'+id+'\n0::/foo', '0::/',
     '0::/docker/'+id.slice(0,12), '0::/docker-'+id.slice(0,12)+'.scope',
     '0::/notdocker-'+id+'.scope', '0::/prefix'+id+'suffix',
     '0::/system.slice/docker-'+id.slice(0,12)+'0'.repeat(52)+'.scope']){
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
