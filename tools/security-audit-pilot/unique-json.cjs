'use strict';

// Bounded-input OCI JSON parser companion: reject duplicate JSON object member
// names, including equivalent JSON-unicode escapes. JSON.parse validates the
// grammar; this deterministic pass checks identity of every object key.
// No filesystem, subprocess, network, bundle mutation or dynamic imports.
function parseUniqueJson(source) {
  if(typeof source!=='string' || source.length>128*1024) {
    throw new Error('bounded UTF-8 JSON string required');
  }
  const data=JSON.parse(source);
  let i=0;
  const len=source.length;
  const fail=()=>{throw new Error('ambiguous or excessive JSON structure')};
  const ws=()=>{while(i<len && (source[i]===' '||source[i]==='\t'||
    source[i]==='\r'||source[i]==='\n'))i++};
  function quoted(){
    if(source[i]!=='"')fail();
    const start=i++;
    let done=false;
    while(i<len){
      const c=source[i++];
      if(c==='\\'){
        if(i>=len)fail();
        i++;
      }else if(c==='"'){
        done=true;
        break;
      }
    }
    if(!done)fail();
    return JSON.parse(source.slice(start,i));
  }
  function value(depth){
    if(depth>64)fail();
    ws();
    if(i>=len)fail();
    if(source[i]==='{'){
      i++;ws();
      const seen=new Set();
      if(source[i]==='}'){i++;return}
      while(i<len){
        const name=quoted();
        if(seen.has(name))throw new Error('duplicate JSON object member name');
        seen.add(name);
        ws();if(source[i++]!==':')fail();
        value(depth+1);ws();
        const next=source[i++];
        if(next==='}')return;
        if(next!==',')fail();
        ws();
      }
      fail();
    }
    if(source[i]==='['){
      i++;ws();
      if(source[i]===']'){i++;return}
      while(i<len){
        value(depth+1);ws();
        const next=source[i++];
        if(next===']')return;
        if(next!==',')fail();
      }
      fail();
    }
    if(source[i]==='"'){
      quoted();return;
    }
    const begin=i;
    while(i<len && !/[\s,}\]]/.test(source[i]))i++;
    if(i===begin)fail();
  }
  value(0);ws();
  if(i!==len)fail();
  return data;
}
module.exports={parseUniqueJson};
