// SPDX-License-Identifier: MIT
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const cmake=new URL('../cmake/',import.meta.url);
test('explicit XML source retains all 99 checks, default behavior and environment isolation',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'nexus-xml-source-'));
 try{
  const lock=JSON.parse(fs.readFileSync(new URL('xml2.lock.json',cmake)));assert.equal(Object.keys(lock.files).length,99);
  const fixture={...lock,files:{}};const wine=path.join(root,'wine'),standard=path.join(wine,'libs/xml2'),override=path.join(root,'explicit');
  for(const [index,name] of Object.keys(lock.files).entries()){
   const bytes=Buffer.from('synthetic locked XML fixture '+index+' '+name);
   fixture.files[name]=createHash('sha256').update(bytes).digest('hex');
   for(const base of [standard,override]){const file=path.join(base,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,bytes);}
  }
  fs.copyFileSync(new URL('Xml2Source.cmake',cmake),path.join(root,'Xml2Source.cmake'));
  fs.writeFileSync(path.join(root,'xml2.lock.json'),JSON.stringify(fixture));
  const script=path.join(root,'verify.cmake');fs.writeFileSync(script,'include("'+root+'/Xml2Source.cmake")\n');
  const run=(args=[],env={})=>spawnSync('cmake',['-DNEXUS_WINE_SOURCE='+wine,...args,'-P',script],{encoding:'utf8',env:{...process.env,...env}});
  assert.equal(run().status,0);assert.equal(run(['-DNEXUS_XML2_SOURCE='+override]).status,0);
  assert.equal(run([],{NEXUS_XML2_SOURCE:'/not-a-selected-source'}).status,0);
  assert.notEqual(run(['-DNEXUS_XML2_SOURCE=relative']).status,0);
  for(const name of ['parser.c',Object.keys(fixture.files).at(-1)]){
   const file=path.join(override,name),old=fs.readFileSync(file);fs.appendFileSync(file,'changed parser');
   const result=run(['-DNEXUS_XML2_SOURCE='+override]);assert.notEqual(result.status,0);assert.match(result.stderr,/Pinned XML source mismatch/);
   fs.writeFileSync(file,old);
  }
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
