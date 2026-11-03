// SPDX-License-Identifier: MIT
// Synthetic receipt and content tests need the matching Wine WinRT engine.
// Public services, accounts, game saves and production trust are never used.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
if(process.argv.length!==4)throw Error('Usage: test-store.mjs BUILD_DIRECTORY PINNED_WINE_EXECUTABLE');
const build=fs.realpathSync(process.argv[2]),engine=fs.realpathSync(process.argv[3]);
const base=path.dirname(path.dirname(engine)),bin=path.join(build,'bin');
const names=['xgameruntime.dll','nexus_store-entitlements.exe','nexus_package-content.exe','nexus_store-context.exe','nexus_store-context-raw.exe'];
const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const snapshot=()=>Object.fromEntries(names.map(x=>[x,hash(path.join(bin,x))]));
const before=snapshot(),root=fs.mkdtempSync(path.join(build,'nexus-store-test-'));fs.chmodSync(root,0o700);
const prefix=path.join(root,'pfx'),env={...process.env,WINEPREFIX:prefix,WINEARCH:'win64',WINEDEBUG:'-all',
  WINEDLLOVERRIDES:'mscoree,mshtml,winemenubuilder.exe=d;xgameruntime=n',LD_LIBRARY_PATH:base+'/lib64:'+base+'/lib'};
for(const key of Object.keys(env))if(/^(XODUS_|XUSER_|NEXUS_|XGAMERUNTIME_|STEAM_COMPAT_|SteamAppId$|SteamGameId$|WINEDLLPATH$|GTEST_)/.test(key))delete env[key];
const proof={scope:'C++ Store helpers and native package API, closed bridges and synthetic receipts',
  engine,engineHash:hash(engine),binaries:before,realAccounts:false,realCloud:false,fullRuntime:false,results:[]};
let passed=false;
function run(name,command,args,timeout=120000){
 const result=spawnSync(command,args,{env,encoding:'utf8',timeout,maxBuffer:2*1024*1024});
 const output=(result.stdout||'')+(result.stderr||'');fs.writeFileSync(path.join(root,name+'.log'),output,{flag:'wx',mode:0o600});
 if(result.error||result.signal||result.status!==0){proof.failure={name,status:result.status,signal:result.signal,error:result.error?.message};throw Error(name+' failed; see '+root);}
 return output;
}
try{
 run('wineboot',engine,['wineboot.exe','--init']);
 const bytes=fs.readFileSync(path.join(bin,'xgameruntime.dll'));
 const machine=bytes.readUInt16LE(bytes.readUInt32LE(0x3c)+4);
 if(machine!==0x8664&&machine!==0x14c)throw Error('Unsupported candidate PE architecture');
 const system=path.join(prefix,'drive_c/windows',machine===0x8664?'system32':'syswow64');
 if(!fs.realpathSync(system).startsWith(prefix+path.sep))throw Error('Prefix system directory escapes test root');
 const staged=path.join(system,'xgameruntime.dll'),temporary=staged+'.nexus-'+process.pid;
 fs.copyFileSync(path.join(bin,'xgameruntime.dll'),temporary,fs.constants.COPYFILE_EXCL);fs.renameSync(temporary,staged);
 if(fs.lstatSync(staged).isSymbolicLink()||hash(staged)!==before['xgameruntime.dll'])throw Error('Exact DLL staging failed');
 const view=machine===0x8664?'64':'32';
 const key='HKLM\\Software\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Services.Store.StoreContext';
 run('register-context',engine,['reg.exe','add',key,'/v','DllPath','/t','REG_SZ','/d','C:\\windows\\system32\\xgameruntime.dll','/f','/reg:'+view]);
 run('register-threading',engine,['reg.exe','add',key,'/v','ThreadingModel','/t','REG_DWORD','/d','0','/f','/reg:'+view]);
 for(const [name,minimum]of [['store-entitlements',1143],['package-content',423],['store-context',61],['store-context-raw',11]]){
  const output=run(name,engine,[path.join(bin,'nexus_'+name+'.exe')]);
  const summary=output.match(/(?:^|\n)CHECKS (\d+) FAILURES (\d+)/);
  if(!summary||Number(summary[1])<minimum||Number(summary[2])||/(?:^|\n)FAIL /.test(output))throw Error(name+' lost required coverage');
  if(name==='store-entitlements'&&!/(?:^|\n)METADATA_MEASURE same_product_skus=2 get_requests=1\r?(?:\n|$)/.test(output))throw Error('Missing bounded product metadata reuse regression');
  proof.results.push({name,checks:Number(summary[1]),failures:0});
 }
 if(JSON.stringify(snapshot())!==JSON.stringify(before)||hash(staged)!==before['xgameruntime.dll'])throw Error('Candidate changed during validation');
 proof.unchanged=true;proof.staged={machine,sha256:hash(staged)};passed=true;
}finally{
 const server=path.join(path.dirname(engine),'wineserver');
 const stop=spawnSync(server,['-k'],{env,timeout:10000,stdio:'ignore'}),drain=spawnSync(server,['-w'],{env,timeout:10000,stdio:'ignore'});
 if(stop.error||drain.error||drain.status!==0){passed=false;proof.cleanupFailed=true;}
 if(passed&&fs.existsSync(prefix)){
  if(fs.realpathSync(prefix)!==prefix||!fs.lstatSync(prefix).isDirectory())throw Error('Unexpected synthetic prefix');
  fs.rmSync(prefix,{recursive:true});proof.syntheticPrefixRemoved=true;
 }
 proof.passed=passed;fs.writeFileSync(path.join(root,'results.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(root);console.log(JSON.stringify(proof));
}
if(!passed)throw Error('Synthetic Store tests failed');
