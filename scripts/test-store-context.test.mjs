// SPDX-License-Identifier: MIT
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
const root=new URL('../',import.meta.url);
const read=name=>fs.readFileSync(new URL(name,root),'utf8');
test('StoreContext and its standalone receipt fixture declare their own clock dependency',()=>{
 for(const file of ['src/System/Store/StoreContext.h','tests/Nexus/store-context.cpp']){
  const source=read(file);
  assert.match(source,/#include <ctime>/);
  assert.match(source,/std::time\(/);
  assert.doesNotMatch(source,/(?<!std::)\btime\(/);
 }
});
test('StoreContext uses the existing receipt transport without a stale global license cache',()=>{
 const objects=read('src/System/Store/StoreContext.h');
 const transport=read('src/System/Store/StoreContextLicense.h');
 assert.doesNotMatch(objects,/license_cached|LICENSE_REUSE_MS/);
 assert.match(objects,/query_game_license\( &license, operation->canceled, operation->cancel_event \)/);
 assert.match(transport,/entitled_begin\([\s\S]*TRUE, TRUE, drained \)/);
 assert.match(transport,/XAsyncGetResult\( &block, &entitled_game_identity/);
 assert.doesNotMatch(transport,/https?:\/\//);
 assert.match(objects,/if \( user \) return E_NOTIMPL/);
});
test('current-game query omits related product hints and keeps verified enumeration',()=>{
 const query=read('src/System/XStore.cpp').split('XStoreQueryProductForCurrentGameAsync')[1].split('XStoreQueryProductForCurrentGameResult')[0];
 assert.match(query,/entitled_begin\([^;]*FALSE, TRUE \)/);
 assert.match(read('src/System/Store/Entitled.h'),/!current_only && i < entitled_related_count/);
});
test('both ABI export lists and account-free native gates include StoreContext',()=>{
 for(const name of ['src/xgameruntime.def','src/xgameruntime-x86.def']){
  assert.match(read(name),/DllGetActivationFactory/);assert.match(read(name),/DllCanUnloadNow/);
 }
 const probe=read('tests/Nexus/store-context-raw.cpp');
 assert.match(probe,/RoGetActivationFactory/);
 assert.match(probe,/AppLicense\(nullptr\)/);
 assert.doesNotMatch(probe,/AppLicense\(&/);
 assert.match(read('scripts/test-component.mjs'),/\['nexus_store-context', 61\]/);
 assert.match(read('scripts/test-store.mjs'),/\['store-context-raw',11\]/);
});

test('WinRT child cancellation and detached-provider lifetime remain mandatory Store coverage',()=>{
 const fixture=read('tests/Nexus/store-context-cancellation.cpp');
 assert.match(read('tests/CMakeLists.txt'),/foreach\(probe store-entitlements package-content store-context-cancellation receipt-ipc\)/);
 assert.match(read('scripts/test-store.mjs'),/'nexus_store-context-cancellation.exe'/);
 assert.match(read('scripts/test-store.mjs'),/\['store-context-cancellation',67\]/);
 for(const label of ['held-forwarded-to-real-child','held-child-abort','held-certificate-get-skipped',
  'held-operation-retained-after-client-release','held-callback-fence-retains-operation',
  'held-no-resurrection','ordinary-error-preserved','ordinary-cleanup-drained',
  'begin-failure-no-drain-deadlock','registration-failure-truthful','pre-cancel-no-child'])
  assert.ok(fixture.includes('"'+label+'"'));
 assert.match(fixture,/#include "..\/..\/src\/System\/Store\/StoreContextLicense.h"/);
 assert.match(fixture,/if \(!synthetic_mode\) return entitled_begin/);
 assert.match(fixture,/SetLastError\(ERROR_CANCELLED\); return FALSE/);
});

test('receipt IPC cancellation and remaining-budget coverage is mandatory without changing direct callers',()=>{
 const fixture=read('tests/Nexus/receipt-ipc.cpp');
 const bridge=read('src/System/Store/Bridge.h');
 assert.match(bridge,/xodus_store_license_xml\( const char \*, SIZE_T, char \*\* \)/);
 assert.match(bridge,/xodus_store_license_xml\( const char \*, SIZE_T, char \*\*, LONG \*, ULONGLONG \)/);
 assert.match(read('scripts/test-store.mjs'),/'nexus_receipt-ipc.exe'/);
 assert.match(read('scripts/test-store.mjs'),/\['receipt-ipc',122\]/);
 assert.match(read('tests/CMakeLists.txt'),/target_sources\(nexus_receipt-ipc PRIVATE "\$\{PROJECT_SOURCE_DIR\}\/src\/System\/XUser.cpp"\)/);
 assert.match(read('tests/CMakeLists.txt'),/target_compile_options\(nexus_receipt-ipc PRIVATE[\s\S]*receipt-ipc-clock.h/);
 for(const label of ['cancel-exits-before-peer-release','cancel-abort-no-partial-output',
  'budget-socket-timeout-preserved','budget-near-expiry-bounded','admission-error-precedence',
  'admission-no-connection-output','ceiling-default-95s-retained','ordinary-verdict-preserved'])
  assert.ok(fixture.includes('"'+label+'"'));
 assert.match(fixture,/if \(entitlement\) advance_after_body=true/);
 assert.match(fixture,/clock_offset=95001/);
 assert.match(read('src/System/Store/Receipts.h'),/xodus_store_license_xml\( body, strlen\( body \), &jwt, canceled, deadline \)/);
});
