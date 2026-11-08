// SPDX-License-Identifier: MIT
// Synthetic protocol tests require the matching Wine WinRT JSON implementation.
// Stock Wine is not an interchangeable authentication test executor.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
if(process.argv.length!==4) throw Error('Usage: test-authentication.mjs BUILD_DIRECTORY PINNED_WINE_EXECUTABLE');
const build=fs.realpathSync(process.argv[2]);
const engine=fs.realpathSync(process.argv[3]);
const root=fs.mkdtempSync(path.join(build,'nexus-authentication-test-'));fs.chmodSync(root,0o700);
const prefix=path.join(root,'pfx'),exe=path.join(build,'bin/test_nexus_user.exe');
const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const before=hash(exe);
const env={...process.env,WINEPREFIX:prefix,WINEDEBUG:'-all',WINEARCH:'win64',WINEDLLOVERRIDES:'mscoree,mshtml,winemenubuilder.exe=d;xgameruntime=n'};
for(const key of Object.keys(env)) if(/^(XODUS_|XUSER_|NEXUS_|XGAMERUNTIME_|STEAM_COMPAT_|SteamAppId$|SteamGameId$|WINEDLLPATH$|GTEST_)/.test(key))delete env[key];
if(engine!=='wine') {const base=path.dirname(path.dirname(engine)); env.LD_LIBRARY_PATH=path.join(base,'lib64')+':'+path.join(base,'lib');}
const result=spawnSync(engine,[exe],{env,encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024});
const output=(result.stdout||'')+(result.stderr||'');
fs.writeFileSync(path.join(root,'tests.log'),output,{flag:'wx',mode:0o600});
const server=engine==='wine'?'wineserver':path.join(path.dirname(engine),'wineserver');
const stop=spawnSync(server,['-k'],{env,timeout:10000,stdio:'ignore'}),drain=spawnSync(server,['-w'],{env,timeout:10000,stdio:'ignore'});
const match=output.match(/\[\s*PASSED\s*\]\s+(\d+) tests/);
const presenceCases=['UsesGenuineTitleDeviceAndMatchingUserAndSignsOnlyCurrentTitle','MissingTitleTokenNeverFallsBackToOrdinaryUserAuthorization','PlatformFallbackKeepsLocalUserButForeignTitleClaimNeverPublishesOrSignsAsTitle','MissingOrMalformedTitleClaimsFailClosedWithoutBreakingSignIn','BoundTitleTokenRequiresTheConfiguredTitleNotCallerMetadata','ReauthenticationClearsAnUnboundOrForeignTitleToken','EmptyTitleTokenNeverBindsPresence','TitleIdentityDiagnosticRecordsSanitizedConfigAndBinding','WrongMalformedOrMissingAuthenticatedIdentityNeverPublishes','MissingEndpointOrUnsupportedPolicyFailsClosedWithoutBreakingLogin','DenialCancelledAndInvalidInputsHaveNoPresenceSideEffects'];
const presencePassed=presenceCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusPresence\\.'+name+'(?:\\s|$)').test(output));
const offlineCases=['KeptOnlyWhenTheBackendReportsAFreshOfflineLease','SignsInOnlyOnALaunchRunningOnAValidatedOfflineLicense','AnotherAccountNeverReceivesTheCachedIdentity','AnOfflineLaunchNeverContactsMicrosoft','AStaleIdentityIsNotUsed','ConnectivityFollowsOnlyThePublishedUserAndReturnsOnline'];
const offlinePassed=offlineCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusOfflineIdentity\\.'+name+'(?:\\s|$)').test(output));
const base64Cases=['StandardEncodingRespectsCapacity','UrlEncodingRespectsCapacity','WideEncodingRespectsCapacity'];
const base64Passed=base64Cases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+Base64\\.'+name+'(?:\\s|$)').test(output));
const authorizationCacheCases=["ReusesOnlyTheSameUserAndAudienceAndResetsWithCredentials", "ConcurrentRequestsShareOneRealTransportExchange", "MissingInvalidOrExpiredServerLifetimeDoesNotBecomePersistent", "ServerExpirySkewClockRollbackAndMonotonicCapAreEnforced", "RefreshDoesNotAcceptOlderInflightResponseOrBlockOtherAudiences", "BoundedEntriesEvictAndClearInvalidatesInflightWork", "PublicForceRefreshWorksInBothEncodingsAndSignsEachRequest", "WaitingCallCancelsWithoutCancellingAnotherCaller", "DelayedWaiterDoesNotReceiveAnExpiredToken"];
const authorizationCachePassed=authorizationCacheCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusAuthorizationCache\\.'+name+'(?:\\s|$)').test(output));
const cancellationCases=['SignInHttpCancellationRetainsHeldCallAndStopsEveryLaterPhase','CooperativeTicketCancellationStopsWorkerBeforePeerRelease','LegacyBackendFallbackWaitsForOwnerThenDiscardsCanceledResponse','CancelSignInCompletesBeforeBlockedTransportReturns','CancelledBlockCanBeReusedWhileTransportIsStillBlocked'];
const cancellationPassed=cancellationCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusAuthentication\\.'+name+'(?:\\s|$)').test(output));
const criticalPathCases=['SuccessfulColdHandshakeAndWarmAuthorizationRemainSeparate','TerminalLocalErrorsDoNotRepeatTheHandshakeOrRetryWait'];
const criticalPathPassed=criticalPathCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusAuthCriticalPath\\.'+name+'(?:\\s|$)').test(output));
const silentOverlapCases=['SilentStartsIndependentPhasesButPublishesOnlyAfterBoth', 'AllowingUiKeepsOrderedDiscoveryBeforeTickets', 'DefaultFailureCancelsChildAndRetainsItsOwnError', 'ParentCancellationWhileWaitingTicketsDrainsChild', 'LateLegacyReplyIsJoinedAndNeverPublishedAfterDefaultFailure', 'TicketFailureWaitsForDefaultValidationWithoutPublishingIdentity', 'ThreadStartupFailurePreservesSequentialHandshakeAndReadiness', 'CurrentMetadataStillGatesCompletionThenGamertagNeedsNoRequest', 'CancellationBetweenAdmissionAndChildRunStartsNoBackendRequest'];
const silentOverlapPassed=silentOverlapCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusSilentAuthOverlap\\.'+name+'(?:\\s|$)').test(output));
const pictureCancellationCases=['HeldProfileReplyCannotStartImageAfterCancellation','HeldAuthorizationAndImageCancellationRemainRequestLocal'];
const pictureCancellationPassed=pictureCancellationCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusPictureCancellation\\.'+name+'(?:\\s|$)').test(output));
const signedRetryCases=['TerminalTransportErrorsDoNotRepeatSignedRequests','GenericAndAccessDeniedTransportFailuresKeepThreeAttempts','HttpServerErrorsRetainRetriesAndReleaseBodies','XstsCallerPropagatesTerminalFailureWithoutRetrying'];
const signedRetryPassed=signedRetryCases.every(name=>new RegExp('\\[\\s*OK\\s*\\]\\s+NexusSignedRequestRetry\\.'+name+'(?:\\s|$)').test(output));
const proof={scope:'C++ authentication implementation, synthetic transport only',engine,engineHash:engine==='wine'?null:hash(engine),exeHash:before,unchanged:hash(exe)===before,status:result.status,signal:result.signal,error:result.error?.message,checks:match?Number(match[1]):0,realAccounts:false,realCloud:false,fullRuntime:false,passed:result.status===0&&!result.error&&!!match&&Number(match[1])>=27&&!/\[\s*(FAILED|SKIPPED)\s*\]/.test(output)};
proof.signedRetryCases=signedRetryCases.length;proof.signedRetryPassed=signedRetryPassed;
if(!signedRetryPassed)proof.passed=false;
proof.cancellationCases=cancellationCases.length;proof.cancellationPassed=cancellationPassed;
if(!cancellationPassed)proof.passed=false;
proof.authorizationCacheCases=authorizationCacheCases.length;proof.authorizationCachePassed=authorizationCachePassed;
if(!authorizationCachePassed)proof.passed=false;
proof.presenceCases=presenceCases.length;proof.presencePassed=presencePassed;
if(!presencePassed)proof.passed=false;
proof.pictureCancellationPassed=pictureCancellationPassed;
if(!pictureCancellationPassed)proof.passed=false;
proof.silentOverlapCases=silentOverlapCases.length;proof.silentOverlapPassed=silentOverlapPassed;
if(!silentOverlapPassed)proof.passed=false;
proof.criticalPathCases=criticalPathCases.length;proof.criticalPathPassed=criticalPathPassed;
if(!criticalPathPassed)proof.passed=false;
proof.offlineCases=offlineCases.length;proof.offlinePassed=offlinePassed;
if(!offlinePassed)proof.passed=false;
proof.base64Cases=base64Cases.length;proof.base64Passed=base64Passed;
if(!base64Passed)proof.passed=false;
if(stop.error||drain.error||drain.status!==0) {proof.passed=false;proof.cleanupFailed=true;}
if(proof.passed&&fs.existsSync(prefix)) {
    if(fs.realpathSync(prefix)!==prefix||!fs.lstatSync(prefix).isDirectory())throw Error('Unexpected synthetic prefix');
    fs.rmSync(prefix,{recursive:true});proof.syntheticPrefixRemoved=true;
}
fs.writeFileSync(path.join(root,'results.json'),JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(root);console.log(JSON.stringify(proof));
if(!proof.passed) console.log(output.slice(-9000));
process.exitCode=proof.passed?0:1;
