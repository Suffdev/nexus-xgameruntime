// SPDX-License-Identifier: MIT
// Actual synchronous HttpClient control flow with explicit WinHTTP API shims.
// Not native TLS/certificate or in-flight WinHTTP interruption evidence.
#include "../../src/private.h"
#include "../../src/HttpClient.h"
#include <winhttp.h>
#include <atomic>
#include <vector>
#include <cstring>
#include <cstdio>

static BOOL WINAPI fake_crack( LPCWSTR,DWORD,DWORD,LPURL_COMPONENTS );
static HINTERNET WINAPI fake_open( LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD );
static HINTERNET WINAPI fake_connect( HINTERNET,LPCWSTR,INTERNET_PORT,DWORD );
static HINTERNET WINAPI fake_request( HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD );
static BOOL WINAPI fake_send( HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR );
static BOOL WINAPI fake_receive( HINTERNET,LPVOID );
static BOOL WINAPI fake_headers( HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD );
static BOOL WINAPI fake_available( HINTERNET,LPDWORD );
static BOOL WINAPI fake_read( HINTERNET,LPVOID,DWORD,LPDWORD );
static BOOL WINAPI fake_close( HINTERNET );
static void WINAPI fake_sleep( DWORD );
static void *tracked_realloc( void *, size_t );
static void tracked_free( void * );
static FARPROC WINAPI no_private_abort(HMODULE,LPCSTR) { return nullptr; }
#define GetProcAddress no_private_abort // deterministic older-Wine cooperative fallback fixture
#define WinHttpCrackUrl fake_crack
#define WinHttpOpen fake_open
#define WinHttpConnect fake_connect
#define WinHttpOpenRequest fake_request
#define WinHttpSendRequest fake_send
#define WinHttpReceiveResponse fake_receive
#define WinHttpQueryHeaders fake_headers
#define WinHttpQueryDataAvailable fake_available
#define WinHttpReadData fake_read
#define WinHttpCloseHandle fake_close
#define Sleep fake_sleep
#define realloc tracked_realloc
#define free tracked_free
#include "../../src/HttpClient.cpp"
#undef GetProcAddress
#undef WinHttpCrackUrl
#undef WinHttpOpen
#undef WinHttpConnect
#undef WinHttpOpenRequest
#undef WinHttpSendRequest
#undef WinHttpReceiveResponse
#undef WinHttpQueryHeaders
#undef WinHttpQueryDataAvailable
#undef WinHttpReadData
#undef WinHttpCloseHandle
#undef Sleep
#undef realloc
#undef free

static unsigned checks, failures;
#define CHECK(label,expr) do { ++checks; if(!(expr)){++failures;printf("FAIL %s line=%u\n",label,__LINE__);} }while(0)
enum class Mode { Success, ReceiveFailure, LateSuccess, SendHeld, QueryHeld, ReadHeld, BackoffHeld, RetryOnce, StatusFailure, CompleteHeld };
struct FakeHandle { unsigned kind; DWORD owner; bool closed = false; };
struct HttpCall
{
    Mode mode; bool cancellable = true; std::atomic<bool> cancel{false};
    HANDLE entered=CreateEventW(NULL,TRUE,FALSE,NULL),release=CreateEventW(NULL,TRUE,FALSE,NULL),thread=NULL;
    std::vector<FakeHandle*> handles; DWORD owner=0;
    unsigned sends=0,receives=0,queries=0,reads=0,closes=0,violations=0,backoffs=0;
    unsigned requestReads=0,requestQueries=0; bool held=false,returnedAllocationFreed=false;
    void *returnedAllocation=NULL; char *borrowedBody=NULL;
    BYTE *response=NULL; SIZE_T size=0; HRESULT result=E_PENDING;
    explicit HttpCall(Mode m):mode(m){}
    ~HttpCall(){for(auto h:handles)delete h;CloseHandle(entered);CloseHandle(release);if(thread)CloseHandle(thread);}
};
static thread_local HttpCall *active;
static FakeHandle *check_handle(HINTERNET handle,unsigned kind)
{
    auto h=static_cast<FakeHandle*>(handle);
    if(!h||h->kind!=kind||h->closed||h->owner!=GetCurrentThreadId())++active->violations;
    return h;
}
static HINTERNET handle(unsigned kind)
{auto h=new FakeHandle{kind,GetCurrentThreadId()};active->handles.push_back(h);return h;}
static void hold()
{
    if(active->held)return;active->held=true;SetEvent(active->entered);
    if(WaitForSingleObject(active->release,5000)!=WAIT_OBJECT_0)++active->violations;
    if(active->borrowedBody&&strcmp(active->borrowedBody,"synthetic-body"))++active->violations;
}
static BOOL WINAPI fake_crack(LPCWSTR url,DWORD,DWORD,LPURL_COMPONENTS parts)
{
    static WCHAR host[]=L"fixture.invalid",path[]=L"/test";
    if(wcscmp(url,L"https://fixture.invalid/test"))++active->violations;
    parts->lpszHostName=host;parts->dwHostNameLength=wcslen(host);parts->lpszUrlPath=path;
    parts->nPort=443;parts->nScheme=INTERNET_SCHEME_HTTPS;return TRUE;
}
static HINTERNET WINAPI fake_open(LPCWSTR,DWORD access,LPCWSTR,LPCWSTR,DWORD flags)
{if(flags||access!=WINHTTP_ACCESS_TYPE_DEFAULT_PROXY)++active->violations;return handle(1);}
static HINTERNET WINAPI fake_connect(HINTERNET parent,LPCWSTR host,INTERNET_PORT port,DWORD)
{check_handle(parent,1);if(wcscmp(host,L"fixture.invalid")||port!=443)++active->violations;return handle(2);}
static HINTERNET WINAPI fake_request(HINTERNET parent,LPCWSTR verb,LPCWSTR path,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD flags)
{
    check_handle(parent,2);if(wcscmp(verb,L"POST")||wcscmp(path,L"/test")||flags!=WINHTTP_FLAG_SECURE)++active->violations;
    active->requestReads=active->requestQueries=0;return handle(3);
}
static BOOL WINAPI fake_send(HINTERNET request,LPCWSTR headers,DWORD,LPVOID body,DWORD count,DWORD total,DWORD_PTR)
{
    check_handle(request,3);++active->sends;active->borrowedBody=static_cast<char*>(body);
    if(!headers||wcscmp(headers,L"Signature: synthetic\r\n")||count!=14||total!=count||memcmp(body,"synthetic-body",14))++active->violations;
    if(active->mode==Mode::SendHeld)hold();return TRUE;
}
static BOOL WINAPI fake_receive(HINTERNET request,LPVOID)
{
    check_handle(request,3);++active->receives;
    if(active->mode==Mode::ReceiveFailure||active->mode==Mode::LateSuccess)hold();
    if(active->mode==Mode::ReceiveFailure||active->mode==Mode::BackoffHeld||
       (active->mode==Mode::RetryOnce&&active->receives==1)){SetLastError(ERROR_WINHTTP_TIMEOUT);return FALSE;}
    return TRUE;
}
static BOOL WINAPI fake_headers(HINTERNET request,DWORD,LPCWSTR,LPVOID buffer,LPDWORD size,LPDWORD)
{check_handle(request,3);*static_cast<DWORD*>(buffer)=active->mode==Mode::StatusFailure?403:200;*size=sizeof(DWORD);return TRUE;}
static BOOL WINAPI fake_available(HINTERNET request,LPDWORD count)
{
    check_handle(request,3);++active->queries;++active->requestQueries;
    if((active->mode==Mode::QueryHeld||active->mode==Mode::CompleteHeld)&&active->requestQueries==2)hold();
    bool partial=active->mode==Mode::QueryHeld||active->mode==Mode::ReadHeld;
    *count=active->requestReads<(partial?2u:1u)?3:0;return TRUE;
}
static BOOL WINAPI fake_read(HINTERNET request,LPVOID buffer,DWORD count,LPDWORD actual)
{
    check_handle(request,3);++active->reads;
    if(active->mode==Mode::ReadHeld)hold();
    if(count!=3)++active->violations;memcpy(buffer,active->requestReads?"def":"abc",3);*actual=3;++active->requestReads;return TRUE;
}
static BOOL WINAPI fake_close(HINTERNET handle)
{auto h=static_cast<FakeHandle*>(handle);check_handle(handle,h->kind);h->closed=true;++active->closes;return TRUE;}
static void WINAPI fake_sleep(DWORD)
{++active->backoffs;if(active->mode==Mode::BackoffHeld)hold();}
static void *tracked_realloc(void *pointer,size_t size)
{void *out=realloc(pointer,size);if(out)active->returnedAllocation=out;return out;}
static void tracked_free(void *pointer)
{if(pointer&&pointer==active->returnedAllocation){active->returnedAllocationFreed=true;active->returnedAllocation=NULL;}free(pointer);}

template<class Cancel> static HRESULT invoke_http(BYTE **buffer,SIZE_T *size,char *body,const Cancel &cancel)
{
    static const WCHAR *accept[]={L"application/json",NULL};
    if constexpr(requires{http_request_cancellable(L"POST",L"https://fixture.invalid/test",body,L"Signature: synthetic\r\n",accept,buffer,size,cancel);})
        return http_request_cancellable(L"POST",L"https://fixture.invalid/test",body,L"Signature: synthetic\r\n",accept,buffer,size,cancel);
    else return http_request(L"POST",L"https://fixture.invalid/test",body,L"Signature: synthetic\r\n",accept,buffer,size);
}
static DWORD WINAPI run_http(void *context)
{
    active=static_cast<HttpCall*>(context);active->owner=GetCurrentThreadId();char body[]="synthetic-body";
    static const WCHAR *accept[]={L"application/json",NULL};
    active->result=active->cancellable?invoke_http(&active->response,&active->size,body,active->cancel):
        http_request(L"POST",L"https://fixture.invalid/test",body,L"Signature: synthetic\r\n",accept,&active->response,&active->size);
    return 0;
}
static void start(HttpCall &call){call.thread=CreateThread(NULL,0,run_http,&call,0,NULL);CHECK("http-worker-created",call.thread!=NULL);}
static void finish(HttpCall &call)
{
    CHECK("http-worker-joined",WaitForSingleObject(call.thread,6000)==WAIT_OBJECT_0);
    CHECK("http-owned-handle-close-once",call.closes==call.handles.size());CHECK("http-handle-body-tls-invariants",!call.violations);
    free(call.response);call.response=NULL;
}
static void canceled_phase(Mode mode)
{
    printf("CASE actual HttpClient cancel phase=%u\n",unsigned(mode));HttpCall call(mode);start(call);
    CHECK("http-native-phase-entered",WaitForSingleObject(call.entered,2000)==WAIT_OBJECT_0);call.cancel=true;
    CHECK("http-cancel-does-not-close-inflight-owner-handles",call.closes==0||mode==Mode::BackoffHeld);
    CHECK("http-worker-retained-until-native-return",WaitForSingleObject(call.thread,0)==WAIT_TIMEOUT);
    SetEvent(call.release);CHECK("http-canceled-operation-exits",WaitForSingleObject(call.thread,3000)==WAIT_OBJECT_0);
    CHECK("http-canceled-result-abort",call.result==E_ABORT);CHECK("http-canceled-output-empty",!call.response&&!call.size);
    CHECK("http-no-retry-after-observed-cancel",call.sends==1);
    if(mode==Mode::QueryHeld)CHECK("http-no-body-read-after-canceled-query",call.reads==1&&call.returnedAllocationFreed);
    if(mode==Mode::ReadHeld)CHECK("http-no-query-after-canceled-read",call.queries==1&&call.returnedAllocationFreed);
    if(mode==Mode::SendHeld)CHECK("http-no-receive-after-canceled-send",call.receives==0);
    if(mode==Mode::CompleteHeld)CHECK("http-complete-response-discarded-before-publication",call.reads==1&&call.returnedAllocationFreed);
    finish(call);
}
static void compatibility()
{
    HttpCall before(Mode::Success);before.cancel=true;start(before);
    CHECK("http-precancel-returns",WaitForSingleObject(before.thread,2000)==WAIT_OBJECT_0);
    CHECK("http-precancel-no-handles",before.handles.empty());CHECK("http-precancel-abort-empty",before.result==E_ABORT&&!before.response&&!before.size);finish(before);
    for(Mode mode:{Mode::Success,Mode::RetryOnce,Mode::StatusFailure})
    {
        HttpCall call(mode);start(call);CHECK("http-uncanceled-call-completes",WaitForSingleObject(call.thread,3000)==WAIT_OBJECT_0);
        CHECK("http-uncanceled-send-count",call.sends==(mode==Mode::RetryOnce?2u:1u));
        CHECK("http-uncanceled-result-preserved",mode==Mode::StatusFailure?call.result==E_FAIL:call.result==S_OK&&call.size==3&&!memcmp(call.response,"abc",3));finish(call);
    }
    HttpCall old(Mode::LateSuccess);old.cancellable=false;start(old);CHECK("http-legacy-phase-entered",WaitForSingleObject(old.entered,2000)==WAIT_OBJECT_0);
    old.cancel=true;SetEvent(old.release);CHECK("http-legacy-finishes",WaitForSingleObject(old.thread,2000)==WAIT_OBJECT_0);
    CHECK("http-legacy-ignores-unpassed-token",old.result==S_OK&&old.size==3);finish(old);
    HttpCall canceled(Mode::LateSuccess),independent(Mode::LateSuccess);start(canceled);CHECK("http-independent-first-held",WaitForSingleObject(canceled.entered,2000)==WAIT_OBJECT_0);
    start(independent);CHECK("http-independent-second-held",WaitForSingleObject(independent.entered,2000)==WAIT_OBJECT_0);
    canceled.cancel=true;SetEvent(canceled.release);
    CHECK("http-other-cancel-completes",WaitForSingleObject(canceled.thread,2000)==WAIT_OBJECT_0);CHECK("http-other-abort-empty",canceled.result==E_ABORT&&!canceled.response&&!canceled.size);finish(canceled);
    CHECK("http-independent-still-owned-after-other-cleanup",WaitForSingleObject(independent.thread,0)==WAIT_TIMEOUT&&!independent.closes);
    SetEvent(independent.release);CHECK("http-independent-completes",WaitForSingleObject(independent.thread,2000)==WAIT_OBJECT_0);
    CHECK("http-independent-not-canceled",independent.result==S_OK&&independent.size==3);finish(independent);
    HttpCall later(Mode::Success);start(later);CHECK("http-post-cancel-request-completes",WaitForSingleObject(later.thread,2000)==WAIT_OBJECT_0);
    CHECK("http-post-cancel-request-valid",later.result==S_OK&&later.size==3);finish(later);
}
int main()
{
    setvbuf(stdout,NULL,_IONBF,0);InitializeLogging();
    for(Mode mode:{Mode::SendHeld,Mode::ReceiveFailure,Mode::LateSuccess,Mode::QueryHeld,Mode::ReadHeld,Mode::BackoffHeld,Mode::CompleteHeld})canceled_phase(mode);
    compatibility();printf("CHECKS %u FAILURES %u\n",checks,failures);return failures?1:0;
}
