// SPDX-License-Identifier: LGPL-2.1-or-later
// Actual XUser licensing helper, entitlement code and socket transport. All
// peers/keys/payloads are synthetic and confined to an owned loopback listener.
#include "../../src/private.h"
#include <xstore.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <atomic>
#include <cstdio>
#include <string>
#include <vector>
#include "../../src/Runtime/Configuration.h"
#include "../../src/System/Store/Bridge.h"
#undef GetTickCount64
static std::atomic<ULONGLONG> clock_offset{0};
static ULONGLONG RealReceiptTick() { return ::GetTickCount64(); }
ULONGLONG WINAPI FixtureReceiptTick() { return RealReceiptTick() + clock_offset; }
#define GetTickCount64 FixtureReceiptTick
UINT64 xuser_get_xuid(XUserHandle);
static const char *GetStoreProductId() { return "B00000000001"; }
static bool advance_after_body;
static HRESULT FixtureBody(const char **ids, SIZE_T count, const char *nonce, char **out)
{
    const auto hr = xodus_store_license_body(ids, count, nonce, out);
    if (advance_after_body && SUCCEEDED(hr)) clock_offset = 119800;
    return hr;
}
// This identical fixture also builds on the original three-argument helper.
// Its before-state adapter can release a held peer after a bounded observation,
// so proving a missing budget never waits the production 95-second ceiling.
template<class Cancel, class Deadline> static HRESULT FixtureLicense(const char *body, SIZE_T size, char **out,
                                                                     Cancel cancel, Deadline deadline)
{
    if constexpr (requires { xodus_store_license_xml(body, size, out, cancel, deadline); })
        return xodus_store_license_xml(body, size, out, cancel, deadline);
    else return xodus_store_license_xml(body, size, out);
}
static HRESULT FixtureLicense(const char *body, SIZE_T size, char **out)
{
    return xodus_store_license_xml(body, size, out);
}
#define xodus_store_license_xml FixtureLicense
#define xodus_store_license_body FixtureBody
#include "../../src/System/Store/Entitled.h"
#undef xodus_store_license_xml
#undef xodus_store_license_body
static unsigned checks, failures;
#define CHECK(label,e) do { ++checks; if (!(e)) { ++failures; printf("FAIL %s line=%d\n",label,__LINE__); } } while(0)
struct Peer
{
    SOCKET listener = INVALID_SOCKET;
    HANDLE thread = nullptr, framed = nullptr, release = nullptr, stop = nullptr, poke = nullptr;
    bool partial_body = false, malformed = false;
    std::atomic<bool> accepted{false}, valid{false};
};
static bool receive_all(SOCKET s, char *out, int length)
{
    while (length) { int n = recv(s,out,length,0); if (n <= 0) return false; out += n; length -= n; } return true;
}
static DWORD WINAPI serve(void *raw)
{
    auto &p = *static_cast<Peer *>(raw);
    SOCKET s = INVALID_SOCKET;
    while (WaitForSingleObject(p.stop,0) == WAIT_TIMEOUT)
    {
        fd_set set; FD_ZERO(&set); FD_SET(p.listener,&set); timeval t{0,10000};
        if (select(0,&set,nullptr,nullptr,&t) > 0) { s=accept(p.listener,nullptr,nullptr); break; }
    }
    if (s == INVALID_SOCKET) return 0;
    p.accepted = true;
    DWORD timeout = 1500; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char *>(&timeout),sizeof(timeout));
    char key[64],header[8]; UINT32 magic=0x58445358; UINT16 type=5,count=0;
    bool valid = receive_all(s,key,64) && receive_all(s,header,8);
    if (valid)
    {
        memcpy(&count,header+6,2); std::vector<char> body(count);
        valid = !memcmp(key,std::string(64,'a').data(),64) && !memcmp(header,&magic,4) &&
                !memcmp(header+4,&type,2) && count && receive_all(s,body.data(),count);
    }
    p.valid = valid;
    const std::string response = p.malformed ? "<Wrong/>" :
        "<StoreLicenseTokenResponse><Hresult>0</Hresult><Token>synthetic-token</Token></StoreLicenseTokenResponse>";
    type=6; count=static_cast<UINT16>(response.size());
    memcpy(header,&magic,4); memcpy(header+4,&type,2); memcpy(header+6,&count,2);
    if (p.partial_body) { send(s,header,8,0); send(s,response.data(),3,0); }
    SetEvent(p.framed);
    bool poked=false, replied=false;
    while (WaitForSingleObject(p.stop,0) == WAIT_TIMEOUT)
    {
        if (!poked && WaitForSingleObject(p.poke,0)==WAIT_OBJECT_0) { send(s,header,1,0); poked=true; }
        if (!replied && WaitForSingleObject(p.release,0)==WAIT_OBJECT_0)
        {
            if (!p.partial_body) send(s,header+(poked?1:0),poked?7:8,0);
            send(s,response.data()+(p.partial_body?3:0),static_cast<int>(response.size())-(p.partial_body?3:0),0);
            replied=true;
        }
        fd_set set; FD_ZERO(&set); FD_SET(s,&set); timeval t{0,10000};
        if (select(0,&set,nullptr,nullptr,&t)>0) { char b; if (recv(s,&b,1,0)<=0) break; }
    }
    closesocket(s); return 0;
}
static void start(Peer &p)
{
    clock_offset=0; advance_after_body=false;
    p.framed=CreateEventW(nullptr,TRUE,FALSE,nullptr); p.release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    p.stop=CreateEventW(nullptr,TRUE,FALSE,nullptr); p.poke=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    p.listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); sockaddr_in addr{};
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK("listener-bind",bind(p.listener,reinterpret_cast<sockaddr *>(&addr),sizeof(addr))==0);
    CHECK("listener-ready",listen(p.listener,1)==0);
    int n=sizeof(addr); getsockname(p.listener,reinterpret_cast<sockaddr *>(&addr),&n);
    char port[16]; snprintf(port,sizeof(port),"%u",ntohs(addr.sin_port));
    SetEnvironmentVariableA("XODUS_BRIDGE_PORT",port); SetEnvironmentVariableA("XODUS_BRIDGE_KEY",std::string(64,'a').c_str());
    p.thread=CreateThread(nullptr,0,serve,&p,0,nullptr); CHECK("peer-thread",p.thread!=nullptr);
}
static void stop(Peer &p)
{
    SetEvent(p.stop); SetEvent(p.release);
    const bool joined=WaitForSingleObject(p.thread,3000)==WAIT_OBJECT_0;
    CHECK("peer-joined",joined);
    if (!joined) ExitProcess(3); // Never release a live peer's stack/handles.
    closesocket(p.listener);
    for (HANDLE h:{p.thread,p.framed,p.release,p.stop,p.poke}) CloseHandle(h);
    clock_offset=0;
}
struct Call
{
    LONG canceled=0; ULONGLONG deadline=0;
    bool entitlement=false, direct=false;
    const char *body="ping"; SIZE_T size=4;
    char *token=nullptr; entitled_snapshot *snapshot=nullptr;
    HRESULT result=E_PENDING; HANDLE thread=nullptr; ULONGLONG elapsed=0;
};
static DWORD WINAPI invoke(void *raw)
{
    auto &c=*static_cast<Call *>(raw); const auto began=RealReceiptTick();
    if (c.entitlement)
        c.result=entitled_fetch("<Request><ParentProductId>B00000000001</ParentProductId><Market>US</Market>"
            "<Language>en-US</Language><ProductKinds>1</ProductKinds></Request>",&c.canceled,&c.snapshot);
    else if (c.direct) c.result=xodus_store_license_xml(c.body,c.size,&c.token);
    else c.result=FixtureLicense(c.body,c.size,&c.token,&c.canceled,c.deadline);
    c.elapsed=RealReceiptTick()-began; return 0;
}
static void launch(Call &c) { c.thread=CreateThread(nullptr,0,invoke,&c,0,nullptr); CHECK("call-thread",c.thread!=nullptr); }
static void finish(Call &c)
{
    const bool joined=WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0;
    CHECK("call-joined",joined);
    if (!joined) ExitProcess(3); // Never release a live worker's stack/outputs.
    CloseHandle(c.thread);
    free(c.token); if(c.snapshot) entitled_snapshot_release(c.snapshot);
}
static void held_cancel(bool entitlement, bool partial)
{
    Peer p; p.partial_body=partial; start(p); Call c; c.entitlement=entitlement; launch(c);
    CHECK("cancel-request-framed",WaitForSingleObject(p.framed,2000)==WAIT_OBJECT_0 && p.valid);
    InterlockedExchange(&c.canceled,1);
    CHECK("cancel-exits-before-peer-release",WaitForSingleObject(c.thread,500)==WAIT_OBJECT_0);
    SetEvent(p.release); CHECK("cancel-eventually-exits",WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0);
    CHECK("cancel-abort-no-partial-output",c.result==E_ABORT && !c.token && !c.snapshot);
    printf("CANCEL entitlement=%d partial=%d elapsed=%llu\n",entitlement,partial,c.elapsed);
    finish(c); stop(p);
}
static void remaining_budget(bool entitlement)
{
    Peer p; start(p); Call c; c.entitlement=entitlement;
    if (entitlement) advance_after_body=true; else c.deadline=GetTickCount64()+200;
    launch(c); CHECK("budget-request-framed",WaitForSingleObject(p.framed,2000)==WAIT_OBJECT_0 && p.valid);
    CHECK("budget-exits-before-peer-release",WaitForSingleObject(c.thread,500)==WAIT_OBJECT_0);
    SetEvent(p.release); CHECK("budget-eventually-exits",WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0);
    CHECK("budget-socket-timeout-preserved",c.result==HRESULT_FROM_WIN32(WSAETIMEDOUT));
    CHECK("budget-near-expiry-bounded",c.elapsed>=100 && c.elapsed<500 && !c.token && !c.snapshot);
    printf("BUDGET entitlement=%d elapsed=%llu\n",entitlement,c.elapsed);
    finish(c); stop(p);
}
static void before_admission(bool cancel, bool invalid)
{
    Peer p; start(p); Call c; c.canceled=cancel;
    c.deadline=GetTickCount64()-1; if(invalid)c.size=65536;
    launch(c); CHECK("admission-client-bounded",WaitForSingleObject(c.thread,500)==WAIT_OBJECT_0);
    SetEvent(p.release); CHECK("admission-eventually-exits",WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0);
    CHECK("admission-error-precedence",c.result==(invalid?E_INVALIDARG:cancel?E_ABORT:HRESULT_FROM_WIN32(ERROR_TIMEOUT)));
    CHECK("admission-no-connection-output",!p.accepted && !c.token);
    finish(c); stop(p);
}
static void ceiling(bool direct)
{
    Peer p; start(p); Call c; c.direct=direct; c.deadline=GetTickCount64()+120000; launch(c);
    CHECK("ceiling-framed",WaitForSingleObject(p.framed,2000)==WAIT_OBJECT_0 && p.valid);
    clock_offset=95001; SetEvent(p.poke);
    CHECK("ceiling-default-95s-retained",WaitForSingleObject(c.thread,500)==WAIT_OBJECT_0);
    SetEvent(p.release); CHECK("ceiling-eventually-exits",WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0);
    CHECK("ceiling-timeout-no-output",c.result==HRESULT_FROM_WIN32(WSAETIMEDOUT) && !c.token);
    finish(c); stop(p);
}
static void ordinary(bool malformed)
{
    Peer p; p.malformed=malformed; start(p); Call c; c.deadline=GetTickCount64()+2000; SetEvent(p.release); launch(c);
    CHECK("ordinary-completes",WaitForSingleObject(c.thread,3000)==WAIT_OBJECT_0);
    CHECK("ordinary-framing",p.valid);
    CHECK("ordinary-verdict-preserved",malformed ? c.result==E_UNEXPECTED && !c.token :
        c.result==S_OK && c.token && !strcmp(c.token,"synthetic-token"));
    finish(c); stop(p);
}
int main()
{
    setvbuf(stdout,nullptr,_IONBF,0); WSADATA data;
    CHECK("winsock",WSAStartup(MAKEWORD(2,2),&data)==0);
    INITIALIZE_OPTIONS options{}; options.isInlineConfig=TRUE;
    options.gameConfig="<Game configVersion=\"1\"><Identity Name=\"Synthetic\" Publisher=\"CN=Synthetic\"/>"
        "<StoreId>B00000000001</StoreId><MSAAppId>0000000000000001</MSAAppId><TitleId>1</TitleId></Game>";
    CHECK("synthetic-config",nexus::InitializeGameConfiguration(&options)==S_OK);
    held_cancel(false,false); held_cancel(false,true); held_cancel(true,true);
    remaining_budget(false); remaining_budget(true);
    before_admission(true,false); before_admission(false,false); before_admission(true,true);
    ceiling(true); ceiling(false); ordinary(false); ordinary(true);
    SetEnvironmentVariableA("XODUS_BRIDGE_PORT",nullptr); SetEnvironmentVariableA("XODUS_BRIDGE_KEY",nullptr);
    WSACleanup(); printf("CHECKS %u FAILURES %u\n",checks,failures); return failures?1:0;
}
