// SPDX-License-Identifier: MIT
// Actual synchronous HttpClient + native WinHTTP on loopback only. The fixture
// routes the fixed HTTPS endpoint to a private port. Plaintext cases explicitly
// strip TLS at that boundary; the handshake case uses real TLS ClientHello and
// holds the peer before any certificate/authentication exchange.
#include "../../src/private.h"
#include "../../src/HttpClient.h"
#include <winhttp.h>
#include <atomic>
#include <cstdio>
#include <vector>
#include <initializer_list>

static INTERNET_PORT fixturePort;
static bool tls;
static HINTERNET WINAPI route_connect(HINTERNET session,LPCWSTR,INTERNET_PORT,DWORD reserved)
{
    return WinHttpConnect(session,L"127.0.0.1",fixturePort,reserved);
}
static HINTERNET WINAPI route_request(HINTERNET connection,LPCWSTR method,LPCWSTR path,LPCWSTR version,
                                      LPCWSTR referer,LPCWSTR *accept,DWORD flags)
{
    return WinHttpOpenRequest(connection,method,path,version,referer,accept,tls?flags:flags&~WINHTTP_FLAG_SECURE);
}
static HINTERNET WINAPI no_proxy(LPCWSTR agent,DWORD,LPCWSTR,LPCWSTR,DWORD flags)
{
    return WinHttpOpen(agent,WINHTTP_ACCESS_TYPE_NO_PROXY,nullptr,nullptr,flags);
}
#define WinHttpConnect route_connect
#define WinHttpOpenRequest route_request
#define WinHttpOpen no_proxy
#include "../../src/HttpClient.cpp"
#undef WinHttpConnect
#undef WinHttpOpenRequest
#undef WinHttpOpen

static unsigned checks,failures;
#define CHECK(expr) do { ++checks; if(!(expr)) { ++failures; printf("FAIL line=%u %s error=%lu\n",__LINE__,#expr,GetLastError()); } } while(0)
enum class Mode {Headers,Body,Upload,TlsHandshake};
struct Fixture
{
    Mode mode;
    SOCKET listener=INVALID_SOCKET;
    HANDLE seen=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE server=nullptr,worker=nullptr;
    std::atomic<bool> cancel{false};
    HRESULT result=E_PENDING;
    BYTE *response=nullptr;
    SIZE_T size=0;
    bool protocolObserved=false;
    explicit Fixture(Mode value):mode(value){}
};
static DWORD WINAPI serve(void *context)
{
    auto &f=*static_cast<Fixture*>(context);
    SOCKET client=accept(f.listener,nullptr,nullptr);
    if(client==INVALID_SOCKET)return 1;
    char buffer[8192]={}; unsigned used=0;
    if(f.mode==Mode::TlsHandshake)
    {
        int count=recv(client,buffer,sizeof(buffer),0);
        f.protocolObserved=count>=3 && static_cast<unsigned char>(buffer[0])==22 && buffer[1]==3;
    }
    else
    {
        while(!strstr(buffer,"\r\n\r\n"))
        {
            int count=recv(client,buffer+used,sizeof(buffer)-used-1,0);
            if(count<=0||used+count>=sizeof(buffer)-1){closesocket(client);return 2;}
            used+=count;
        }
        f.protocolObserved=true;
        if(f.mode==Mode::Body)
        {
            const char headers[]="HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n";
            send(client,headers,sizeof(headers)-1,0);
        }
    }
    SetEvent(f.seen);
    WaitForSingleObject(f.release,10000);
    closesocket(client);
    return 0;
}
static DWORD WINAPI request(void *context)
{
    auto &f=*static_cast<Fixture*>(context);
    std::vector<char> body;
    if(f.mode==Mode::Upload){body.resize(32*1024*1024,'x');body.back()=0;}
    const WCHAR *accept[]={L"application/json",nullptr};
    f.result=http_request_cancellable(L"POST",L"https://127.0.0.1/synthetic",body.empty()?nullptr:body.data(),
                                      nullptr,accept,&f.response,&f.size,f.cancel);
    return 0;
}
int main()
{
    setvbuf(stdout,nullptr,_IONBF,0);
    WSADATA data; CHECK(!WSAStartup(MAKEWORD(2,2),&data));
    auto module=LoadLibraryW(L"winhttp.dll");
    CHECK(module && GetProcAddress(module,"__wine_winhttp_cancel_request_v1"));
    if(!module||!GetProcAddress(module,"__wine_winhttp_cancel_request_v1"))return 2;
    for(Mode mode:{Mode::Headers,Mode::Body,Mode::Upload,Mode::TlsHandshake})
    {
        Fixture f(mode); tls=mode==Mode::TlsHandshake;
        f.listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        int size=1024; setsockopt(f.listener,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<char*>(&size),sizeof(size));
        sockaddr_in address={}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        CHECK(!bind(f.listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)));
        CHECK(!listen(f.listener,1)); size=sizeof(address);
        getsockname(f.listener,reinterpret_cast<sockaddr*>(&address),&size); fixturePort=ntohs(address.sin_port);
        f.server=CreateThread(nullptr,0,serve,&f,0,nullptr);
        f.worker=CreateThread(nullptr,0,request,&f,0,nullptr);
        CHECK(f.server&&f.worker);
        CHECK(WaitForSingleObject(f.seen,5000)==WAIT_OBJECT_0);
        CHECK(f.protocolObserved);
        CHECK(WaitForSingleObject(f.worker,100)==WAIT_TIMEOUT);
        ULONGLONG start=GetTickCount64(); f.cancel=true;
        bool drained=WaitForSingleObject(f.worker,1500)==WAIT_OBJECT_0;
        printf("NATIVE_HTTP mode=%u drained_before_peer_release=%d ms=%llu hr=%#lx\n",unsigned(mode),drained,GetTickCount64()-start,f.result);
        CHECK(drained);
        SetEvent(f.release);
        CHECK(WaitForSingleObject(f.worker,5000)==WAIT_OBJECT_0);
        CHECK(f.result==E_ABORT); CHECK(f.response==nullptr&&f.size==0);
        CHECK(WaitForSingleObject(f.server,5000)==WAIT_OBJECT_0);
        closesocket(f.listener); CloseHandle(f.server); CloseHandle(f.worker); CloseHandle(f.seen); CloseHandle(f.release);
        free(f.response);
    }
    FreeLibrary(module); WSACleanup();
    printf("CHECKS %u FAILURES %u\n",checks,failures);
    return failures?1:0;
}
