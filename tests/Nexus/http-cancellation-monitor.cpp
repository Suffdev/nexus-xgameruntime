// SPDX-License-Identifier: MIT
// Private cancellation ownership/lifetime fixture, not native transport proof.
#include <windows.h>
#include <winhttp.h>
#include <initializer_list>
#include <atomic>
#include <cstdio>
#include <cstring>
static bool supported = true, failThread = false, failEvent = false;
struct Request
{
    std::atomic<unsigned> aborts{0};
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    std::atomic<bool> alive{true};
    std::atomic<bool> violation{false};
    ~Request() { CloseHandle(entered); CloseHandle(release); }
};
static BOOL WINAPI abort_request(HINTERNET handle)
{
    auto request = reinterpret_cast<Request *>(handle);
    if (!request->alive) request->violation = true;
    ++request->aborts;
    SetEvent(request->entered);
    if (WaitForSingleObject(request->release, 3000) != WAIT_OBJECT_0) request->violation = true;
    if (!request->alive) request->violation = true;
    return TRUE;
}
static FARPROC WINAPI find_abort(HMODULE, const char *name)
{
    return supported && !strcmp(name, "__wine_winhttp_cancel_request_v1") ? reinterpret_cast<FARPROC>(abort_request) : nullptr;
}
static HANDLE WINAPI create_thread(LPSECURITY_ATTRIBUTES a, SIZE_T s, LPTHREAD_START_ROUTINE f, void *p, DWORD flags, DWORD *id)
{
    if (failThread) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return nullptr; }
    return CreateThread(a,s,f,p,flags,id);
}
static HANDLE WINAPI create_event(LPSECURITY_ATTRIBUTES a, BOOL manual, BOOL initial, LPCWSTR name)
{
    if (failEvent) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return nullptr; }
    return CreateEventW(a,manual,initial,name);
}
#define GetProcAddress find_abort
#define CreateThread create_thread
#define CreateEventW create_event
#define WARN(...) ((void)0)
#include "../../src/HttpCancellation.h"
#undef GetProcAddress
#undef CreateThread
#undef CreateEventW
#undef WARN
static unsigned checks, failures;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; printf("FAIL line=%u %s\n", __LINE__, #expr); } } while (0)
static DWORD WINAPI join_monitor(void *p) { static_cast<HttpCancellationMonitor *>(p)->join(); return 0; }
int main()
{
    {
        Request request; std::atomic<bool> cancel{false}; HttpCancellationMonitor monitor;
        CHECK(SUCCEEDED(monitor.start(reinterpret_cast<HINTERNET>(&request), &cancel)));
        CHECK(!request.aborts); cancel = true;
        CHECK(WaitForSingleObject(request.entered, 1000) == WAIT_OBJECT_0);
        monitor.join(); CHECK(request.aborts == 1); CHECK(!request.violation);
        cancel = false; cancel = true; monitor.join(); CHECK(request.aborts == 1);
        request.alive = false;
    }
    {
        Request a,b; std::atomic<bool> ca{false},cb{false}; HttpCancellationMonitor ma,mb;
        CHECK(SUCCEEDED(ma.start(reinterpret_cast<HINTERNET>(&a), &ca)));
        CHECK(SUCCEEDED(mb.start(reinterpret_cast<HINTERNET>(&b), &cb)));
        ca = true; CHECK(WaitForSingleObject(a.entered,1000) == WAIT_OBJECT_0);
        ma.join(); CHECK(a.aborts == 1); CHECK(b.aborts == 0);
        mb.join(); b.alive = false; CHECK(!b.violation);
    }
    {
        Request request; ResetEvent(request.release); std::atomic<bool> cancel{true}; HttpCancellationMonitor monitor;
        CHECK(SUCCEEDED(monitor.start(reinterpret_cast<HINTERNET>(&request), &cancel)));
        CHECK(WaitForSingleObject(request.entered,1000) == WAIT_OBJECT_0);
        HANDLE thread = CreateThread(nullptr,0,join_monitor,&monitor,0,nullptr);
        CHECK(thread != nullptr); CHECK(WaitForSingleObject(thread,50) == WAIT_TIMEOUT);
        CHECK(request.alive); SetEvent(request.release);
        CHECK(WaitForSingleObject(thread,1000) == WAIT_OBJECT_0); CloseHandle(thread);
        request.alive = false; CHECK(request.aborts == 1); CHECK(!request.violation);
    }
    {
        Request request; std::atomic<bool> cancel{true}; HttpCancellationMonitor monitor;
        supported = false;
        CHECK(SUCCEEDED(monitor.start(reinterpret_cast<HINTERNET>(&request), &cancel)));
        monitor.join(); CHECK(request.aborts == 0); supported = true;
        CHECK(SUCCEEDED(monitor.start(reinterpret_cast<HINTERNET>(&request), nullptr)));
        monitor.join(); CHECK(request.aborts == 0);
    }
    for (bool event : {false,true})
    {
        Request request; std::atomic<bool> cancel{true}; HttpCancellationMonitor monitor;
        failEvent = event; failThread = !event;
        CHECK(monitor.start(reinterpret_cast<HINTERNET>(&request), &cancel) == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY));
        monitor.join(); CHECK(request.aborts == 0); CHECK(!request.violation);
        failThread = failEvent = false;
    }
    printf("CHECKS %u FAILURES %u\n", checks, failures);
    return failures ? 1 : 0;
}
