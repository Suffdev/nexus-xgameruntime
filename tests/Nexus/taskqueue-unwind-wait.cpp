/* Account-free actual-port unwind regression. No timer or OS interception. */
#include <bits/stdc++.h>
#include "src/private.h"
#define private public
#include "src/System/Threading/XTaskQueue.h"
#undef private
#include "src/System/Threading/QueueHandles.h"
static unsigned checks, failures;
#define CHECK(x) do { ++checks; if(!(x)){++failures;printf("FAIL line=%d\n",__LINE__);} } while(0)
struct Held { HANDLE entered, release; DWORD result=WAIT_FAILED; };
static void WINAPI callback(void* p, BOOLEAN) { auto h=static_cast<Held*>(p); SetEvent(h->entered); h->result=WaitForSingleObject(h->release,5000); }
static uint64_t value(FILETIME f) { return (uint64_t(f.dwHighDateTime)<<32)|f.dwLowDateTime; }
int main() {
 XTaskQueueHandle q=nullptr; CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::ThreadPool,XTaskQueueDispatchMode::ThreadPool,&q)));
 Held held{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
 CHECK(SUCCEEDED(XTaskQueueSubmitCallback(q,XTaskQueuePort::Work,&held,callback)));
 CHECK(WaitForSingleObject(held.entered,5000)==WAIT_OBJECT_0);
 XTaskQueuePortHandle h; CHECK(SUCCEEDED(XTaskQueueGetPort(q,XTaskQueuePort::Work,&h)));
 auto port=static_cast<TaskQueuePortImpl*>(h->m_port);
 HANDLE entered=CreateEventW(nullptr,TRUE,FALSE,nullptr),done=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 uint64_t cpu=0; BOOL timesBefore=FALSE,timesAfter=FALSE; std::thread waiter([&]{FILETIME c{},e{},k0{},u0{},k1{},u1{}; timesBefore=GetThreadTimes(GetCurrentThread(),&c,&e,&k0,&u0);SetEvent(entered);port->WaitForUnwind();timesAfter=GetThreadTimes(GetCurrentThread(),&c,&e,&k1,&u1);cpu=value(k1)+value(u1)-value(k0)-value(u0);SetEvent(done);});
 CHECK(WaitForSingleObject(entered,5000)==WAIT_OBJECT_0);
 HANDLE entered2=CreateEventW(nullptr,TRUE,FALSE,nullptr),done2=CreateEventW(nullptr,TRUE,FALSE,nullptr);
 std::thread waiter2([&]{SetEvent(entered2);port->WaitForUnwind();SetEvent(done2);});
 CHECK(WaitForSingleObject(entered2,5000)==WAIT_OBJECT_0);
 CHECK(WaitForSingleObject(done2,0)==WAIT_TIMEOUT);
 CHECK(WaitForSingleObject(done,250)==WAIT_TIMEOUT);
 CHECK(SetEvent(held.release));
 auto finish=[&](HANDLE event){DWORD result=WaitForSingleObject(event,5000);CHECK(result==WAIT_OBJECT_0);if(result!=WAIT_OBJECT_0){printf("CHECKS %u FAILURES %u\n",checks,failures);fflush(stdout);ExitProcess(1);}};
 finish(done);waiter.join();finish(done2);waiter2.join();CHECK(timesBefore);CHECK(timesAfter);CHECK(held.result==WAIT_OBJECT_0);CloseHandle(entered2);CloseHandle(done2);
 CHECK(port->m_processingCallback.load()==0);
 // A second call with no active work must return immediately, not require a notification.
 port->WaitForUnwind(); CHECK(true);
 CHECK(SUCCEEDED(XTaskQueueTerminate(q,true,nullptr,nullptr)));XTaskQueueCloseHandle(q);
 for(HANDLE e:{held.entered,held.release,entered,done})CloseHandle(e);
 printf("HELD_MS 250 WAITER_CPU_100NS %llu\nCHECKS %u FAILURES %u\n",(unsigned long long)cpu,checks,failures);return failures?1:0;
}
