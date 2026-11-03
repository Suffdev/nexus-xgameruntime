/* Account-free regression: the actual queue implementation, real manual event waits.
 * Only this fixture's build suppresses TP arming to force the losing-manual race. */
#include <bits/stdc++.h>
#include "src/private.h"
#define private public
#include "src/System/Threading/XTaskQueue.h"
#undef private
#include "src/System/Threading/QueueHandles.h"
#undef SetThreadpoolWait
#undef WaitForMultipleObjects
#undef DisassociateCurrentThreadFromCallback
static std::atomic<bool> suppress{true};
extern "C" void WINAPI NexusWaiterSetThreadpoolWait(PTP_WAIT wait,HANDLE handle,PFILETIME timeout)
{
    if(handle && suppress.load()) return;
    SetThreadpoolWait(wait,handle,timeout);
}
static HANDLE snapshotEntered, snapshotRelease;
static std::atomic<DWORD> snapshotThread{};
static std::atomic<void*> watched{};
static std::atomic<unsigned> deletedCount{};
static HANDLE watchedFreed;
void operator delete(void* p) noexcept { if(p&&p==watched.load()){++deletedCount;if(watchedFreed)SetEvent(watchedFreed);} free(p); }
void operator delete(void* p,size_t) noexcept { ::operator delete(p); }
extern "C" DWORD WINAPI NexusWaiterWaitForMultipleObjects(DWORD n,const HANDLE* handles,BOOL all,DWORD timeout)
{
    DWORD expected=GetCurrentThreadId();
    if(snapshotThread.compare_exchange_strong(expected,0))
    {
        SetEvent(snapshotEntered);
        if(WaitForSingleObject(snapshotRelease,5000)!=WAIT_OBJECT_0) return WAIT_TIMEOUT;
    }
    return WaitForMultipleObjects(n,handles,all,timeout);
}
static HANDLE retainedEntered,retainedRelease;
static std::atomic<bool> retainedArmed{},retainedTimedOut{};
extern "C" void WINAPI NexusWaiterDisassociate(PTP_CALLBACK_INSTANCE instance)
{
    DisassociateCurrentThreadFromCallback(instance);
    if(retainedArmed.exchange(false))
    {
        SetEvent(retainedEntered);
        if(WaitForSingleObject(retainedRelease,5000)!=WAIT_OBJECT_0)retainedTimedOut=true;
    }
}
static std::atomic<unsigned> checks{},failures{};
#define CHECK(x,label) do { ++checks; if(!(x)) {++failures;printf("FAIL %s line=%d\n",label,__LINE__);fflush(stdout);} } while(0)
struct State { LONG calls=0,canceled=0; XTaskQueueHandle queue=nullptr; XTaskQueueRegistrationToken token{}; HANDLE done=nullptr; bool unregister=false;bool close=false; };
static void WINAPI task(void* p,BOOLEAN canceled) {auto s=(State*)p;InterlockedIncrement(&s->calls);if(canceled)InterlockedIncrement(&s->canceled);}
static void WINAPI terminated(void* p) {SetEvent((HANDLE)p);}
static void drain(XTaskQueueHandle q) {for(unsigned n=0;n<64;++n){bool a=XTaskQueueDispatch(q,XTaskQueuePort::Work,0);bool b=XTaskQueueDispatch(q,XTaskQueuePort::Completion,0);if(!a&&!b)return;}CHECK(false,"bounded-drain");}
static void manual(bool shared)
{
    suppress=true;
    State base,composite;HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr),other=shared?event:CreateEventW(nullptr,FALSE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Manual,XTaskQueueDispatchMode::Manual,&base.queue)),"create-base");
    XTaskQueuePortHandle handle;CHECK(SUCCEEDED(XTaskQueueGetPort(base.queue,XTaskQueuePort::Work,&handle)),"get-port");
    auto port=static_cast<TaskQueuePortImpl*>(handle->m_port);
    CHECK(SUCCEEDED(XTaskQueueCreateComposite(handle,handle,&composite.queue)),"create-composite");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(base.queue,XTaskQueuePort::Work,event,&base,task,&base.token)),"register-base");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(composite.queue,XTaskQueuePort::Work,other,&composite,task,&composite.token)),"register-composite");
    auto surviving=port->m_waits[0];
    for(unsigned n=0;n<8;++n) XTaskQueueDispatch(base.queue,XTaskQueuePort::Work,0);
    CHECK(surviving->refs.load()==1,"timeout-snapshot-refs-balanced");
    HANDLE done=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueTerminate(composite.queue,false,done,terminated)),"terminate-composite");drain(base.queue);
    CHECK(WaitForSingleObject(done,0)==WAIT_OBJECT_0,"composite-termination-complete");
    CHECK(composite.calls==1&&composite.canceled==1,"composite-canceled-once");
    CHECK(port->m_waits.count()==1&&port->m_waits[0]==surviving,"sibling-registration-retained");
    CHECK(port->m_events.count()==2,"one-surviving-event-slot");
    CHECK(SetEvent(event),"signal-base");drain(base.queue);
    CHECK(base.calls==1&&base.canceled==0,"base-manual-wait-delivered");
    CHECK(composite.calls==1,"terminated-waiter-not-repeated");
    XTaskQueueUnregisterWaiter(base.queue,base.token);XTaskQueueCloseHandle(composite.queue);XTaskQueueCloseHandle(base.queue);
    CloseHandle(done);CloseHandle(event);if(!shared)CloseHandle(other);
}
static void WINAPI self_callback(void* p,BOOLEAN canceled)
{
    auto s=(State*)p;task(p,canceled);
    if(s->close){XTaskQueueCloseHandle(s->queue);SetEvent(s->done);return;}
    if(s->unregister)XTaskQueueUnregisterWaiter(s->queue,s->token);
    CHECK(SUCCEEDED(XTaskQueueTerminate(s->queue,false,s->done,terminated)),"immediate-self-terminate");
}
static void immediate(bool unregister)
{
    suppress=false;State state;state.unregister=unregister;state.done=CreateEventW(nullptr,TRUE,FALSE,nullptr);HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&state.queue)),"immediate-create");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(state.queue,XTaskQueuePort::Work,event,&state,self_callback,&state.token)),"immediate-register");
    CHECK(SetEvent(event),"immediate-signal");
    if(WaitForSingleObject(state.done,5000)!=WAIT_OBJECT_0){CHECK(false,"immediate-self-drain-completed");printf("CHECKS %u FAILURES %u\n",checks.load(),failures.load());fflush(stdout);ExitProcess(1);}
    CHECK(state.calls==1&&state.canceled==0,"immediate-once-not-canceled");XTaskQueueCloseHandle(state.queue);CloseHandle(event);CloseHandle(state.done);
}
struct DispatchWork { XTaskQueueHandle queue; };
static DWORD WINAPI held_dispatch(void* p)
{
    snapshotThread=GetCurrentThreadId();
    XTaskQueueDispatch(((DispatchWork*)p)->queue,XTaskQueuePort::Work,5000);
    return 0;
}
static void held_snapshot()
{
    suppress=true;
    State base,composite;HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Manual,XTaskQueueDispatchMode::Manual,&base.queue)),"snapshot-base");
    XTaskQueuePortHandle handle;CHECK(SUCCEEDED(XTaskQueueGetPort(base.queue,XTaskQueuePort::Work,&handle)),"snapshot-port");
    auto port=static_cast<TaskQueuePortImpl*>(handle->m_port);
    CHECK(SUCCEEDED(XTaskQueueCreateComposite(handle,handle,&composite.queue)),"snapshot-composite");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(composite.queue,XTaskQueuePort::Work,event,&composite,task,&composite.token)),"snapshot-register");
    auto registration=port->m_waits[0];watched=registration;deletedCount=0;
    drain(base.queue);snapshotEntered=CreateEventW(nullptr,TRUE,FALSE,nullptr);snapshotRelease=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    DispatchWork work{base.queue};HANDLE worker=CreateThread(nullptr,0,held_dispatch,&work,0,nullptr);
    CHECK(WaitForSingleObject(snapshotEntered,5000)==WAIT_OBJECT_0,"snapshot-held-before-removal");
    CHECK(SUCCEEDED(XTaskQueueTerminate(composite.queue,false,nullptr,nullptr)),"snapshot-terminate");
    if(deletedCount.load()) {CHECK(false,"snapshot-registration-not-prematurely-freed");printf("CHECKS %u FAILURES %u\n",checks.load(),failures.load());fflush(stdout);ExitProcess(1);}
    CHECK(registration->deleted&&registration->refs.load()>=1,"snapshot-reference-retained");
    SetEvent(snapshotRelease);CHECK(WaitForSingleObject(worker,5000)==WAIT_OBJECT_0,"snapshot-dispatch-unwound");drain(base.queue);
    CHECK(deletedCount.load()==1,"snapshot-registration-freed-once-after-drain");
    CHECK(composite.calls==1&&composite.canceled==1,"snapshot-cancellation-once");watched=nullptr;
    XTaskQueueCloseHandle(composite.queue);XTaskQueueCloseHandle(base.queue);CloseHandle(worker);CloseHandle(snapshotEntered);CloseHandle(snapshotRelease);CloseHandle(event);
}
struct CloseGate: XTaskQueueTestHooks
{
    HANDLE entered=CreateEventW(nullptr,TRUE,FALSE,nullptr),release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    bool first=true;
    void PendingEntriesRemovedDuringTermination(XTaskQueuePort) override
    {
        if(!first)return;first=false;SetEvent(entered);CHECK(WaitForSingleObject(release,5000)==WAIT_OBJECT_0,"owner-zero-barrier-released");
    }
    ~CloseGate(){CloseHandle(entered);CloseHandle(release);}
};
static DWORD WINAPI close_queue(void* p) {XTaskQueueCloseHandle((XTaskQueueHandle)p);return 0;}
static void owner_zero()
{
    suppress=true;
    State base,composite;HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Manual,XTaskQueueDispatchMode::Manual,&base.queue)),"zero-base");
    XTaskQueuePortHandle port;CHECK(SUCCEEDED(XTaskQueueGetPort(base.queue,XTaskQueuePort::Work,&port)),"zero-port");
    CHECK(SUCCEEDED(XTaskQueueCreateComposite(port,port,&composite.queue)),"zero-composite");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(composite.queue,XTaskQueuePort::Work,event,&composite,task,&composite.token)),"zero-register");
    CloseGate gate;TaskQueueImpl* owner;
    {auto ref=nexus::acquire_queue(composite.queue);owner=static_cast<TaskQueueImpl*>(ref.get());owner->SetTestHooks(&gate);}
    HANDLE worker=CreateThread(nullptr,0,close_queue,composite.queue,0,nullptr);
    CHECK(WaitForSingleObject(gate.entered,5000)==WAIT_OBJECT_0,"owner-zero-before-partition");
    CHECK(owner->m_refs.load()==0,"owner-really-zero");SetEvent(event);drain(base.queue);
    CHECK(composite.calls==0,"owner-zero-not-resurrected-or-dispatched");SetEvent(gate.release);
    CHECK(WaitForSingleObject(worker,5000)==WAIT_OBJECT_0,"owner-zero-rundown-complete");
    XTaskQueueCloseHandle(base.queue);CloseHandle(worker);CloseHandle(event);
}
struct ExternalState {State state;HANDLE entered,release,exited,workerStarted,workerDone;};
static void WINAPI blocked_callback(void* p,BOOLEAN canceled)
{
    auto s=(ExternalState*)p;task(&s->state,canceled);SetEvent(s->entered);
    CHECK(WaitForSingleObject(s->release,5000)==WAIT_OBJECT_0,"external-callback-release");SetEvent(s->exited);
}
static DWORD WINAPI external_unregister(void* p)
{
    auto s=(ExternalState*)p;SetEvent(s->workerStarted);XTaskQueueUnregisterWaiter(s->state.queue,s->state.token);
    CHECK(WaitForSingleObject(s->exited,0)==WAIT_OBJECT_0,"external-unregister-waits-for-user-context");SetEvent(s->workerDone);return 0;
}
static void external()
{
    suppress=false;ExternalState s{};HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    s.entered=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.release=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.exited=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.workerStarted=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.workerDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&s.state.queue)),"external-create");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(s.state.queue,XTaskQueuePort::Work,event,&s,blocked_callback,&s.state.token)),"external-register");SetEvent(event);
    CHECK(WaitForSingleObject(s.entered,5000)==WAIT_OBJECT_0,"external-callback-entered");HANDLE worker=CreateThread(nullptr,0,external_unregister,&s,0,nullptr);
    CHECK(WaitForSingleObject(s.workerStarted,5000)==WAIT_OBJECT_0,"external-worker-started");
    CHECK(WaitForSingleObject(s.workerDone,250)==WAIT_TIMEOUT,"external-unregister-still-blocked");SetEvent(s.release);
    CHECK(WaitForSingleObject(s.workerDone,5000)==WAIT_OBJECT_0,"external-unregister-finished");CHECK(WaitForSingleObject(worker,5000)==WAIT_OBJECT_0,"external-worker-joined");
    CHECK(s.state.calls==1,"external-single-callback");XTaskQueueCloseHandle(s.state.queue);
    for(HANDLE h:{event,s.entered,s.release,s.exited,s.workerStarted,s.workerDone,worker})CloseHandle(h);
}
struct AsyncTerminate {ExternalState callback;HANDLE terminated;};
static void WINAPI async_terminated(void* p)
{
    auto s=(AsyncTerminate*)p;CHECK(WaitForSingleObject(s->callback.exited,0)==WAIT_OBJECT_0,"async-termination-after-callback");SetEvent(s->terminated);
}
static DWORD WINAPI terminate_async(void* p)
{
    auto s=(AsyncTerminate*)p;SetEvent(s->callback.workerStarted);CHECK(SUCCEEDED(XTaskQueueTerminate(s->callback.state.queue,false,s,async_terminated)),"external-terminate-call");SetEvent(s->callback.workerDone);return 0;
}
static void external_terminate()
{
    suppress=false;AsyncTerminate state{};auto& s=state.callback;HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    s.entered=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.release=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.exited=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.workerStarted=CreateEventW(nullptr,TRUE,FALSE,nullptr);s.workerDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);state.terminated=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&s.state.queue)),"async-create");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(s.state.queue,XTaskQueuePort::Work,event,&s,blocked_callback,&s.state.token)),"async-register");SetEvent(event);
    CHECK(WaitForSingleObject(s.entered,5000)==WAIT_OBJECT_0,"async-callback-entered");HANDLE worker=CreateThread(nullptr,0,terminate_async,&state,0,nullptr);
    CHECK(WaitForSingleObject(s.workerStarted,5000)==WAIT_OBJECT_0,"async-worker-started");
    bool returned=WaitForSingleObject(s.workerDone,500)==WAIT_OBJECT_0;CHECK(returned,"terminate-false-returns-before-user-release");printf("ASYNC_RETURNED_BEFORE_RELEASE %u\n",returned);fflush(stdout);
    CHECK(WaitForSingleObject(state.terminated,0)==WAIT_TIMEOUT,"termination-not-premature");SetEvent(s.release);
    CHECK(WaitForSingleObject(s.workerDone,5000)==WAIT_OBJECT_0,"async-call-complete");CHECK(WaitForSingleObject(state.terminated,5000)==WAIT_OBJECT_0,"async-termination-complete");CHECK(WaitForSingleObject(worker,5000)==WAIT_OBJECT_0,"async-worker-joined");
    XTaskQueueCloseHandle(s.state.queue);for(HANDLE h:{event,s.entered,s.release,s.exited,s.workerStarted,s.workerDone,state.terminated,worker})CloseHandle(h);
}
static void self_close()
{
    suppress=false;State s;s.close=true;s.done=CreateEventW(nullptr,TRUE,FALSE,nullptr);HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&s.queue)),"self-close-create");
    XTaskQueuePortHandle h;CHECK(SUCCEEDED(XTaskQueueGetPort(s.queue,XTaskQueuePort::Work,&h)),"self-close-port");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(s.queue,XTaskQueuePort::Work,event,&s,self_callback,&s.token)),"self-close-register");
    watched=static_cast<TaskQueuePortImpl*>(h->m_port)->m_waits[0];deletedCount=0;watchedFreed=CreateEventW(nullptr,TRUE,FALSE,nullptr);SetEvent(event);
    CHECK(WaitForSingleObject(s.done,5000)==WAIT_OBJECT_0,"self-close-user-callback-returned");
    CHECK(WaitForSingleObject(watchedFreed,5000)==WAIT_OBJECT_0,"self-close-owner-rundown-drained");
    CHECK(deletedCount.load()==1&&s.calls==1,"self-close-single-release");watched=nullptr;CloseHandle(watchedFreed);watchedFreed=nullptr;CloseHandle(event);CloseHandle(s.done);
}
static void retained_skip()
{
    suppress=false;State s;HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr),done=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    retainedEntered=CreateEventW(nullptr,TRUE,FALSE,nullptr);retainedRelease=CreateEventW(nullptr,TRUE,FALSE,nullptr);retainedTimedOut=false;
    CHECK(SUCCEEDED(XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&s.queue)),"retained-create");
    XTaskQueuePortHandle h;CHECK(SUCCEEDED(XTaskQueueGetPort(s.queue,XTaskQueuePort::Work,&h)),"retained-port");
    CHECK(SUCCEEDED(XTaskQueueRegisterWaiter(s.queue,XTaskQueuePort::Work,event,&s,task,&s.token)),"retained-register");
    watched=static_cast<TaskQueuePortImpl*>(h->m_port)->m_waits[0];deletedCount=0;watchedFreed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    retainedArmed=true;SetEvent(event);CHECK(WaitForSingleObject(retainedEntered,5000)==WAIT_OBJECT_0,"retained-before-append");
    CHECK(SUCCEEDED(XTaskQueueTerminate(s.queue,false,done,terminated)),"retained-terminate-false");
    CHECK(s.calls==1&&s.canceled==1,"retained-canceled-once");
    CHECK(WaitForSingleObject(done,0)==WAIT_TIMEOUT,"retained-termination-not-premature");
    CHECK(SetEvent(retainedRelease),"retained-release");CHECK(WaitForSingleObject(done,5000)==WAIT_OBJECT_0,"skipped-tail-completes-termination");
    CHECK(WaitForSingleObject(watchedFreed,5000)==WAIT_OBJECT_0,"retained-registration-released");
    CHECK(!retainedTimedOut.load()&&s.calls==1&&deletedCount.load()==1,"retained-no-late-duplicate");
    watched=nullptr;CloseHandle(watchedFreed);watchedFreed=nullptr;XTaskQueueCloseHandle(s.queue);
    for(HANDLE handle:{event,done,retainedEntered,retainedRelease})CloseHandle(handle);
}
static bool run_case(const char* name)
{
    if(!strcmp(name,"manual")){manual(false);manual(true);}
    else if(!strcmp(name,"self-unregister"))immediate(true);
    else if(!strcmp(name,"self-terminate"))immediate(false);
    else if(!strcmp(name,"snapshot"))held_snapshot();
    else if(!strcmp(name,"owner-zero"))owner_zero();
    else if(!strcmp(name,"external"))external();
    else if(!strcmp(name,"external-terminate"))external_terminate();
    else if(!strcmp(name,"self-close"))self_close();
    else if(!strcmp(name,"retained-skip"))retained_skip();
    else return false;
    return true;
}
int main(int argc,char**argv)
{
    if(argc==1){for(auto name:{"manual","snapshot","owner-zero","retained-skip","self-unregister","self-terminate","external","external-terminate","self-close"})run_case(name);}
    else if(argc!=2||!run_case(argv[1]))return 2;
    printf("CHECKS %u FAILURES %u\n",checks.load(),failures.load());return failures.load()?1:0;
}
