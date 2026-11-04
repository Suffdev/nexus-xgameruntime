// Test-build API interposition only; production objects never include this header.
#include <winsock2.h>
#include <windows.h>
extern "C" void WINAPI NexusWaiterSetThreadpoolWait(PTP_WAIT,HANDLE,PFILETIME);
extern "C" DWORD WINAPI NexusWaiterWaitForMultipleObjects(DWORD,const HANDLE*,BOOL,DWORD);
extern "C" void WINAPI NexusWaiterDisassociate(PTP_CALLBACK_INSTANCE);
#define DisassociateCurrentThreadFromCallback NexusWaiterDisassociate
#define SetThreadpoolWait NexusWaiterSetThreadpoolWait
#define WaitForMultipleObjects NexusWaiterWaitForMultipleObjects
