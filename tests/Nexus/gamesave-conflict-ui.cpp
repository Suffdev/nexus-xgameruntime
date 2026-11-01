/* SPDX-License-Identifier: MIT
 * Actual modal UI with synthetic controller states; no account, network or saves. */
#include <algorithm>
#include <windows.h>
#include <xinput.h>
#include <stdio.h>
#include <wchar.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
enum class SaveConflictChoice { Cancel, Local, Cloud };
static volatile LONG buttons;
static unsigned checks, failures;
#define CHECK(label,expr) do {++checks;if(!(expr)){++failures;printf("FAIL %s\n",label);fflush(stdout);}}while(0)
static DWORD WINAPI fake_state(DWORD index,XINPUT_STATE*out){if(index)return ERROR_DEVICE_NOT_CONNECTED;*out={};out->Gamepad.wButtons=(WORD)InterlockedCompareExchange(&buttons,0,0);return ERROR_SUCCESS;}
static FARPROC proc(HMODULE module,LPCSTR name){return !strcmp(name,"XInputGetState")?(FARPROC)fake_state:GetProcAddress(module,name);}
#define GetProcAddress proc
#include "../../src/System/GameSave/ConflictDialog.h"
#undef GetProcAddress
static HWND parent;
static unsigned scenario;
static void press(WORD button){InterlockedExchange(&buttons,button);Sleep(180);InterlockedExchange(&buttons,0);Sleep(180);}
static DWORD WINAPI exercise(void*){
 HWND dialog=NULL;for(int i=0;i<100&&!dialog;i++){Sleep(100);dialog=FindWindowW(NULL,L"Nexus - Cloud saves");}
 CHECK("dialog-visible",dialog!=NULL);if(!dialog)return 1;Sleep(300);
 CHECK("modal-owned-by-game",GetWindow(dialog,GW_OWNER)==parent);
 CHECK("dialog-has-foreground",GetForegroundWindow()==dialog);
 GUITHREADINFO gui={sizeof(gui)};GetGUIThreadInfo(GetWindowThreadProcessId(dialog,NULL),&gui);
 CHECK("default-cancel",gui.hwndFocus==GetDlgItem(dialog,IDCANCEL));
 RECT work,rect;SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);GetWindowRect(dialog,&rect);
 CHECK("fits-screen",rect.left>=work.left&&rect.top>=work.top&&rect.right<=work.right&&rect.bottom<=work.bottom);
 for(int id:{100,101,IDCANCEL}){RECT child;GetWindowRect(GetDlgItem(dialog,id),&child);CHECK("button-visible",IsWindowVisible(GetDlgItem(dialog,id))&&child.left>=rect.left&&child.right<=rect.right&&child.top>=rect.top&&child.bottom<=rect.bottom);}
 if(scenario==3){CHECK("held-A-does-not-dismiss",IsWindow(dialog));InterlockedExchange(&buttons,0);Sleep(200);}
 if(scenario==0){press(XINPUT_GAMEPAD_DPAD_RIGHT);press(XINPUT_GAMEPAD_A);}
 else if(scenario==1){press(XINPUT_GAMEPAD_DPAD_LEFT);press(XINPUT_GAMEPAD_A);}
 else if(scenario==4){PostMessageW(dialog,WM_KEYDOWN,VK_ESCAPE,0);PostMessageW(dialog,WM_KEYUP,VK_ESCAPE,0);}
 else press(XINPUT_GAMEPAD_B);
 for(int i=0;i<20&&IsWindow(dialog);i++)Sleep(100);
 CHECK("input-dismissed-dialog",!IsWindow(dialog));if(IsWindow(dialog))PostMessageW(dialog,WM_CLOSE,0,0);
 return 0;
}
int main(){
 WNDCLASSW cls={};cls.lpfnWndProc=DefWindowProcW;cls.hInstance=GetModuleHandleW(NULL);cls.lpszClassName=L"SaveConflictFixture";RegisterClassW(&cls);
 parent=CreateWindowExW(0,cls.lpszClassName,L"Synthetic game window",WS_OVERLAPPEDWINDOW|WS_VISIBLE,10,10,500,350,NULL,NULL,cls.hInstance,NULL);
 for(scenario=0;scenario<5;scenario++){
  SetForegroundWindow(parent);buttons=scenario==3?XINPUT_GAMEPAD_A:0;
  HANDLE worker=CreateThread(NULL,0,exercise,NULL,0,NULL);
  auto result=show_save_conflict(L"Local and cloud progress differ. Choose the version to use.\n\nSave: Campaign\nLOCAL: 2026-11-01T20:15:00Z (245760 bytes)\nCLOUD: 2026-11-01T16:10:00Z (204800 bytes)\n\nBoth versions are backed up in:\nC:\\Nexus\\Saves\\.conflict-example\n\nCancel keeps both versions unchanged.");
  WaitForSingleObject(worker,6000);CloseHandle(worker);
  CHECK("selected-expected-choice",result==(scenario==0?SaveConflictChoice::Local:scenario==1?SaveConflictChoice::Cloud:SaveConflictChoice::Cancel));
 }
 DestroyWindow(parent);printf("CHECKS %u FAILURES %u\n",checks,failures);return failures?1:0;
}
