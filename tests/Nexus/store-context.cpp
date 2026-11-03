// SPDX-License-Identifier: LGPL-2.1-or-later
// Exact WinRT objects, synthetic receipts only. No real service can be called.
#define INITGUID
#include "../../src/private.h"
#include <xstore.h>
#include <cstdio>
#include <ctime>
#include <atomic>
#include "../../src/System/Store/StoreContext.h"
static std::atomic<int> queries{0};
static std::atomic<bool> gate{false};
static HRESULT verdict = S_OK;
static XStoreGameLicense receipt{};
namespace nexus_store_context
{
static HRESULT query_addon_licenses(AddonLicenseSnapshot *out) { *out = {}; return E_ACCESSDENIED; }
static HRESULT query_game_license( XStoreGameLicense *out, const std::atomic<bool> &canceled, HANDLE )
{
    ++queries;
    for ( int i=0; gate && !canceled && i<500; ++i ) Sleep(1);
    *out = receipt;
    return canceled ? E_ABORT : verdict;
}
}
using namespace nexus_store_context;
static unsigned checks=0,failures=0;
#define CHECK(expr) do { ++checks; if(!(expr)){++failures;printf("FAIL line=%d\n",__LINE__);} } while(0)
class Handler final : public ICompletedHandler_
{
public:
    std::atomic<ULONG> refs{1};
    std::atomic<int> calls{0};
    std::atomic<int> terminal{-1};
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID,void **out) override { if(!out)return E_POINTER;*out=this;AddRef();return S_OK; }
    ULONG STDMETHODCALLTYPE AddRef() override {return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override {return --refs;}
    HRESULT STDMETHODCALLTYPE Invoke(IAsyncOperation_StoreAppLicense *,int status) override {terminal=status;++calls;return S_OK;}
};
static int wait(AppLicenseOperation *op)
{
    int state=0;
    for(int i=0;i<3000;++i){if(op->get_Status(&state)!=S_OK||state!=STATUS_STARTED)break;Sleep(1);}
    return state;
}
static bool activeOperation()
{
    auto *op=new AppLicenseOperation;
    CHECK(op->start()==S_OK);
    CHECK(wait(op)==STATUS_COMPLETED);
    IStoreAppLicense_ *result=nullptr;
    CHECK(op->GetResults(&result)==S_OK && result);
    boolean active=false;
    if(result){CHECK(result->get_IsActive(&active)==S_OK);result->Release();}
    op->Release();
    return active;
}
int main()
{
    void *unknown=nullptr;
    CHECK(DllGetActivationFactory(nullptr,nullptr)==E_POINTER);
    HSTRING name=nullptr;
    const WCHAR *className=L"Windows.Services.Store.StoreContext";
    CHECK(WindowsCreateString(className,wcslen(className),&name)==S_OK);
    CHECK(DllGetActivationFactory(name,&unknown)==S_OK && unknown);
    WindowsDeleteString(name);
    if(!unknown)return 1;
    auto *activation=static_cast<IActivationFactory_ *>(unknown);
    IStoreContextStatics_ *statics=nullptr;
    CHECK(activation->QueryInterface(IID_IStoreContextStatics,(void **)&statics)==S_OK);
    CHECK(statics->GetDefault(nullptr)==E_POINTER);
    IStoreContext_ *ctx=nullptr;
    CHECK(statics->GetDefault(&ctx)==S_OK && ctx);
    CHECK(statics->GetForUser(ctx,&ctx)==E_NOTIMPL && !ctx);
    CHECK(statics->GetDefault(&ctx)==S_OK);
    CHECK(ctx->GetAppLicenseAsync(nullptr)==E_POINTER);
    CHECK(ctx->get_User(nullptr)==E_POINTER);
    INT64 event=99;
    CHECK(ctx->add_OfflineLicensesChanged(nullptr,&event)==E_NOTIMPL && event==0);
    CHECK(ctx->remove_OfflineLicensesChanged(99)==E_NOTIMPL);
    CHECK(ctx->QueryInterface(IID_IUnknown,nullptr)==E_POINTER);
    AppLicense empty({});
    boolean active=true;
    CHECK(empty.get_IsActive(&active)==S_OK && !active);
    CHECK(empty.get_IsActive(nullptr)==E_POINTER);
    CHECK(empty.get_IsTrial(nullptr)==E_POINTER);
    CHECK(empty.get_ExpirationDate(nullptr)==E_POINTER);
    CHECK(empty.get_SkuStoreId(nullptr)==E_POINTER);
    CHECK(empty.GetRuntimeClassName(nullptr)==E_POINTER);
    receipt.isActive=true;receipt.expirationDate=std::time(nullptr)+60;
    CHECK(activeOperation());
    verdict=E_ACCESSDENIED;
    auto *failed=new AppLicenseOperation;
    Handler failedHandler;
    CHECK(failed->put_Completed(&failedHandler)==S_OK);
    CHECK(failed->start()==S_OK);
    CHECK(wait(failed)==STATUS_ERROR);
    HRESULT failure=S_OK;
    CHECK(failed->get_ErrorCode(&failure)==S_OK && failure==E_ACCESSDENIED);
    IStoreAppLicense_ *denied=reinterpret_cast<IStoreAppLicense_ *>(1);
    CHECK(failed->GetResults(&denied)==E_ACCESSDENIED && !denied);
    for(int i=0;i<100 && !failedHandler.calls;++i)Sleep(1);
    CHECK(failedHandler.calls==1 && failedHandler.terminal==STATUS_ERROR);
    failed->Release();
    Sleep(10);
    CHECK(failedHandler.refs==1);
    verdict=S_OK;receipt.isActive=false;
    CHECK(!activeOperation()); // Different account, no rights.
    receipt.isActive=true;receipt.expirationDate=std::time(nullptr)-1;
    CHECK(!activeOperation());
    CHECK(queries==4);
    auto *op=new AppLicenseOperation;
    Handler handler;
    gate=true;
    CHECK(op->start()==S_OK);
    CHECK(op->put_Completed(&handler)==S_OK);
    CHECK(op->put_Completed(&handler)==E_ILLEGAL_DELEGATE_ASSIGNMENT_);
    CHECK(op->Close()==E_ILLEGAL_METHOD_CALL_);
    CHECK(op->Cancel()==S_OK);
    CHECK(wait(op)==STATUS_CANCELED);
    CHECK(handler.calls==1 && handler.terminal==STATUS_CANCELED);
    IStoreAppLicense_ *result=reinterpret_cast<IStoreAppLicense_ *>(1);
    CHECK(op->GetResults(&result)==E_ABORT && !result);
    ICompletedHandler_ *retained=nullptr;
    CHECK(op->get_Completed(&retained)==S_OK && retained==&handler);
    if(retained)retained->Release();
    CHECK(op->Cancel()==S_OK && handler.calls==1);
    gate=false;
    Sleep(30);
    CHECK(handler.calls==1);
    CHECK(op->Close()==S_OK);
    int status;
    CHECK(op->get_Status(&status)==RO_E_CLOSED);
    CHECK(op->GetResults(&result)==RO_E_CLOSED);
    op->Release();
    Sleep(10);
    CHECK(handler.refs==1);
    gate=false;
    auto *done=new AppLicenseOperation;
    CHECK(done->start()==S_OK);
    CHECK(wait(done)==STATUS_COMPLETED);
    Handler late;
    CHECK(done->put_Completed(&late)==S_OK && late.calls==1);
    CHECK(done->get_Completed(&retained)==S_OK && retained==&late);
    if(retained)retained->Release();
    CHECK(done->Cancel()==S_OK && late.calls==1);
    done->Release();Sleep(10);
    CHECK(late.refs==1);
    activation->Release();
    statics->Release();
    ctx->Release();
    printf("CHECKS %u FAILURES %u\n",checks,failures);
    return failures?1:0;
}
