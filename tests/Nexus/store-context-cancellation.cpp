// SPDX-License-Identifier: LGPL-2.1-or-later
// Exact WinRT adapter + entitlement provider. IPC and public send are local
// fixtures; no account service, real receipt or production trust override.
#define INITGUID
#include "../../src/private.h"
#include <xstore.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <atomic>
#include <cstdio>
#include <ctime>
#include "../../src/Runtime/Configuration.h"
static HANDLE bridge_started, bridge_gate, forwarded, callback_gate, worker_result;
static std::atomic<int> public_sends{0}, bridge_calls{0}, query_calls{0};
static std::atomic<HRESULT> worker_hr{E_PENDING};
static const char *store_id = "B00000000001";
static HRESULT bridge_hr = S_OK;
static std::string bridge_jwt;
static int query_fail_at;
static HRESULT (WINAPI *runtime_query)(REFCLSID, REFIID, void **);
static HRESULT WINAPI FixtureQueryApiImpl(REFCLSID clsid, REFIID iid, void **out)
{
    if (++query_calls == query_fail_at) { *out = nullptr; return E_OUTOFMEMORY; }
    return runtime_query(clsid, iid, out);
}
namespace nexus
{
const GameConfiguration *GetGameConfiguration() noexcept { static GameConfiguration value; return &value; }
}
UINT64 xuser_get_xuid(XUserHandle) { return 1; }
static const char *GetStoreProductId() { return store_id; }
HRESULT xodus_store_license_body(const char **, SIZE_T, const char *, char **out)
{
    *out = strdup("synthetic"); return *out ? S_OK : E_OUTOFMEMORY;
}
HRESULT xodus_store_license_xml(const char *, SIZE_T, char **out)
{
    *out = nullptr; ++bridge_calls;
    SetEvent(bridge_started);
    if (WaitForSingleObject(bridge_gate, 10000) != WAIT_OBJECT_0) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    if (SUCCEEDED(bridge_hr)) *out = strdup(bridge_jwt.c_str());
    return bridge_hr;
}
HRESULT xodus_store_license_xml(const char *request, SIZE_T size, char **out, LONG *, ULONGLONG)
{
    return xodus_store_license_xml(request, size, out);
}
void xodus_store_license_note(const char *phase, HRESULT hr)
{
    if (!strcmp(phase, "store-entitled-result")) { worker_hr = hr; SetEvent(worker_result); }
}
static BOOL WINAPI FixturePublicSend(HINTERNET, LPCWSTR, DWORD, void *, DWORD, DWORD, DWORD_PTR)
{
    ++public_sends; SetLastError(ERROR_CANCELLED); return FALSE;
}
#define QueryApiImpl FixtureQueryApiImpl
#define WinHttpSendRequest FixturePublicSend
#include "../../src/System/Store/Entitled.h"
#undef WinHttpSendRequest
#include "../../src/System/Store/StoreContext.h"

// Observe the actual cancellation callback, then optionally hold its return to
// prove teardown fences it even when the underlying worker has already drained.
static bool fail_wait;
static PTP_WAIT_CALLBACK real_notify;
static void *real_notify_context;
static void CALLBACK FixtureNotify(PTP_CALLBACK_INSTANCE instance, void *, PTP_WAIT wait, TP_WAIT_RESULT result)
{
    real_notify(instance, real_notify_context, wait, result);
    SetEvent(forwarded);
    WaitForSingleObject(callback_gate, 10000);
}
static PTP_WAIT WINAPI FixtureCreateWait(PTP_WAIT_CALLBACK notify, void *context, PTP_CALLBACK_ENVIRON environment)
{
    if (fail_wait) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return nullptr; }
    real_notify = notify; real_notify_context = context;
    return CreateThreadpoolWait(FixtureNotify, nullptr, environment);
}
// Success/GetResult-failure cases use the established internal fetch boundary.
// All held-IPC cancellation cases call the unmodified production entitled_begin
// and entitled_fetch above, including receipt_load and guarded public transport.
static int synthetic_mode;
static HRESULT FixtureFetch(const char *, LONG *, entitled_snapshot **out)
{
    auto *s = static_cast<entitled_snapshot *>(calloc(1, sizeof(entitled_snapshot)));
    if (!s) return E_OUTOFMEMORY;
    s->refs = 1; s->valid_until = s->proof_until = std::time(nullptr) + 60;
    s->count = 1; s->products = static_cast<XStoreProduct *>(calloc(1, sizeof(XStoreProduct)));
    auto &p = s->products[0]; p.storeId = strdup("B00000000001"); p.isInUserCollection = TRUE;
    p.productKind = synthetic_mode == 1 ? XStoreProductKind::Game : XStoreProductKind::Durable;
    p.skusCount = 1; p.skus = static_cast<XStoreSku *>(calloc(1, sizeof(XStoreSku)));
    p.skus[0].skuId = strdup("0010"); p.skus[0].isInUserCollection = TRUE;
    p.skus[0].collectionData.endDate = std::time(nullptr) + 60;
    *out = s; return S_OK;
}
static bool FixtureDrain(entitled_async *) { return true; }
template<class Context> static bool FixtureDrain(Context *context, HANDLE event)
{
    return DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &context->drained,
                           0, FALSE, DUPLICATE_SAME_ACCESS);
}
template<class... Drain> static HRESULT FixtureBegin(XStoreContextHandle store, UINT32 kinds, UINT32 size,
                                                     XAsyncBlock *block, BOOL game = FALSE, BOOL current = FALSE, Drain... drain)
{
    if (!synthetic_mode) return entitled_begin(store, kinds, size, block, game, current, drain...);
    auto *context = static_cast<entitled_async *>(calloc(1, sizeof(entitled_async)));
    if (!context) return E_OUTOFMEMORY;
    UINT64 xuid;
    HRESULT hr = entitled_store_identity(store, &xuid, &context->store_serial);
    if (FAILED(hr) || !FixtureDrain(context, drain...)) { free(context); return E_FAIL; }
    context->store = store; context->game = TRUE; context->page_size = size; context->fetch = FixtureFetch;
    context->request = strdup("synthetic");
    return entitled_start(context, block, FALSE);
}
#define entitled_begin FixtureBegin
#define CreateThreadpoolWait FixtureCreateWait
#include "../../src/System/Store/StoreContextLicense.h"
#undef CreateThreadpoolWait
#undef entitled_begin
using namespace nexus_store_context;
static unsigned checks, failures;
#define CHECK(label, expression) do { ++checks; if (!(expression)) { ++failures; printf("FAIL %s line=%d\n", label, __LINE__); } } while(0)
class Handler final : public ICompletedHandler_
{
public:
    std::atomic<ULONG> refs{1};
    std::atomic<int> calls{0}, terminal{-1};
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void **out) override { if (!out) return E_POINTER; *out = this; AddRef(); return S_OK; }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs; }
    HRESULT STDMETHODCALLTYPE Invoke(IAsyncOperation_StoreAppLicense *, int status) override { terminal = status; ++calls; return S_OK; }
};
static bool wait_value(const std::atomic<ULONG> &value, ULONG target)
{
    const auto start = GetTickCount64();
    while (value != target && GetTickCount64() - start < 5000) Sleep(1);
    return value == target;
}
static int terminal(AppLicenseOperation *op)
{
    int status = STATUS_STARTED;
    const auto start = GetTickCount64();
    while (SUCCEEDED(op->get_Status(&status)) && status == STATUS_STARTED && GetTickCount64() - start < 5000) Sleep(1);
    return status;
}
static void reset()
{
    ResetEvent(bridge_started); ResetEvent(bridge_gate); ResetEvent(forwarded); ResetEvent(worker_result);
    SetEvent(callback_gate); bridge_calls = public_sends = query_calls = 0; worker_hr = E_PENDING;
    bridge_hr = S_OK; query_fail_at = 0; fail_wait = false; synthetic_mode = 0; store_id = "B00000000001";
}
static void held_cancel()
{
    reset(); ResetEvent(callback_gate);
    Handler handler;
    auto *op = new AppLicenseOperation;
    CHECK("held-handler", op->put_Completed(&handler) == S_OK);
    CHECK("held-start", op->start() == S_OK);
    CHECK("held-ipc-started", WaitForSingleObject(bridge_started, 3000) == WAIT_OBJECT_0);
    CHECK("held-cancel", op->Cancel() == S_OK);
    CHECK("held-immediate-outer-cancel", terminal(op) == STATUS_CANCELED && handler.calls == 1 && handler.terminal == STATUS_CANCELED);
    IStoreAppLicense_ *license = reinterpret_cast<IStoreAppLicense_ *>(1);
    CHECK("held-no-result", op->GetResults(&license) == E_ABORT && !license);
    CHECK("held-repeat-cancel-once", op->Cancel() == S_OK && handler.calls == 1);
    CHECK("held-forwarded-to-real-child", WaitForSingleObject(forwarded, 1000) == WAIT_OBJECT_0);
    CHECK("held-no-early-worker-completion", WaitForSingleObject(worker_result, 0) == WAIT_TIMEOUT);
    CHECK("held-close", op->Close() == S_OK); op->Release();
    CHECK("held-operation-retained-after-client-release", handler.refs == 2 && entitled_stores != nullptr);
    SetEvent(bridge_gate);
    CHECK("held-worker-drained-after-ipc", WaitForSingleObject(worker_result, 3000) == WAIT_OBJECT_0);
    CHECK("held-child-abort", worker_hr == E_ABORT);
    CHECK("held-certificate-get-skipped", public_sends == 0);
    CHECK("held-callback-fence-retains-operation", handler.refs == 2);
    SetEvent(callback_gate);
    CHECK("held-operation-final-release", wait_value(handler.refs, 1));
    CHECK("held-no-resurrection", handler.calls == 1 && handler.terminal == STATUS_CANCELED);
    CHECK("held-store-drained", entitled_stores == nullptr);
}
static void ordinary(int mode, HRESULT expected)
{
    reset(); synthetic_mode = mode; bridge_hr = E_FAIL; SetEvent(bridge_gate);
    Handler handler; auto *op = new AppLicenseOperation;
    CHECK("ordinary-handler", op->put_Completed(&handler) == S_OK);
    CHECK("ordinary-start", op->start() == S_OK);
    CHECK("ordinary-terminal", terminal(op) == (SUCCEEDED(expected) ? STATUS_COMPLETED : STATUS_ERROR));
    HRESULT hr; CHECK("ordinary-error-preserved", op->get_ErrorCode(&hr) == S_OK && hr == expected);
    IStoreAppLicense_ *license = nullptr;
    CHECK("ordinary-result", op->GetResults(&license) == expected && (!!license == SUCCEEDED(expected)));
    if (license) license->Release();
    op->Release(); CHECK("ordinary-cleanup-drained", wait_value(handler.refs, 1));
    CHECK("ordinary-callback-once", handler.calls == 1);
    CHECK("ordinary-no-store-leak", entitled_stores == nullptr);
}
static void begin_failure(int fail_at, const char *id)
{
    reset(); query_fail_at = fail_at; store_id = id;
    Handler handler; auto *op = new AppLicenseOperation;
    op->put_Completed(&handler); CHECK("begin-failure-start", op->start() == S_OK);
    CHECK("begin-failure-no-drain-deadlock", terminal(op) == STATUS_ERROR);
    HRESULT hr; const auto expected = fail_at ? E_OUTOFMEMORY : E_GAME_MISSING_GAME_CONFIG;
    CHECK("begin-failure-preserved", op->get_ErrorCode(&hr) == S_OK && hr == expected);
    op->Release(); CHECK("begin-failure-worker-release", wait_value(handler.refs, 1));
    CHECK("begin-failure-no-ipc", bridge_calls == 0 && entitled_stores == nullptr);
}
static void registration_failure()
{
    reset(); fail_wait = true;
    Handler handler; auto *op = new AppLicenseOperation; op->put_Completed(&handler);
    CHECK("registration-failure-start", op->start() == S_OK);
    // Cancellation can win before the detached worker starts. In either case
    // cleanup must complete; release the fixture IPC if it was admitted.
    SetEvent(bridge_gate);
    CHECK("registration-failure-terminal", terminal(op) == STATUS_ERROR);
    HRESULT hr; CHECK("registration-failure-truthful", op->get_ErrorCode(&hr) == S_OK && hr == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY));
    op->Release(); CHECK("registration-failure-drain", wait_value(handler.refs, 1));
    CHECK("registration-failure-no-leak", entitled_stores == nullptr && handler.calls == 1);
}
static void pre_canceled()
{
    reset(); Handler handler; auto *op = new AppLicenseOperation; op->put_Completed(&handler);
    CHECK("pre-cancel", op->Cancel() == S_OK && handler.calls == 1);
    CHECK("pre-cancel-start", op->start() == S_OK);
    op->Release(); CHECK("pre-cancel-drain", wait_value(handler.refs, 1));
    CHECK("pre-cancel-no-child", bridge_calls == 0 && query_calls == 0 && handler.calls == 1);
}
int main()
{
    const auto dll = LoadLibraryA("xgameruntime.dll");
    if (!dll || !(runtime_query = reinterpret_cast<decltype(runtime_query)>(GetProcAddress(dll, "QueryApiImpl")))) return 2;
    const auto com = RoInitialize(RO_INIT_MULTITHREADED);
    CHECK("winrt", SUCCEEDED(com));
    bridge_started = CreateEventW(nullptr, TRUE, FALSE, nullptr); bridge_gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    forwarded = CreateEventW(nullptr, TRUE, FALSE, nullptr); callback_gate = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    worker_result = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // An unsigned synthetic token only reaches the certificate-send boundary,
    // which fails locally; it can never grant ownership or contact a service.
    bridge_jwt = "e30.eyJMaWNlbnNlVG9rZW5DbGFpbSI6ImV5SmpaWEowYVdacFkyRjBaVWxrSWpvaU1EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNREF3TURBd01EQXdNQ0o5In0.signature";
    held_cancel(); ordinary(0, E_FAIL); ordinary(1, S_OK); ordinary(2, E_ACCESSDENIED);
    begin_failure(1, "B00000000001"); begin_failure(2, "B00000000001"); begin_failure(0, "invalid");
    registration_failure(); pre_canceled();
    CloseHandle(bridge_started); CloseHandle(bridge_gate); CloseHandle(forwarded); CloseHandle(callback_gate); CloseHandle(worker_result);
    if (SUCCEEDED(com)) RoUninitialize();
    printf("CHECKS %u FAILURES %u\n", checks, failures); return failures ? 1 : 0;
}
