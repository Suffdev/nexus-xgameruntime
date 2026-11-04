/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Windows.Services.Store.StoreContext for packaged desktop titles.
 *
 * App licenses use the same verified receipts as XStoreQueryGameLicenseAsync.
 * Durable add-on collections use fresh verified entitlements, including
 * packaged and package-free products. Unsupported Store operations retain
 * E_NOTIMPL; unavailable licenses never fall back to an empty owned collection. */

#include <inspectable.h>
#include <winstring.h>
#include <atomic>
#include <ctime>
#include <cstdio>
#include <new>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include "StoreLicenseData.h"

namespace nexus_store_context
{

static const GUID IID_IActivationFactory_ = { 0x00000035, 0x0000, 0x0000, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID IID_IAsyncInfo_ = { 0x00000036, 0x0000, 0x0000, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID IID_IAgileObject_ = { 0x94ea2b94, 0xe9cc, 0x49e0, { 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90 } };
static const GUID IID_IStoreContextStatics = { 0x9c06ee5f, 0x15c0, 0x4e72, { 0x93, 0x30, 0xd6, 0x19, 0x1c, 0xeb, 0xd1, 0x9c } };
static const GUID IID_IStoreContext = { 0xac98b6be, 0xf4fd, 0x4912, { 0xba, 0xbd, 0x50, 0x35, 0xe5, 0xe8, 0xbc, 0xab } };
static const GUID IID_IStoreAppLicense = { 0xf389f9de, 0x73c0, 0x45ce, { 0x9b, 0xab, 0xb2, 0xfe, 0x3e, 0x5e, 0xaf, 0xd3 } };
/* IAsyncOperation<StoreAppLicense> (parameterized interface ID) */
static const GUID IID_IAsyncOperation_StoreAppLicense = { 0x3866370b, 0xafc6, 0x5d01, { 0x84, 0xc2, 0x45, 0x74, 0x62, 0x8d, 0xe5, 0x39 } };

enum : int { STATUS_STARTED = 0, STATUS_COMPLETED = 1, STATUS_CANCELED = 2, STATUS_ERROR = 3 };

static const HRESULT E_ILLEGAL_METHOD_CALL_ = static_cast<HRESULT>( 0x8000000E );
static const HRESULT E_ILLEGAL_DELEGATE_ASSIGNMENT_ = static_cast<HRESULT>( 0x80000018 );
#ifndef RO_E_CLOSED
#define RO_E_CLOSED _HRESULT_TYPEDEF_(0x80000013)
#endif

/* Interface layouts, in Windows metadata order. */

struct IActivationFactory_ : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE ActivateInstance( IInspectable **instance ) = 0;
};

struct IStoreAppLicense_ : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE get_SkuStoreId( HSTRING *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsActive( boolean *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsTrial( boolean *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_ExpirationDate( INT64 *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData( HSTRING *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_AddOnLicenses( IInspectable **value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_TrialTimeRemaining( INT64 *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsTrialOwnedByThisUser( boolean *value ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_TrialUniqueId( HSTRING *value ) = 0;
};

struct IAsyncInfo_ : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE get_Id( UINT32 *id ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Status( int *status ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_ErrorCode( HRESULT *code ) = 0;
    virtual HRESULT STDMETHODCALLTYPE Cancel() = 0;
    virtual HRESULT STDMETHODCALLTYPE Close() = 0;
};

struct IAsyncOperation_StoreAppLicense;

/* AsyncOperationCompletedHandler<StoreAppLicense> */
struct ICompletedHandler_ : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE Invoke( IAsyncOperation_StoreAppLicense *operation, int status ) = 0;
};

struct IAsyncOperation_StoreAppLicense : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE put_Completed( ICompletedHandler_ *handler ) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Completed( ICompletedHandler_ **handler ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetResults( IStoreAppLicense_ **license ) = 0;
};

struct IStoreContext_ : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE get_User( IInspectable **user ) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_OfflineLicensesChanged( IUnknown *handler, INT64 *token ) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_OfflineLicensesChanged( INT64 token ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCustomerPurchaseIdAsync( HSTRING, HSTRING, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCustomerCollectionsIdAsync( HSTRING, HSTRING, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAppLicenseAsync( IAsyncOperation_StoreAppLicense **operation ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStoreProductForCurrentAppAsync( IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStoreProductsAsync( IInspectable *, IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsAsync( IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsWithPagingAsync( IInspectable *, UINT32, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetUserCollectionAsync( IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetUserCollectionWithPagingAsync( IInspectable *, UINT32, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE ReportConsumableFulfillmentAsync( HSTRING, UINT32, GUID, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetConsumableBalanceRemainingAsync( HSTRING, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE AcquireStoreLicenseForOptionalPackageAsync( IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestPurchaseAsync( HSTRING, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync( HSTRING, IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAppAndOptionalStorePackageUpdatesAsync( IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestDownloadStorePackageUpdatesAsync( IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackageUpdatesAsync( IInspectable *, IInspectable ** ) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackagesAsync( IInspectable *, IInspectable ** ) = 0;
};

struct IStoreContextStatics_ : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE GetDefault( IStoreContext_ **context ) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetForUser( IInspectable *user, IStoreContext_ **context ) = 0;
};

/* ---- the verified license ---- */

/* Use the existing verified receipt path for every operation. A denial or an
 * account change must never fall back to a previously successful license. */
static HRESULT query_game_license( XStoreGameLicense *out, const std::atomic<bool> &canceled, HANDLE cancel_event );

static HRESULT make_hstring( const char *text, HSTRING *out )
{
    WCHAR wide[128];
    int length;

    if ( !out ) return E_POINTER;
    *out = nullptr;
    if ( !text || !*text ) return S_OK;
    if ( !( length = MultiByteToWideChar( CP_UTF8, 0, text, -1, wide, ARRAY_SIZE( wide ) ) ) ) return E_FAIL;
    return WindowsCreateString( wide, length - 1, out );
}

/* ---- objects ---- */

#define INSPECTABLE_STUBS                                                                                            \
    HRESULT STDMETHODCALLTYPE GetIids( ULONG *count, IID **iids ) override                                           \
    {                                                                                                                \
        if ( !count || !iids ) return E_POINTER;                                                                      \
        *count = 0;                                                                                                  \
        *iids = nullptr;                                                                                             \
        return S_OK;                                                                                                 \
    }                                                                                                                \
    HRESULT STDMETHODCALLTYPE GetTrustLevel( TrustLevel *level ) override                                            \
    {                                                                                                                \
        if ( !level ) return E_POINTER;                                                                               \
        *level = BaseTrust;                                                                                          \
        return S_OK;                                                                                                 \
    }

#include "StoreLicenseMap.h"

class AppLicense final : public IStoreAppLicense_
{
    std::atomic<ULONG> refs{ 1 };
    XStoreGameLicense license;

public:
    explicit AppLicense( const XStoreGameLicense &value ) : license( value ) {}

    HRESULT STDMETHODCALLTYPE QueryInterface( REFIID iid, void **out ) override
    {
        if ( !out ) return E_POINTER;
        if ( IsEqualGUID( iid, IID_IUnknown ) || IsEqualGUID( iid, IID_IInspectable ) ||
             IsEqualGUID( iid, IID_IAgileObject_ ) || IsEqualGUID( iid, IID_IStoreAppLicense ) )
        {
            *out = static_cast<IStoreAppLicense_ *>( this );
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        const ULONG count = --refs;
        if ( !count ) delete this;
        return count;
    }
    INSPECTABLE_STUBS
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName( HSTRING *name ) override
    {
        return make_hstring( "Windows.Services.Store.StoreAppLicense", name );
    }

    HRESULT STDMETHODCALLTYPE get_SkuStoreId( HSTRING *value ) override { return make_hstring( license.skuStoreId, value ); }
    HRESULT STDMETHODCALLTYPE get_IsActive( boolean *value ) override
    {
        if ( !value ) return E_POINTER;
        *value = license.isActive && license.expirationDate > std::time( nullptr ) ? TRUE : FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_IsTrial( boolean *value ) override
    {
        if ( !value ) return E_POINTER;
        *value = license.isTrial ? TRUE : FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_ExpirationDate( INT64 *value ) override
    {
        if ( !value ) return E_POINTER;
        /* DateTime: 100 ns units since 1601-01-01 */
        *value = license.expirationDate > 0 ? ( static_cast<INT64>( license.expirationDate ) + 11644473600LL ) * 10000000LL : 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_ExtendedJsonData( HSTRING *value ) override
    {
        if ( !value ) return E_POINTER;
        *value = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_AddOnLicenses( IInspectable **value ) override
    {
        if ( !value ) return E_POINTER;
        *value = nullptr;
        if (!license.isActive || license.expirationDate <= std::time(nullptr)) return E_ACCESSDENIED;
        try
        {
            AddonLicenseSnapshot snapshot;
            HRESULT hr = query_addon_licenses(&snapshot);
            if (FAILED(hr)) return hr;
            return make_addon_license_map(std::move(snapshot), value);
        }
        catch (const std::bad_alloc &) { return E_OUTOFMEMORY; }
    }
    HRESULT STDMETHODCALLTYPE get_TrialTimeRemaining( INT64 *value ) override
    {
        if ( !value ) return E_POINTER;
        *value = static_cast<INT64>( license.trialTimeRemainingInSeconds ) * 10000000LL;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_IsTrialOwnedByThisUser( boolean *value ) override
    {
        if ( !value ) return E_POINTER;
        *value = license.isTrialOwnedByThisUser ? TRUE : FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_TrialUniqueId( HSTRING *value ) override { return make_hstring( license.trialUniqueId, value ); }
};

class AppLicenseOperation final : public IAsyncOperation_StoreAppLicense, public IAsyncInfo_
{
    std::atomic<ULONG> refs{ 1 };
    SRWLOCK lock = SRWLOCK_INIT;
    int status = STATUS_STARTED;
    BOOL handler_set = FALSE;
    bool closed = false;
    std::atomic<bool> canceled{ false };
    HANDLE cancel_event = nullptr;
    HRESULT error = S_OK;
    ICompletedHandler_ *handler = nullptr;
    AppLicense *result = nullptr;

    static DWORD WINAPI worker( void *arg )
    {
        auto *operation = static_cast<AppLicenseOperation *>( arg );
        XStoreGameLicense license;
        ICompletedHandler_ *notify;

        /* A failed query has no license result. Preserve its HRESULT for both
         * IAsyncInfo and GetResults instead of completing with an inactive license. */
        HRESULT hr = query_game_license( &license, operation->canceled, operation->cancel_event );
        AppLicense *value = SUCCEEDED( hr ) ? new ( std::nothrow ) AppLicense( license ) : nullptr;
        if ( SUCCEEDED( hr ) && !value ) hr = E_OUTOFMEMORY;
        AcquireSRWLockExclusive( &operation->lock );
        if ( operation->status != STATUS_STARTED )
        {
            ReleaseSRWLockExclusive( &operation->lock );
            if ( value ) value->Release();
            operation->Release();
            return 0;
        }
        operation->result = value;
        operation->error = hr;
        operation->status = SUCCEEDED( hr ) ? STATUS_COMPLETED : STATUS_ERROR;
        const int terminal = operation->status;
        notify = operation->handler;
        if ( notify ) notify->AddRef();
        ReleaseSRWLockExclusive( &operation->lock );
        if ( notify )
        {
            notify->Invoke( operation, terminal );
            notify->Release();
        }
        operation->Release(); /* worker reference */
        return 0;
    }

public:
    HRESULT start()
    {
        cancel_event = CreateEventW( nullptr, TRUE, canceled.load(), nullptr );
        if ( !cancel_event ) return HRESULT_FROM_WIN32( GetLastError() );
        AddRef(); /* worker reference */
        HANDLE thread = CreateThread( nullptr, 0, worker, this, 0, nullptr );
        if ( !thread )
        {
            Release();
            return HRESULT_FROM_WIN32( GetLastError() );
        }
        CloseHandle( thread );
        return S_OK;
    }

    ~AppLicenseOperation()
    {
        if ( cancel_event ) CloseHandle( cancel_event );
        if ( handler ) handler->Release();
        if ( result ) result->Release();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface( REFIID iid, void **out ) override
    {
        if ( !out ) return E_POINTER;
        if ( IsEqualGUID( iid, IID_IUnknown ) || IsEqualGUID( iid, IID_IInspectable ) ||
             IsEqualGUID( iid, IID_IAgileObject_ ) || IsEqualGUID( iid, IID_IAsyncOperation_StoreAppLicense ) )
            *out = static_cast<IAsyncOperation_StoreAppLicense *>( this );
        else if ( IsEqualGUID( iid, IID_IAsyncInfo_ ) )
            *out = static_cast<IAsyncInfo_ *>( this );
        else
        {
            *out = nullptr;
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        const ULONG count = --refs;
        if ( !count ) delete this;
        return count;
    }
    INSPECTABLE_STUBS
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName( HSTRING *name ) override
    {
        if ( !name ) return E_POINTER;
        *name = nullptr;
        return E_NOTIMPL;
    }

    /* IAsyncOperation<StoreAppLicense> */
    HRESULT STDMETHODCALLTYPE put_Completed( ICompletedHandler_ *value ) override
    {
        int terminal;
        AcquireSRWLockExclusive( &lock );
        if ( closed ) { ReleaseSRWLockExclusive( &lock ); return RO_E_CLOSED; }
        if ( handler_set )
        {
            ReleaseSRWLockExclusive( &lock );
            return E_ILLEGAL_DELEGATE_ASSIGNMENT_;
        }
        handler_set = TRUE;
        terminal = status;
        if ( value ) value->AddRef();
        handler = value;
        if ( terminal != STATUS_STARTED && value ) value->AddRef();
        ReleaseSRWLockExclusive( &lock );
        if ( terminal != STATUS_STARTED && value )
        {
            value->Invoke( this, terminal );
            value->Release();
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_Completed( ICompletedHandler_ **value ) override
    {
        if ( !value ) return E_POINTER;
        *value = nullptr;
        AcquireSRWLockShared( &lock );
        if ( closed ) { ReleaseSRWLockShared( &lock ); return RO_E_CLOSED; }
        *value = handler;
        if ( handler ) handler->AddRef();
        ReleaseSRWLockShared( &lock );
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetResults( IStoreAppLicense_ **value ) override
    {
        if ( !value ) return E_POINTER;
        *value = nullptr;
        HRESULT hr = S_OK;
        AcquireSRWLockShared( &lock );
        if ( closed ) hr = RO_E_CLOSED;
        else if ( status == STATUS_CANCELED ) hr = E_ABORT;
        else if ( status == STATUS_ERROR ) hr = error;
        else if ( status != STATUS_COMPLETED )
            hr = E_ILLEGAL_METHOD_CALL_;
        else if ( !result )
            hr = E_OUTOFMEMORY;
        else
        {
            *value = result;
            result->AddRef();
        }
        ReleaseSRWLockShared( &lock );
        return hr;
    }

    /* IAsyncInfo */
    HRESULT STDMETHODCALLTYPE get_Id( UINT32 *id ) override
    {
        if ( !id ) return E_POINTER;
        *id = 1;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_Status( int *value ) override
    {
        if ( !value ) return E_POINTER;
        AcquireSRWLockShared( &lock );
        if ( closed ) { ReleaseSRWLockShared( &lock ); return RO_E_CLOSED; }
        *value = status;
        ReleaseSRWLockShared( &lock );
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_ErrorCode( HRESULT *code ) override
    {
        if ( !code ) return E_POINTER;
        AcquireSRWLockShared( &lock );
        if ( closed ) { ReleaseSRWLockShared( &lock ); return RO_E_CLOSED; }
        *code = error;
        ReleaseSRWLockShared( &lock );
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Cancel() override
    {
        ICompletedHandler_ *notify = nullptr;
        AcquireSRWLockExclusive( &lock );
        if ( closed ) { ReleaseSRWLockExclusive( &lock ); return RO_E_CLOSED; }
        if ( status == STATUS_STARTED )
        {
            canceled = true;
            if ( cancel_event ) SetEvent( cancel_event );
            status = STATUS_CANCELED;
            error = E_ABORT;
            notify = handler;
            if ( notify ) notify->AddRef();
        }
        ReleaseSRWLockExclusive( &lock );
        if ( notify ) { notify->Invoke( this, STATUS_CANCELED ); notify->Release(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Close() override
    {
        AcquireSRWLockExclusive( &lock );
        if ( status == STATUS_STARTED ) { ReleaseSRWLockExclusive( &lock ); return E_ILLEGAL_METHOD_CALL_; }
        closed = true;
        ReleaseSRWLockExclusive( &lock );
        return S_OK;
    }
};

class StoreContext final : public IStoreContext_
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface( REFIID iid, void **out ) override
    {
        if ( !out ) return E_POINTER;
        if ( IsEqualGUID( iid, IID_IUnknown ) || IsEqualGUID( iid, IID_IInspectable ) ||
             IsEqualGUID( iid, IID_IAgileObject_ ) || IsEqualGUID( iid, IID_IStoreContext ) )
        {
            *out = static_cast<IStoreContext_ *>( this );
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    INSPECTABLE_STUBS
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName( HSTRING *name ) override
    {
        return make_hstring( "Windows.Services.Store.StoreContext", name );
    }

    HRESULT STDMETHODCALLTYPE get_User( IInspectable **user ) override
    {
        if ( !user ) return E_POINTER;
        *user = nullptr;
        return S_OK;
    }
    /* No change-event source exists yet. Do not invent a successful subscription. */
    HRESULT STDMETHODCALLTYPE add_OfflineLicensesChanged( IUnknown *, INT64 *token ) override
    {
        if ( !token ) return E_POINTER;
        *token = 0;
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE remove_OfflineLicensesChanged( INT64 ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAppLicenseAsync( IAsyncOperation_StoreAppLicense **operation ) override
    {
        if ( !operation ) return E_POINTER;
        auto *value = new ( std::nothrow ) AppLicenseOperation();
        *operation = nullptr;
        if ( !value ) return E_OUTOFMEMORY;
        const HRESULT hr = value->start();
        if ( FAILED( hr ) )
        {
            value->Release();
            return hr;
        }
        *operation = value;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCustomerPurchaseIdAsync( HSTRING, HSTRING, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCustomerCollectionsIdAsync( HSTRING, HSTRING, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetStoreProductForCurrentAppAsync( IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetStoreProductsAsync( IInspectable *, IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsWithPagingAsync( IInspectable *, UINT32, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUserCollectionAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUserCollectionWithPagingAsync( IInspectable *, UINT32, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE ReportConsumableFulfillmentAsync( HSTRING, UINT32, GUID, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetConsumableBalanceRemainingAsync( HSTRING, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE AcquireStoreLicenseForOptionalPackageAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RequestPurchaseAsync( HSTRING, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync( HSTRING, IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAppAndOptionalStorePackageUpdatesAsync( IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RequestDownloadStorePackageUpdatesAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackageUpdatesAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackagesAsync( IInspectable *, IInspectable ** ) override { return E_NOTIMPL; }
};

static StoreContext default_context;

/* Activation factory for Windows.Services.Store.StoreContext: IActivationFactory + statics. */
class StoreContextFactory final : public IActivationFactory_, public IStoreContextStatics_
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface( REFIID iid, void **out ) override
    {
        if ( !out ) return E_POINTER;
        if ( IsEqualGUID( iid, IID_IUnknown ) || IsEqualGUID( iid, IID_IInspectable ) ||
             IsEqualGUID( iid, IID_IAgileObject_ ) || IsEqualGUID( iid, IID_IActivationFactory_ ) )
            *out = static_cast<IActivationFactory_ *>( this );
        else if ( IsEqualGUID( iid, IID_IStoreContextStatics ) )
            *out = static_cast<IStoreContextStatics_ *>( this );
        else
        {
            *out = nullptr;
            return E_NOINTERFACE;
        }
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    INSPECTABLE_STUBS
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName( HSTRING *name ) override
    {
        return make_hstring( "Windows.Services.Store.StoreContext", name );
    }

    HRESULT STDMETHODCALLTYPE ActivateInstance( IInspectable **instance ) override
    {
        if ( !instance ) return E_POINTER;
        *instance = nullptr;
        return E_NOTIMPL; /* StoreContext has no public constructor */
    }
    HRESULT STDMETHODCALLTYPE GetDefault( IStoreContext_ **context ) override
    {
        if ( !context ) return E_POINTER;
        *context = &default_context;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetForUser( IInspectable *user, IStoreContext_ **context ) override
    {
        if ( !context ) return E_POINTER;
        *context = nullptr;
        /* Mapping a Windows.System.User to a Store identity is unsupported. */
        if ( user ) return E_NOTIMPL;
        *context = &default_context;
        return S_OK;
    }
};

static StoreContextFactory factory;

} // namespace nexus_store_context

extern "C" HRESULT WINAPI DllGetActivationFactory( HSTRING class_id, void **out )
{
    UINT32 length;
    const WCHAR *name = WindowsGetStringRawBuffer( class_id, &length );

    if ( !out ) return E_POINTER;
    *out = nullptr;
    static const WCHAR supported[] = L"Windows.Services.Store.StoreContext";
    if ( !name || length != ARRAY_SIZE( supported ) - 1 ||
         memcmp( name, supported, length * sizeof( WCHAR ) ) ) return CLASS_E_CLASSNOTAVAILABLE;
    *out = static_cast<nexus_store_context::IActivationFactory_ *>( &nexus_store_context::factory );
    return S_OK;
}

extern "C" HRESULT WINAPI DllCanUnloadNow( void )
{
    return S_FALSE;
}
