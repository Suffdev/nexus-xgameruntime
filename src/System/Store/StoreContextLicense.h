// SPDX-License-Identifier: LGPL-2.1-or-later
// Production receipt transport, separate from the account-free WinRT ABI tests.
#include "StoreLicenseProjection.h"
namespace nexus_store_context
{
struct ChildLicenseCancellation
{
    IXThreadingImpl *threading;
    XAsyncBlock *block;
    static void CALLBACK notify( PTP_CALLBACK_INSTANCE, void *context, PTP_WAIT, TP_WAIT_RESULT )
    {
        auto *self = static_cast<ChildLicenseCancellation *>( context );
        self->threading->XAsyncCancel( self->block );
    }
};

static HRESULT query_game_license( XStoreGameLicense *out, const std::atomic<bool> &canceled, HANDLE cancel_event )
{
    XStoreContextHandle store = nullptr;
    XTaskQueueHandle queue = nullptr;
    IXThreadingImpl *threading = nullptr;
    XAsyncBlock block = {};
    *out = {};
    for ( int i = 0; i < 300 && !canceled && !nexus::GetGameConfiguration(); ++i ) Sleep( 100 );
    if ( canceled ) return E_ABORT;
    if ( !GetStoreProductId() ) return E_GAME_MISSING_GAME_CONFIG;
    HRESULT hr = entitled_store_create( nullptr, &store );
    if ( FAILED( hr ) ) return hr;
    HANDLE drained = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    if ( !drained )
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        entitled_store_close( store );
        return hr;
    }
    if ( SUCCEEDED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading ) ) &&
         SUCCEEDED( hr = threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool,
                                                      XTaskQueueDispatchMode::ThreadPool, &queue ) ) )
    {
        block.queue = queue;
        hr = entitled_begin( store, static_cast<UINT32>( XStoreProductKind::Game ), ENTITLED_MAX_PRODUCTS, &block, TRUE, TRUE, drained );
        if ( SUCCEEDED( hr ) )
        {
            ChildLicenseCancellation child{ threading, &block };
            PTP_WAIT registration = nullptr;
            HRESULT registration_hr = S_OK;
            if ( cancel_event && !( registration = CreateThreadpoolWait( ChildLicenseCancellation::notify, &child, nullptr ) ) )
            {
                registration_hr = HRESULT_FROM_WIN32( GetLastError() );
                threading->XAsyncCancel( &block );
            }
            if ( registration ) SetThreadpoolWait( registration, cancel_event, nullptr );
            hr = threading->XAsyncGetStatus( &block, TRUE );
            // Fence the callback before any block, queue or threading teardown.
            if ( registration )
            {
                SetThreadpoolWait( registration, nullptr, nullptr );
                WaitForThreadpoolWaitCallbacks( registration, TRUE );
                CloseThreadpoolWait( registration );
            }
            if ( SUCCEEDED( hr ) ) hr = threading->XAsyncGetResult( &block, &entitled_game_identity, sizeof( *out ), out, nullptr );
            // Cancellation completes XAsync immediately. Its detached worker
            // still owns the provider and may be draining an uncancellable IPC.
            WaitForSingleObject( drained, INFINITE );
            if ( FAILED( registration_hr ) ) hr = registration_hr;
            if ( canceled ) hr = E_ABORT;
        }
        threading->XTaskQueueCloseHandle( queue );
    }
    CloseHandle( drained );
    if ( threading ) threading->Release();
    entitled_store_close( store );
    if ( SUCCEEDED( hr ) && !out->isActive ) hr = E_ACCESSDENIED;
    if ( FAILED( hr ) ) *out = {};
    return hr;
}
/* Use the same account-backed, signed-receipt enumeration as XStore. The
 * result includes both packaged and package-free durables, excludes consumables,
 * and never substitutes an empty success for an unavailable/denied query. */
static HRESULT query_addon_licenses(AddonLicenseSnapshot *out)
{
    *out = {};
    if (!nexus::GetGameConfiguration() || !GetStoreProductId()) return E_GAME_MISSING_GAME_CONFIG;
    XStoreContextHandle store = nullptr;
    XTaskQueueHandle queue = nullptr;
    XStoreProductQueryHandle handle = nullptr;
    IXThreadingImpl *threading = nullptr;
    XAsyncBlock block = {};
    HRESULT hr = entitled_store_create(nullptr, &store);
    if (FAILED(hr)) return hr;
    if (SUCCEEDED(hr = QueryApiImpl(CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading)) &&
        SUCCEEDED(hr = threading->XTaskQueueCreate(XTaskQueueDispatchMode::ThreadPool,
                                                   XTaskQueueDispatchMode::ThreadPool, &queue)))
    {
        block.queue = queue;
        hr = entitled_begin(store, static_cast<UINT32>(XStoreProductKind::Durable), ENTITLED_MAX_PRODUCTS, &block);
        if (SUCCEEDED(hr)) hr = threading->XAsyncGetStatus(&block, TRUE);
        if (SUCCEEDED(hr)) hr = threading->XAsyncGetResult(&block, &entitled_identity, sizeof(handle), &handle, nullptr);
        if (SUCCEEDED(hr))
        {
            auto *page = entitled_page_acquire(handle);
            if (!page || !entitled_page_valid(page)) hr = E_ACCESSDENIED;
            if (SUCCEEDED(hr))
            {
                hr = addon_data_from_verified_snapshot(page->snapshot, out);
            }
            if (page) entitled_page_release(page);
        }
        if (handle) entitled_page_close(handle);
        threading->XTaskQueueCloseHandle(queue);
    }
    if (threading) threading->Release();
    entitled_store_close(store);
    if (FAILED(hr)) *out = {};
    xodus_store_license_note("store-winrt-addon-license-result", hr);
    return hr;
}

}
