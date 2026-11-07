/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XStore
 *
 * Copyright 2026 Olivia Ryan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include "XStore.h"
#include "XPackage.h"
#include "../Runtime/Configuration.h"
#include "Store/Bridge.h"
#include <mutex>

static const char *GetStoreProductId();
#include "Store/Entitled.h"
#include "Store/Catalog.h"
#include "Store/PackageLicense.h"
#include "Store/CanAcquireLicense.h"
#include "Store/AddonLicense.h"
#include "Store/StoreContext.h"
#include "Store/StoreContextLicense.h"

HRESULT WINAPI XStoreImpl::XStoreCreateContext( const XUserHandle user, XStoreContextHandle *storeContextHandle )
{
    HRESULT hr = entitled_store_create( user, storeContextHandle );
    NEXUS_STORE_META( 20, hr, ( user ? 1 : 0 ) | ( storeContextHandle ? 2 : 0 ), NULL );
    return hr;
}

void WINAPI XStoreImpl::XStoreCloseContextHandle( XStoreContextHandle storeContextHandle )
{
    entitled_store_close( storeContextHandle );
}

HRESULT WINAPI XStoreImpl::XStoreQueryAssociatedProductsAsync( const XStoreContextHandle storeContextHandle,
                                                               XStoreProductKind productKinds,
                                                               UINT32 maxItemsToRetrievePerPage, XAsyncBlock *async )
{
    ( void )0;
    NEXUS_STORE_META( 32, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryAssociatedProductsResult( XAsyncBlock *async,
                                                                XStoreProductQueryHandle *productQueryHandle )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductsAsync( const XStoreContextHandle storeContextHandle,
                                                     XStoreProductKind productKinds, const char **storeIds,
                                                     SIZE_T storeIdsCount, const char **actionFilters,
                                                     SIZE_T actionFiltersCount, XAsyncBlock *async )
{
    HRESULT hr = catalog_begin( storeContextHandle, static_cast<UINT32>( productKinds ), storeIds,
                                storeIdsCount, actionFilters, actionFiltersCount, async );
    NEXUS_STORE_META( 33, hr, 0, NULL );
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductsResult( XAsyncBlock *async, XStoreProductQueryHandle *productQueryHandle )
{
    return catalog_result( async, productQueryHandle );
}

HRESULT WINAPI XStoreImpl::XStoreQueryEntitledProductsAsync( const XStoreContextHandle storeContextHandle,
                                                             XStoreProductKind productKinds,
                                                             UINT32 maxItemsToRetrievePerPage, XAsyncBlock *async )
{
    return entitled_begin( storeContextHandle, static_cast<UINT32>( productKinds ), maxItemsToRetrievePerPage, async );
}

HRESULT WINAPI XStoreImpl::XStoreQueryEntitledProductsResult( XAsyncBlock *async,
                                                              XStoreProductQueryHandle *productQueryHandle )
{
    return entitled_result( async, productQueryHandle, FALSE );
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductForCurrentGameAsync( const XStoreContextHandle storeContextHandle,
                                                                  XAsyncBlock *async )
{
    HRESULT hr = entitled_begin( storeContextHandle, static_cast<UINT32>( XStoreProductKind::Game ), 1, async, FALSE, TRUE );
    NEXUS_STORE_META( 31, hr, 0, NULL );
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductForCurrentGameResult( XAsyncBlock *async,
                                                                   XStoreProductQueryHandle *productQueryHandle )
{
    return entitled_result( async, productQueryHandle, FALSE );
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductForPackageAsync( const XStoreContextHandle storeContextHandle,
                                                              XStoreProductKind productKinds,
                                                              const char *packageIdentifier, XAsyncBlock *async )
{
    return catalog_package_begin( storeContextHandle, static_cast<UINT32>( productKinds ), packageIdentifier, async );
}

HRESULT WINAPI XStoreImpl::XStoreQueryProductForPackageResult( XAsyncBlock *async,
                                                               XStoreProductQueryHandle *productQueryHandle )
{
    return catalog_result( async, productQueryHandle, &catalog_package_identity );
}

HRESULT WINAPI XStoreImpl::XStoreEnumerateProductsQuery( const XStoreProductQueryHandle productQueryHandle,
                                                         void *context, XStoreProductQueryCallback *callback )
{
    return entitled_enumerate( productQueryHandle, context, callback );
}

BOOLEAN WINAPI XStoreImpl::XStoreProductsQueryHasMorePages( const XStoreProductQueryHandle productQueryHandle )
{
    return entitled_has_more( productQueryHandle );
}

HRESULT WINAPI XStoreImpl::XStoreProductsQueryNextPageAsync( const XStoreProductQueryHandle productQueryHandle,
                                                             XAsyncBlock *async )
{
    return entitled_next( productQueryHandle, async );
}

HRESULT WINAPI XStoreImpl::XStoreProductsQueryNextPageResult( XAsyncBlock *async,
                                                              XStoreProductQueryHandle *productQueryHandle )
{
    return entitled_result( async, productQueryHandle, TRUE );
}

void WINAPI XStoreImpl::XStoreCloseProductsQueryHandle( XStoreProductQueryHandle productQueryHandle )
{
    entitled_page_close( productQueryHandle );
}

HRESULT WINAPI XStoreImpl::XStoreAcquireLicenseForPackageAsync( const XStoreProductQueryHandle productQueryHandle,
                                                                const char *packageIdentifier, XAsyncBlock *async )
{
    return package_license_begin( ( XStoreContextHandle )productQueryHandle, packageIdentifier, async );
}

HRESULT WINAPI XStoreImpl::XStoreAcquireLicenseForPackageResult( XAsyncBlock *async,
                                                                 XStoreLicenseHandle *storeLicenseHandle )
{
    return package_license_result( async, storeLicenseHandle );
}

BOOLEAN WINAPI XStoreImpl::XStoreIsLicenseValid( const XStoreLicenseHandle storeLicenseHandle )
{
    return package_license_valid( storeLicenseHandle );
}

void WINAPI XStoreImpl::XStoreCloseLicenseHandle( XStoreLicenseHandle storeLicenseHandle )
{
    package_license_close( storeLicenseHandle );
}

HRESULT WINAPI XStoreImpl::XStoreCanAcquireLicenseForStoreIdAsync( const XStoreContextHandle storeContextHandle,
                                                                   const char *storeProductId, XAsyncBlock *async )
{
    return can_acquire_begin( storeContextHandle, storeProductId, async, &can_acquire_store_identity );
}

HRESULT WINAPI XStoreImpl::XStoreCanAcquireLicenseForStoreIdResult(
    XAsyncBlock *async, XStoreCanAcquireLicenseResult *storeCanAcquireLicense )
{
    return can_acquire_result( async, storeCanAcquireLicense, &can_acquire_store_identity );
}

HRESULT WINAPI XStoreImpl::XStoreCanAcquireLicenseForPackageAsync( const XStoreContextHandle storeContextHandle,
                                                                   const char *packageIdentifier, XAsyncBlock *async )
{
    return can_acquire_package_begin( storeContextHandle, packageIdentifier, async );
}

HRESULT WINAPI XStoreImpl::XStoreCanAcquireLicenseForPackageResult(
    XAsyncBlock *async, XStoreCanAcquireLicenseResult *storeCanAcquireLicense )
{
    return can_acquire_result( async, storeCanAcquireLicense, &can_acquire_package_identity );
}

HRESULT WINAPI XStoreImpl::XStoreQueryGameLicenseAsync( const XStoreContextHandle store, XAsyncBlock *async )
{
    return entitled_begin( store, static_cast<UINT32>( XStoreProductKind::Game ), ENTITLED_MAX_PRODUCTS, async, TRUE );
}
HRESULT WINAPI XStoreImpl::XStoreQueryGameLicenseResult( XAsyncBlock *async, XStoreGameLicense *license )
{
    if ( !async || !license ) return E_INVALIDARG;
    *license = {};
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    hr = threading->XAsyncGetResult( async, &entitled_game_identity, sizeof( *license ), license, nullptr );
    threading->Release();
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryAddOnLicensesAsync( const XStoreContextHandle storeContextHandle,
                                                          XAsyncBlock *async )
{
    return addon_license_begin( storeContextHandle, async );
}

HRESULT WINAPI XStoreImpl::XStoreQueryAddOnLicensesResultCount( XAsyncBlock *async, UINT32 *count )
{
    return addon_license_count( async, count );
}

HRESULT WINAPI XStoreImpl::XStoreQueryAddOnLicensesResult( XAsyncBlock *async, UINT32 count,
                                                           XStoreAddonLicense *addOnLicenses )
{
    return addon_license_result( async, count, addOnLicenses );
}

HRESULT WINAPI XStoreImpl::XStoreQueryConsumableBalanceRemainingAsync( const XStoreContextHandle storeContextHandle,
                                                                       const char *storeProductId, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryConsumableBalanceRemainingResult( XAsyncBlock *async,
                                                                        XStoreConsumableResult *consumableResult )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreReportConsumableFulfillmentAsync( const XStoreContextHandle storeContextHandle,
                                                                   const char *storeProductId, UINT32 quantity,
                                                                   GUID trackingId, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreReportConsumableFulfillmentResult( XAsyncBlock *async,
                                                                    XStoreConsumableResult *consumableResult )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserCollectionsIdAsync( const XStoreContextHandle storeContextHandle,
                                                            const char *serviceTicket, const char *publisherUserId,
                                                            XAsyncBlock *async )
{
    ( void )0;
    NEXUS_STORE_META( 21, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserCollectionsIdResultSize( XAsyncBlock *async, SIZE_T *size )
{
    ( void )0;
    NEXUS_STORE_META( 22, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserCollectionsIdResult( XAsyncBlock *async, SIZE_T size, char *result )
{
    ( void )0;
    NEXUS_STORE_META( 23, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserPurchaseIdAsync( const XStoreContextHandle storeContextHandle,
                                                         const char *serviceTicket, const char *publisherUserId,
                                                         XAsyncBlock *async )
{
    ( void )0;
    NEXUS_STORE_META( 24, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserPurchaseIdResultSize( XAsyncBlock *async, SIZE_T *size )
{
    ( void )0;
    NEXUS_STORE_META( 25, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreGetUserPurchaseIdResult( XAsyncBlock *async, SIZE_T size, char *result )
{
    ( void )0;
    NEXUS_STORE_META( 26, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

struct store_license_context
{
    char *request, *token;
    SIZE_T size;
};
static const char store_license_identity{};

static HRESULT WINAPI store_license_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    store_license_context *context = static_cast<store_license_context *>( data->context );
    IXThreadingImpl *threading;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = ( threading )->XAsyncSchedule( data->async, 0 );
        break;
    case XAsyncOp::DoWork:
        hr = xodus_store_license_xml( context->request, strlen( context->request ), &context->token );
        if ( SUCCEEDED( hr ) ) context->size = strlen( context->token ) + 1;
        /* Completion may synchronously consume/free context. */
        ( threading )->XAsyncComplete( data->async, hr, SUCCEEDED( hr ) ? context->size : 0 );
        hr = S_OK;
        break;
    case XAsyncOp::GetResult:
        if ( !data->buffer || data->bufferSize < context->size )
            hr = HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        else
        {
            memcpy( data->buffer, context->token, context->size );
            hr = S_OK;
        }
        break;
    case XAsyncOp::Cleanup:
        if ( context->token )
        {
            SecureZeroMemory( context->token, context->size );
            free( context->token );
        }
        free( context->request );
        free( context );
        hr = S_OK;
        break;
    case XAsyncOp::Cancel:
        hr = S_OK;
        break;
    default:
        hr = E_NOTIMPL;
    }
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryLicenseTokenAsync( const XStoreContextHandle storeContextHandle,
                                                         const char **productIds, SIZE_T productIdsCount,
                                                         const char *customDeveloperString, XAsyncBlock *async )
{
    struct store_license_context *context;
    IXThreadingImpl *threading;
    HRESULT hr;
    SIZE_T i;

    ( void )0;
    if ( !storeContextHandle || !async || !productIds || !productIdsCount || productIdsCount > 64 ||
         !customDeveloperString || !*customDeveloperString )
        return E_INVALIDARG;
    UINT64 xuid;
    if ( FAILED( hr = entitled_store_user( storeContextHandle, &xuid ) ) ) return hr;
    for ( i = 0; i < productIdsCount; i++ )
        if ( !productIds[i] || !*productIds[i] ) return E_INVALIDARG;
    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, sizeof( *context ) ) ) ) )
        return E_OUTOFMEMORY;
    hr = xodus_store_license_body( productIds, productIdsCount, customDeveloperString, &context->request );
    if ( FAILED( hr ) ) goto error;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) goto error;
    hr = ( threading )
             ->XAsyncBegin( async, context, &store_license_identity, "XStoreQueryLicenseTokenAsync",
                            store_license_provider );
    xodus_store_license_note( "store-license-begin", hr );
    ( threading )->Release();
    if ( SUCCEEDED( hr ) ) return hr;
error:
    free( context->request );
    free( context );
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryLicenseTokenResultSize( XAsyncBlock *async, SIZE_T *size )
{
    IXThreadingImpl *threading;
    HRESULT hr;
    if ( !async || !size ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResultSize( async, size );
    xodus_store_license_note( "store-license-size", hr );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryLicenseTokenResult( XAsyncBlock *async, SIZE_T size, char *result )
{
    IXThreadingImpl *threading;
    HRESULT hr;
    if ( !async || !result ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResult( async, &store_license_identity, size, result, NULL );
    xodus_store_license_note( "store-license-result", hr );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XStoreImpl::__PADDING__()
{
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::__PADDING_2__()
{
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::__PADDING_3__()
{
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowPurchaseUIAsync( const XStoreContextHandle storeContextHandle,
                                                      const char *productId, const char *name,
                                                      const char *extendedJsonData, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowPurchaseUIResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowRateAndReviewUIAsync( const XStoreContextHandle storeContextHandle,
                                                           XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowRateAndReviewUIResult( XAsyncBlock *async, XStoreRateAndReviewResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowRedeemTokenUIAsync( const XStoreContextHandle storeContextHandle,
                                                         const char *token, const char **allowedStoreIds,
                                                         SIZE_T allowedStoreIdsCount, BOOLEAN disallowCsvRedemption,
                                                         XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowRedeemTokenUIResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

static const char store_updates_identity[] = "XStorePackageUpdates";

struct store_updates_context
{
    LONG refs;
    char request[256];
    BOOL package_found;
    IXThreadingImpl *threading;
    XAsyncBlock *async;
};

static void store_updates_release( struct store_updates_context *context )
{
    if ( !InterlockedDecrement( &context->refs ) )
    {
        ( context->threading )->Release();
        free( context );
    }
}

static BOOLEAN WINAPI store_updates_package( void *arg, const XPackageDetails *details )
{
    store_updates_context *context = static_cast<store_updates_context *>( arg );
    SIZE_T i;
    if ( !details->storeId || strlen( details->storeId ) != 12 || context->package_found ) return FALSE;
    for ( i = 0; i < 12; ++i )
        if ( !( ( details->storeId[i] >= 'A' && details->storeId[i] <= 'Z' ) ||
                ( details->storeId[i] >= 'a' && details->storeId[i] <= 'z' ) ||
                ( details->storeId[i] >= '0' && details->storeId[i] <= '9' ) ) )
            return FALSE;
    snprintf( context->request, sizeof( context->request ),
              "<Request><ProductId>%s</ProductId><InstalledVersion>%u.%u.%u.%u</InstalledVersion></Request>",
              details->storeId, details->version.major, details->version.minor, details->version.build,
              details->version.revision );
    context->package_found = TRUE;
    return FALSE; /* One installed package is exposed by this runtime. */
}

static xmlNodePtr store_updates_child( xmlNodePtr root, const char *name )
{
    xmlNodePtr child;
    for ( child = root ? root->children : NULL; child; child = child->next )
        if ( child->type == XML_ELEMENT_NODE && !strcmp( ( char * )child->name, name ) ) return child;
    return NULL;
}

static HRESULT store_updates_response( const char *response, UINT16 size )
{
    xmlDocPtr document;
    xmlNodePtr root;
    xmlChar *value;
    char *end;
    HRESULT hr = E_FAIL;
    if ( !( document = xmlReadMemory( response, size, NULL, NULL,
                                      XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING ) ) )
        return E_FAIL;
    root = xmlDocGetRootElement( document );
    if ( !( value = xmlNodeGetContent( store_updates_child( root, "HResult" ) ) ) ) goto done;
    hr = strtoul( ( char * )value, &end, 10 );
    if ( end == ( char * )value || *end ) hr = E_FAIL;
    xmlFree( value );
    if ( FAILED( hr ) ) goto done;
    hr = E_FAIL;
    if ( !( value = xmlNodeGetContent( store_updates_child( root, "Checked" ) ) ) ) goto done;
    if ( strcmp( ( char * )value, "true" ) )
    {
        xmlFree( value );
        goto done;
    }
    xmlFree( value );
    if ( !( value = xmlNodeGetContent( store_updates_child( root, "Count" ) ) ) ) goto done;
    if ( !strcmp( ( char * )value, "0" ) ) hr = S_OK;
    xmlFree( value );
done:
    xmlFreeDoc( document );
    return hr;
}

static DWORD WINAPI XStorePackageUpdatesWorker( void *arg )
{
    store_updates_context *context = static_cast<store_updates_context *>( arg );
    IXThreadingImpl *threading = context->threading;
    XAsyncBlock *async = context->async;
    char *response = NULL;
    UINT16 size = 0;
    HRESULT hr = xodus_store_package_updates_xml( context->request, strlen( context->request ), &response, &size );
    if ( SUCCEEDED( hr ) ) hr = response && size ? store_updates_response( response, size ) : E_FAIL;
    free( response );
    ( void )0;
    store_updates_release( context );
    /* Completion can synchronously clean context: do not touch it afterward. */
    ( threading )->XAsyncComplete( async, hr, 0 );
    ( threading )->Release();
    return 0;
}

static HRESULT WINAPI store_updates_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    store_updates_context *context = static_cast<store_updates_context *>( data->context );
    HANDLE worker;
    switch ( op )
    {
    case XAsyncOp::Begin:
        return ( context->threading )->XAsyncSchedule( data->async, 0 );
    case XAsyncOp::DoWork:
        context->async = data->async;
        InterlockedIncrement( &context->refs );
        ( context->threading )->AddRef();
        if ( !( worker = CreateThread( NULL, 0, XStorePackageUpdatesWorker, context, 0, NULL ) ) )
        {
            HRESULT hr = HRESULT_FROM_WIN32( GetLastError() );
            ( context->threading )->Release();
            store_updates_release( context );
            return hr;
        }
        CloseHandle( worker );
        return E_PENDING;
    case XAsyncOp::Cleanup:
        store_updates_release( context );
        break;
    default:
        break;
    }
    return S_OK;
}

HRESULT WINAPI XStoreImpl::XStoreQueryGameAndDlcPackageUpdatesAsync( const XStoreContextHandle storeContextHandle,
                                                                     XAsyncBlock *async )
{
    struct store_updates_context *context;
    IXPackageImpl *package;
    HRESULT hr;
    ( void )0;
    if ( !storeContextHandle || !async ) return E_INVALIDARG;
    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, sizeof( *context ) ) ) ) )
        return E_OUTOFMEMORY;
    context->refs = 1;
    if ( FAILED( hr = QueryApiImpl( CLSID_XPackageImpl, IID_IXPackageImpl, ( void ** )&package ) ) ) goto error;
    hr = ( package )->XPackageEnumeratePackages( XPackageKind::Game, XPackageEnumerationScope::ThisOnly, context,
                                                 store_updates_package );
    ( package )->Release();
    if ( FAILED( hr ) ) goto error;
    if ( !context->package_found )
    {
        hr = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED );
        goto error;
    }
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&context->threading ) ) )
        goto error;
    hr = ( context->threading )
             ->XAsyncBegin( async, context, store_updates_identity, "XStoreQueryGameAndDlcPackageUpdatesAsync",
                            store_updates_provider );
    if ( SUCCEEDED( hr ) ) return hr;
    ( context->threading )->Release();
error:
    free( context );
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryGameAndDlcPackageUpdatesResultCount( XAsyncBlock *async, UINT32 *count )
{
    IXThreadingImpl *threading;
    SIZE_T size;
    HRESULT hr;
    ( void )0;
    if ( !async || !count ) return E_INVALIDARG;
    *count = 0;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResultSize( async, &size );
    ( threading )->Release();
    if ( SUCCEEDED( hr ) && size ) return E_UNEXPECTED;
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreQueryGameAndDlcPackageUpdatesResult( XAsyncBlock *async, UINT32 count,
                                                                      XStorePackageUpdate *packageUpdates )
{
    IXThreadingImpl *threading;
    HRESULT hr;
    if ( !async || count ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResult( async, store_updates_identity, 0, NULL, NULL );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadPackageUpdatesAsync( XStoreContextHandle storeContextHandle,
                                                              const char **packageIdentifiers,
                                                              SIZE_T packageIdentifiersCount, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadPackageUpdatesResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadAndInstallPackageUpdatesAsync( const XStoreContextHandle storeContextHandle,
                                                                        const char **packageIdentifiers,
                                                                        SIZE_T packageIdentifiersCount,
                                                                        XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadAndInstallPackageUpdatesResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadAndInstallPackagesAsync( const XStoreContextHandle storeContextHandle,
                                                                  const char **storeIds, SIZE_T storeIdsCount,
                                                                  XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadAndInstallPackagesResultCount( XAsyncBlock *async, UINT32 *count )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreDownloadAndInstallPackagesResult( XAsyncBlock *async, UINT32 count,
                                                                   char **packageIdentifiers )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryPackageIdentifier( const char *productId, SIZE_T size, char *packageIdentifier )
{
    ( void )0;
    return xpackage_query_identifier( productId, size, packageIdentifier );
}

HRESULT WINAPI XStoreImpl::XStoreRegisterGameLicenseChanged( XStoreContextHandle storeContextHandle,
                                                             XTaskQueueHandle queue, void *context,
                                                             XStoreGameLicenseChangedCallback *callback,
                                                             XTaskQueueRegistrationToken *token )
{
    return game_license_register( storeContextHandle, queue, context, callback, token );
}

BOOLEAN WINAPI XStoreImpl::XStoreUnregisterGameLicenseChanged( XStoreContextHandle storeContextHandle,
                                                               XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    return game_license_unregister( storeContextHandle, token, wait );
}

HRESULT WINAPI XStoreImpl::XStoreRegisterPackageLicenseLost( XStoreLicenseHandle storeLicenseHandle,
                                                             XTaskQueueHandle queue, void *context,
                                                             XStorePackageLicenseLostCallback *callback,
                                                             XTaskQueueRegistrationToken *token )
{
    return package_license_register( storeLicenseHandle, queue, context, callback, token );
}

BOOLEAN WINAPI XStoreImpl::XStoreUnregisterPackageLicenseLost( XStoreLicenseHandle licenseHandle,
                                                               XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    return package_license_unregister( licenseHandle, token, wait );
}

BOOLEAN WINAPI XStoreImpl::XStoreIsAvailabilityPurchasable( const XStoreAvailability availability )
{
    ( void )0;
    return FALSE;
}

HRESULT WINAPI XStoreImpl::XStoreAcquireLicenseForDurablesAsync( const XStoreContextHandle storeContextHandle,
                                                                 const char *productId, XAsyncBlock *async )
{
    return durable_license_begin( storeContextHandle, productId, async );
}

HRESULT WINAPI XStoreImpl::XStoreAcquireLicenseForDurablesResult( XAsyncBlock *async,
                                                                  XStoreLicenseHandle *storeLicenseHandle )
{
    return durable_license_result( async, storeLicenseHandle );
}

HRESULT WINAPI XStoreImpl::XStoreShowAssociatedProductsUIAsync( const XStoreContextHandle storeContextHandle,
                                                                const char *productId, XStoreProductKind productKinds,
                                                                XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowAssociatedProductsUIResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowProductPageUIAsync( const XStoreContextHandle storeContextHandle,
                                                         const char *productId, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowProductPageUIResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryAssociatedProductsForStoreIdAsync( const XStoreContextHandle storeContextHandle,
                                                                         const char *productId,
                                                                         XStoreProductKind productKinds,
                                                                         UINT32 maxItemsToRetrievePerPage,
                                                                         XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryAssociatedProductsForStoreIdResult( XAsyncBlock *async,
                                                                          XStoreProductQueryHandle *productQueryHandle )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryPackageUpdatesAsync( XStoreContextHandle storeContextHandle,
                                                           const char **packageIdentifiers,
                                                           SIZE_T packageIdentifiersCount, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryPackageUpdatesResultCount( XAsyncBlock *async, UINT32 *count )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreQueryPackageUpdatesResult( XAsyncBlock *async, UINT32 count,
                                                            XStorePackageUpdate *packageUpdates )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowGiftingUIAsync( const XStoreContextHandle storeContextHandle,
                                                     const char *productId, const char *name,
                                                     const char *extendedJsonData, XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XStoreImpl::XStoreShowGiftingUIResult( XAsyncBlock *async )
{
    ( void )0;
    return E_NOTIMPL;
}

static std::once_flag storeConfigurationOnce;
static const char *GetStoreProductId()
{
    const auto config = nexus::GetGameConfiguration();
    if ( !config || config->storeId.empty() ) return nullptr;
    std::call_once( storeConfigurationOnce,
                    [config]
                    {
                        char ids[256][13]{};
                        UINT32 count = 0;
                        for ( const auto &id : config->relatedProducts )
                            if ( count < 256 && entitled_id( id.c_str() ) ) memcpy( ids[count++], id.c_str(), 13 );
                        char hint[256 * 13];
                        const auto size = GetEnvironmentVariableA( "NEXUS_RELATED_PRODUCT_IDS", hint, sizeof( hint ) );
                        if ( size && size < sizeof( hint ) ) entitled_merge_hint( ids, &count, hint );
                        memcpy( entitled_related, ids, count * 13 );
                        entitled_related_count = count;
                    } );
    return config->storeId.c_str();
}
IXStoreImpl *GetStoreInterface() noexcept
{
    static XStoreImpl store;
    return &store;
}
