/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only preview of an exact signed licensable row. Positive evidence only:
 * the current-title store-license token is not an authoritative negative proof
 * for arbitrary or foreign products, so absence fails instead of reporting
 * NotLicensableToUser. No license handle, lease or concurrency slot is taken. */
struct can_acquire_async
{
    LONG refs, canceled, started;
    XStoreContextHandle store;
    UINT64 store_serial, until;
    char store_id[13];
    char request[512];
    XStoreCanAcquireLicenseResult result;
    IXThreadingImpl *threading;
    XAsyncBlock *async;
    HRESULT ( *fetch )( const char *, LONG *, struct entitled_snapshot ** );
};
static const char can_acquire_store_identity{};
static const char can_acquire_package_identity{};

static void can_acquire_release( struct can_acquire_async *context )
{
    if ( InterlockedDecrement( &context->refs ) ) return;
    ( context->threading )->Release();
    free( context );
}

/* Durable and Game are the only kinds with evidence of an individually
 * licensable signed row in this scope. Consumable/Pass/Unmanaged rows, an
 * absent product, an expired SKU or a malformed SKU are not turned into a
 * fabricated NotLicensableToUser or status 2; they fail for the caller. */
static HRESULT can_acquire_from_snapshot( struct entitled_snapshot *snapshot, const char *store_id,
                                          XStoreCanAcquireLicenseResult *out, UINT64 *until )
{
    XStoreCanAcquireLicenseResult found = {};
    UINT64 now = ( UINT64 )time( NULL );
    UINT32 i, j;
    *until = 0;
    if ( !snapshot || !store_id || !out ) return E_INVALIDARG;
    if ( snapshot->proof_until <= now ) return E_ACCESSDENIED;
    if ( snapshot->count && !snapshot->products ) return E_UNEXPECTED;
    for ( i = 0; i < snapshot->count; ++i )
    {
        XStoreProduct *product = &snapshot->products[i];
        if ( !product->storeId ) return E_UNEXPECTED;
        if ( strcmp( product->storeId, store_id ) ) continue;
        /* Both the product and its SKU must be in the verified collection. */
        if ( !product->isInUserCollection ) return E_NOTIMPL;
        if ( product->productKind != XStoreProductKind::Durable &&
             product->productKind != XStoreProductKind::Game )
            return E_NOTIMPL;
        if ( product->skusCount > 100 || ( product->skusCount && !product->skus ) ) return E_UNEXPECTED;
        for ( j = 0; j < product->skusCount; ++j )
        {
            XStoreSku *sku = &product->skus[j];
            UINT64 end;
            /* Existing Durable acquisition rejects trials; a positive preview
             * must not claim more than that path would grant. Skip trials and
             * let the unsupported result stay an error if none remain. */
            if ( sku->isTrial ) continue;
            if ( !sku->isInUserCollection || sku->collectionData.endDate <= 0 ) continue;
            end = ( UINT64 )sku->collectionData.endDate;
            if ( end <= now ) continue;
            if ( !entitled_sku_id( sku->skuId ) ) return E_UNEXPECTED;
            memcpy( found.licensableSku, sku->skuId, 4 );
            found.licensableSku[4] = 0;
            found.status = XStoreCanLicenseStatus::Licensable;
            *out = found;
            *until = snapshot->proof_until < end ? snapshot->proof_until : end;
            return S_OK;
        }
        return E_NOTIMPL;
    }
    return E_NOTIMPL;
}

static DWORD WINAPI can_acquire_worker( void *arg )
{
    can_acquire_async *context = static_cast<can_acquire_async *>( arg );
    struct entitled_snapshot *snapshot = NULL;
    HRESULT hr = E_ABORT;
    if ( !InterlockedCompareExchange( &context->canceled, 0, 0 ) )
        hr = context->fetch ? context->fetch( context->request, &context->canceled, &snapshot )
                            : entitled_fetch( context->request, &context->canceled, &snapshot );
    if ( SUCCEEDED( hr ) )
    {
        UINT64 xuid, serial;
        if ( FAILED( entitled_store_identity( context->store, &xuid, &serial ) ) || serial != context->store_serial )
            hr = E_INVALIDARG;
    }
    if ( SUCCEEDED( hr ) )
        hr = can_acquire_from_snapshot( snapshot, context->store_id, &context->result, &context->until );
    if ( snapshot ) entitled_snapshot_release( snapshot );
    if ( InterlockedCompareExchange( &context->canceled, 0, 0 ) ) hr = E_ABORT;
    xodus_store_license_note( "store-can-acquire-result", hr );
    ( context->threading )
        ->XAsyncComplete( context->async, hr, SUCCEEDED( hr ) ? sizeof( XStoreCanAcquireLicenseResult ) : 0 );
    can_acquire_release( context );
    return 0;
}

static HRESULT WINAPI can_acquire_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    can_acquire_async *context = static_cast<can_acquire_async *>( data->context );
    HANDLE worker;
    HRESULT hr;
    switch ( op )
    {
    case XAsyncOp::Begin:
        return ( context->threading )->XAsyncSchedule( data->async, 0 );
    case XAsyncOp::DoWork:
        if ( InterlockedCompareExchange( &context->started, 1, 0 ) ) return E_PENDING;
        if ( InterlockedCompareExchange( &context->canceled, 0, 0 ) ) return E_ABORT;
        context->async = data->async;
        InterlockedIncrement( &context->refs );
        if ( !( worker = CreateThread( NULL, 0, can_acquire_worker, context, 0, NULL ) ) )
        {
            hr = HRESULT_FROM_WIN32( GetLastError() );
            can_acquire_release( context );
            return hr;
        }
        CloseHandle( worker );
        return E_PENDING;
    case XAsyncOp::GetResult:
        if ( !data->buffer || data->bufferSize < sizeof( XStoreCanAcquireLicenseResult ) ) return E_INVALIDARG;
        {
            UINT64 xuid, serial;
            if ( FAILED( entitled_store_identity( context->store, &xuid, &serial ) ) ||
                 serial != context->store_serial )
                return E_INVALIDARG;
        }
        if ( !context->until || ( UINT64 )time( NULL ) >= context->until ) return E_ACCESSDENIED;
        memcpy( data->buffer, &context->result, sizeof( context->result ) );
        break;
    case XAsyncOp::Cancel:
        InterlockedExchange( &context->canceled, TRUE );
        break;
    case XAsyncOp::Cleanup:
        can_acquire_release( context );
        break;
    default:
        break;
    }
    return S_OK;
}

static HRESULT can_acquire_start( struct can_acquire_async *context, XAsyncBlock *async, const void *identity )
{
    HRESULT hr;
    context->refs = 1;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&context->threading ) ) )
    {
        free( context );
        return hr;
    }
    hr = ( context->threading )
             ->XAsyncBegin( async, context, identity, "XStoreCanAcquireLicenseAsync", can_acquire_provider );
    if ( FAILED( hr ) ) can_acquire_release( context );
    return hr;
}

static HRESULT can_acquire_begin( XStoreContextHandle store, const char *store_id, XAsyncBlock *async,
                                  const void *identity )
{
    can_acquire_async *context;
    UINT64 xuid, serial;
    char language[128] = "en-US", market[16] = "US";
    WCHAR locale[85], country[16];
    HRESULT hr;
    int length;
    if ( !async || !entitled_id( store_id ) ) return E_INVALIDARG;
    if ( FAILED( hr = entitled_store_identity( store, &xuid, &serial ) ) ) return hr;
    if ( !entitled_id( GetStoreProductId() ) ) return E_GAME_MISSING_GAME_CONFIG;
    if ( GetUserDefaultLocaleName( locale, ARRAY_SIZE( locale ) ) )
        WideCharToMultiByte( CP_UTF8, 0, locale, -1, language, sizeof( language ), NULL, NULL );
    if ( GetLocaleInfoEx( LOCALE_NAME_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, country, ARRAY_SIZE( country ) ) )
        WideCharToMultiByte( CP_UTF8, 0, country, -1, market, sizeof( market ), NULL, NULL );
    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, sizeof( *context ) ) ) ) )
        return E_OUTOFMEMORY;
    context->store = store;
    context->store_serial = serial;
    memcpy( context->store_id, store_id, sizeof( context->store_id ) );
    /* The parent product is already the current game; never duplicate it as a
     * ProductId. Other products are requested explicitly under this parent. */
    if ( !strcmp( store_id, GetStoreProductId() ) )
        length = snprintf( context->request, sizeof( context->request ),
                           "<Request><ParentProductId>%s</ParentProductId><ProductKinds>31</ProductKinds>"
                           "<Market>%s</Market><Language>%s</Language></Request>",
                           GetStoreProductId(), market, language );
    else
        length = snprintf( context->request, sizeof( context->request ),
                           "<Request><ParentProductId>%s</ParentProductId><ProductId>%s</ProductId>"
                           "<ProductKinds>31</ProductKinds><Market>%s</Market><Language>%s</Language></Request>",
                           GetStoreProductId(), store_id, market, language );
    if ( length < 0 || ( SIZE_T )length >= sizeof( context->request ) )
    {
        free( context );
        return E_INVALIDARG;
    }
    return can_acquire_start( context, async, identity );
}

static HRESULT can_acquire_package_begin( XStoreContextHandle store, const char *identifier, XAsyncBlock *async )
{
    char store_id[13];
    HRESULT hr;
    if ( !async || !identifier ) return E_INVALIDARG;
    if ( FAILED( hr = xpackage_query_content_store( identifier, sizeof( store_id ), store_id ) ) ) return hr;
    return can_acquire_begin( store, store_id, async, &can_acquire_package_identity );
}

static HRESULT can_acquire_result( XAsyncBlock *async, XStoreCanAcquireLicenseResult *out, const void *identity )
{
    XStoreCanAcquireLicenseResult local = {};
    IXThreadingImpl *threading = NULL;
    HRESULT hr;
    if ( !out || !async ) return E_INVALIDARG;
    /* A default/never-started block or a foreign result family must never
     * leave a caller-provided positive-looking record. */
    memset( out, 0, sizeof( *out ) );
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResult( async, identity, sizeof( local ), &local, NULL );
    ( threading )->Release();
    if ( FAILED( hr ) ) return hr;
    if ( local.status != XStoreCanLicenseStatus::Licensable || !entitled_sku_id( local.licensableSku ) )
        return E_UNEXPECTED;
    *out = local;
    return S_OK;
}
