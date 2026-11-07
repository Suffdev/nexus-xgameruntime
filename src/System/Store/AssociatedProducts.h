/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Public Store listing discovery. Public metadata is never a license and never
 * an ownership proof. The verified current-title receipt join is the only
 * collection source. The service window is the documented GDK/default 25; the
 * service's HasMorePages is the only completion signal, so empty pages are not
 * treated as the end. The 120 s deadline checks the public lookup and metadata
 * budget between requests; the current-title entitled_fetch has its own
 * separate 120 s deadline. */
#include <stdint.h>

#define ASSOCIATED_MAX_PRODUCTS 100 /* existing catalog_fetch batch capacity */
#define ASSOCIATED_SERVICE_PAGE 25  /* documented GDK/default service window */
#define ASSOCIATED_MAX_PAGES 1024

static const char associated_identity{};
static const char associated_store_identity{};

static HRESULT associated_id_at( IJsonArray *array, UINT32 index, char out[13] )
{
    HSTRING value = NULL;
    const WCHAR *text;
    UINT32 length, i;
    out[0] = 0;
    if ( FAILED( array->GetStringAt( index, &value ) ) ) return E_UNEXPECTED;
    text = WindowsGetStringRawBuffer( value, &length );
    if ( length != 12 )
    {
        WindowsDeleteString( value );
        return E_UNEXPECTED;
    }
    for ( i = 0; i < 12; ++i )
    {
        WCHAR c = text[i];
        if ( !( ( c >= L'A' && c <= L'Z' ) || ( c >= L'0' && c <= L'9' ) ) )
        {
            WindowsDeleteString( value );
            return E_UNEXPECTED;
        }
        out[i] = (char)c;
    }
    out[12] = 0;
    WindowsDeleteString( value );
    return S_OK;
}

static HRESULT associated_id( IJsonObject *object, const WCHAR *name, char out[13] )
{
    char *id = receipt_string( object, name, 12 );
    HRESULT hr = id && entitled_id( id ) ? S_OK : E_UNEXPECTED;
    if ( SUCCEEDED( hr ) ) memcpy( out, id, 13 );
    else out[0] = 0;
    free( id );
    return hr;
}

/* A missing or wrongly-typed HasMorePages is not a false completion. Some
 * JSON providers return a default for GetNamedBoolean, so inspect the value
 * type explicitly. */
static HRESULT associated_bool( IJsonObject *object, const WCHAR *name, bool *out )
{
    HSTRING key = NULL;
    IJsonValue *value = NULL;
    JsonValueType type;
    HRESULT hr = WindowsCreateString( name, wcslen( name ), &key );
    *out = false;
    if ( FAILED( hr ) ) return hr;
    hr = object->GetNamedValue( key, &value );
    WindowsDeleteString( key );
    if ( FAILED( hr ) || !value ) return E_UNEXPECTED;
    hr = value->get_ValueType( &type );
    if ( SUCCEEDED( hr ) && type == JsonValueType_Boolean ) hr = value->GetBoolean( out );
    else hr = E_UNEXPECTED;
    value->Release();
    return hr;
}

/* The StoreSDK projection may carry inverse relationships. A product can be
 * listed against multiple parents, so a current-root match anywhere in the
 * projection is valid even when other SellableBy/addOnParent roots are
 * present. Fail only when a relevant relationship is present and NONE matches
 * the current root, or a relevant RelatedProductId is malformed. An absent
 * projection is not itself a contradiction. */
static HRESULT associated_related( IJsonObject *product, const char *root )
{
    catalog_json_ptr<IJsonArray> markets;
    UINT32 market_count;
    BOOL any_relevant = FALSE, any_match = FALSE;
    if ( FAILED( receipt_get_array( product, L"MarketProperties", &markets.p ) ) ) return S_OK;
    if ( FAILED( receipt_array_size( markets.p, &market_count ) ) || market_count > 8 ) return E_UNEXPECTED;
    for ( UINT32 i = 0; i < market_count; ++i )
    {
        catalog_json_ptr<IJsonObject> market;
        catalog_json_ptr<IJsonArray> relations;
        UINT32 relation_count;
        if ( FAILED( markets.p->GetObjectAt( i, &market.p ) ) ) return E_UNEXPECTED;
        if ( FAILED( receipt_get_array( market.p, L"RelatedProducts", &relations.p ) ) ) continue;
        if ( FAILED( receipt_array_size( relations.p, &relation_count ) ) || relation_count > 64 )
            return E_UNEXPECTED;
        for ( UINT32 j = 0; j < relation_count; ++j )
        {
            catalog_json_ptr<IJsonObject> relation;
            char *type = NULL, *id = NULL;
            BOOL relevant;
            if ( FAILED( relations.p->GetObjectAt( j, &relation.p ) ) ) return E_UNEXPECTED;
            type = receipt_string( relation.p, L"RelationshipType", 32 );
            id = receipt_string( relation.p, L"RelatedProductId", 12 );
            relevant = type && ( !strcmp( type, "SellableBy" ) || !strcmp( type, "addOnParent" ) );
            if ( relevant )
            {
                if ( !id || !entitled_id( id ) )
                {
                    free( type );
                    free( id );
                    return E_UNEXPECTED;
                }
                any_relevant = TRUE;
                any_match |= !strcmp( id, root );
            }
            free( type );
            free( id );
        }
    }
    if ( any_relevant && !any_match ) return E_UNEXPECTED;
    return S_OK;
}


static HRESULT associated_fetch( const char *request, LONG *canceled, struct entitled_snapshot **out )
{
    xmlDocPtr doc = NULL, license_doc = NULL;
    xmlNodePtr root, license_root;
    char *parent = NULL, *market = NULL, *language = NULL;
    char storage[ASSOCIATED_MAX_PRODUCTS][13];
    UINT32 count = 0, pages = 0;
    UINT64 kinds, skip = 0, expiry;
    ULONGLONG deadline = GetTickCount64() + 120000;
    BYTE *bytes = NULL, *metadata = NULL;
    SIZE_T length = 0, metadata_length = 0;
    HRESULT hr = E_UNEXPECTED, com = CoInitializeEx( NULL, COINIT_MULTITHREADED );
    struct entitled_snapshot *catalog = NULL, *owned = NULL;
    *out = NULL;
    doc = xmlReadMemory( request, strlen( request ), NULL, NULL, XML_PARSE_NONET );
    if ( !doc ) goto done;
    root = xmlDocGetRootElement( doc );
    parent = entitled_text( root, "ParentProductId" );
    market = entitled_text( root, "Market" );
    language = entitled_text( root, "Language" );
    if ( !parent || !entitled_id( parent ) || strcmp( parent, GetStoreProductId() ) || !market ||
         strlen( market ) != 2 || !language || !language[0] ||
         FAILED( entitled_uint( root, "ProductKinds", &kinds ) ) || !kinds || ( kinds & ~31 ) )
        goto done;
    for ( UINT32 i = 0; market[i]; ++i )
        if ( market[i] < 'A' || market[i] > 'Z' ) goto done;
    for ( UINT32 i = 0; language[i]; ++i )
        if ( !( ( language[i] >= 'A' && language[i] <= 'Z' ) || ( language[i] >= 'a' && language[i] <= 'z' ) ||
                ( language[i] >= '0' && language[i] <= '9' ) || language[i] == '-' ) )
            goto done;

    for ( ;; )
    {
        catalog_json_ptr<IJsonObject> document;
        catalog_json_ptr<IJsonArray> big_ids, products;
        char page[ASSOCIATED_SERVICE_PAGE][13], product_ids[ASSOCIATED_SERVICE_PAGE][13];
        char skip_text[32];
        WCHAR path[2048];
        UINT32 big_count, product_count;
        bool has_more;
        if ( InterlockedCompareExchange( canceled, 0, 0 ) )
        {
            hr = E_ABORT;
            goto done;
        }
        if ( GetTickCount64() >= deadline )
        {
            hr = HRESULT_FROM_WIN32( ERROR_TIMEOUT );
            goto done;
        }
        if ( pages++ >= ASSOCIATED_MAX_PAGES ) goto done;
        snprintf( skip_text, sizeof( skip_text ), "%llu", ( unsigned long long )skip );
        if ( swprintf( path, ARRAY_SIZE( path ),
                       L"/v7/products/lookup?value=%hs&market=%hs&languages=%hs&$top=%u&$skip=%hs"
                       L"&fieldsTemplate=StoreSDK&actionFilter=Purchase&alternateId=SellableBy",
                       parent, market, language, (unsigned)ASSOCIATED_SERVICE_PAGE, skip_text ) < 0 )
            goto done;
        free( bytes );
        bytes = NULL;
        length = 0;
        if ( FAILED( hr = receipt_public_get( L"displaycatalog.mp.microsoft.com", path, 2 * 1024 * 1024, &bytes,
                                              &length ) ) )
            goto done;
        hr = E_UNEXPECTED;
        if ( InterlockedCompareExchange( canceled, 0, 0 ) )
        {
            hr = E_ABORT;
            goto done;
        }
        if ( FAILED( receipt_json( bytes, length, &document.p ) ) ||
             FAILED( receipt_get_array( document.p, L"BigIds", &big_ids.p ) ) || !big_ids.p ||
             FAILED( receipt_array_size( big_ids.p, &big_count ) ) || big_count > ASSOCIATED_SERVICE_PAGE ||
             FAILED( receipt_get_array( document.p, L"Products", &products.p ) ) || !products.p ||
             FAILED( receipt_array_size( products.p, &product_count ) ) || product_count != big_count ||
             FAILED( associated_bool( document.p, L"HasMorePages", &has_more ) ) )
            goto done;
        for ( UINT32 i = 0; i < big_count; ++i )
            if ( FAILED( associated_id_at( big_ids.p, i, page[i] ) ) ) goto done;
        for ( UINT32 i = 0; i < product_count; ++i )
        {
            catalog_json_ptr<IJsonObject> product;
            if ( FAILED( products.p->GetObjectAt( i, &product.p ) ) ||
                 FAILED( associated_id( product.p, L"ProductId", product_ids[i] ) ) ||
                 FAILED( associated_related( product.p, parent ) ) )
                goto done;
            for ( UINT32 j = 0; j < i; ++j )
                if ( !strcmp( product_ids[i], product_ids[j] ) ) goto done;
        }
        for ( UINT32 i = 0; i < product_count; ++i )
        {
            BOOL found = FALSE;
            for ( UINT32 j = 0; j < big_count; ++j )
                found |= !strcmp( product_ids[i], page[j] );
            if ( !found ) goto done;
        }
        /* Distinct raw SKU windows can legitimately repeat BigIds; $skip always
         * advances, so page/time caps plus the authoritative HasMorePages bound
         * the loop. Duplicate ids are deduped, never treated as invalid. */
        for ( UINT32 i = 0; i < big_count; ++i )
        {
            BOOL duplicate = FALSE;
            for ( UINT32 j = 0; j < count; ++j )
                duplicate |= !strcmp( page[i], storage[j] );
            if ( duplicate ) continue;
            if ( count == ASSOCIATED_MAX_PRODUCTS )
            {
                hr = HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
                goto done;
            }
            memcpy( storage[count], page[i], 13 );
            ++count;
        }
        if ( !has_more ) break;
        skip += ASSOCIATED_SERVICE_PAGE;
    }
    if ( GetTickCount64() >= deadline )
    {
        hr = HRESULT_FROM_WIN32( ERROR_TIMEOUT );
        goto done;
    }

    if ( count )
    {
        char combined[1301] = {};
        char *metadata_ids[ASSOCIATED_MAX_PRODUCTS];
        const char *purchase[] = { "Purchase" };
        WCHAR path[2048];
        for ( UINT32 i = 0; i < count; ++i )
        {
            if ( i ) strcat( combined, "," );
            strcat( combined, storage[i] );
            metadata_ids[i] = storage[i];
        }
        if ( swprintf( path, ARRAY_SIZE( path ), L"/v7.0/products?bigIds=%hs&market=%hs&languages=%hs", combined,
                       market, language ) < 0 )
            goto done;
        if ( FAILED( hr = receipt_public_get( L"displaycatalog.mp.microsoft.com", path, 4 * 1024 * 1024, &metadata,
                                              &metadata_length ) ) )
            goto done;
        hr = E_UNEXPECTED;
        if ( InterlockedCompareExchange( canceled, 0, 0 ) )
        {
            hr = E_ABORT;
            goto done;
        }
        if ( FAILED( hr = catalog_parse( metadata, metadata_length, (const char **)metadata_ids, count,
                                         (UINT32)kinds, purchase, 1, &catalog ) ) )
            goto done;
        if ( GetTickCount64() >= deadline )
        {
            hr = HRESULT_FROM_WIN32( ERROR_TIMEOUT );
            goto done;
        }
    }
    else
    {
        catalog = static_cast<std::remove_reference_t<decltype( catalog )>>( calloc( 1, sizeof( *catalog ) ) );
        if ( !catalog )
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        catalog->refs = 1;
        catalog->valid_until = time( NULL ) + 60;
    }

    /* The current-title signed receipt is the only collection proof. It is
     * joined only after the public listing has been parsed, and the hardcoded
     * current-game parent binding is not changed here. */
    if ( count )
    {
        char kind_text[16];
        xmlChar *license_bytes = NULL;
        int license_size;
        license_doc = xmlNewDoc( BAD_CAST "1.0" );
        if ( !license_doc )
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        license_root = xmlNewNode( NULL, BAD_CAST "Request" );
        if ( !license_root )
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        xmlDocSetRootElement( license_doc, license_root );
        snprintf( kind_text, sizeof( kind_text ), "%u", (UINT32)kinds );
        if ( !xmlNewTextChild( license_root, NULL, BAD_CAST "ParentProductId", BAD_CAST parent ) ||
             !xmlNewTextChild( license_root, NULL, BAD_CAST "ProductKinds", BAD_CAST kind_text ) ||
             !xmlNewTextChild( license_root, NULL, BAD_CAST "Market", BAD_CAST market ) ||
             !xmlNewTextChild( license_root, NULL, BAD_CAST "Language", BAD_CAST language ) )
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        for ( UINT32 i = 0; i < count; ++i )
            if ( !xmlNewTextChild( license_root, NULL, BAD_CAST "ProductId", BAD_CAST storage[i] ) )
            {
                hr = E_OUTOFMEMORY;
                goto done;
            }
        xmlDocDumpMemory( license_doc, &license_bytes, &license_size );
        if ( !license_bytes )
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        if ( license_size <= 0 || license_size > 60000 )
        {
            xmlFree( license_bytes );
            hr = E_UNEXPECTED;
            goto done;
        }
        hr = entitled_fetch( (char *)license_bytes, canceled, &owned );
        xmlFree( license_bytes );
        if ( FAILED( hr ) ) goto done;
        if ( FAILED( hr = catalog_join_collection( catalog, owned ) ) ) goto done;
        expiry = catalog->valid_until;
        if ( owned && owned->valid_until < expiry ) expiry = owned->valid_until;
        catalog->valid_until = expiry;
    }
    hr = S_OK;
    *out = catalog;
    catalog = NULL;

done:
    if ( catalog ) entitled_snapshot_release( catalog );
    if ( owned ) entitled_snapshot_release( owned );
    free( bytes );
    free( metadata );
    free( parent );
    free( market );
    free( language );
    if ( doc ) xmlFreeDoc( doc );
    if ( license_doc ) xmlFreeDoc( license_doc );
    if ( SUCCEEDED( com ) ) CoUninitialize();
    /* A successful return must carry a real snapshot. */
    if ( SUCCEEDED( hr ) && !*out ) hr = E_UNEXPECTED;
    return hr;
}

static HRESULT associated_begin( XStoreContextHandle store, const char *target, UINT32 kinds, UINT32 page_size,
                                 XAsyncBlock *async, const void *identity = &associated_identity )
{
    UINT64 xuid, serial;
    if ( !async || !kinds || ( kinds & ~31 ) || !page_size ) return E_INVALIDARG;
    if ( target && !entitled_id( target ) ) return E_INVALIDARG;
    HRESULT hr = entitled_store_identity( store, &xuid, &serial );
    if ( FAILED( hr ) ) return hr;
    if ( !entitled_id( GetStoreProductId() ) ) return E_GAME_MISSING_GAME_CONFIG;
    const char *parent = target ? target : GetStoreProductId();
    if ( strcmp( parent, GetStoreProductId() ) ) return E_NOTIMPL;
    char language[128] = "en-US", market[16] = "US", number[16];
    WCHAR locale[85], country[16];
    if ( GetUserDefaultLocaleName( locale, ARRAY_SIZE( locale ) ) )
        WideCharToMultiByte( CP_UTF8, 0, locale, -1, language, sizeof( language ), NULL, NULL );
    if ( GetLocaleInfoEx( LOCALE_NAME_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, country, ARRAY_SIZE( country ) ) )
        WideCharToMultiByte( CP_UTF8, 0, country, -1, market, sizeof( market ), NULL, NULL );
    xmlDocPtr doc = xmlNewDoc( BAD_CAST "1.0" );
    if ( !doc ) return E_OUTOFMEMORY;
    xmlNodePtr root = xmlNewNode( NULL, BAD_CAST "Request" );
    if ( !root )
    {
        xmlFreeDoc( doc );
        return E_OUTOFMEMORY;
    }
    xmlDocSetRootElement( doc, root );
    snprintf( number, sizeof( number ), "%u", kinds );
    if ( !xmlNewTextChild( root, NULL, BAD_CAST "ParentProductId", BAD_CAST parent ) ||
         !xmlNewTextChild( root, NULL, BAD_CAST "ProductKinds", BAD_CAST number ) ||
         !xmlNewTextChild( root, NULL, BAD_CAST "Market", BAD_CAST market ) ||
         !xmlNewTextChild( root, NULL, BAD_CAST "Language", BAD_CAST language ) )
    {
        xmlFreeDoc( doc );
        return E_OUTOFMEMORY;
    }
    xmlChar *bytes = NULL;
    int length;
    xmlDocDumpMemory( doc, &bytes, &length );
    xmlFreeDoc( doc );
    if ( !bytes || length <= 0 )
    {
        xmlFree( bytes );
        return E_OUTOFMEMORY;
    }
    entitled_async *context = static_cast<std::remove_reference_t<decltype( context )>>(
        calloc( 1, sizeof( *context ) ) );
    if ( context ) context->request = strdup( (char *)bytes );
    xmlFree( bytes );
    if ( !context || !context->request )
    {
        free( context );
        return E_OUTOFMEMORY;
    }
    context->store = store;
    context->store_serial = serial;
    context->page_size = page_size < ASSOCIATED_MAX_PRODUCTS ? page_size : ASSOCIATED_MAX_PRODUCTS;
    context->identity = identity;
    context->fetch = associated_fetch;
    return entitled_start( context, async, FALSE );
}

static HRESULT associated_store_begin( XStoreContextHandle store, const char *product_id, UINT32 kinds,
                                       UINT32 page_size, XAsyncBlock *async )
{
    if ( !product_id ) return E_INVALIDARG;
    return associated_begin( store, product_id, kinds, page_size, async, &associated_store_identity );
}
