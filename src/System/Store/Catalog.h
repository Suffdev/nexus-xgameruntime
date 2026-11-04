/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Public Store listings are not licenses. Collection flags are joined by exact
 * product/SKU against verified receipts; this snapshot never carries proof. */
#include <float.h>
#include <limits>

static const char catalog_identity{};
static const char catalog_package_identity{};

template <typename T> struct catalog_json_ptr
{
    T *p = NULL;
    ~catalog_json_ptr ()
    {
        if ( p )
            p->Release ();
    }
};

static UINT32 catalog_kind ( const char *type )
{
    if ( !type )
        return 0;
    const char *names[] = { "Consumable", "Durable", "Game", "Pass", "UnmanagedConsumable" };
    for ( UINT32 i = 0; i < ARRAY_SIZE ( names ); ++i )
        if ( !strcmp ( type, names[i] ) )
            return 1u << i;
    return 0;
}

static BOOL catalog_string_in_array ( IJsonArray *array, const char *wanted )
{
    UINT32 count;
    if ( FAILED ( receipt_array_size ( array, &count ) ) || count > 256 )
        return FALSE;
    for ( UINT32 i = 0; i < count; ++i )
    {
        HSTRING value = NULL;
        if ( FAILED ( array->GetStringAt ( i, &value ) ) )
            return FALSE;
        UINT32 length;
        const WCHAR *text = WindowsGetStringRawBuffer ( value, &length );
        BOOL match = length == strlen ( wanted );
        for ( UINT32 j = 0; match && j < length; ++j )
            match = text[j] == (BYTE)wanted[j];
        WindowsDeleteString ( value );
        if ( match )
            return TRUE;
    }
    return FALSE;
}

static HRESULT catalog_date ( IJsonObject *object, const WCHAR *key, INT64 *out )
{
    char *text = receipt_string ( object, key, 64 );
    UINT64 value;
    HRESULT hr = text ? receipt_date ( text, &value ) : E_UNEXPECTED;
    /* DisplayCatalog uses 1753 as the start of an unbounded availability.
     * Receipt expiry deliberately rejects pre-epoch values; do not relax it. */
    if ( FAILED ( hr ) && text && !strcmp ( text, "1753-01-01T00:00:00.0000000Z" ) )
    {
        value = 0;
        hr = S_OK;
    }
    free ( text );
    if ( SUCCEEDED ( hr ) )
    {
        if ( value > static_cast<UINT64>( INT64_MAX ) ) return E_UNEXPECTED;
        *out = static_cast<INT64>( value );
    }
    return hr;
}

/* Server availability ordering includes subscriptions and bundle-only licenses.
 * Only an active desktop Purchase offer supplies the displayed purchase price. */
static HRESULT catalog_availability ( IJsonObject *object, const char *filters[], UINT32 filters_count, BOOL *include,
                                      BOOL *purchase, INT64 *end )
{
    catalog_json_ptr<IJsonObject> conditions, client;
    catalog_json_ptr<IJsonArray> actions, platforms;
    INT64 start;
    *include = *purchase = FALSE;
    if ( FAILED ( receipt_get_object ( object, L"Conditions", &conditions.p ) ) ||
         FAILED ( catalog_date ( conditions.p, L"StartDate", &start ) ) ||
         FAILED ( catalog_date ( conditions.p, L"EndDate", end ) ) ||
         FAILED ( receipt_get_array ( object, L"Actions", &actions.p ) ) )
        return E_UNEXPECTED;
    if ( start > time ( NULL ) || *end <= time ( NULL ) )
        return S_OK;
    catalog_json_ptr<IJsonArray> predicates;
    if ( SUCCEEDED ( receipt_get_array ( conditions.p, L"EligibilityPredicateIds", &predicates.p ) ) )
    {
        UINT32 count;
        if ( FAILED ( receipt_array_size ( predicates.p, &count ) ) )
            return E_UNEXPECTED;
        /* Public metadata cannot establish account-specific offer eligibility. */
        if ( count )
            return S_OK;
    }
    if ( SUCCEEDED ( receipt_get_object ( conditions.p, L"ClientConditions", &client.p ) ) &&
         SUCCEEDED ( receipt_get_array ( client.p, L"AllowedPlatforms", &platforms.p ) ) )
    {
        UINT32 count;
        BOOL desktop = FALSE;
        if ( FAILED ( receipt_array_size ( platforms.p, &count ) ) || count > 64 )
            return E_UNEXPECTED;
        for ( UINT32 i = 0; i < count; ++i )
        {
            catalog_json_ptr<IJsonObject> platform;
            if ( FAILED ( platforms.p->GetObjectAt ( i, &platform.p ) ) )
                return E_UNEXPECTED;
            char *name = receipt_string ( platform.p, L"PlatformName", 64 );
            desktop |= name && !strcmp ( name, "Windows.Desktop" );
            free ( name );
        }
        if ( count && !desktop )
            return S_OK;
    }
    *purchase = catalog_string_in_array ( actions.p, "Purchase" );
    *include = filters_count == 0;
    for ( UINT32 i = 0; i < filters_count; ++i )
        *include |= catalog_string_in_array ( actions.p, filters[i] );
    return S_OK;
}

static HRESULT catalog_price ( IJsonObject *availability, INT64 end, XStorePrice *out )
{
    catalog_json_ptr<IJsonObject> order, price;
    double list, base;
    if ( FAILED ( receipt_get_object ( availability, L"OrderManagementData", &order.p ) ) ||
         FAILED ( receipt_get_object ( order.p, L"Price", &price.p ) ) ||
         FAILED ( receipt_get_number ( price.p, L"ListPrice", &list ) ) ||
         FAILED ( receipt_get_number ( price.p, L"MSRP", &base ) ) || !isfinite ( list ) || !isfinite ( base ) ||
         list < 0 || base < 0 || list > FLT_MAX || base > FLT_MAX )
        return E_UNEXPECTED;
    char *currency = receipt_string ( price.p, L"CurrencyCode", 3 );
    if ( !currency || strlen ( currency ) != 3 )
    {
        free ( currency );
        return E_UNEXPECTED;
    }
    for ( UINT32 i = 0; i < 3; ++i )
        if ( currency[i] < 'A' || currency[i] > 'Z' )
        {
            free ( currency );
            return E_UNEXPECTED;
        }
    out->currencyCode = currency;
    out->price = list;
    out->basePrice = base;
    out->isOnSale = list < base;
    out->saleEndDate = out->isOnSale ? end : 0;
    /* Keep the currency explicit, never use the locale's potentially different
     * currency symbol. These ABI buffers include the terminating byte. */
    int n = snprintf ( out->formattedPrice, sizeof ( out->formattedPrice ), "%.8g %s", list, currency );
    int m = snprintf ( out->formattedBasePrice, sizeof ( out->formattedBasePrice ), "%.8g %s", base, currency );
    if ( n < 0 || n >= sizeof ( out->formattedPrice ) || m < 0 || m >= sizeof ( out->formattedBasePrice ) )
        return E_UNEXPECTED;
    return S_OK;
}

static HRESULT catalog_images ( IJsonObject *localized, XStoreImage **out, UINT32 *out_count )
{
    catalog_json_ptr<IJsonArray> array;
    UINT32 count;
    if ( FAILED ( receipt_get_array ( localized, L"Images", &array.p ) ) )
        return S_OK;
    if ( FAILED ( receipt_array_size ( array.p, &count ) ) || count > 256 )
        return E_UNEXPECTED;
    if ( !count )
        return S_OK;
    *out = (XStoreImage *)calloc ( count, sizeof ( **out ) );
    if ( !*out )
        return E_OUTOFMEMORY;
    *out_count = count;
    for ( UINT32 i = 0; i < count; ++i )
    {
        catalog_json_ptr<IJsonObject> image;
        double height, width;
        if ( FAILED ( array.p->GetObjectAt ( i, &image.p ) ) )
            return E_UNEXPECTED;
        XStoreImage *target = &( *out )[i];
        char *uri = receipt_string ( image.p, L"Uri", 4096 );
        target->uri = uri;
        if ( !uri )
            return E_UNEXPECTED;
        if ( !strncmp ( uri, "//", 2 ) )
        {
            target->uri = (char *)malloc ( strlen ( uri ) + 7 );
            if ( !target->uri )
            {
                free ( uri );
                return E_OUTOFMEMORY;
            }
            sprintf ( (char *)target->uri, "https:%s", uri );
            free ( uri );
        }
        if ( strncmp ( target->uri, "https://", 8 ) || FAILED ( receipt_get_number ( image.p, L"Height", &height ) ) ||
             FAILED ( receipt_get_number ( image.p, L"Width", &width ) ) || !isfinite ( height ) ||
             !isfinite ( width ) || height < 0 || width < 0 || height > UINT32_MAX || width > UINT32_MAX ||
             floor ( height ) != height || floor ( width ) != width )
            return E_UNEXPECTED;
        target->height = height;
        target->width = width;
        target->caption = receipt_string ( image.p, L"Caption", 1024 );
        if ( !target->caption )
            target->caption = strdup ( "" ); /* nullable public field */
        target->imagePurposeTag = receipt_string ( image.p, L"ImagePurpose", 128 );
        if ( !target->caption || !target->imagePurposeTag )
            return E_UNEXPECTED;
    }
    return S_OK;
}

static HRESULT catalog_parse_product ( IJsonObject *source, UINT32 kinds, const char *filters[], UINT32 filters_count,
                                       XStoreProduct *out, BOOL *include )
{
    catalog_json_ptr<IJsonObject> properties, localized;
    catalog_json_ptr<IJsonArray> locals, skus;
    UINT32 count;
    *include = FALSE;
    char *type = receipt_string ( source, L"ProductType", 32 );
    UINT32 kind = catalog_kind ( type );
    free ( type );
    if ( !( kind & kinds ) )
        return S_OK;
    /* Recurring subscription policies need their own complete billing mapping.
     * Do not advertise a subscription as a one-time, zero-price purchase. */
    if ( kind == 8 )
        return E_NOTIMPL;
    out->productKind = (XStoreProductKind)kind;
    out->storeId = receipt_string ( source, L"ProductId", 12 );
    if ( !entitled_id ( out->storeId ) || FAILED ( receipt_get_array ( source, L"LocalizedProperties", &locals.p ) ) ||
         FAILED ( locals.p->GetObjectAt ( 0, &localized.p ) ) ||
         FAILED ( receipt_get_object ( source, L"Properties", &properties.p ) ) )
        return E_UNEXPECTED;
    out->title = receipt_string ( localized.p, L"ProductTitle", 1024 );
    out->description = receipt_string ( localized.p, L"ProductDescription", 65536 );
    out->language = receipt_string ( localized.p, L"Language", 35 );
    out->inAppOfferToken = receipt_string ( properties.p, L"InAppOfferToken", 256 );
    if ( !out->inAppOfferToken )
        out->inAppOfferToken = strdup ( "" );
    out->linkUri = (char *)malloc ( 64 );
    if ( out->linkUri )
        snprintf ( out->linkUri, 64, "https://www.microsoft.com/store/productId/%s", out->storeId );
    if ( !out->title || !out->description || !out->language || !out->inAppOfferToken || !out->linkUri )
        return E_UNEXPECTED;
    HRESULT hr = catalog_images ( localized.p, &out->images, &out->imagesCount );
    if ( FAILED ( hr ) )
        return hr;
    if ( FAILED ( receipt_get_array ( source, L"DisplaySkuAvailabilities", &skus.p ) ) ||
         FAILED ( receipt_array_size ( skus.p, &count ) ) || count > 100 )
        return E_UNEXPECTED;
    out->skus = (XStoreSku *)calloc ( count ? count : 1, sizeof ( *out->skus ) );
    if ( !out->skus )
        return E_OUTOFMEMORY;
    BOOL product_price = FALSE;
    for ( UINT32 i = 0; i < count; ++i )
    {
        catalog_json_ptr<IJsonObject> entry, sku, props, local;
        catalog_json_ptr<IJsonArray> sku_locals, availabilities, packages;
        UINT32 available_count, packages_count = 0;
        if ( FAILED ( skus.p->GetObjectAt ( i, &entry.p ) ) ||
             FAILED ( receipt_get_object ( entry.p, L"Sku", &sku.p ) ) ||
             FAILED ( receipt_get_object ( sku.p, L"Properties", &props.p ) ) ||
             FAILED ( receipt_get_array ( entry.p, L"Availabilities", &availabilities.p ) ) ||
             FAILED ( receipt_array_size ( availabilities.p, &available_count ) ) || available_count > 256 )
            return E_UNEXPECTED;
        XStoreSku *target = &out->skus[out->skusCount++];
        target->skuId = receipt_string ( sku.p, L"SkuId", 4 );
        if ( !entitled_sku_id ( target->skuId ) )
            return E_UNEXPECTED;
        for ( UINT32 j = 0; j + 1 < out->skusCount; ++j )
            if ( !strcmp ( out->skus[j].skuId, target->skuId ) )
                return E_UNEXPECTED;
        if ( SUCCEEDED ( receipt_get_array ( sku.p, L"LocalizedProperties", &sku_locals.p ) ) &&
             SUCCEEDED ( sku_locals.p->GetObjectAt ( 0, &local.p ) ) )
        {
            target->title = receipt_string ( local.p, L"SkuTitle", 1024 );
            target->description = receipt_string ( local.p, L"SkuDescription", 65536 );
            target->language = receipt_string ( local.p, L"Language", 35 );
        }
        if ( !target->title )
            target->title = strdup ( out->title );
        if ( !target->description )
            target->description = strdup ( out->description );
        if ( !target->language )
            target->language = strdup ( out->language );
        boolean trial;
        if ( !target->title || !target->description || !target->language ||
             FAILED ( receipt_get_boolean ( props.p, L"IsTrial", &trial ) ) )
            return E_UNEXPECTED;
        target->isTrial = trial;
        if ( SUCCEEDED ( receipt_get_array ( props.p, L"Packages", &packages.p ) ) )
        {
            if ( FAILED ( receipt_array_size ( packages.p, &packages_count ) ) )
                return E_UNEXPECTED;
            out->hasDigitalDownload |= packages_count != 0;
        }
        target->availabilities =
            (XStoreAvailability *)calloc ( available_count ? available_count : 1, sizeof ( *target->availabilities ) );
        if ( !target->availabilities )
            return E_OUTOFMEMORY;
        BOOL sku_price = FALSE;
        for ( UINT32 j = 0; j < available_count; ++j )
        {
            catalog_json_ptr<IJsonObject> available;
            BOOL match, purchase;
            INT64 end;
            if ( FAILED ( availabilities.p->GetObjectAt ( j, &available.p ) ) ||
                 FAILED ( hr = catalog_availability ( available.p, filters, filters_count, &match, &purchase, &end ) ) )
                return E_UNEXPECTED;
            *include |= match;
            if ( !match )
                continue;
            XStoreAvailability *item = &target->availabilities[target->availabilitiesCount++];
            item->availabilityId = receipt_string ( available.p, L"AvailabilityId", 12 );
            item->endDate = end;
            if ( !entitled_id ( item->availabilityId ) ||
                 FAILED ( hr = catalog_price ( available.p, end, &item->price ) ) )
                return E_UNEXPECTED;
            if ( purchase && !sku_price )
            {
                target->price = item->price;
                target->price.currencyCode = strdup ( item->price.currencyCode );
                if ( !target->price.currencyCode )
                    return E_OUTOFMEMORY;
                sku_price = TRUE;
                if ( !product_price )
                {
                    out->price = item->price;
                    out->price.currencyCode = strdup ( item->price.currencyCode );
                    if ( !out->price.currencyCode )
                        return E_OUTOFMEMORY;
                    product_price = TRUE;
                }
            }
        }
    }
    /* No action filter includes historic/unavailable listings, as required by
     * QueryProducts. An explicit filter must match an active PC availability. */
    if ( !filters_count )
        *include = TRUE;
    return S_OK;
}

static HRESULT catalog_parse ( const BYTE *bytes, SIZE_T length, const char *ids[], UINT32 ids_count, UINT32 kinds,
                               const char *filters[], UINT32 filters_count, struct entitled_snapshot **out )
{
    catalog_json_ptr<IJsonObject> document;
    catalog_json_ptr<IJsonArray> products;
    UINT32 count;
    *out = NULL;
    HRESULT hr = receipt_json ( bytes, length, &document.p );
    if ( FAILED ( hr ) || FAILED ( receipt_get_array ( document.p, L"Products", &products.p ) ) ||
         FAILED ( receipt_array_size ( products.p, &count ) ) || count > ids_count )
        return E_UNEXPECTED;
    entitled_snapshot *snapshot = (entitled_snapshot *)calloc ( 1, sizeof ( *snapshot ) );
    if ( !snapshot )
        return E_OUTOFMEMORY;
    snapshot->refs = 1;
    snapshot->valid_until = time ( NULL ) + 60;
    snapshot->products = (XStoreProduct *)calloc ( count ? count : 1, sizeof ( *snapshot->products ) );
    if ( !snapshot->products )
    {
        entitled_snapshot_release ( snapshot );
        return E_OUTOFMEMORY;
    }
    char seen[100][13]{};
    for ( UINT32 i = 0; i < count; ++i )
    {
        catalog_json_ptr<IJsonObject> product;
        if ( FAILED ( products.p->GetObjectAt ( i, &product.p ) ) )
        {
            hr = E_UNEXPECTED;
            break;
        }
        char *id = receipt_string ( product.p, L"ProductId", 12 );
        BOOL requested = FALSE, duplicate = FALSE;
        for ( UINT32 j = 0; id && j < ids_count; ++j )
            requested |= !strcmp ( ids[j], id );
        for ( UINT32 j = 0; id && j < i; ++j )
            duplicate |= !strcmp ( seen[j], id );
        if ( !entitled_id ( id ) || !requested || duplicate )
        {
            free ( id );
            hr = E_UNEXPECTED;
            break;
        }
        strcpy ( seen[i], id );
        free ( id );
        BOOL include = FALSE;
        XStoreProduct *target = &snapshot->products[snapshot->count++];
        hr = catalog_parse_product ( product.p, kinds, filters, filters_count, target, &include );
        if ( FAILED ( hr ) )
            break;
        if ( !include )
        {
            /* Reuse the single owner to free a filtered product without exposing
             * it. Compact only after all remaining elements are initialized. */
            entitled_snapshot *discard = (entitled_snapshot *)calloc ( 1, sizeof ( *discard ) );
            if ( !discard )
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            discard->refs = 1;
            discard->count = 1;
            discard->products = (XStoreProduct *)malloc ( sizeof ( *target ) );
            if ( !discard->products )
            {
                free ( discard );
                hr = E_OUTOFMEMORY;
                break;
            }
            *discard->products = *target;
            *target = {};
            entitled_snapshot_release ( discard );
            --snapshot->count;
        }
    }
    if ( FAILED ( hr ) )
    {
        entitled_snapshot_release ( snapshot );
        return hr;
    }
    *out = snapshot;
    return S_OK;
}

static HRESULT catalog_join_collection ( entitled_snapshot *catalog, const entitled_snapshot *owned )
{
    if ( !owned || owned->proof_until <= (UINT64)time ( NULL ) )
        return E_ACCESSDENIED;
    catalog->valid_until = std::min ( catalog->valid_until, owned->valid_until );
    for ( UINT32 i = 0; i < catalog->count; ++i )
        for ( UINT32 j = 0; j < owned->count; ++j )
        {
            XStoreProduct *p = &catalog->products[i];
            const XStoreProduct *o = &owned->products[j];
            if ( strcmp ( p->storeId, o->storeId ) )
                continue;
            for ( UINT32 k = 0; k < p->skusCount; ++k )
                for ( UINT32 l = 0; l < o->skusCount; ++l )
                {
                    XStoreSku *sku = &p->skus[k];
                    const XStoreSku *license = &o->skus[l];
                    if ( strcmp ( sku->skuId, license->skuId ) || !license->isInUserCollection ||
                         license->collectionData.endDate <= time ( NULL ) )
                        continue;
                    sku->isInUserCollection = p->isInUserCollection = TRUE;
                    sku->collectionData = license->collectionData;
                    sku->isTrial = license->isTrial;
                }
        }
    return S_OK;
}

static HRESULT catalog_fetch ( const char *request, LONG *canceled, entitled_snapshot **out )
{
    *out = NULL;
    xmlDocPtr doc = xmlReadMemory ( request, strlen ( request ), NULL, NULL, XML_PARSE_NONET );
    if ( !doc )
        return E_UNEXPECTED;
    xmlNodePtr root = xmlDocGetRootElement ( doc );
    char *market = entitled_text ( root, "Market" ), *language = entitled_text ( root, "Language" );
    char *ids[100]{}, *filters[7]{};
    UINT32 count = 0, filter_count = 0;
    UINT64 kinds;
    HRESULT hr = E_UNEXPECTED, com = CoInitializeEx ( NULL, COINIT_MULTITHREADED );
    BYTE *bytes = NULL;
    SIZE_T length;
    entitled_snapshot *catalog = NULL, *owned = NULL;
    for ( xmlNodePtr node = root->children; node; node = node->next )
    {
        if ( node->type != XML_ELEMENT_NODE )
            continue;
        if ( !strcmp ( (char *)node->name, "CatalogId" ) )
        {
            if ( count == ARRAY_SIZE ( ids ) )
                goto done;
            ids[count++] = (char *)xmlNodeGetContent ( node );
        }
        if ( !strcmp ( (char *)node->name, "Action" ) )
        {
            if ( filter_count == ARRAY_SIZE ( filters ) )
                goto done;
            filters[filter_count++] = (char *)xmlNodeGetContent ( node );
        }
    }
    if ( !count || !market || !language || FAILED ( entitled_uint ( root, "ProductKinds", &kinds ) ) )
        goto done;
    if ( InterlockedCompareExchange ( canceled, 0, 0 ) )
    {
        hr = E_ABORT;
        goto done;
    }
    {
        WCHAR path[2048];
        char combined[1301]{};
        for ( UINT32 i = 0; i < count; ++i )
        {
            if ( !entitled_id ( ids[i] ) )
                goto done;
            if ( i )
                strcat ( combined, "," );
            strcat ( combined, ids[i] );
        }
        if ( swprintf ( path, ARRAY_SIZE ( path ), L"/v7.0/products?bigIds=%hs&market=%hs&languages=%hs", combined,
                        market, language ) < 0 )
            goto done;
        hr = receipt_public_get ( L"displaycatalog.mp.microsoft.com", path, 4 * 1024 * 1024, &bytes, &length );
    }
    if ( SUCCEEDED ( hr ) )
        hr = catalog_parse ( bytes, length, (const char **)ids, count, kinds, (const char **)filters, filter_count,
                             &catalog );
    if ( SUCCEEDED ( hr ) && InterlockedCompareExchange ( canceled, 0, 0 ) )
        hr = E_ABORT;
    if ( SUCCEEDED ( hr ) )
        hr = entitled_fetch ( request, canceled, &owned );
    if ( SUCCEEDED ( hr ) )
        hr = catalog_join_collection ( catalog, owned );
    if ( SUCCEEDED ( hr ) )
    {
        *out = catalog;
        catalog = NULL;
    }
done:
    if ( catalog )
        entitled_snapshot_release ( catalog );
    if ( owned )
        entitled_snapshot_release ( owned );
    free ( bytes );
    free ( market );
    free ( language );
    for ( UINT32 i = 0; i < count; ++i )
        xmlFree ( ids[i] );
    for ( UINT32 i = 0; i < filter_count; ++i )
        xmlFree ( filters[i] );
    xmlFreeDoc ( doc );
    if ( SUCCEEDED ( com ) )
        CoUninitialize ();
    return hr;
}

static HRESULT catalog_begin ( XStoreContextHandle store, UINT32 kinds, const char **ids, SIZE_T count,
                               const char **filters, SIZE_T filters_count, XAsyncBlock *async,
                               const void *identity = &catalog_identity )
{
    UINT64 xuid, serial;
    if ( !async || !kinds || ( kinds & ~31 ) || !ids || !count || count > 100 || filters_count > 7 ||
         ( filters_count && !filters ) )
        return E_INVALIDARG;
    const char *actions[] = { "Purchase", "License", "Fulfill", "Browse", "Curate", "Details", "Redeem" };
    for ( SIZE_T i = 0; i < count; ++i )
        if ( !entitled_id ( ids[i] ) )
            return E_INVALIDARG;
    for ( SIZE_T i = 0; i < filters_count; ++i )
    {
        BOOL valid = FALSE;
        for ( UINT32 j = 0; filters[i] && j < ARRAY_SIZE ( actions ); ++j )
            valid |= !strcmp ( filters[i], actions[j] );
        if ( !valid )
            return E_INVALIDARG;
    }
    HRESULT hr = entitled_store_identity ( store, &xuid, &serial );
    if ( FAILED ( hr ) )
        return hr;
    if ( !entitled_id ( GetStoreProductId () ) )
        return E_GAME_MISSING_GAME_CONFIG;
    char language[128] = "en-US", market[16] = "US", number[16];
    WCHAR locale[85], country[16];
    if ( GetUserDefaultLocaleName ( locale, ARRAY_SIZE ( locale ) ) )
        WideCharToMultiByte ( CP_UTF8, 0, locale, -1, language, sizeof ( language ), NULL, NULL );
    if ( GetLocaleInfoEx ( LOCALE_NAME_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, country, ARRAY_SIZE ( country ) ) )
        WideCharToMultiByte ( CP_UTF8, 0, country, -1, market, sizeof ( market ), NULL, NULL );
    xmlDocPtr doc = xmlNewDoc ( BAD_CAST "1.0" );
    if ( !doc )
        return E_OUTOFMEMORY;
    xmlNodePtr root = xmlNewNode ( NULL, BAD_CAST "Request" );
    if ( !root )
    {
        xmlFreeDoc ( doc );
        return E_OUTOFMEMORY;
    }
    xmlDocSetRootElement ( doc, root );
    snprintf ( number, sizeof ( number ), "%u", kinds );
    xmlNewTextChild ( root, NULL, BAD_CAST "ParentProductId", BAD_CAST GetStoreProductId () );
    xmlNewTextChild ( root, NULL, BAD_CAST "ProductKinds", BAD_CAST number );
    xmlNewTextChild ( root, NULL, BAD_CAST "Market", BAD_CAST market );
    xmlNewTextChild ( root, NULL, BAD_CAST "Language", BAD_CAST language );
    for ( SIZE_T i = 0; i < count; ++i )
    {
        BOOL duplicate = FALSE;
        for ( SIZE_T j = 0; j < i; ++j )
            duplicate |= !strcmp ( ids[i], ids[j] );
        if ( duplicate )
            continue;
        xmlNewTextChild ( root, NULL, BAD_CAST "CatalogId", BAD_CAST ids[i] );
        if ( strcmp ( ids[i], GetStoreProductId () ) )
            xmlNewTextChild ( root, NULL, BAD_CAST "ProductId", BAD_CAST ids[i] );
    }
    for ( SIZE_T i = 0; i < filters_count; ++i )
        xmlNewTextChild ( root, NULL, BAD_CAST "Action", BAD_CAST filters[i] );
    xmlChar *bytes = NULL;
    int length;
    xmlDocDumpMemory ( doc, &bytes, &length );
    xmlFreeDoc ( doc );
    if ( !bytes )
        return E_OUTOFMEMORY;
    entitled_async *context = (entitled_async *)calloc ( 1, sizeof ( *context ) );
    if ( context )
        context->request = strdup ( (char *)bytes );
    xmlFree ( bytes );
    if ( !context || !context->request )
    {
        free ( context );
        return E_OUTOFMEMORY;
    }
    context->store = store;
    context->store_serial = serial;
    context->page_size = 100;
    context->identity = identity;
    context->fetch = catalog_fetch;
    return entitled_start ( context, async, FALSE );
}

static HRESULT catalog_result ( XAsyncBlock *async, XStoreProductQueryHandle *out,
                                const void *identity = &catalog_identity )
{
    if ( !out )
        return E_INVALIDARG;
    *out = NULL;
    if ( !async )
        return E_INVALIDARG;
    IXThreadingImpl *threading = NULL;
    HRESULT hr = QueryApiImpl ( CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading );
    if ( FAILED ( hr ) )
        return hr;
    hr = threading->XAsyncGetResult ( async, identity, sizeof ( *out ), out, NULL );
    threading->Release ();
    /* A zero-initialized, never-started XAsyncBlock can report S_OK with no
     * provider data. A successful product query always transfers a real page. */
    if ( SUCCEEDED ( hr ) && !*out )
        return E_INVALIDARG;
    return hr;
}

static HRESULT catalog_package_begin ( XStoreContextHandle store, UINT32 kinds, const char *identifier,
                                       XAsyncBlock *async )
{
    UINT64 xuid, serial;
    if ( !async || !identifier || !kinds || ( kinds & ~31 ) )
        return E_INVALIDARG;
    HRESULT hr = entitled_store_identity ( store, &xuid, &serial );
    if ( FAILED ( hr ) )
        return hr;
    char id[13];
    /* The installed package index validates identity/layout/current-title scope.
     * It only resolves an ID. The catalog worker still verifies ownership. */
    hr = xpackage_query_content_store ( identifier, sizeof ( id ), id );
    if ( FAILED ( hr ) && hr != E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER )
        return hr;
    IXPackageImpl *package = NULL;
    if ( SUCCEEDED ( QueryApiImpl ( CLSID_XPackageImpl, IID_IXPackageImpl, (void **)&package ) ) )
    {
        char current[33];
        HRESULT current_hr = package->XPackageGetCurrentProcessPackageIdentifier ( sizeof ( current ), current );
        package->Release ();
        if ( SUCCEEDED ( current_hr ) && !strcmp ( current, identifier ) )
        {
            const char *base = GetStoreProductId ();
            if ( !entitled_id ( base ) )
                return E_GAME_MISSING_GAME_CONFIG;
            if ( SUCCEEDED ( hr ) && strcmp ( id, base ) )
                return E_INVALIDARG; /* A GUID cannot identify two products. */
            strcpy ( id, base );
            hr = S_OK;
        }
    }
    if ( FAILED ( hr ) )
        return hr;
    const char *ids[] = { id };
    return catalog_begin ( store, kinds, ids, 1, NULL, 0, async, &catalog_package_identity );
}
