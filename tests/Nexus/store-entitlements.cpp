/* Account-free tests of the exact runtime helpers and actual XAsync provider.
 * Synthetic RSA keys stay in this process. No production trust override exists.
 * The license bridge below always fails except for locally signed fixture receipts; no mode contacts an account service. */
#define INITGUID
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <type_traits>
#include <limits>
#include <stddef.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "../../src/private.h"
#include <xstore.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <xpackage.h>

const char *storeId = "B00000000001";
static HANDLE bridge_started, bridge_gate;
static LONG bridge_active;
static DWORD bridge_timeout = 1500;
static HRESULT( WINAPI *runtime_query )( REFCLSID, REFIID, void ** );
static HRESULT WINAPI FixtureQueryApiImpl( REFCLSID clsid, REFIID iid, void **out )
{
    return runtime_query( clsid, iid, out );
}
UINT64 xuser_get_xuid( XUserHandle user )
{
    return 1;
}
static bool certificate_mode, certificate_stage_only;
static HCRYPTPROV certificate_provider;
static char certificate_id[41];
static std::string certificate_document, certificate_nonce;
static std::vector<std::string> certificate_nonces;
static unsigned certificate_requests, certificate_verifications, certificate_signatures, certificate_batches;
static bool certificate_expired, certificate_stop_after_reply, certificate_advance_clock;
static LONG *certificate_cancel_target;
static char *token( HCRYPTPROV provider, const char *cert_id, int variant, const char *nonce = "synthetic-nonce" );
static bool metadata_mode, metadata_oversize, metadata_match_product = true, metadata_advance_clock;
static ULONGLONG metadata_ticks;
static LONG *metadata_cancel_after_row;
static std::string metadata_body, public_body;
static SIZE_T public_cursor;
static DWORD metadata_status = 200;
void xodus_store_license_note( const char *phase, HRESULT hr )
{
    if ( certificate_mode && certificate_advance_clock && !strcmp( phase, "store-entitled-receipt" ) ) metadata_ticks = 200000;
    if ( metadata_mode && !strcmp( phase, "store-entitled-metadata" ) )
    {
        if ( metadata_cancel_after_row ) InterlockedExchange( metadata_cancel_after_row, 1 );
        if ( metadata_advance_clock ) metadata_ticks = 100000;
    }
}
static ULONGLONG FixturePublicTick()
{
    return metadata_mode ? metadata_ticks : GetTickCount64();
}
HRESULT xodus_store_license_body( const char **ids, SIZE_T count, const char *nonce, char **out )
{
    if ( certificate_mode ) { certificate_nonce = nonce; certificate_nonces.emplace_back( nonce ); }
    *out = strdup( "synthetic" );
    return *out ? S_OK : E_OUTOFMEMORY;
}
HRESULT xodus_store_license_xml( const char *request, SIZE_T size, char **out )
{
    *out = NULL;
    if ( certificate_mode )
    {
        ++certificate_batches;
        *out = token( certificate_provider, certificate_id, 0, certificate_nonce.c_str() );
        if ( certificate_stop_after_reply && certificate_batches == 2 && certificate_cancel_target ) InterlockedExchange( certificate_cancel_target, 1 );
        return *out ? S_OK : E_OUTOFMEMORY;
    }
    InterlockedIncrement( &bridge_active );
    SetEvent( bridge_started );
    WaitForSingleObject( bridge_gate, bridge_timeout );
    InterlockedDecrement( &bridge_active );
    return E_FAIL;
}
HRESULT xodus_store_license_xml(const char *request, SIZE_T size, char **out, LONG *, ULONGLONG)
{
    return xodus_store_license_xml(request, size, out);
}
static const char *GetStoreProductId()
{
    return storeId;
}
/* Capture only synthetic public paths and stop before any network send. */
static WCHAR public_path[256];
static DWORD public_flags;
static unsigned public_requests, public_sends;
static HINTERNET WINAPI FixturePublicOpenRequest( HINTERNET connection, LPCWSTR verb, LPCWSTR path,
                                                 LPCWSTR version, LPCWSTR referrer, LPCWSTR *accept, DWORD flags )
{
    ++public_requests;
    public_flags = flags;
    public_path[0] = 0;
    if ( path && wcslen( path ) < ARRAY_SIZE( public_path ) ) wcscpy( public_path, path );
    public_cursor = 0; public_body = metadata_body;
    if ( certificate_mode && path && wcsstr( path, L"/v8.0/licenseToken/fullCertificate/" ) )
    {
        ++certificate_requests; public_body = certificate_document;
    }
    if ( metadata_mode && metadata_match_product && path && wcsstr( path, L"bigIds=B00000000002&" ) )
    {
        const auto pos = public_body.find( "B00000000001" );
        if ( pos != std::string::npos ) public_body.replace( pos, 12, "B00000000002" );
    }
    return WinHttpOpenRequest( connection, verb, path, version, referrer, accept, flags );
}
static BOOL WINAPI FixturePublicSendRequest( HINTERNET request, LPCWSTR headers, DWORD headers_size,
                                            void *body, DWORD body_size, DWORD total_size, DWORD_PTR context )
{
    ++public_sends;
    if ( metadata_mode ) return TRUE;
    SetLastError( ERROR_CANCELLED );
    return FALSE;
}
static BOOL WINAPI FixturePublicReceive( HINTERNET, void * ) { return metadata_mode; }
static BOOL WINAPI FixturePublicHeaders( HINTERNET, DWORD, LPCWSTR, void *buffer, DWORD *size, DWORD * )
{
    if ( !metadata_mode || !buffer || !size || *size < sizeof( DWORD ) ) return FALSE;
    *static_cast<DWORD *>( buffer ) = metadata_status; *size = sizeof( DWORD ); return TRUE;
}
static BOOL WINAPI FixturePublicAvailable( HINTERNET, DWORD *available )
{
    *available = metadata_oversize ? 4 * 1024 * 1024 + 1 : static_cast<DWORD>( public_body.size() - public_cursor );
    return metadata_mode;
}
static BOOL WINAPI FixturePublicRead( HINTERNET, void *buffer, DWORD size, DWORD *read )
{
    *read = std::min<SIZE_T>( size, public_body.size() - public_cursor );
    memcpy( buffer, public_body.data() + public_cursor, *read ); public_cursor += *read; return metadata_mode;
}
static LONG WINAPI FixtureCertificateTime( LPFILETIME when, PCERT_INFO info )
{
    if ( certificate_mode ) { ++certificate_verifications; if ( certificate_expired ) return 1; }
    return CertVerifyTimeValidity( when, info );
}
static NTSTATUS WINAPI FixtureCertificateSignature( BCRYPT_KEY_HANDLE key, void *padding, PUCHAR hash, ULONG hash_size,
                                                     PUCHAR signature, ULONG signature_size, ULONG flags )
{
    if ( certificate_mode ) ++certificate_signatures;
    return BCryptVerifySignature( key, padding, hash, hash_size, signature, signature_size, flags );
}
#define BCryptVerifySignature FixtureCertificateSignature
#define CertVerifyTimeValidity FixtureCertificateTime
#define GetTickCount64 FixturePublicTick
#define WinHttpReceiveResponse FixturePublicReceive
#define WinHttpQueryHeaders FixturePublicHeaders
#define WinHttpQueryDataAvailable FixturePublicAvailable
#define WinHttpReadData FixturePublicRead
#define QueryApiImpl FixtureQueryApiImpl
#define WinHttpOpenRequest FixturePublicOpenRequest
#define WinHttpSendRequest FixturePublicSendRequest
#include "../../src/System/Store/Entitled.h"
#undef WinHttpOpenRequest
#undef WinHttpSendRequest
#undef WinHttpReceiveResponse
#undef WinHttpQueryHeaders
#undef WinHttpQueryDataAvailable
#undef WinHttpReadData
#undef GetTickCount64
#undef CertVerifyTimeValidity
#undef BCryptVerifySignature
/* Only this account-free executable has a synthetic installed-package index. */
HRESULT xpackage_query_content_store( const char *identifier, SIZE_T size, char *store )
{
    if ( !identifier || strcmp( identifier, "00000001111122223333444444444444" ) )
        return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    if ( size < 13 ) return E_NOT_SUFFICIENT_BUFFER;
    strcpy( store, "B00000000001" );
    return S_OK;
}
#include "../../src/System/Store/Catalog.h"
#include "../../src/System/Store/PackageLicense.h"
#include "../../src/System/Store/AddonLicense.h"
#include "../../src/System/Store/StoreLicenseProjection.h"

static unsigned checks, failures, callbacks, enumerated;
#define CHECK( name, expr )                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ++checks;                                                                                                      \
        if ( !( expr ) )                                                                                               \
        {                                                                                                              \
            ++failures;                                                                                                \
            printf( "FAIL %s line=%d\n", name, __LINE__ );                                                             \
        }                                                                                                              \
    } while ( 0 )

template<typename T> constexpr bool store_timestamp_abi = sizeof( T ) == 8 && std::is_signed_v<T>;
static_assert( store_timestamp_abi<decltype( XStoreAddonLicense{}.expirationDate )> );
static_assert( store_timestamp_abi<decltype( XStorePrice{}.saleEndDate )> );
static_assert( store_timestamp_abi<decltype( XStoreAvailability{}.endDate )> );
static_assert( store_timestamp_abi<decltype( XStoreCollectionData{}.acquiredDate )> );
static_assert( store_timestamp_abi<decltype( XStoreCollectionData{}.startDate )> );
static_assert( store_timestamp_abi<decltype( XStoreCollectionData{}.endDate )> );
static_assert( store_timestamp_abi<decltype( XStoreGameLicense{}.expirationDate )> );
// Microsoft default packing and signed __time64_t, not the compiler's CRTtime_t.
static_assert( sizeof( XStoreAddonLicense ) == 96 && offsetof( XStoreAddonLicense, expirationDate ) == 88 );
static_assert( sizeof( XStoreGameLicense ) == 104 && offsetof( XStoreGameLicense, expirationDate ) == 96 );
static_assert( sizeof( XStorePrice ) == ( sizeof( void * ) == 8 ? 88 : 80 ) );
static_assert( offsetof( XStorePrice, saleEndDate ) == ( sizeof( void * ) == 8 ? 80 : 72 ) );
static_assert( sizeof( XStoreAvailability ) == ( sizeof( void * ) == 8 ? 104 : 96 ) );
static_assert( sizeof( XStoreCollectionData ) == ( sizeof( void * ) == 8 ? 56 : 48 ) );
static_assert( offsetof( XStoreCollectionData, endDate ) == 16 && offsetof( XStoreCollectionData, isTrial ) == 24 );
static_assert( sizeof( XStoreSku ) == ( sizeof( void * ) == 8 ? 272 : 208 ) );
static_assert( offsetof( XStoreSku, collectionData ) == ( sizeof( void * ) == 8 ? 128 : 104 ) );
static_assert( sizeof( XStoreProduct ) == ( sizeof( void * ) == 8 ? 208 : 152 ) );
static_assert( offsetof( XStoreProduct, price ) == ( sizeof( void * ) == 8 ? 56 : 32 ) );
static void test_store_time_abi()
{
    const INT64 future = 253402300799LL;
    XStoreAddonLicense addon{}; XStorePrice price{}; XStoreAvailability available{};
    XStoreCollectionData collection{}; XStoreGameLicense game{};
    addon.expirationDate = price.saleEndDate = available.endDate = collection.acquiredDate =
        collection.startDate = collection.endDate = game.expirationDate = future;
    CHECK( "store-abi-future-time-roundtrip", addon.expirationDate == future && price.saleEndDate == future &&
           available.endDate == future && collection.acquiredDate == future && collection.startDate == future &&
           collection.endDate == future && game.expirationDate == future );
    collection.endDate = INT64_MAX;
    CHECK( "store-abi-signed-time-max", collection.endDate == INT64_MAX );
    collection.endDate = INT64_MIN;
    CHECK( "store-abi-signed-time-min", collection.endDate == INT64_MIN && collection.endDate < 0 );
    struct Guarded { UINT64 before; XStoreCollectionData value; UINT64 after; } guarded{};
    guarded.before = 0x123456789abcdef0ULL; guarded.after = 0xfedcba9876543210ULL;
    guarded.value.acquiredDate = future; guarded.value.startDate = future - 1; guarded.value.endDate = future - 2;
    guarded.value.quantity = 9; guarded.value.isTrial = TRUE;
    CHECK( "store-abi-timestamp-field-isolation", guarded.before == 0x123456789abcdef0ULL && guarded.after == 0xfedcba9876543210ULL &&
           guarded.value.acquiredDate == future && guarded.value.startDate == future - 1 && guarded.value.endDate == future - 2 &&
           guarded.value.quantity == 9 && guarded.value.isTrial );
    printf( "STORE_TIME_ABI crt=%u field=%u collection=%u end_offset=%u future=%llu\n", static_cast<unsigned>( sizeof( time_t ) ),
            static_cast<unsigned>( sizeof( collection.endDate ) ), static_cast<unsigned>( sizeof( collection ) ),
            static_cast<unsigned>( offsetof( XStoreCollectionData, endDate ) ), static_cast<unsigned long long>( future ) );
}

static void test_store_time_consumers()
{
    IJsonObject *object = nullptr;
    const char *json = R"({"Conditions":{"StartDate":"1753-01-01T00:00:00.0000000Z","EndDate":"9999-12-31T23:59:59Z"},"Actions":["Purchase"],"OrderManagementData":{"Price":{"ListPrice":10,"MSRP":20,"CurrencyCode":"USD"}},"Future":"9999-12-31T23:59:59Z","Past":"1753-01-01T00:00:00.0000000Z","Bad":"not-a-date","Overflow":"999999999999-12-31T23:59:59Z"})";
    CHECK( "store-time-consumer-json", receipt_json( reinterpret_cast<const BYTE *>( json ), strlen( json ), &object ) == S_OK );
    if ( object )
    {
        INT64 end = 0;
        CHECK( "store-time-catalog-future-unclamped", catalog_date( object, L"Future", &end ) == S_OK && end == 253402300799LL );
        CHECK( "store-time-catalog-unbounded-start", catalog_date( object, L"Past", &end ) == S_OK && end == 0 );
        CHECK( "store-time-catalog-malformed-refused", FAILED( catalog_date( object, L"Bad", &end ) ) );
        CHECK( "store-time-catalog-overflow-refused", FAILED( catalog_date( object, L"Overflow", &end ) ) );
        BOOL include = FALSE, purchase = FALSE;
        CHECK( "store-time-availability-future", catalog_availability( object, nullptr, 0, &include, &purchase, &end ) == S_OK &&
               include && purchase && end == 253402300799LL );
        XStorePrice price{};
        CHECK( "store-time-sale-future", catalog_price( object, end, &price ) == S_OK && price.isOnSale && price.saleEndDate == end );
        free( const_cast<char *>( price.currencyCode ) ); object->Release();
    }
    XStoreSku sku{}; sku.skuId = "AB12"; sku.isInUserCollection = TRUE; sku.collectionData.endDate = 253402300799LL;
    XStoreProduct product{}; product.storeId = storeId; product.productKind = XStoreProductKind::Game;
    product.isInUserCollection = TRUE; product.skusCount = 1; product.skus = &sku;
    entitled_snapshot snapshot{}; snapshot.count = 1; snapshot.products = &product; snapshot.proof_until = 253402300789ULL;
    XStoreGameLicense result{};
    CHECK( "store-time-game-proof-future", game_license_from_snapshot( &snapshot, storeId, &result ) == S_OK &&
           result.isActive && result.expirationDate == 253402300789LL );
    sku.collectionData.endDate = -1;
    CHECK( "store-time-negative-expiry-denied", game_license_from_snapshot( &snapshot, storeId, &result ) == E_ACCESSDENIED && !result.isActive );
}

static char *encode( const BYTE *bytes, DWORD size, BOOL url )
{
    DWORD length = 0, i;
    char *text;
    if ( !CryptBinaryToStringA( bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &length ) ||
         !( text = static_cast<std::remove_reference_t<decltype( text )>>( malloc( length ) ) ) )
        return NULL;
    if ( !CryptBinaryToStringA( bytes, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, text, &length ) )
    {
        free( text );
        return NULL;
    }
    if ( url )
        for ( i = 0; text[i]; i++ )
        {
            if ( text[i] == '+' )
                text[i] = '-';
            else if ( text[i] == '/' )
                text[i] = '_';
            else if ( text[i] == '=' )
            {
                text[i] = 0;
                break;
            }
        }
    return text;
}

static char *token( HCRYPTPROV provider, const char *cert_id, int variant, const char *nonce )
{
    const char *header = variant == 1 ? "{\"alg\":\"HS256\"}" : "{\"alg\":\"RS256\"}";
    char claim[2048], payload[4096], *h = NULL, *p = NULL, *c = NULL, *s = NULL, *input = NULL, *jwt = NULL;
    BYTE signature[512], swap;
    DWORD size = sizeof( signature ), i;
    HCRYPTHASH hash = 0;
    UINT64 now = time( NULL );
    snprintf( claim, sizeof( claim ),
              "{\"tokenVersion\":1,\"certificateId\":\"%s\",\"customDeveloperString\":\"%s\","
              "\"licensableProducts\":[{\"productId\":\"B00000000001\",\"skuId\":\"0010\",\"endDate\":\"9999-12-31T23:"
              "59:59Z\"}]}",
              cert_id, nonce );
    std::string rows = claim;
    if ( variant == 5 )
        rows.insert( rows.size() - 2,
            ",{\"productId\":\"B00000000002\",\"skuId\":\"0010\",\"endDate\":\"9999-12-31T23:59:59Z\"},"
            "{\"productId\":\"B00000000001\",\"skuId\":\"0020\",\"endDate\":\"9999-12-31T23:59:59Z\"}" );
    c = encode( ( BYTE * )rows.data(), rows.size(), FALSE );
    if ( !c ) goto done;
    snprintf( payload, sizeof( payload ),
              "{\"iss\":\"LicensingFD\",\"aud\":\"%s\",\"nbf\":%llu,\"exp\":%llu,\"LicenseTokenClaim\":\"%s\"}",
              variant == 2 ? "wrong" : "SDK/ISV", ( unsigned long long )( variant == 4 ? now + 300 : now - 10 ),
              ( unsigned long long )( variant == 3 ? now - 1 : now + 600 ), c );
    h = encode( ( BYTE * )header, strlen( header ), TRUE );
    p = encode( ( BYTE * )payload, strlen( payload ), TRUE );
    if ( !h || !p ||
         !( input =
                static_cast<std::remove_reference_t<decltype( input )>>( malloc( strlen( h ) + strlen( p ) + 2 ) ) ) )
        goto done;
    sprintf( input, "%s.%s", h, p );
    if ( !CryptCreateHash( provider, CALG_SHA_256, 0, 0, &hash ) ||
         !CryptHashData( hash, ( BYTE * )input, strlen( input ), 0 ) ||
         !CryptSignHashA( hash, AT_SIGNATURE, NULL, 0, signature, &size ) )
        goto done;
    for ( i = 0; i < size / 2; i++ )
    {
        swap = signature[i];
        signature[i] = signature[size - 1 - i];
        signature[size - 1 - i] = swap;
    }
    s = encode( signature, size, TRUE );
    if ( s && ( jwt = static_cast<std::remove_reference_t<decltype( jwt )>>(
                    malloc( strlen( input ) + strlen( s ) + 2 ) ) ) )
        sprintf( jwt, "%s.%s", input, s );
done:
    if ( hash ) CryptDestroyHash( hash );
    free( h );
    free( p );
    free( c );
    free( s );
    free( input );
    return jwt;
}

static std::string certificate_request( unsigned count )
{
    std::string request = "<Request><ParentProductId>B00000000001</ParentProductId><Market>US</Market><Language>en-US</Language><ProductKinds>31</ProductKinds>";
    for ( unsigned i = 2; i <= count; ++i ) { char row[64]; snprintf( row, sizeof( row ), "<ProductId>B%011u</ProductId>", i ); request += row; }
    return request + "</Request>";
}
static std::string certificate_json( PCCERT_CONTEXT cert )
{
    char *base64 = encode( cert->pbCertEncoded, cert->cbCertEncoded, FALSE );
    CHECK( "certificate-operation-encoded", base64 != nullptr );
    if ( !base64 ) return {};
    std::string result = std::string( "{\"certificate\":\"" ) + base64 + "\"}"; free( base64 ); return result;
}
static HRESULT certificate_operation( unsigned count, LONG *canceled = nullptr )
{
    certificate_requests = certificate_verifications = certificate_signatures = certificate_batches = 0; certificate_nonces.clear(); metadata_ticks = 0;
    LONG local = 0; entitled_snapshot *snapshot = nullptr;
    const auto hr = entitled_fetch( certificate_request( count ).c_str(), canceled ? canceled : &local, &snapshot );
    if ( SUCCEEDED( hr ) ) CHECK( "certificate-operation-success", snapshot && snapshot->count == 1 );
    else CHECK( "certificate-operation-no-failed-output", snapshot == nullptr );
    if ( snapshot ) entitled_snapshot_release( snapshot ); return hr;
}
static HRESULT certificate_cached_load( receipt_certificate_cache *cache, const char *issued = "fresh-nonce",
                                         const char *expected = "fresh-nonce", int variant = 0, bool tamper = false )
{
    char *jwt = token( certificate_provider, certificate_id, variant, issued );
    CHECK( "certificate-cache-signed-input", jwt != nullptr );
    if ( !jwt ) return E_OUTOFMEMORY;
    if ( tamper ) { char *signature = strchr( strchr( jwt, '.' ) + 1, '.' ) + 1; signature[0] = signature[0] == 'A' ? 'B' : 'A'; }
    IJsonObject *claim = nullptr; UINT64 expiry = 0;
    const auto hr = receipt_load( jwt, expected, &claim, &expiry, cache );
    CHECK( "certificate-cache-claim-follows-verification", SUCCEEDED( hr ) ? claim != nullptr : claim == nullptr );
    if ( claim ) claim->Release(); free( jwt ); return hr;
}
static void test_certificate_operation( HCRYPTPROV provider, const char *id, PCCERT_CONTEXT cert )
{
    certificate_provider = provider; strcpy( certificate_id, id );
    const auto document = certificate_json( cert ); if ( document.empty() ) return;
    certificate_document = document;
    metadata_body = R"({"Products":[{"ProductId":"B00000000001","ProductType":"Durable","LocalizedProperties":[{"ProductTitle":"Synthetic","Language":"en-US"}],"DisplaySkuAvailabilities":[{"Sku":{"SkuId":"0010","Properties":{"IsTrial":false}}}]}]})";
    metadata_mode = certificate_mode = true;
    CHECK( "certificate-operation-two-batch-result", certificate_operation( 65 ) == S_OK );
    CHECK( "certificate-operation-two-fresh-receipts", certificate_batches == 2 && certificate_nonces.size() == 2 && certificate_nonces[0] != certificate_nonces[1] );
    CHECK( "certificate-operation-two-validations", certificate_verifications == 2 && certificate_signatures == 2 );
    CHECK( "certificate-operation-one-public-get", certificate_requests == 1 );
    printf( "CERTIFICATE_MEASURE batches=%u certificate_gets=%u verified=%u signatures=%u\n", certificate_batches, certificate_requests, certificate_verifications, certificate_signatures );
    CHECK( "certificate-operation-separated-no-retention", certificate_operation( 65 ) == S_OK && certificate_requests == 1 && certificate_verifications == 2 );
    CHECK( "certificate-operation-five-batches-one-get", certificate_operation( 257 ) == S_OK && certificate_batches == 5 && certificate_requests == 1 && certificate_verifications == 5 && certificate_signatures == 5 );
    LONG canceled = 1;
    CHECK( "certificate-operation-precancel-no-work", certificate_operation( 65, &canceled ) == E_ABORT && !certificate_batches && !certificate_requests );
    canceled = 0; certificate_stop_after_reply = true; certificate_cancel_target = &canceled;
    CHECK( "certificate-operation-observed-cancel-before-cache-hit", certificate_operation( 65, &canceled ) == E_ABORT && certificate_batches == 2 && certificate_requests == 1 && certificate_verifications == 1 );
    certificate_stop_after_reply = false; certificate_cancel_target = nullptr;
    certificate_advance_clock = true;
    CHECK( "certificate-operation-deadline-before-next-hit", certificate_operation( 65 ) == HRESULT_FROM_WIN32( ERROR_TIMEOUT ) && certificate_batches == 1 && certificate_requests == 1 && certificate_verifications == 1 );
    certificate_advance_clock = false; metadata_ticks = 0;

    receipt_certificate_cache cache{}; certificate_requests = certificate_verifications = certificate_signatures = 0;
    CHECK( "certificate-cache-first-success", certificate_cached_load( &cache ) == S_OK && cache.der && certificate_requests == 1 );
    CHECK( "certificate-cache-fresh-nonce-reverified", certificate_cached_load( &cache, "other-nonce", "other-nonce" ) == S_OK && certificate_requests == 1 && certificate_verifications == 2 && certificate_signatures == 2 );
    CHECK( "certificate-cache-tampered-signature-denied", FAILED( certificate_cached_load( &cache, "fresh-nonce", "fresh-nonce", 0, true ) ) && certificate_requests == 1 );
    CHECK( "certificate-cache-wrong-nonce-denied", FAILED( certificate_cached_load( &cache, "issued", "different" ) ) && certificate_requests == 1 );
    CHECK( "certificate-cache-expired-jwt-denied", FAILED( certificate_cached_load( &cache, "fresh-nonce", "fresh-nonce", 3 ) ) && certificate_requests == 1 );
    CHECK( "certificate-cache-future-jwt-denied", FAILED( certificate_cached_load( &cache, "fresh-nonce", "fresh-nonce", 4 ) ) && certificate_requests == 1 );
    CHECK( "certificate-cache-wrong-algorithm-denied", FAILED( certificate_cached_load( &cache, "fresh-nonce", "fresh-nonce", 1 ) ) && certificate_requests == 1 );
    certificate_expired = true;
    CHECK( "certificate-cache-expired-certificate-denied", FAILED( certificate_cached_load( &cache ) ) && certificate_requests == 1 );
    certificate_expired = false; free( cache.der );
    for ( unsigned mode = 0; mode < 4; ++mode )
    {
        receipt_certificate_cache fresh{}; certificate_requests = 0;
        if ( mode == 1 ) certificate_document = "{}";
        if ( mode == 2 ) certificate_document = std::string( 64001, 'x' );
        if ( mode == 3 ) metadata_status = 400;
        CHECK( "certificate-cache-failure-not-admitted", FAILED( certificate_cached_load( &fresh, "fresh-nonce", "fresh-nonce", 0, mode == 0 ) ) && !fresh.der && certificate_requests == 1 );
        certificate_document = document; metadata_status = 200;
        CHECK( "certificate-cache-failure-not-negative-cached", certificate_cached_load( &fresh ) == S_OK && fresh.der && certificate_requests == 2 );
        free( fresh.der );
    }
    certificate_requests = 0; certificate_id[0] = 'G'; receipt_certificate_cache invalid{};
    CHECK( "certificate-cache-malformed-id-no-request", FAILED( certificate_cached_load( &invalid ) ) && !invalid.der && !certificate_requests );
    strcpy( certificate_id, id );

    CERT_NAME_BLOB name{}; CRYPT_ALGORITHM_IDENTIFIER algorithm{ szOID_RSA_SHA256RSA, {0} };
    SYSTEMTIME start{2020,1,0,1}, end{2099,1,0,1}; PCCERT_CONTEXT rotated = nullptr;
    CHECK( "certificate-rotation-name-size", CertStrToNameW( X509_ASN_ENCODING, L"CN=Nexus synthetic rotated certificate", CERT_X500_NAME_STR, nullptr, nullptr, &name.cbData, nullptr ) );
    name.pbData = static_cast<BYTE *>( malloc( name.cbData ) );
    if ( name.pbData && CertStrToNameW( X509_ASN_ENCODING, L"CN=Nexus synthetic rotated certificate", CERT_X500_NAME_STR, nullptr, name.pbData, &name.cbData, nullptr ) )
        rotated = CertCreateSelfSignCertificate( provider, &name, CERT_CREATE_SELFSIGN_NO_KEY_INFO, nullptr, &algorithm, &start, &end, nullptr );
    CHECK( "certificate-rotation-context", rotated != nullptr );
    if ( rotated )
    {
        BYTE digest[20]; DWORD size = sizeof( digest ); char rotated_id[41]{};
        CHECK( "certificate-rotation-thumbprint", CryptHashCertificate( 0, CALG_SHA1, 0, rotated->pbCertEncoded, rotated->cbCertEncoded, digest, &size ) );
        for ( unsigned i = 0; i < 20; ++i ) sprintf( rotated_id + i * 2, "%02X", digest[i] );
        CHECK( "certificate-rotation-distinct-id", strcmp( rotated_id, id ) != 0 );
        receipt_certificate_cache rotation{}; certificate_requests = 0;
        CHECK( "certificate-cache-rotation-a", certificate_cached_load( &rotation ) == S_OK && certificate_requests == 1 );
        strcpy( certificate_id, rotated_id ); certificate_document = certificate_json( rotated );
        CHECK( "certificate-cache-rotation-b-refetch", certificate_cached_load( &rotation ) == S_OK && certificate_requests == 2 && !strcmp( rotation.id, rotated_id ) );
        strcpy( certificate_id, id ); certificate_document = document;
        CHECK( "certificate-cache-one-slot-a-b-a", certificate_cached_load( &rotation ) == S_OK && certificate_requests == 3 && !strcmp( rotation.id, id ) );
        free( rotation.der ); CertFreeCertificateContext( rotated );
    }
    free( name.pbData );
    metadata_mode = certificate_mode = false; certificate_provider = 0; certificate_document.clear(); certificate_nonce.clear(); certificate_nonces.clear();
}

static void test_metadata_reuse( IJsonObject *claim );

static void test_receipts( void )
{
    const char *expired = nullptr, *malformed = nullptr;
    HCRYPTPROV provider = 0;
    HCRYPTKEY key = 0;
    CERT_NAME_BLOB name = { 0 };
    CRYPT_ALGORITHM_IDENTIFIER algorithm = { szOID_RSA_SHA256RSA, { 0 } };
    SYSTEMTIME start = { 2020, 1, 0, 1 }, end = { 2099, 1, 0, 1 };
    PCCERT_CONTEXT cert = NULL;
    BYTE digest[20];
    DWORD size = sizeof( digest );
    char cert_id[41], *jwt;
    UINT i, count;
    UINT64 expiry;
    IJsonObject *claim = NULL;
    struct receipt_license licenses[ENTITLED_MAX_PRODUCTS];
    const char *ids[] = { "B00000000001" };
    BYTE *decoded = NULL;
    DWORD decoded_size;
    CHECK( "invalid-base64-alphabet",
           FAILED( receipt_decode( "AA?A", 4, FALSE, &decoded, &decoded_size ) ) && !decoded );
    CHECK( "invalid-base64-padding",
           FAILED( receipt_decode( "A=AA", 4, FALSE, &decoded, &decoded_size ) ) && !decoded );
    CHECK( "invalid-base64-length", FAILED( receipt_decode( "A", 1, TRUE, &decoded, &decoded_size ) ) && !decoded );
    CHECK( "invalid-date-zone", FAILED( receipt_date( "2026-10-15T10:00:00+02:00", &expiry ) ) );
    CHECK( "crypto-provider",
           CryptAcquireContextW( &provider, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT ) );
    if ( !provider ) return;
    CHECK( "synthetic-key", CryptGenKey( provider, AT_SIGNATURE, ( 2048 << 16 ) | CRYPT_EXPORTABLE, &key ) );
    if ( !key ) goto done;
    CHECK( "certificate-name-size", CertStrToNameW( X509_ASN_ENCODING, L"CN=Nexus synthetic test only",
                                                    CERT_X500_NAME_STR, NULL, NULL, &name.cbData, NULL ) );
    name.pbData = static_cast<std::remove_reference_t<decltype( name.pbData )>>( malloc( name.cbData ) );
    if ( !name.pbData ) goto done;
    CHECK( "certificate-name", CertStrToNameW( X509_ASN_ENCODING, L"CN=Nexus synthetic test only", CERT_X500_NAME_STR,
                                               NULL, name.pbData, &name.cbData, NULL ) );
    cert = CertCreateSelfSignCertificate( provider, &name, CERT_CREATE_SELFSIGN_NO_KEY_INFO, NULL, &algorithm, &start,
                                          &end, NULL );
    CHECK( "synthetic-certificate", cert != NULL );
    if ( !cert ) goto done;
    CHECK( "thumbprint",
           CryptHashCertificate( 0, CALG_SHA1, 0, cert->pbCertEncoded, cert->cbCertEncoded, digest, &size ) );
    for ( i = 0; i < 20; i++ )
        sprintf( cert_id + i * 2, "%02X", digest[i] );
    test_certificate_operation( provider, cert_id, cert );
    if ( certificate_stage_only ) goto done;
    for ( i = 0; i < 5; i++ )
    {
        jwt = token( provider, cert_id, i );
        CHECK( "synthetic-signed-token", jwt != NULL );
        if ( !jwt ) continue;
        if ( !i )
        {
            WCHAR expected[160] = L"/v8.0/licenseToken/fullCertificate/";
            SIZE_T prefix = wcslen( expected );
            for ( UINT j = 0; j <= 40; ++j ) expected[prefix + j] = ( unsigned char )cert_id[j];
            public_requests = public_sends = 0;
            IJsonObject *public_claim = nullptr;
            UINT64 public_expiry = 0;
            CHECK( "public-certificate-no-network-grant",
                   FAILED( receipt_load( jwt, "synthetic-nonce", &public_claim, &public_expiry ) ) && !public_claim );
            CHECK( "public-certificate-request-captured", public_requests == 1 && public_sends == 1 );
            CHECK( "public-certificate-path-exact", !wcscmp( public_path, expected ) );
            CHECK( "public-certificate-remains-https", public_flags == WINHTTP_FLAG_SECURE );
            BYTE *decoded = NULL;
            DWORD length = 0;
            const char *dot = strchr( jwt, '.' ), *second = strchr( dot + 1, '.' );
            CHECK( "header-base64", receipt_decode( jwt, dot - jwt, TRUE, &decoded, &length ) == S_OK );
            if ( decoded )
            {
                CHECK( "header-json", receipt_json( decoded, length, &claim ) == S_OK );
                free( decoded );
            }
            if ( claim )
            {
                ( claim )->Release();
                claim = NULL;
            }
            CHECK( "payload-base64", receipt_decode( dot + 1, second - dot - 1, TRUE, &decoded, &length ) == S_OK );
            if ( decoded )
            {
                CHECK( "payload-json", receipt_json( decoded, length, &claim ) == S_OK );
                free( decoded );
            }
            if ( claim )
            {
                ( claim )->Release();
                claim = NULL;
            }
            CHECK( "signature-base64",
                   receipt_decode( second + 1, strlen( second + 1 ), TRUE, &decoded, &length ) == S_OK );
            free( decoded );
        }
        HRESULT hr = receipt_verify( jwt, "synthetic-nonce", cert_id, cert->pbCertEncoded, cert->cbCertEncoded, &claim,
                                     &expiry );
        CHECK( "signature-and-claims", i ? FAILED( hr ) && !claim : hr == S_OK && claim );
        if ( claim )
        {
            count = 0;
            CHECK( "signed-inventory",
                   receipt_inventory( claim, ids, 1, licenses, &count, &expiry ) == S_OK && count == 1 );
            CHECK( "exact-signed-sku", count && !strcmp( licenses[0].sku, "0010" ) );
            count = 0;
            CHECK( "no-unrequested-product",
                   receipt_inventory( claim, NULL, 0, licenses, &count, &expiry ) == S_OK && !count );
            ( claim )->Release();
            claim = NULL;
        }
        CHECK( "nonce-replay-rejected", FAILED( receipt_verify( jwt, "other-nonce", cert_id, cert->pbCertEncoded,
                                                                cert->cbCertEncoded, &claim, &expiry ) ) &&
                                            !claim );
        if ( !i )
            CHECK( "certificate-id-mismatch",
                   FAILED( receipt_verify( jwt, "synthetic-nonce", "0000000000000000000000000000000000000000",
                                           cert->pbCertEncoded, cert->cbCertEncoded, &claim, &expiry ) ) &&
                       !claim );
        char *signature = strrchr( jwt, '.' ) + 1;
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        CHECK( "tampered-signature-rejected",
               FAILED( receipt_verify( jwt, "synthetic-nonce", cert_id, cert->pbCertEncoded, cert->cbCertEncoded,
                                       &claim, &expiry ) ) &&
                   !claim );
        free( jwt );
    }
    jwt = token( provider, cert_id, 5 );
    CHECK( "metadata-stage-signed-token", jwt && receipt_verify( jwt, "synthetic-nonce", cert_id,
           cert->pbCertEncoded, cert->cbCertEncoded, &claim, &expiry ) == S_OK );
    if ( claim ) { test_metadata_reuse( claim ); claim->Release(); claim = nullptr; }
    free( jwt );
    expired = "{\"tokenVersion\":1,\"licensableProducts\":[{\"productId\":\"B00000000001\",\"skuId\":\"0010\","
              "\"endDate\":\"2020-01-01T00:00:00Z\"}]}";
    CHECK( "inventory-json", receipt_json( ( BYTE * )expired, strlen( expired ), &claim ) == S_OK );
    count = 0;
    expiry = UINT64_MAX;
    CHECK( "expired-license-excluded",
           claim && receipt_inventory( claim, ids, 1, licenses, &count, &expiry ) == S_OK && !count );
    if ( claim )
    {
        ( claim )->Release();
        claim = NULL;
    }
    malformed = "{\"tokenVersion\":1,\"licensableProducts\":[null]}";
    CHECK( "malformed-json", receipt_json( ( BYTE * )malformed, strlen( malformed ), &claim ) == S_OK );
    CHECK( "malformed-license-rejected",
           claim && FAILED( receipt_inventory( claim, ids, 1, licenses, &count, &expiry ) ) );
done:
    if ( claim ) ( claim )->Release();
    if ( cert ) CertFreeCertificateContext( cert );
    free( name.pbData );
    if ( key ) CryptDestroyKey( key );
    CryptReleaseContext( provider, 0 );
}

static void test_metadata_reuse( IJsonObject *claim )
{
    const char *ids[] = { "B00000000001", "B00000000002" };
    receipt_license verified[ENTITLED_MAX_PRODUCTS]{}; UINT32 count = 0; UINT64 expiry = UINT64_MAX;
    CHECK( "metadata-stage-verified-inventory", receipt_inventory( claim, ids, 2, verified, &count, &expiry ) == S_OK && count == 3 );
    if ( count != 3 ) return;
    const std::string valid = R"({"Products":[{"ProductId":"B00000000001","ProductType":"Durable","LocalizedProperties":[{"ProductTitle":"Synthetic","Language":"en-US"}],"DisplaySkuAvailabilities":[{"Sku":{"SkuId":"0010","Properties":{"IsTrial":false}}},{"Sku":{"SkuId":"0020","Properties":{"IsTrial":true}}}]}]})";
    metadata_mode = true; metadata_body = valid;
    receipt_license same[] = { verified[0], verified[2] };
    auto run = [&]( receipt_license *licenses, UINT32 size, const char *market = "US" ) {
        metadata_ticks = 0; public_requests = public_sends = 0;
        auto doc = xmlNewDoc( BAD_CAST "1.0" ); auto root = xmlNewNode( nullptr, BAD_CAST "Response" ); xmlDocSetRootElement( doc, root );
        LONG canceled = 0;
        const auto hr = receipt_metadata_rows( licenses, size, 31, market, "en-US", root, &canceled, 50000 );
        if ( SUCCEEDED( hr ) )
        {
            char until[32]; snprintf( until, sizeof( until ), "%llu", static_cast<unsigned long long>( time( nullptr ) + 60 ) );
            xmlNewTextChild( root, nullptr, BAD_CAST "HResult", BAD_CAST "0" );
            xmlNewTextChild( root, nullptr, BAD_CAST "ValidUntil", BAD_CAST until );
            xmlChar *bytes = nullptr; int length = 0; xmlDocDumpMemory( doc, &bytes, &length );
            entitled_snapshot *snapshot = nullptr;
            CHECK( "metadata-reuse-output-parse", bytes && entitled_parse( reinterpret_cast<char *>( bytes ), length, &snapshot ) == S_OK );
            if ( snapshot )
            {
                CHECK( "metadata-reuse-product-order", snapshot->count == ( size == 3 ? 2u : 1u ) &&
                       !strcmp( snapshot->products[0].storeId, licenses[0].id ) );
                if ( size >= 2 )
                    CHECK( "metadata-reuse-sku-order-trial-expiry", snapshot->products[0].skusCount == 2 &&
                           !strcmp( snapshot->products[0].skus[0].skuId, "0010" ) &&
                           !strcmp( snapshot->products[0].skus[1].skuId, "0020" ) &&
                           !snapshot->products[0].skus[0].isTrial && snapshot->products[0].skus[1].isTrial &&
                           snapshot->products[0].skus[0].collectionData.endDate == licenses[0].expiry );
                entitled_snapshot_release( snapshot );
            }
            if ( bytes ) xmlFree( bytes );
        }
        xmlFreeDoc( doc ); return hr;
    };
    CHECK( "same-product-two-verified-skus", run( same, 2 ) == S_OK );
    printf( "METADATA_MEASURE same_product_skus=2 get_requests=%u\n", public_requests );
    CHECK( "same-product-single-public-get", public_requests == 1 && public_sends == 1 );
    CHECK( "nonadjacent-products-evict", run( verified, 3 ) == S_OK && public_requests == 3 );
    CHECK( "separate-operation-fetches", run( same, 2 ) == S_OK && public_requests == 1 );
    CHECK( "separate-market-fetches", run( same, 2, "CZ" ) == S_OK && public_requests == 1 && wcsstr( public_path, L"market=CZ&" ) );
    metadata_body = "{}"; CHECK( "metadata-reuse-malformed", FAILED( run( same, 2 ) ) && public_requests == 1 );
    metadata_body = valid; metadata_match_product = false;
    CHECK( "metadata-reuse-mismatched-product", FAILED( run( &verified[1], 1 ) ) && public_requests == 1 );
    metadata_match_product = true;
    auto missing = same[1]; strcpy( missing.sku, "0030" ); receipt_license absent[] = { same[0], missing };
    CHECK( "metadata-reuse-missing-sku", FAILED( run( absent, 2 ) ) );
    metadata_body.replace( metadata_body.find( "true" ), 4, "null" );
    CHECK( "metadata-reuse-malformed-trial", FAILED( run( same, 2 ) ) ); metadata_body = valid;
    metadata_oversize = true; CHECK( "metadata-reuse-body-limit", FAILED( run( same, 2 ) ) && public_requests == 1 ); metadata_oversize = false;
    metadata_status = 400; CHECK( "metadata-reuse-http-failure", FAILED( run( same, 2 ) ) && public_requests == 1 ); metadata_status = 200;
    for ( bool timeout : { false, true } )
    {
        metadata_ticks = 0; public_requests = public_sends = 0; LONG canceled = 0;
        auto doc = xmlNewDoc( BAD_CAST "1.0" ); auto root = xmlNewNode( nullptr, BAD_CAST "Response" ); xmlDocSetRootElement( doc, root );
        metadata_cancel_after_row = timeout ? nullptr : &canceled; metadata_advance_clock = timeout;
        const auto hr = receipt_metadata_rows( same, 2, 31, "US", "en-US", root, &canceled, 50000 );
        CHECK( "metadata-reuse-between-row-stop", hr == ( timeout ? HRESULT_FROM_WIN32( ERROR_TIMEOUT ) : E_ABORT ) && public_requests == 1 );
        metadata_cancel_after_row = nullptr; metadata_advance_clock = false; xmlFreeDoc( doc );
    }
    metadata_mode = false; metadata_body.clear(); public_body.clear();
}

static struct entitled_snapshot *test_metadata( void )
{
    const char *json = "{\"Products\":[{\"ProductId\":\"B00000000001\",\"ProductType\":\"Durable\",\"Properties\":{"
                       "\"InAppOfferToken\":\"Synthetic offer\"},"
                       "\"LocalizedProperties\":[{\"ProductTitle\":\"Synthetic & add-on\",\"Language\":\"en-US\"}],"
                       "\"DisplaySkuAvailabilities\":[{\"Sku\":{\"SkuId\":\"0010\",\"Properties\":{\"IsTrial\":false,"
                       "\"Packages\":[{}]}}},"
                       "{\"Sku\":{\"SkuId\":\"0020\",\"Properties\":{\"IsTrial\":true}}}]}]}";
    struct receipt_license license = { "B00000000001", "0010", 0 };
    license.expiry = time( NULL ) + 3600;
    xmlDocPtr doc = xmlNewDoc( BAD_CAST "1.0" );
    xmlNodePtr root = xmlNewNode( NULL, BAD_CAST "Response" );
    xmlChar *bytes;
    int size;
    char until[32];
    struct entitled_snapshot *snapshot = NULL;
    xmlDocSetRootElement( doc, root );
    public_requests = public_sends = 0;
    LONG metadata_canceled = 0;
    CHECK( "public-catalog-no-network-grant", FAILED( receipt_metadata_rows( &license, 1, 31, "US", "en-US", root, &metadata_canceled, GetTickCount64() + 5000 ) ) );
    CHECK( "public-catalog-request-captured", public_requests == 1 && public_sends == 1 );
    CHECK( "public-catalog-path-exact",
           !wcscmp( public_path, L"/v7.0/products?bigIds=B00000000001&market=US&languages=en-US" ) );
    CHECK( "public-catalog-remains-https", public_flags == WINHTTP_FLAG_SECURE );
    public_requests = public_sends = 0;
    CHECK( "public-catalog-language-no-network-grant",
           FAILED( receipt_metadata_rows( &license, 1, 31, "CZ", "zh-Hans-CN", root, &metadata_canceled, GetTickCount64() + 5000 ) ) );
    CHECK( "public-catalog-language-request-captured", public_requests == 1 && public_sends == 1 );
    CHECK( "public-catalog-language-path-exact",
           !wcscmp( public_path, L"/v7.0/products?bigIds=B00000000001&market=CZ&languages=zh-Hans-CN" ) );
    xmlNewTextChild( root, NULL, BAD_CAST "HResult", BAD_CAST "0" );
    snprintf( until, sizeof( until ), "%llu", ( unsigned long long )time( NULL ) + 60 );
    xmlNewTextChild( root, NULL, BAD_CAST "ValidUntil", BAD_CAST until );
    CHECK( "metadata", receipt_metadata_parse( &license, 31, ( BYTE * )json, strlen( json ), root ) == S_OK );
    xmlDocDumpMemory( doc, &bytes, &size );
    CHECK( "parsed-owned-product",
           entitled_parse( ( char * )bytes, size, &snapshot ) == S_OK && snapshot && snapshot->count == 1 );
    if ( snapshot )
    {
        CHECK( "only-owned-sku",
               snapshot->products[0].skusCount == 1 && !strcmp( snapshot->products[0].skus[0].skuId, "0010" ) );
        CHECK( "normal-sku-not-trial", !snapshot->products[0].skus[0].isTrial );
        /* An enumerating consumer may copy the currency string directly even
         * when collection metadata does not include a purchasable price. */
        const auto &product_price = snapshot->products[0].price;
        const auto &sku_price = snapshot->products[0].skus[0].price;
        CHECK( "entitled-product-currency-readable", product_price.currencyCode != nullptr );
        CHECK( "entitled-sku-currency-readable", sku_price.currencyCode != nullptr );
        CHECK( "entitled-product-currency-unknown", product_price.currencyCode &&
               std::string( product_price.currencyCode ).empty() );
        CHECK( "entitled-sku-currency-unknown", sku_price.currencyCode &&
               std::string( sku_price.currencyCode ).empty() );
        CHECK( "entitled-no-invented-price", !product_price.formattedPrice[0] &&
               !sku_price.formattedPrice[0] && !product_price.isOnSale && !sku_price.isOnSale );
        CHECK( "xml-escape", !strcmp( snapshot->products[0].title, "Synthetic & add-on" ) );
        CHECK( "package-metadata", snapshot->products[0].hasDigitalDownload );
        CHECK( "developer-offer-token", !strcmp( snapshot->products[0].inAppOfferToken, "Synthetic offer" ) );
        CHECK( "signed-license-end-date", snapshot->products[0].skus[0].collectionData.endDate == license.expiry );
        entitled_snapshot_release( snapshot );
        snapshot = NULL;
    }
    xmlFree( bytes );
    strcpy( license.sku, "0020" );
    CHECK( "second-owned-sku", receipt_metadata_parse( &license, 31, ( BYTE * )json, strlen( json ), root ) == S_OK );
    xmlDocDumpMemory( doc, &bytes, &size );
    CHECK( "merged-skus", entitled_parse( ( char * )bytes, size, &snapshot ) == S_OK && snapshot &&
                              snapshot->count == 1 && snapshot->products[0].skusCount == 2 );
    if ( snapshot ) entitled_snapshot_release( snapshot );
    xmlFree( bytes );
    snapshot = NULL;
    strcpy( license.sku, "0030" );
    CHECK( "missing-sku-not-inferred",
           FAILED( receipt_metadata_parse( &license, 31, ( BYTE * )json, strlen( json ), root ) ) );
    CHECK( "malformed-metadata-rejected", FAILED( receipt_metadata_parse( &license, 31, ( BYTE * )"{}", 2, root ) ) );
    char *bad_trial = strdup( json ), *trial_field = strstr( bad_trial, "false" );
    memcpy( trial_field, "null ", 5 );
    strcpy( license.sku, "0010" );
    CHECK( "unknown-trial-not-full-license",
           FAILED( receipt_metadata_parse( &license, 31, ( BYTE * )bad_trial, strlen( bad_trial ), root ) ) );
    free( bad_trial );
    CHECK( "doctype-rejected", FAILED( entitled_parse( "<!DOCTYPE Response><Response/>", 30, &snapshot ) ) );
    xmlFreeDoc( doc );
    snapshot = static_cast<std::remove_reference_t<decltype( snapshot )>>( calloc( 1, sizeof( *snapshot ) ) );
    snapshot->refs = 1;
    snapshot->valid_until = time( NULL ) + 60;
    snapshot->count = 3;
    snapshot->products =
        static_cast<std::remove_reference_t<decltype( snapshot->products )>>( calloc( 3, sizeof( XStoreProduct ) ) );
    return snapshot;
}

static BOOLEAN CALLBACK enumerate( const XStoreProduct *product, void *context )
{
    enumerated++;
    return TRUE;
}
static BOOLEAN CALLBACK close_during_callback( const XStoreProduct *product, void *context )
{
    enumerated++;
    entitled_page_close( context );
    return FALSE;
}
static void CALLBACK complete( XAsyncBlock *async )
{
    callbacks++;
}
static void dispatch_until_complete( IXThreadingImpl *threads, XTaskQueueHandle queue, XAsyncBlock *block )
{
    ULONGLONG start = GetTickCount64();
    do
    {
        ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 );
        Sleep( 1 );
    } while ( ( !callbacks || ( threads )->XAsyncGetStatus( block, FALSE ) == E_PENDING ) &&
              GetTickCount64() - start < 3000 );
}

static void test_async( struct entitled_snapshot *snapshot )
{
    IXThreadingImpl *threads;
    XTaskQueueHandle queue;
    XStoreContextHandle store;
    XStoreProductQueryHandle next = NULL;
    XAsyncBlock block = { 0 };
    struct entitled_page *page;
    ULONGLONG start;
    if ( !snapshot ) return;
    CHECK( "threading", FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK );
    CHECK( "manual-queue", ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
                                                          XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    CHECK( "store-context", entitled_store_create( NULL, &store ) == S_OK );
    block.queue = queue;
    block.callback = complete;
    CHECK( "query-begin", entitled_begin( store, 31, 10, &block ) == S_OK );
    entitled_store_close( store ); /* In-flight request owns copied parameters. */
    start = GetTickCount64();
    CHECK( "work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
    CHECK( "manual-work-does-not-block", GetTickCount64() - start < 200 );
    CHECK( "license-worker-started", WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "pending-during-network", ( threads )->XAsyncGetStatus( &block, FALSE ) == E_PENDING );
    SetEvent( bridge_gate );
    dispatch_until_complete( threads, queue, &block );
    CHECK( "failure-propagated", ( threads )->XAsyncGetStatus( &block, FALSE ) == E_FAIL );
    CHECK( "completion-once", callbacks == 1 );
    next = ( void * )1;
    CHECK( "failure-no-query-handle", FAILED( entitled_result( &block, &next, FALSE ) ) && !next );

    for ( UINT mode = 0; mode < 2; mode++ )
    {
        callbacks = 0;
        ResetEvent( bridge_started );
        ResetEvent( bridge_gate );
        memset( &block, 0, sizeof( block ) );
        block.queue = queue;
        block.callback = complete;
        CHECK( "cancel-store", entitled_store_create( NULL, &store ) == S_OK );
        CHECK( "cancel-query", entitled_begin( store, 31, 10, &block ) == S_OK );
        entitled_store_close( store );
        if ( mode )
        {
            CHECK( "cancel-work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            CHECK( "cancel-worker-running", WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 );
        }
        ( threads )->XAsyncCancel( &block );
        if ( !mode ) ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
        SetEvent( bridge_gate );
        dispatch_until_complete( threads, queue, &block );
        CHECK( "cancel-terminal", ( threads )->XAsyncGetStatus( &block, FALSE ) == E_ABORT );
        CHECK( "cancel-completion-once", callbacks == 1 );
        start = GetTickCount64();
        while ( bridge_active && GetTickCount64() - start < 2000 )
            Sleep( 1 );
        CHECK( "canceled-worker-finished", !bridge_active );
    }
    CHECK( "invalid-store-handle", entitled_begin( ( void * )1, 31, 10, &block ) == E_INVALIDARG );
    CHECK( "create-requires-output", entitled_store_create( NULL, NULL ) == E_POINTER );
    CHECK( "begin-store", entitled_store_create( NULL, &store ) == S_OK );
    ( threads )->XTaskQueueSetCurrentProcessTaskQueue( NULL );
    memset( &block, 0, sizeof( block ) );
    CHECK( "begin-failure-without-queue", FAILED( entitled_begin( store, 31, 10, &block ) ) );
    entitled_store_close( store );

    page = static_cast<std::remove_reference_t<decltype( page )>>( calloc( 1, sizeof( *page ) ) );
    page->refs = 1;
    page->snapshot = snapshot;
    page->size = 1;
    page->next = entitled_pages;
    entitled_pages = page;
    enumerated = 0;
    CHECK( "first-page", entitled_enumerate( page, NULL, enumerate ) == S_OK && enumerated == 1 );
    CHECK( "has-more", entitled_has_more( page ) );
    memset( &block, 0, sizeof( block ) );
    block.queue = queue;
    block.callback = complete;
    CHECK( "next-begin", entitled_next( page, &block ) == S_OK );
    entitled_page_close( page );
    CHECK( "next-work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
    dispatch_until_complete( threads, queue, &block );
    CHECK( "next-survives-original-close", entitled_result( &block, &next, TRUE ) == S_OK && next );
    page = entitled_page_acquire( next );
    CHECK( "retained-page", page && page->offset == 1 );
    if ( page )
    {
        page->offset = 2;
        CHECK( "last-page", !entitled_has_more( next ) );
        CHECK( "no-next-after-last", entitled_next( next, &block ) == HRESULT_FROM_WIN32( ERROR_NO_MORE_ITEMS ) );
        page->snapshot->valid_until = time( NULL );
        CHECK( "expired-page",
               entitled_enumerate( next, NULL, enumerate ) == E_ACCESSDENIED && !entitled_has_more( next ) );
        page->snapshot->valid_until = time( NULL ) + 60;
        entitled_page_release( page );
    }
    enumerated = 0;
    CHECK( "close-in-callback-and-stop",
           entitled_enumerate( next, next, close_during_callback ) == S_OK && enumerated == 1 );
    CHECK( "closed-query-rejected", entitled_enumerate( next, NULL, enumerate ) == E_INVALIDARG );
    entitled_page_close( next );
    CHECK( "foreign-query-rejected",
           !entitled_has_more( ( void * )1 ) && entitled_next( ( void * )1, &block ) == E_INVALIDARG );
    ( threads )->XTaskQueueCloseHandle( queue );
    ( threads )->Release();
}

/* Synthetic handle lifetime/event fixtures only. Actual acquisition below uses
 * the always-failing bridge; no synthetic proof can reach the shipped runtime. */
struct license_callback_context
{
    XStoreLicenseHandle handle;
    XTaskQueueRegistrationToken token;
    UINT mode;
    BOOL ok, waited;
    HANDLE started, gate, wait_started, finished;
};
static LONG lost_callbacks;

static void CALLBACK license_lost( void *arg )
{
    license_callback_context *context = static_cast<license_callback_context *>( arg );
    InterlockedIncrement( &lost_callbacks );
    if ( context->mode == 1 )
        context->ok = package_license_unregister( context->handle, context->token, TRUE );
    else if ( context->mode == 2 )
    {
        package_license_close( context->handle );
        context->ok = TRUE;
    }
    else if ( context->mode == 3 )
    {
        SetEvent( context->started );
        context->ok = WaitForSingleObject( context->gate, 3000 ) == WAIT_OBJECT_0;
    }
}

static void publish_test_license( struct package_license *license )
{
    AcquireSRWLockExclusive( &package_license_lock );
    license->next = package_licenses;
    package_licenses = license;
    ReleaseSRWLockExclusive( &package_license_lock );
}

static DWORD WINAPI trigger_test_loss( void *arg )
{
    package_license *license = static_cast<package_license *>( arg );
    InterlockedExchange( &license->lost, TRUE );
    package_license_notify( license );
    return 0;
}

static DWORD WINAPI wait_test_unregister( void *arg )
{
    license_callback_context *context = static_cast<license_callback_context *>( arg );
    SetEvent( context->wait_started );
    context->waited = package_license_unregister( context->handle, context->token, TRUE );
    SetEvent( context->finished );
    return 0;
}

static void test_package_licenses( void )
{
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL, immediate = NULL;
    struct package_license *license = NULL;
    XStoreProduct product = { 0 };
    XStoreSku sku = { 0 };
    struct entitled_snapshot proof = { 0 };
    struct license_callback_context context = { 0 };
    XStoreContextHandle store;
    XStoreLicenseHandle result;
    XAsyncBlock block = { 0 };
    HANDLE trigger, waiter;
    ULONGLONG start;
    CHECK( "license-threading",
           FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
    if ( !threads ) return;
    CHECK( "license-queue", ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
                                                           XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    CHECK( "license-immediate",
           ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Immediate,
                                          &immediate ) == S_OK );
    product.storeId = "B00000000001";
    product.productKind = XStoreProductKind::Durable;
    product.isInUserCollection = product.hasDigitalDownload = TRUE;
    product.skus = &sku;
    product.skusCount = 1;
    sku.isInUserCollection = TRUE;
    sku.collectionData.endDate = time( NULL ) + 3600;
    proof.count = 1;
    proof.products = &product;
    proof.valid_until = time( NULL ) + 60;
    CHECK( "license-no-proof-no-grant",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    proof.proof_until = time( NULL ) + 60;
    product.isInUserCollection = FALSE;
    CHECK( "license-unowned-no-grant",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    product.isInUserCollection = TRUE;
    product.hasDigitalDownload = FALSE;
    CHECK( "license-no-package-no-grant",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED );
    CHECK( "durable-no-package-proof-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == S_OK && license );
    if ( license )
    {
        CHECK( "durable-no-package-proof-bound", license->until == proof.proof_until );
        package_license_dispose( license );
        license = NULL;
    }
    product.hasDigitalDownload = TRUE;
    CHECK( "durable-package-proof-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == S_OK && license );
    if ( license )
    {
        package_license_dispose( license );
        license = NULL;
    }
    proof.proof_until = 0;
    CHECK( "durable-no-proof-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    proof.proof_until = time( NULL ) + 60;
    sku.isTrial = TRUE;
    CHECK( "durable-trial-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    sku.isTrial = FALSE;
    sku.isInUserCollection = FALSE;
    CHECK( "durable-unowned-sku-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    sku.isInUserCollection = TRUE;
    product.isInUserCollection = FALSE;
    CHECK( "durable-unowned-product-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    product.isInUserCollection = TRUE;
    CHECK( "durable-wrong-product-no-grant",
           durable_license_from_snapshot( &proof, "B00000000002", threads, &license ) == E_ACCESSDENIED && !license );
    sku.collectionData.endDate = -1;
    CHECK( "durable-negative-expiry-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    sku.collectionData.endDate = time( NULL ) - 1;
    CHECK( "durable-expired-sku-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    sku.collectionData.endDate = time( NULL ) + 3600;
    product.hasDigitalDownload = TRUE;
    product.productKind = XStoreProductKind::Game;
    CHECK( "durable-base-no-grant",
           durable_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED && !license );
    CHECK( "license-base-not-durable",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED );
    product.productKind = XStoreProductKind::Durable;
    sku.isTrial = TRUE;
    CHECK( "license-trial-not-full",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED );
    sku.isTrial = FALSE;
    CHECK( "license-wrong-product",
           package_license_from_snapshot( &proof, "B00000000002", threads, &license ) == E_ACCESSDENIED );
    sku.collectionData.endDate = time( NULL );
    CHECK( "license-expired-sku",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED );
    sku.collectionData.endDate = -1;
    CHECK( "license-negative-expiry",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == E_ACCESSDENIED );
    sku.collectionData.endDate = time( NULL ) + 3600;
    CHECK( "license-fixture",
           package_license_from_snapshot( &proof, product.storeId, threads, &license ) == S_OK && license );
    if ( !license ) goto done;
    CHECK( "license-proof-bounded", license->until == proof.proof_until );
    {
        struct package_license_async acquired = { 0 };
        XAsyncProviderData data = { 0 };
        UINT64 xuid;
        CHECK( "license-result-live-store", entitled_store_create( NULL, &acquired.store_context ) == S_OK );
        CHECK( "license-result-live-generation",
               entitled_store_identity( acquired.store_context, &xuid, &acquired.store_serial ) == S_OK );
        acquired.license = license;
        data.context = &acquired;
        CHECK( "license-result-buffer-required",
               package_license_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG && acquired.license == license );
        data.buffer = &result;
        data.bufferSize = sizeof( result );
        CHECK( "license-provider-result-transfer", package_license_provider( XAsyncOp::GetResult, &data ) == S_OK &&
                                                       result == license && !acquired.license );
        CHECK( "license-provider-result-once", package_license_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG );
        entitled_store_close( acquired.store_context );
    }
    CHECK( "license-valid", package_license_valid( license ) );
    CHECK( "license-foreign-invalid", !package_license_valid( ( void * )1 ) );
    context.handle = license;
    lost_callbacks = 0;
    CHECK( "license-register",
           package_license_register( license, queue, &context, license_lost, &context.token ) == S_OK &&
               context.token.token );
    CHECK( "license-no-initial-event",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && !lost_callbacks );
    InterlockedExchange( &license->lost, TRUE );
    package_license_notify( license );
    package_license_notify( license );
    CHECK( "license-lost-invalid", !package_license_valid( license ) );
    CHECK( "license-loss-on-completion",
           ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && lost_callbacks == 1 );
    CHECK( "license-no-duplicate-event", !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    CHECK( "license-unregister", package_license_unregister( license, context.token, TRUE ) );
    package_license_close( license );
    CHECK( "license-close-invalid", !package_license_valid( license ) );
    package_license_close( license );
    package_license_close( ( void * )1 );

    CHECK( "license-queued-fixture", package_license_create( threads, time( NULL ) + 60, &license ) == S_OK );
    publish_test_license( license );
    context.handle = license;
    lost_callbacks = 0;
    CHECK( "license-queued-register",
           package_license_register( license, queue, &context, license_lost, &context.token ) == S_OK );
    InterlockedExchange( &license->lost, TRUE );
    package_license_notify( license );
    CHECK( "license-unregister-pending", !package_license_unregister( license, context.token, FALSE ) );
    CHECK( "license-unregister-wait-after-pending", package_license_unregister( license, context.token, TRUE ) );
    CHECK( "license-pending-suppressed",
           ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && !lost_callbacks );
    package_license_close( license );

    CHECK( "license-expiry-fixture", package_license_create( threads, time( NULL ) + 1, &license ) == S_OK );
    publish_test_license( license );
    context.handle = license;
    lost_callbacks = 0;
    CHECK( "license-expiry-register",
           package_license_register( license, queue, &context, license_lost, &context.token ) == S_OK );
    start = GetTickCount64();
    while ( !lost_callbacks && GetTickCount64() - start < 2500 )
    {
        ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 10 );
        Sleep( 1 );
    }
    CHECK( "license-actual-expiry-event", lost_callbacks == 1 && !package_license_valid( license ) );
    CHECK( "license-expired-register-denied",
           package_license_register( license, queue, &context, license_lost, &context.token ) == E_ACCESSDENIED );
    package_license_close( license );

    for ( UINT mode = 1; mode <= 2; mode++ )
    {
        CHECK( "license-reentrant-fixture", package_license_create( threads, time( NULL ) + 60, &license ) == S_OK );
        publish_test_license( license );
        memset( &context, 0, sizeof( context ) );
        context.handle = license;
        context.mode = mode;
        lost_callbacks = 0;
        CHECK( "license-reentrant-register",
               package_license_register( license, immediate, &context, license_lost, &context.token ) == S_OK );
        InterlockedExchange( &license->lost, TRUE );
        package_license_notify( license );
        CHECK( "license-reentrant-callback", lost_callbacks == 1 && context.ok );
        package_license_close( license );
    }

    CHECK( "license-wait-fixture", package_license_create( threads, time( NULL ) + 60, &license ) == S_OK );
    publish_test_license( license );
    memset( &context, 0, sizeof( context ) );
    context.handle = license;
    context.mode = 3;
    context.started = CreateEventW( NULL, TRUE, FALSE, NULL );
    context.gate = CreateEventW( NULL, TRUE, FALSE, NULL );
    context.wait_started = CreateEventW( NULL, TRUE, FALSE, NULL );
    context.finished = CreateEventW( NULL, TRUE, FALSE, NULL );
    CHECK( "license-wait-register",
           package_license_register( license, immediate, &context, license_lost, &context.token ) == S_OK );
    trigger = CreateThread( NULL, 0, trigger_test_loss, license, 0, NULL );
    CHECK( "license-running-callback", trigger && WaitForSingleObject( context.started, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "license-unregister-running-pending", !package_license_unregister( license, context.token, FALSE ) );
    waiter = CreateThread( NULL, 0, wait_test_unregister, &context, 0, NULL );
    CHECK( "license-wait-started", waiter && WaitForSingleObject( context.wait_started, 1000 ) == WAIT_OBJECT_0 );
    CHECK( "license-wait-really-blocks", WaitForSingleObject( context.finished, 20 ) == WAIT_TIMEOUT );
    SetEvent( context.gate );
    CHECK( "license-wait-finishes", WaitForSingleObject( context.finished, 2000 ) == WAIT_OBJECT_0 && context.waited );
    CHECK( "license-callback-finishes", WaitForSingleObject( trigger, 2000 ) == WAIT_OBJECT_0 && context.ok );
    WaitForSingleObject( waiter, 2000 );
    CloseHandle( waiter );
    CloseHandle( trigger );
    CloseHandle( context.started );
    CloseHandle( context.gate );
    CloseHandle( context.wait_started );
    CloseHandle( context.finished );
    package_license_close( license );

    CHECK( "license-no-live-handles", !package_licenses && !package_license_registrations );
    CHECK( "license-invalid-register",
           package_license_register( ( void * )1, queue, NULL, license_lost, &context.token ) == E_INVALIDARG );
    CHECK( "license-null-callback",
           package_license_register( ( void * )1, queue, NULL, NULL, &context.token ) == E_POINTER );
    CHECK( "license-foreign-store",
           package_license_begin( ( void * )1, "00000001111122223333444444444444", &block ) == E_INVALIDARG );
    for ( UINT mode = 0; mode < 3; mode++ )
    {
        ResetEvent( bridge_started );
        ResetEvent( bridge_gate );
        callbacks = 0;
        memset( &block, 0, sizeof( block ) );
        block.queue = queue;
        block.callback = complete;
        CHECK( "license-context", entitled_store_create( NULL, &store ) == S_OK );
        CHECK( "license-unknown-package",
               package_license_begin( store, "unknown", &block ) == E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
        CHECK( "license-acquire-begin",
               package_license_begin( store, "00000001111122223333444444444444", &block ) == S_OK );
        entitled_store_close( store );
        if ( mode != 1 )
        {
            start = GetTickCount64();
            CHECK( "license-dispatch-work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            CHECK( "license-nonblocking-work", GetTickCount64() - start < 200 );
            CHECK( "license-worker-started", WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 );
        }
        if ( mode ) ( threads )->XAsyncCancel( &block );
        if ( mode == 1 ) ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
        SetEvent( bridge_gate );
        dispatch_until_complete( threads, queue, &block );
        CHECK( "license-failure-preserved",
               ( threads )->XAsyncGetStatus( &block, FALSE ) == ( mode ? E_ABORT : E_FAIL ) );
        CHECK( "license-completion-once", callbacks == 1 );
        result = ( void * )1;
        CHECK( "license-no-handle-on-failure", FAILED( package_license_result( &block, &result ) ) && !result );
        start = GetTickCount64();
        while ( bridge_active && GetTickCount64() - start < 2000 )
            Sleep( 1 );
        CHECK( "license-failed-worker-finishes", !bridge_active );
    }
done:
    if ( immediate ) ( threads )->XTaskQueueCloseHandle( immediate );
    if ( queue ) ( threads )->XTaskQueueCloseHandle( queue );
    ( threads )->Release();
}

/* Result handoff must still belong to the Store context that initiated it.
 * The positive license is the same receipt-bound fixture used above. */
static void test_package_result_context( void )
{
    IXThreadingImpl *threads = NULL;
    CHECK( "package-context-threading",
           FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
    if ( !threads ) return;
    for ( UINT mode = 0; mode < 2; ++mode )
    {
        struct package_license_async context = { 0 };
        XStoreContextHandle store = NULL;
        XStoreLicenseHandle result = NULL;
        XAsyncProviderData data = { 0 };
        UINT64 xuid;
        context.durable = mode;
        CHECK( "package-context-create", entitled_store_create( NULL, &store ) == S_OK );
        context.store_context = store;
        CHECK( "package-context-identity", entitled_store_identity( store, &xuid, &context.store_serial ) == S_OK );
        CHECK( "package-context-license", package_license_create( threads, time( NULL ) + 60, &context.license ) == S_OK );
        if ( !context.license ) { entitled_store_close( store ); continue; }
        data.context = &context;
        data.buffer = &result;
        data.bufferSize = sizeof( result );
        CHECK( "package-context-live", package_license_context_valid( &context ) );
        context.store_serial++;
        CHECK( "package-context-wrong-generation", !package_license_context_valid( &context ) );
        CHECK( "package-context-rejects-wrong-generation",
               package_license_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG && !result && context.license );
        if ( result ) { package_license_close( result ); result = NULL; }
        context.store_serial--;
        if ( !context.license )
            CHECK( "package-context-fresh-closed-proof",
                   package_license_create( threads, time( NULL ) + 60, &context.license ) == S_OK );
        entitled_store_close( store );
        CHECK( "package-context-closed", !package_license_context_valid( &context ) );
        CHECK( "package-context-rejects-closed",
               package_license_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG && !result && context.license );
        if ( result ) { package_license_close( result ); result = NULL; }
        if ( context.license ) package_license_dispose( context.license );
    }
    CHECK( "package-context-no-live-licenses", !package_licenses );
    ( threads )->Release();
}

static void test_durable_acquisition( void )
{
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL;
    XStoreContextHandle store = NULL;
    XStoreLicenseHandle result;
    XAsyncBlock block = { 0 };
    struct package_license_async context = { 0 };
    UINT64 xuid;
    UINT mode;
    ULONGLONG start;
    CHECK( "durable-threading",
           FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
    if ( !threads ) return;
    CHECK( "durable-queue", ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
                                                           XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    CHECK( "durable-invalid-context", durable_license_begin( ( void * )1, "B00000000001", &block ) == E_INVALIDARG );
    CHECK( "durable-context-create", entitled_store_create( NULL, &store ) == S_OK );
    CHECK( "durable-invalid-id", durable_license_begin( store, "invalid<&", &block ) == E_INVALIDARG );
    CHECK( "durable-null-id", durable_license_begin( store, NULL, &block ) == E_INVALIDARG );
    CHECK( "durable-null-async", durable_license_begin( store, "B00000000001", NULL ) == E_INVALIDARG );
    context.durable = TRUE;
    context.store_context = store;
    CHECK( "durable-store-identity", entitled_store_identity( store, &xuid, &context.store_serial ) == S_OK );
    CHECK( "durable-store-live", package_license_context_valid( &context ) );
    context.store_serial++;
    CHECK( "durable-wrong-generation", !package_license_context_valid( &context ) );
    context.store_serial--;
    entitled_store_close( store );
    CHECK( "durable-store-closed", !package_license_context_valid( &context ) );
    for ( mode = 0; mode < 3; mode++ )
    {
        ResetEvent( bridge_started );
        ResetEvent( bridge_gate );
        callbacks = 0;
        memset( &block, 0, sizeof( block ) );
        block.queue = queue;
        block.callback = complete;
        CHECK( "durable-store", entitled_store_create( NULL, &store ) == S_OK );
        CHECK( "durable-begin", durable_license_begin( store, "B00000000002", &block ) == S_OK );
        if ( mode != 1 )
        {
            start = GetTickCount64();
            CHECK( "durable-work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            CHECK( "durable-work-nonblocking", GetTickCount64() - start < 200 );
            CHECK( "durable-worker-started", WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 );
        }
        if ( mode ) ( threads )->XAsyncCancel( &block );
        if ( mode == 1 ) ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
        SetEvent( bridge_gate );
        dispatch_until_complete( threads, queue, &block );
        CHECK( "durable-error-preserved",
               ( threads )->XAsyncGetStatus( &block, FALSE ) == ( mode ? E_ABORT : E_FAIL ) );
        CHECK( "durable-callback-once", callbacks == 1 );
        result = ( void * )1;
        CHECK( "durable-failed-no-license", FAILED( durable_license_result( &block, &result ) ) && !result );
        entitled_store_close( store );
        start = GetTickCount64();
        while ( bridge_active && GetTickCount64() - start < 2000 )
            Sleep( 1 );
        CHECK( "durable-worker-drained", !bridge_active );
    }
    CHECK( "durable-no-live-handles", !package_licenses && !package_license_registrations );
    ( threads )->XTaskQueueCloseHandle( queue );
    ( threads )->Release();
}

/* Only this test executable constructs successful fixture snapshots. The DLL
 * still obtains every successful result through the real signed transport. */
static HRESULT WINAPI addon_fixture_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    addon_license_async *context = static_cast<addon_license_async *>( data->context );
    if ( op == XAsyncOp::Begin )
    {
        ( context->threading )
            ->XAsyncComplete( data->async, S_OK,
                              sizeof( struct addon_result_header ) + context->count * sizeof( XStoreAddonLicense ) );
        return S_OK;
    }
    return addon_license_provider( op, data );
}

static void test_addon_licenses( void )
{
    XStoreProduct products[2] = { { 0 } };
    XStoreSku skus[2] = { { 0 } };
    struct entitled_snapshot proof = { 0 };
    XStoreAddonLicense *licenses = NULL, output[2];
    UINT32 count = 99, repeated;
    UINT64 until, xuid;
    UINT mode;
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL;
    XStoreContextHandle store;
    XStoreLicenseHandle wrong;
    XAsyncBlock block = { 0 };
    struct addon_license_async *context;
    ULONGLONG start;
    products[0].storeId = storeId;
    products[0].productKind = XStoreProductKind::Game;
    products[0].isInUserCollection = products[0].hasDigitalDownload = TRUE;
    products[0].skus = &skus[0];
    products[0].skusCount = 1;
    products[1].storeId = "B00000000002";
    products[1].productKind = XStoreProductKind::Durable;
    products[1].isInUserCollection = TRUE;
    products[1].inAppOfferToken = "bonus";
    products[1].skus = &skus[1];
    products[1].skusCount = 1;
    skus[0].skuId = skus[1].skuId = "0010";
    skus[0].isInUserCollection = skus[1].isInUserCollection = TRUE;
    skus[0].collectionData.endDate = time( NULL ) + 3600;
    skus[1].collectionData.endDate = time( NULL ) + 1800;
    proof.products = products;
    proof.count = 2;
    CHECK( "addon-unsigned-denied",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == E_ACCESSDENIED && !licenses && !count );
    proof.proof_until = time( NULL ) + 60;
    CHECK( "addon-proof",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && count == 1 && licenses );
    nexus_store_context::AddonLicenseSnapshot projected;
    CHECK("winrt-durable-projection", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK &&
          projected.licenses.size()==1 && projected.licenses[0].sku=="B00000000002/0010" &&
          projected.licenses[0].offer=="bonus" && projected.licenses[0].expiration==(INT64)proof.proof_until);
    skus[1].isTrial=TRUE;
    CHECK("winrt-trial-projection", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK && projected.licenses.size()==1 && projected.licenses[0].trial);
    skus[1].isTrial=FALSE;
    products[1].hasDigitalDownload=TRUE;
    CHECK("winrt-packaged-durable-included", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK && projected.licenses.size()==1);
    products[1].hasDigitalDownload=FALSE;
    products[1].productKind=XStoreProductKind::Consumable;
    CHECK("winrt-consumable-excluded", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK && projected.licenses.empty());
    products[1].productKind=XStoreProductKind::Durable;
    skus[1].isInUserCollection=FALSE;
    CHECK("winrt-unowned-excluded", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK && projected.licenses.empty());
    skus[1].isInUserCollection=TRUE;
    const auto old_end=skus[1].collectionData.endDate;
    skus[1].collectionData.endDate=time(NULL)-1;
    CHECK("winrt-expired-excluded", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==S_OK && projected.licenses.empty());
    skus[1].collectionData.endDate=old_end;
    UINT64 old_proof=proof.proof_until;proof.proof_until=0;
    CHECK("winrt-unsigned-denied", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==E_ACCESSDENIED && projected.licenses.empty());
    proof.proof_until=time(NULL)-1;
    CHECK("winrt-stale-denied", nexus_store_context::addon_data_from_verified_snapshot(&proof, &projected)==E_ACCESSDENIED && projected.licenses.empty());
    proof.proof_until=old_proof;
    CHECK("winrt-null-snapshot", nexus_store_context::addon_data_from_verified_snapshot(nullptr, &projected)==E_ACCESSDENIED);
    CHECK("winrt-null-output", nexus_store_context::addon_data_from_verified_snapshot(&proof, nullptr)==E_POINTER);

    if ( licenses )
    {
        CHECK( "addon-sku-id", !strcmp( licenses[0].skuStoreId, "B00000000002/0010" ) );
        CHECK( "addon-offer-token", !strcmp( licenses[0].inAppOfferToken, "bonus" ) );
        CHECK( "addon-proof-expiry",
               licenses[0].isActive && licenses[0].expirationDate == proof.proof_until && until == proof.proof_until );
        free( licenses );
        licenses = NULL;
    }
    skus[0].collectionData.endDate = time( NULL ) + 10;
    CHECK( "addon-base-expiry", addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK &&
                                    count == 1 && until == skus[0].collectionData.endDate );
    free( licenses );
    licenses = NULL;
    skus[0].collectionData.endDate = time( NULL ) + 3600;
    skus[1].collectionData.endDate = time( NULL ) + 20;
    CHECK( "addon-sku-expiry", addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK &&
                                   count == 1 && until == skus[1].collectionData.endDate );
    free( licenses );
    licenses = NULL;
    skus[1].isTrial = TRUE;
    CHECK( "addon-trial-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    skus[1].isTrial = FALSE;
    skus[1].isInUserCollection = FALSE;
    CHECK( "addon-unowned-sku-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    skus[1].isInUserCollection = TRUE;
    skus[1].collectionData.endDate = -1;
    CHECK( "addon-negative-expiry-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    skus[1].collectionData.endDate = time( NULL ) - 1;
    CHECK( "addon-expired-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    skus[1].collectionData.endDate = time( NULL ) + 1800;
    products[1].isInUserCollection = FALSE;
    CHECK( "addon-unowned-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    products[1].isInUserCollection = TRUE;
    products[1].hasDigitalDownload = TRUE;
    CHECK( "addon-package-excluded",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    products[1].hasDigitalDownload = FALSE;
    products[0].isInUserCollection = FALSE;
    CHECK( "addon-no-base-license-empty",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    products[0].isInUserCollection = TRUE;
    products[0].hasDigitalDownload = FALSE;
    CHECK( "addon-no-digital-base-empty",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == S_OK && !licenses && !count );
    products[0].hasDigitalDownload = TRUE;
    products[1].inAppOfferToken = "0123456789012345678901234567890123456789012345678901234567890123";
    CHECK( "addon-long-token-not-truncated",
           addon_licenses_from_snapshot( &proof, &licenses, &count, &until ) == E_UNEXPECTED && !licenses && !count );
    products[1].inAppOfferToken = "bonus";
    CHECK( "addon-threading",
           FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
    if ( !threads ) return;
    CHECK( "addon-queue", ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual,
                                                         &queue ) == S_OK );
    CHECK( "addon-invalid-store", addon_license_begin( ( void * )1, &block ) == E_INVALIDARG );
    CHECK( "addon-null-async", addon_license_begin( NULL, NULL ) == E_INVALIDARG );
    for ( mode = 0; mode < 4; mode++ )
    {
        CHECK( "addon-result-store", entitled_store_create( NULL, &store ) == S_OK );
        context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, sizeof( *context ) ) );
        CHECK( "addon-result-context", context != NULL );
        if ( !context ) break;
        context->refs = 1;
        context->threading = threads;
        ( threads )->AddRef();
        context->store = store;
        context->until = time( NULL ) + 60;
        entitled_store_identity( store, &xuid, &context->serial );
        if ( mode )
            CHECK( "addon-result-proof", addon_licenses_from_snapshot( &proof, &context->licenses, &context->count,
                                                                       &context->until ) == S_OK );
        memset( &block, 0, sizeof( block ) );
        block.queue = queue;
        context->async = &block;
        AcquireSRWLockExclusive( &addon_license_lock );
        context->next = addon_license_requests;
        addon_license_requests = context;
        ReleaseSRWLockExclusive( &addon_license_lock );
        CHECK( "addon-fixture-begin", ( threads )->XAsyncBegin( &block, context, &addon_license_identity, "fixture",
                                                                addon_fixture_provider ) == S_OK );
        CHECK( "addon-result-count", addon_license_count( &block, &count ) == S_OK && count == ( mode ? 1 : 0 ) );
        CHECK( "addon-count-repeat-not-consumed",
               addon_license_count( &block, &repeated ) == S_OK && repeated == count );
        wrong = ( void * )1;
        CHECK( "addon-wrong-result-identity", durable_license_result( &block, &wrong ) == E_INVALIDARG && !wrong );
        if ( mode == 1 )
        {
            CHECK( "addon-short-buffer-retry", addon_license_result( &block, 0, output ) == E_NOT_SUFFICIENT_BUFFER );
            CHECK( "addon-null-buffer-retry", addon_license_result( &block, count, NULL ) == E_INVALIDARG );
        }
        if ( mode == 2 ) context->until = time( NULL ) - 1;
        if ( mode == 3 ) entitled_store_close( store );
        memset( output, 0xa5, sizeof( output ) );
        CHECK( "addon-result",
               addon_license_result( &block, count, mode ? output : NULL ) == ( mode == 2   ? E_ACCESSDENIED
                                                                                : mode == 3 ? E_INVALIDARG
                                                                                            : S_OK ) );
        if ( mode == 1 )
            CHECK( "addon-result-data", !strcmp( output[0].skuStoreId, "B00000000002/0010" ) && output[0].isActive );
        if ( mode >= 2 ) CHECK( "addon-result-error-preserves-buffer", ( ( BYTE * )output )[0] == 0xa5 );
        CHECK( "addon-result-consumed", addon_license_count( &block, &count ) == E_INVALIDARG && !count );
        if ( mode != 3 ) entitled_store_close( store );
        CHECK( "addon-context-drained", !addon_license_requests );
    }
    for ( mode = 0; mode < 3; mode++ )
    {
        ResetEvent( bridge_started );
        ResetEvent( bridge_gate );
        callbacks = 0;
        memset( &block, 0, sizeof( block ) );
        block.queue = queue;
        block.callback = complete;
        CHECK( "addon-worker-store", entitled_store_create( NULL, &store ) == S_OK );
        CHECK( "addon-worker-begin", addon_license_begin( store, &block ) == S_OK );
        CHECK( "addon-count-pending", addon_license_count( &block, &count ) == E_PENDING && !count );
        if ( mode != 1 )
        {
            start = GetTickCount64();
            CHECK( "addon-dispatch-work", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            CHECK( "addon-nonblocking-work", GetTickCount64() - start < 200 );
            CHECK( "addon-worker-started", WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 );
        }
        if ( mode ) ( threads )->XAsyncCancel( &block );
        if ( mode == 1 ) ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
        SetEvent( bridge_gate );
        dispatch_until_complete( threads, queue, &block );
        CHECK( "addon-error-preserved",
               addon_license_count( &block, &count ) == ( mode ? E_ABORT : E_FAIL ) && !count );
        CHECK( "addon-result-error-preserved", addon_license_result( &block, 0, NULL ) == ( mode ? E_ABORT : E_FAIL ) );
        CHECK( "addon-callback-once", callbacks == 1 );
        entitled_store_close( store );
        start = GetTickCount64();
        while ( bridge_active && GetTickCount64() - start < 2000 )
            Sleep( 1 );
        CHECK( "addon-worker-drained", !bridge_active && !addon_license_requests );
    }
    ( threads )->XTaskQueueCloseHandle( queue );
    ( threads )->Release();
}

static void test_related_hints( void )
{
    char ids[256][13] = { { 0 } }, before[256][13], hint[3400];
    UINT32 count, i;
    const char *bad[] = { "invalid",
                          "B00000000002,",
                          ",B00000000002",
                          "B00000000002,,B00000000003",
                          "B00000000002,B0000000000<",
                          "B00000000002;B00000000003",
                          "b00000000002",
                          "B00000000002\n" };
    strcpy( ids[0], "B00000000001" );
    count = 1;
    CHECK( "related-hint-merge",
           entitled_merge_hint( ids, &count, "B00000000002,B00000000001,B00000000003" ) && count == 3 );
    CHECK( "related-hint-order", !strcmp( ids[0], "B00000000001" ) && !strcmp( ids[1], "B00000000002" ) &&
                                     !strcmp( ids[2], "B00000000003" ) );
    CHECK( "related-hint-null", entitled_merge_hint( ids, &count, NULL ) && count == 3 );
    CHECK( "related-hint-empty", entitled_merge_hint( ids, &count, "" ) && count == 3 );
    memcpy( before, ids, sizeof( ids ) );
    for ( i = 0; i < ARRAY_SIZE( bad ); i++ )
        CHECK( "related-hint-invalid-atomic",
               !entitled_merge_hint( ids, &count, bad[i] ) && count == 3 && !memcmp( ids, before, sizeof( ids ) ) );
    memset( hint, 'B', sizeof( hint ) - 1 );
    hint[sizeof( hint ) - 1] = 0;
    CHECK( "related-hint-oversized",
           !entitled_merge_hint( ids, &count, hint ) && count == 3 && !memcmp( ids, before, sizeof( ids ) ) );
    for ( i = 0; i < 256; i++ )
        snprintf( ids[i], sizeof( ids[i] ), "B%011u", i );
    count = 256;
    memcpy( before, ids, sizeof( ids ) );
    CHECK( "related-hint-limit-duplicate", entitled_merge_hint( ids, &count, "B00000000000" ) && count == 256 );
    CHECK( "related-hint-limit-atomic", !entitled_merge_hint( ids, &count, "B00000000000,B00000000999" ) &&
                                            count == 256 && !memcmp( ids, before, sizeof( ids ) ) );
}

struct game_test_context
{
    XStoreContextHandle store;
    XTaskQueueRegistrationToken token;
    UINT64 serial, version;
    LONG calls;
    UINT mode;
    BOOL ok, waited;
    HANDLE started, gate, waiting, finished;
};

static void CALLBACK game_changed( void *arg )
{
    game_test_context *context = static_cast<game_test_context *>( arg );
    InterlockedIncrement( &context->calls );
    if ( context->mode == 1 )
        context->ok = game_license_unregister( context->store, context->token, TRUE );
    else if ( context->mode == 2 )
    {
        entitled_store_close( context->store );
        context->ok = TRUE;
    }
    else if ( context->mode == 3 )
    {
        SetEvent( context->started );
        context->ok = WaitForSingleObject( context->gate, 3000 ) == WAIT_OBJECT_0;
    }
    else if ( context->mode == 4 && context->calls == 1 )
        game_license_notify( context->serial, ++context->version );
}

static DWORD WINAPI game_test_trigger( void *arg )
{
    game_test_context *context = static_cast<game_test_context *>( arg );
    game_license_notify( context->serial, ++context->version );
    return 0;
}

static DWORD WINAPI game_test_wait( void *arg )
{
    game_test_context *context = static_cast<game_test_context *>( arg );
    SetEvent( context->waiting );
    if ( context->mode == 5 )
    {
        entitled_store_close( context->store );
        context->waited = TRUE;
    }
    else
        context->waited = game_license_unregister( context->store, context->token, TRUE );
    SetEvent( context->finished );
    return 0;
}

static void test_game_licenses( void )
{
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL, immediate = NULL, terminated = NULL, process_queue = NULL, pool = NULL;
    struct game_test_context context = { 0 }, other = { 0 };
    XStoreSku skus[2] = { { 0 } }, swap;
    XStoreProduct product = { 0 };
    struct entitled_snapshot proof = { 0 };
    UINT64 now = time( NULL ), refresh = 0, serial, xuid;
    XTaskQueueRegistrationToken token = { 0 };
    HANDLE trigger, waiter;
    CHECK( "game-threading",
           FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
    if ( !threads ) return;
    CHECK( "game-manual-queue", ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
                                                               XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    CHECK( "game-immediate-queue",
           ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Immediate,
                                          &immediate ) == S_OK );
    CHECK( "game-create", entitled_store_create( NULL, &context.store ) == S_OK );
    CHECK( "game-create-other", entitled_store_create( NULL, &other.store ) == S_OK );
    CHECK( "game-identity",
           entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK && context.serial );
    CHECK( "game-other-identity",
           entitled_store_identity( other.store, &xuid, &other.serial ) == S_OK && other.serial != context.serial );
    CHECK( "game-null-token", game_license_register( context.store, queue, NULL, game_changed, NULL ) == E_POINTER );
    token.token = 123;
    CHECK( "game-null-callback-clears-token",
           game_license_register( context.store, queue, NULL, NULL, &token ) == E_POINTER && !token.token );
    token.token = 123;
    CHECK( "game-invalid-context-clears-token",
           game_license_register( ( void * )1, queue, NULL, game_changed, &token ) == E_INVALIDARG && !token.token );
    CHECK( "game-register",
           game_license_register( context.store, queue, &context, game_changed, &context.token ) == S_OK &&
               context.token.token );
    CHECK( "game-register-other",
           game_license_register( other.store, queue, &other, game_changed, &other.token ) == S_OK &&
               other.token.token != context.token.token );
    CHECK( "game-no-initial-event",
           !context.calls && !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    CHECK( "game-wrong-context-token-noop", game_license_unregister( other.store, context.token, TRUE ) );
    proof.valid_until = now + 60;
    proof.proof_until = now + 600;
    proof.count = 1;
    proof.products = &product;
    product.storeId = storeId;
    product.productKind = XStoreProductKind::Game;
    product.isInUserCollection = TRUE;
    product.skusCount = 1;
    product.skus = skus;
    skus[0].skuId = "0010";
    skus[0].isInUserCollection = TRUE;
    skus[0].isTrial = TRUE;
    skus[0].collectionData.endDate = now + 3600;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-first-proof-only-baseline",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && !context.calls );
    skus[0].isTrial = FALSE;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-completion-not-work-port",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) && !context.calls );
    CHECK( "game-trial-full-change", ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) &&
                                         context.calls == 1 && !other.calls );
    CHECK( "game-no-duplicate-event", !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    proof.proof_until++;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-proof-ttl-not-license-change",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    skus[1] = skus[0];
    skus[1].skuId = "0020";
    product.skusCount = 2;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-sku-set-change",
           ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && context.calls == 2 );
    swap = skus[0];
    skus[0] = skus[1];
    skus[1] = swap;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-sku-order-not-change", !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    skus[0].isTrial = TRUE;
    game_license_observe( context.serial, refresh - 1, &proof );
    proof.proof_until = 0;
    game_license_observe( context.serial, ++refresh, &proof );
    proof.proof_until = now + 600;
    proof.valid_until = now - 1;
    game_license_observe( context.serial, ++refresh, &proof );
    proof.valid_until = now + 60;
    product.storeId = "B00000000002";
    game_license_observe( context.serial, ++refresh, &proof );
    product.storeId = storeId;
    product.productKind = XStoreProductKind::Durable;
    game_license_observe( context.serial, ++refresh, &proof );
    product.productKind = XStoreProductKind::Game;
    proof.count = 0;
    game_license_observe( context.serial, ++refresh, &proof );
    proof.count = 1;
    skus[0].collectionData.endDate = -1;
    game_license_observe( context.serial, ++refresh, &proof );
    skus[0].collectionData.endDate = now + 3600;
    CHECK( "game-no-unverified-expired-related-absent-stale-events",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && context.calls == 2 );
    game_license_observe( context.serial, ++refresh, &proof );
    skus[0].isTrial = FALSE;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-coalesced-refresh",
           ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && context.calls == 3 );
    CHECK( "game-coalesced-no-extra", !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    skus[0].collectionData.endDate++;
    game_license_observe( context.serial, ++refresh, &proof );
    CHECK( "game-unregister-queued-false", !game_license_unregister( context.store, context.token, FALSE ) );
    CHECK( "game-wait-after-pending", game_license_unregister( context.store, context.token, TRUE ) );
    ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 );
    CHECK( "game-queued-event-suppressed", context.calls == 3 );
    CHECK( "game-repeat-unregister-safe", game_license_unregister( context.store, context.token, TRUE ) );
    CHECK( "game-other-still-registered",
           game_license_registrations && game_license_registrations->serial == other.serial );
    CHECK( "game-other-unregister", game_license_unregister( other.store, other.token, FALSE ) );
    CHECK( "game-register-after-baseline",
           game_license_register( context.store, queue, &context, game_changed, &context.token ) == S_OK );
    CHECK( "game-no-event-after-register-known",
           !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    skus[0].collectionData.endDate++;
    game_license_observe( context.serial, ++refresh, &proof );
    serial = context.serial;
    entitled_store_close( context.store );
    ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 );
    CHECK( "game-close-queued-suppressed", context.calls == 3 && !game_license_registrations );
    CHECK( "game-closed-context-denied",
           game_license_register( context.store, queue, &context, game_changed, &token ) == E_INVALIDARG );
    game_license_observe( serial, ++refresh, &proof );
    entitled_store_close( other.store );
    CHECK( "game-new-context-after-close", entitled_store_create( NULL, &context.store ) == S_OK );
    CHECK( "game-new-context-serial",
           entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK && context.serial != serial );
    game_license_observe( serial, ++refresh, &proof );
    CHECK( "game-stale-async-cannot-touch-new-context",
           !( ( struct entitled_store_context * )context.store )->license_version );
    entitled_store_close( context.store );

    for ( UINT mode = 1; mode <= 4; mode++ )
    {
        if ( mode == 3 ) continue;
        memset( &context, 0, sizeof( context ) );
        context.mode = mode;
        CHECK( "game-reentrant-create", entitled_store_create( NULL, &context.store ) == S_OK );
        CHECK( "game-reentrant-identity", entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK );
        CHECK( "game-reentrant-register",
               game_license_register( context.store, immediate, &context, game_changed, &context.token ) == S_OK );
        game_test_trigger( &context );
        CHECK( "game-reentrant-completes", mode == 4 ? context.calls == 2 : context.calls == 1 && context.ok );
        if ( mode != 2 ) entitled_store_close( context.store );
        CHECK( "game-reentrant-no-live-registration", !game_license_registrations );
    }
    for ( UINT close = 0; close < 2; close++ )
    {
        memset( &context, 0, sizeof( context ) );
        context.mode = 3;
        CHECK( "game-wait-create", entitled_store_create( NULL, &context.store ) == S_OK );
        CHECK( "game-wait-identity", entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK );
        context.started = CreateEventW( NULL, TRUE, FALSE, NULL );
        context.gate = CreateEventW( NULL, TRUE, FALSE, NULL );
        context.waiting = CreateEventW( NULL, TRUE, FALSE, NULL );
        context.finished = CreateEventW( NULL, TRUE, FALSE, NULL );
        CHECK( "game-wait-register",
               game_license_register( context.store, immediate, &context, game_changed, &context.token ) == S_OK );
        if ( close )
        {
            memset( &other, 0, sizeof( other ) );
            other.store = context.store;
            CHECK( "game-close-multiple-register",
                   game_license_register( context.store, queue, &other, game_changed, &other.token ) == S_OK );
        }
        trigger = CreateThread( NULL, 0, game_test_trigger, &context, 0, NULL );
        CHECK( "game-running-callback", trigger && WaitForSingleObject( context.started, 2000 ) == WAIT_OBJECT_0 );
        CHECK( "game-running-unregister-false", !game_license_unregister( context.store, context.token, FALSE ) );
        /* The callback has already selected mode 3 before waiting on its gate. */
        context.mode = close ? 5 : 3;
        waiter = CreateThread( NULL, 0, game_test_wait, &context, 0, NULL );
        CHECK( "game-wait-started", waiter && WaitForSingleObject( context.waiting, 1000 ) == WAIT_OBJECT_0 );
        CHECK( "game-wait-blocks-until-callback-return", WaitForSingleObject( context.finished, 20 ) == WAIT_TIMEOUT );
        SetEvent( context.gate );
        CHECK( "game-wait-finishes", WaitForSingleObject( context.finished, 2000 ) == WAIT_OBJECT_0 && context.waited );
        CHECK( "game-running-callback-finishes", WaitForSingleObject( trigger, 2000 ) == WAIT_OBJECT_0 && context.ok );
        WaitForSingleObject( waiter, 2000 );
        CloseHandle( waiter );
        CloseHandle( trigger );
        CloseHandle( context.started );
        CloseHandle( context.gate );
        CloseHandle( context.waiting );
        CloseHandle( context.finished );
        if ( !close )
            entitled_store_close( context.store );
        else
        {
            ( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 );
            CHECK( "game-close-suppresses-all-other-registrations", !other.calls );
        }
        CHECK( "game-wait-clean", !game_license_registrations );
    }

    CHECK( "game-threadpool-queue",
           ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::ThreadPool,
                                          &pool ) == S_OK );
    for ( UINT i = 0; i < 100; i++ )
    {
        memset( &context, 0, sizeof( context ) );
        CHECK( "game-race-create", entitled_store_create( NULL, &context.store ) == S_OK );
        CHECK( "game-race-identity", entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK );
        CHECK( "game-race-register",
               game_license_register( context.store, pool, &context, game_changed, &context.token ) == S_OK );
        game_test_trigger( &context );
        CHECK( "game-race-unregister", game_license_unregister( context.store, context.token, TRUE ) );
        CHECK( "game-race-at-most-once", context.calls <= 1 );
        entitled_store_close( context.store );
    }
    ( threads )->XTaskQueueCloseHandle( pool );

    memset( &context, 0, sizeof( context ) );
    CHECK( "game-process-context", entitled_store_create( NULL, &context.store ) == S_OK );
    ( threads )->XTaskQueueGetCurrentProcessTaskQueue( &process_queue );
    ( threads )->XTaskQueueSetCurrentProcessTaskQueue( queue );
    CHECK( "game-null-queue-uses-process-queue",
           game_license_register( context.store, NULL, &context, game_changed, &context.token ) == S_OK );
    CHECK( "game-null-queue-unregister", game_license_unregister( context.store, context.token, TRUE ) );
    ( threads )->XTaskQueueSetCurrentProcessTaskQueue( process_queue );
    if ( process_queue ) ( threads )->XTaskQueueCloseHandle( process_queue );
    CHECK( "game-cancel-queue-create",
           ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual,
                                          &terminated ) == S_OK );
    CHECK( "game-cancel-identity", entitled_store_identity( context.store, &xuid, &context.serial ) == S_OK );
    CHECK( "game-cancel-register",
           game_license_register( context.store, terminated, &context, game_changed, &context.token ) == S_OK );
    game_test_trigger( &context );
    CHECK( "game-terminate-start", ( threads )->XTaskQueueTerminate( terminated, FALSE, NULL, NULL ) == S_OK );
    for ( UINT i = 0; i < 20; i++ )
    {
        ( threads )->XTaskQueueDispatch( terminated, XTaskQueuePort::Work, 0 );
        ( threads )->XTaskQueueDispatch( terminated, XTaskQueuePort::Completion, 0 );
    }
    CHECK( "game-canceled-not-delivered", !context.calls );
    game_test_trigger( &context ); /* Submission to a terminated queue must unwind. */
    CHECK( "game-submit-failure-unregister", game_license_unregister( context.store, context.token, FALSE ) );
    ( threads )->XTaskQueueCloseHandle( terminated );
    entitled_store_close( context.store );
    ( threads )->XTaskQueueCloseHandle( queue );
    ( threads )->XTaskQueueCloseHandle( immediate );
    ( threads )->Release();
    CHECK( "game-no-live-stores-or-registrations", !entitled_stores && !game_license_registrations );
}

static void test_current_game_license()
{
    const UINT64 now = time( nullptr );
    XStoreSku sku{};
    sku.skuId = "AB12";
    sku.isInUserCollection = TRUE;
    sku.collectionData.endDate = now + 900;
    XStoreProduct products[2]{};
    products[0].storeId = storeId;
    products[0].productKind = XStoreProductKind::Game;
    products[0].isInUserCollection = TRUE;
    products[0].skus = &sku;
    products[0].skusCount = 1;
    entitled_snapshot proof{};
    proof.products = products;
    proof.count = 1;
    proof.proof_until = now + 600;
    XStoreGameLicense result{};
    CHECK( "current-game-real-sku-and-proof-expiry", game_license_from_snapshot( &proof, storeId, &result ) == S_OK &&
                                                         result.isActive &&
                                                         !strcmp( result.skuStoreId, "B00000000001/AB12" ) &&
                                                         static_cast<UINT64>( result.expirationDate ) == now + 600 );
    CHECK( "current-game-no-fabricated-trial-or-disc",
           !result.isTrial && !result.isDiscLicense && !result.isTrialOwnedByThisUser &&
               !result.trialTimeRemainingInSeconds && !result.trialUniqueId[0] );
    proof.proof_until = 0;
    CHECK( "current-game-no-proof-no-license",
           game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED && !result.isActive &&
               !result.skuStoreId[0] && !result.expirationDate );
    proof.proof_until = now - 1;
    CHECK( "current-game-expired-proof", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    proof.proof_until = now + 600;
    CHECK( "current-game-must-match-parent",
           game_license_from_snapshot( &proof, "B00000000002", &result ) == E_ACCESSDENIED );
    products[0].isInUserCollection = FALSE;
    CHECK( "current-game-unowned-product", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    products[0].isInUserCollection = TRUE;
    sku.isInUserCollection = FALSE;
    CHECK( "current-game-unowned-sku", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    sku.isInUserCollection = TRUE;
    sku.collectionData.endDate = -1;
    CHECK( "current-game-negative-expiry", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    sku.collectionData.endDate = now - 1;
    CHECK( "current-game-expired-sku", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    sku.collectionData.endDate = now + 300;
    CHECK( "current-game-sku-bounds-expiry", game_license_from_snapshot( &proof, storeId, &result ) == S_OK &&
                                                 static_cast<UINT64>( result.expirationDate ) == now + 300 );
    sku.isTrial = TRUE;
    CHECK( "current-game-trial-not-promoted-to-full",
           game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED && !result.isActive );
    sku.isTrial = FALSE;
    sku.skuId = "not-a-sku";
    CHECK( "current-game-malformed-sku", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    sku.skuId = "AB12";
    products[0].productKind = XStoreProductKind::Durable;
    CHECK( "current-game-dlc-not-base-license",
           game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    products[0].productKind = XStoreProductKind::Game;
    products[1] = products[0];
    proof.count = 2;
    CHECK( "current-game-ambiguous-parent", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    proof.count = 1;
    products[0].skusCount = ENTITLED_MAX_SKUS + 1;
    CHECK( "current-game-bounded-skus", game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    products[0].skusCount = 1;
    proof.products = nullptr;
    CHECK( "current-game-invalid-snapshot-storage",
           game_license_from_snapshot( &proof, storeId, &result ) == E_ACCESSDENIED );
    CHECK( "current-game-null-result", game_license_from_snapshot( &proof, storeId, nullptr ) == E_POINTER );
}

static void WINAPI store_lifetime_completion( XAsyncBlock *block )
{
    InterlockedIncrement( static_cast<LONG *>( block->context ) );
}

static void test_current_game_result_lifetime()
{
    XStoreContextHandle store = nullptr, other = nullptr;
    UINT64 xuid, serial;
    CHECK( "current-result-store", entitled_store_create( nullptr, &store ) == S_OK );
    CHECK( "current-result-real-context-serial", entitled_store_identity( store, &xuid, &serial ) == S_OK );
    XStoreSku sku{};
    sku.skuId = "AB12";
    sku.isInUserCollection = TRUE;
    sku.collectionData.endDate = time( nullptr ) + 900;
    XStoreProduct product{};
    product.storeId = storeId;
    product.productKind = XStoreProductKind::Game;
    product.isInUserCollection = TRUE;
    product.skus = &sku;
    product.skusCount = 1;
    entitled_snapshot proof{};
    proof.products = &product;
    proof.count = 1;
    proof.proof_until = time( nullptr ) + 600;
    entitled_page page{};
    page.snapshot = &proof;
    entitled_async context{};
    context.game = TRUE;
    context.store = store;
    context.store_serial = serial;
    context.page = &page;
    XStoreGameLicense result{};
    XAsyncProviderData data{};
    data.context = &context;
    data.buffer = &result;
    data.bufferSize = 1;
    CHECK( "current-result-small-buffer-retains-payload",
           entitled_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG && context.page == &page );
    data.bufferSize = sizeof( result );
    CHECK( "current-result-corrected-buffer-actual-sku", entitled_provider( XAsyncOp::GetResult, &data ) == S_OK &&
                                                             result.isActive &&
                                                             !strcmp( result.skuStoreId, "B00000000001/AB12" ) );
    entitled_store_close( store );
    CHECK( "current-result-closed-context-refused", entitled_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG );
    CHECK( "current-result-replacement-store", entitled_store_create( nullptr, &other ) == S_OK );
    CHECK( "current-result-old-serial-never-rebound", entitled_provider( XAsyncOp::GetResult, &data ) == E_INVALIDARG );
    entitled_store_close( other );
}

struct immediate_license_observation
{
    IXThreadingImpl *threads;
    DWORD callback_thread;
    LONG callbacks;
    HRESULT status;
};
static void WINAPI immediate_license_completed(XAsyncBlock *block)
{
    auto *observation=static_cast<immediate_license_observation *>(block->context);
    observation->status=observation->threads->XAsyncGetStatus(block,FALSE);
    observation->callback_thread=GetCurrentThreadId();
    InterlockedIncrement(&observation->callbacks);
}
static DWORD WINAPI release_immediate_license_bridge(void *)
{
    if(WaitForSingleObject(bridge_started,2000)==WAIT_OBJECT_0) Sleep(20);
    SetEvent(bridge_gate);
    return 0;
}
static void test_immediate_license_work_stays_on_submitting_thread()
{
    IXThreadingImpl *threads=nullptr;
    XTaskQueueHandle queue=nullptr;
    XStoreContextHandle store=nullptr;
    CHECK("immediate-license-threading",FixtureQueryApiImpl(CLSID_XThreadingImpl,IID_IXThreadingImpl,(void **)&threads)==S_OK && threads);
    if(!threads)return;
    CHECK("immediate-license-queue",threads->XTaskQueueCreate(XTaskQueueDispatchMode::Immediate,XTaskQueueDispatchMode::Immediate,&queue)==S_OK);
    CHECK("immediate-license-store",entitled_store_create(nullptr,&store)==S_OK);
    immediate_license_observation observation{threads,0,0,E_PENDING};
    XAsyncBlock block{};block.queue=queue;block.context=&observation;block.callback=immediate_license_completed;
    ResetEvent(bridge_started);ResetEvent(bridge_gate);
    HANDLE release=CreateThread(nullptr,0,release_immediate_license_bridge,nullptr,0,nullptr);
    CHECK("immediate-license-release-thread",release!=nullptr);
    const DWORD caller=GetCurrentThreadId();
    CHECK("immediate-license-begin",entitled_begin(store,4,10,&block,TRUE)==S_OK);
    const LONG callbacks_on_return=InterlockedCompareExchange(&observation.callbacks,0,0);
    CHECK("immediate-license-completed-before-return",callbacks_on_return==1);
    CHECK("immediate-license-failure-status",threads->XAsyncGetStatus(&block,TRUE)==E_FAIL);
    CHECK("immediate-license-same-thread",observation.callback_thread==caller);
    CHECK("immediate-license-no-fabricated-grant",observation.status==E_FAIL && observation.callbacks==1);
    if(release){WaitForSingleObject(release,3000);CloseHandle(release);}
    entitled_store_close(store);threads->XTaskQueueCloseHandle(queue);threads->Release();
}

static void test_cancel_can_free_async_block_before_network_finishes()
{
    IXThreadingImpl *threads = nullptr;
    XTaskQueueHandle queue = nullptr;
    XStoreContextHandle store = nullptr;
    CHECK( "store-free-block-threading", FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl,
                                                              reinterpret_cast<void **>( &threads ) ) == S_OK &&
                                             threads );
    if ( !threads ) return;
    CHECK( "store-free-block-queue", threads->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
                                                                XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    CHECK( "store-free-block-store", entitled_store_create( nullptr, &store ) == S_OK );
    auto block = static_cast<XAsyncBlock *>(
        VirtualAlloc( nullptr, sizeof( XAsyncBlock ), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) );
    CHECK( "store-free-block-allocation", block != nullptr );
    if ( block )
    {
        LONG completions = 0;
        block->queue = queue;
        block->callback = store_lifetime_completion;
        block->context = &completions;
        ResetEvent( bridge_started );
        ResetEvent( bridge_gate );
        bridge_timeout = 30000;
        CHECK( "store-free-block-begin", entitled_begin( store, 31, 10, block ) == S_OK );
        CHECK( "store-free-block-work", threads->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
        CHECK( "store-free-block-network-pending",
               WaitForSingleObject( bridge_started, 2000 ) == WAIT_OBJECT_0 && bridge_active );
        threads->XAsyncCancel( block );
        CHECK( "store-free-block-terminal-abort", threads->XAsyncGetStatus( block, FALSE ) == E_ABORT );
        CHECK( "store-free-block-completion",
               threads->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 2000 ) && completions == 1 );
        CHECK( "store-free-block-release", VirtualFree( block, 0, MEM_RELEASE ) );
        // The network worker is still running, but may no longer touch this
        // freed caller block, invoke its callback or overwrite another result.
        SetEvent( bridge_gate );
        const auto start = GetTickCount64();
        while ( InterlockedCompareExchange( &entitled_worker_count, 0, 0 ) && GetTickCount64() - start < 5000 )
            Sleep( 1 );
        CHECK( "store-free-block-worker-drained",
               !InterlockedCompareExchange( &entitled_worker_count, 0, 0 ) && !bridge_active );
        CHECK( "store-free-block-no-second-callback",
               completions == 1 && !threads->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
        bridge_timeout = 1500;
    }
    entitled_store_close( store );
    if ( queue ) threads->XTaskQueueCloseHandle( queue );
    threads->Release();
}

static HRESULT catalog_fixture_fetch( const char *request, LONG *canceled, entitled_snapshot **out )
{
    *out = ( entitled_snapshot * )calloc( 1, sizeof( **out ) );
    if ( !*out ) return E_OUTOFMEMORY;
    (*out)->refs = 1;
    (*out)->valid_until = time( NULL ) + 60;
    return S_OK;
}

static void test_public_catalog_async()
{
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL;
    CHECK( "catalog-async-threading", FixtureQueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl,
        ( void ** )&threads ) == S_OK );
    if ( !threads ) return;
    CHECK( "catalog-async-queue", threads->XTaskQueueCreate( XTaskQueueDispatchMode::Manual,
        XTaskQueueDispatchMode::Manual, &queue ) == S_OK );
    if ( !queue ) { threads->Release(); return; }
    for ( UINT32 mode = 0; mode < 8; ++mode )
    {
        XStoreContextHandle store = NULL;
        UINT64 xuid, serial;
        CHECK( "catalog-async-context", entitled_store_create( NULL, &store ) == S_OK &&
            entitled_store_identity( store, &xuid, &serial ) == S_OK );
        entitled_async *context = ( entitled_async * )calloc( 1, sizeof( *context ) );
        context->store = store; context->store_serial = serial + ( mode % 4 == 2 );
        context->identity = mode < 4 ? &catalog_identity : &catalog_package_identity; context->fetch = catalog_fixture_fetch; context->page_size = 100;
        XAsyncBlock block{};
        block.queue = queue; block.callback = complete; callbacks = 0;
        CHECK( "catalog-async-begin", entitled_start( context, &block, FALSE ) == S_OK );
        if ( mode % 4 == 1 ) entitled_store_close( store );
        if ( mode % 4 == 3 ) threads->XAsyncCancel( &block );
        threads->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
        dispatch_until_complete( threads, queue, &block );
        CHECK( "catalog-async-completion-once", callbacks == 1 );
        XStoreProductQueryHandle handle = ( void * )1;
        if ( mode % 4 == 0 )
        {
            CHECK( "catalog-async-distinct-result-identity", entitled_result( &block, &handle, FALSE ) == E_INVALIDARG && !handle );
            if ( mode >= 4 ) CHECK( "catalog-package-distinct-result-identity", catalog_result( &block, &handle ) == E_INVALIDARG && !handle );
            CHECK( "catalog-async-public-result", catalog_result( &block, &handle,
                mode < 4 ? &catalog_identity : &catalog_package_identity ) == S_OK && handle );
            if ( handle )
            {
                enumerated = 0;
                CHECK( "catalog-async-enumerate-empty", entitled_enumerate( handle, NULL, enumerate ) == S_OK && !enumerated );
                CHECK( "catalog-async-no-pages", !entitled_has_more( handle ) );
                entitled_page_close( handle );
            }
        }
        else CHECK( "catalog-async-invalid-delivery-refused", FAILED( catalog_result( &block, &handle, mode < 4 ? &catalog_identity : &catalog_package_identity ) ) && !handle );
        if ( mode % 4 != 1 ) entitled_store_close( store );
    }
    ULONGLONG deadline = GetTickCount64() + 3000;
    while ( entitled_worker_count && GetTickCount64() < deadline ) Sleep( 1 );
    CHECK( "catalog-async-workers-drained", !entitled_worker_count );
    threads->XTaskQueueCloseHandle( queue ); threads->Release();
    callbacks = 0;
}

static const char catalog_fixture[] = R"json({"Products":[{
 "ProductId":"B00000000002","ProductType":"Durable","IsInUserCollection":true,"Properties":{"InAppOfferToken":"synthetic-offer"},
 "LocalizedProperties":[{"ProductTitle":"Public DLC","ProductDescription":"Public description","Language":"en-US",
 "Images":[{"Uri":"//store-images.s-microsoft.com/synthetic","Height":300,"Width":400,"Caption":null,"ImagePurpose":"BoxArt"}]}],
 "DisplaySkuAvailabilities":[{"Sku":{"SkuId":"0010","IsInUserCollection":true,"Properties":{"IsTrial":false,"Packages":[{}]}},
 "Availabilities":[{"AvailabilityId":"B00000000003","Actions":["Purchase","Browse","Details"],
 "Conditions":{"StartDate":"1753-01-01T00:00:00.0000000Z","EndDate":"9998-12-30T00:00:00.0000000Z",
 "ClientConditions":{"AllowedPlatforms":[{"PlatformName":"Windows.Desktop"}]}},
 "OrderManagementData":{"Price":{"CurrencyCode":"USD","ListPrice":7.99,"MSRP":14.99}}}]},
 {"Sku":{"SkuId":"0020","Properties":{"IsTrial":true}},"Availabilities":[]}]}]})json";

static void test_public_catalog()
{
    const char *ids[] = { "B00000000002" }, *purchase[] = { "Purchase" }, *license[] = { "License" };
    entitled_snapshot *snapshot = NULL;
    CHECK( "catalog-public-parse", catalog_parse( ( BYTE * )catalog_fixture, strlen( catalog_fixture ), ids, 1,
        31, NULL, 0, &snapshot ) == S_OK && snapshot && snapshot->count == 1 );
    if ( snapshot && snapshot->count )
    {
        XStoreProduct *p = &snapshot->products[0];
        CHECK( "catalog-never-license-proof", !snapshot->proof_until );
        CHECK( "catalog-unowned-product-not-granted", !p->isInUserCollection );
        CHECK( "catalog-unowned-skus-not-granted", p->skusCount == 2 && !p->skus[0].isInUserCollection &&
            !p->skus[1].isInUserCollection && !p->skus[0].collectionData.endDate );
        CHECK( "catalog-public-title-description", !strcmp( p->title, "Public DLC" ) && !strcmp( p->description, "Public description" ) );
        CHECK( "catalog-public-offer-token", !strcmp( p->inAppOfferToken, "synthetic-offer" ) );
        CHECK( "catalog-full-and-trial-skus", p->skusCount == 2 && !p->skus[0].isTrial && p->skus[1].isTrial );
        CHECK( "catalog-public-download", p->hasDigitalDownload );
        CHECK( "catalog-public-price", fabs( p->price.price - 7.99 ) < .001 && fabs( p->price.basePrice - 14.99 ) < .001 );
        CHECK( "catalog-price-currency-explicit", p->price.currencyCode && !strcmp( p->price.currencyCode, "USD" ) &&
            !strcmp( p->price.formattedPrice, "7.99 USD" ) );
        CHECK( "catalog-sale-date", p->price.isOnSale && p->price.saleEndDate > time( NULL ) );
        CHECK( "catalog-purchase-not-bundle-free", p->skus[0].availabilitiesCount == 1 &&
            fabs( p->skus[0].price.price - 7.99 ) < .001 && !p->skus[1].price.currencyCode );
        CHECK( "catalog-public-image", p->imagesCount == 1 && p->images[0].height == 300 && p->images[0].width == 400 &&
            !strcmp( p->images[0].uri, "https://store-images.s-microsoft.com/synthetic" ) && !strcmp( p->images[0].caption, "" ) );
        entitled_snapshot owned{};
        XStoreProduct owned_product{};
        XStoreSku owned_sku{};
        owned.count = 1; owned.products = &owned_product;
        owned.valid_until = time( NULL ) + 30;
        owned_product.storeId = "B00000000002"; owned_product.skusCount = 1; owned_product.skus = &owned_sku;
        owned_sku.skuId = "0010"; owned_sku.isInUserCollection = TRUE;
        owned_sku.collectionData.endDate = time( NULL ) + 3600;
        CHECK( "catalog-rejects-unverified-ownership", catalog_join_collection( snapshot, &owned ) == E_ACCESSDENIED && !p->isInUserCollection );
        owned.proof_until = time( NULL ) + 3600;
        owned_sku.skuId = "0030";
        CHECK( "catalog-no-different-sku-grant", catalog_join_collection( snapshot, &owned ) == S_OK && !p->isInUserCollection );
        owned_sku.skuId = "0010"; owned_product.storeId = "B00000000004";
        CHECK( "catalog-no-different-product-grant", catalog_join_collection( snapshot, &owned ) == S_OK && !p->isInUserCollection );
        owned_product.storeId = "B00000000002";
        CHECK( "catalog-verified-exact-sku-owned", catalog_join_collection( snapshot, &owned ) == S_OK && p->isInUserCollection &&
            p->skus[0].isInUserCollection && !p->skus[1].isInUserCollection );
        CHECK( "catalog-owned-expiry-bound", snapshot->valid_until == owned.valid_until &&
            p->skus[0].collectionData.endDate == owned_sku.collectionData.endDate && !snapshot->proof_until );
    }
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    CHECK( "catalog-kind-filter", catalog_parse( ( BYTE * )catalog_fixture, strlen( catalog_fixture ), ids, 1,
        4, NULL, 0, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    CHECK( "catalog-action-purchase", catalog_parse( ( BYTE * )catalog_fixture, strlen( catalog_fixture ), ids, 1,
        2, purchase, 1, &snapshot ) == S_OK && snapshot && snapshot->count == 1 );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    CHECK( "catalog-action-missing", catalog_parse( ( BYTE * )catalog_fixture, strlen( catalog_fixture ), ids, 1,
        2, license, 1, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    const char *foreign[] = { "B00000000099" };
    CHECK( "catalog-rejects-foreign-response", FAILED( catalog_parse( ( BYTE * )catalog_fixture, strlen( catalog_fixture ),
        foreign, 1, 31, NULL, 0, &snapshot ) ) && !snapshot );
    CHECK( "catalog-rejects-malformed", FAILED( catalog_parse( ( BYTE * )"{}", 2, ids, 1, 31, NULL, 0, &snapshot ) ) && !snapshot );
    CHECK( "catalog-empty-response", catalog_parse( ( BYTE * )"{\"Products\":[]}", 15, ids, 1, 31, NULL, 0, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    char *changed = strdup( catalog_fixture );
    memcpy( strstr( changed, "7.99" ), "-1.0", 4 );
    CHECK( "catalog-rejects-negative-price", FAILED( catalog_parse( ( BYTE * )changed, strlen( changed ), ids, 1, 31, NULL, 0, &snapshot ) ) && !snapshot );
    free( changed );
    changed = strdup( catalog_fixture );
    memcpy( strstr( changed, "Windows.Desktop" ), "Windows.Xbox   ", 15 );
    CHECK( "catalog-excludes-console-offer", catalog_parse( ( BYTE * )changed, strlen( changed ), ids, 1, 2,
        purchase, 1, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    free( changed );
    std::string conditional = catalog_fixture;
    conditional.insert( conditional.find( "\"Conditions\":{" ) + strlen( "\"Conditions\":{" ),
        "\"EligibilityPredicateIds\":[\"RequiresSubscription\"]," );
    CHECK( "catalog-account-conditional-price-not-advertised", catalog_parse( ( BYTE * )conditional.data(),
        conditional.size(), ids, 1, 2, purchase, 1, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    std::string fractional = catalog_fixture;
    fractional.replace( fractional.find( "7.99" ), 4, "7.999" );
    CHECK( "catalog-preserves-fractional-price", catalog_parse( ( BYTE * )fractional.data(), fractional.size(), ids,
        1, 2, NULL, 0, &snapshot ) == S_OK && snapshot && snapshot->count == 1 &&
        fabs( snapshot->products[0].price.price - 7.999 ) < .00001 &&
        !strcmp( snapshot->products[0].price.formattedPrice, "7.999 USD" ) );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    std::string expired = catalog_fixture;
    expired.replace( expired.find( "9998-12-30" ), 10, "2000-01-01" );
    CHECK( "catalog-expired-offer-filtered", catalog_parse( ( BYTE * )expired.data(), expired.size(), ids, 1,
        2, purchase, 1, &snapshot ) == S_OK && snapshot && !snapshot->count );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    CHECK( "catalog-delisted-listing-retained", catalog_parse( ( BYTE * )expired.data(), expired.size(), ids, 1,
        2, NULL, 0, &snapshot ) == S_OK && snapshot && snapshot->count == 1 &&
        !snapshot->products[0].skus[0].availabilitiesCount && !snapshot->products[0].isInUserCollection );
    if ( snapshot ) entitled_snapshot_release( snapshot ); snapshot = NULL;
    XStoreContextHandle store = NULL;
    XAsyncBlock async{};
    CHECK( "catalog-context", entitled_store_create( NULL, &store ) == S_OK );
    const char *bad_filter[] = { "Purchase&evil=1" };
    CHECK( "catalog-rejects-action-injection", catalog_begin( store, 31, ids, 1, bad_filter, 1, &async ) == E_INVALIDARG );
    CHECK( "catalog-rejects-null-action", catalog_begin( store, 31, ids, 1, foreign, 1, &async ) == E_INVALIDARG );
    CHECK( "catalog-package-foreign-identifier", catalog_package_begin( store, 31, "foreign-package", &async ) == E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
    CHECK( "catalog-package-null-async", catalog_package_begin( store, 31, "00000001111122223333444444444444", NULL ) == E_INVALIDARG );
    entitled_store_close( store );
}

int main( int argc, char **argv )
{
    test_store_time_abi();
    if ( argc == 2 && !strcmp( argv[1], "--store-time-abi" ) )
    {
        const auto status = RoInitialize( RO_INIT_MULTITHREADED );
        CHECK( "store-time-mode-winrt", SUCCEEDED( status ) );
        if ( SUCCEEDED( status ) ) { test_store_time_consumers(); RoUninitialize(); }
        printf( "CHECKS %u FAILURES %u\n", checks, failures );
        return failures ? 1 : 0;
    }
    if ( argc == 2 && !strcmp( argv[1], "--certificate-stage" ) ) certificate_stage_only = true;
    if ( argc == 2 && ( !strcmp( argv[1], "--metadata-stage" ) || certificate_stage_only ) )
    {
        const auto hr = RoInitialize( RO_INIT_MULTITHREADED );
        CHECK( "metadata-stage-winrt", SUCCEEDED( hr ) );
        if ( SUCCEEDED( hr ) ) { test_receipts(); RoUninitialize(); }
        printf( "CHECKS %u FAILURES %u\n", checks, failures );
        return failures ? 1 : 0;
    }
    HMODULE dll = LoadLibraryA( "xgameruntime.dll" );
    if ( !dll ||
         !( runtime_query = reinterpret_cast<decltype( runtime_query )>( GetProcAddress( dll, "QueryApiImpl" ) ) ) )
        return 2;
    HRESULT hr = RoInitialize( RO_INIT_MULTITHREADED );
    CHECK( "winrt", SUCCEEDED( hr ) );
    if ( SUCCEEDED( hr ) ) test_store_time_consumers();
    IXStoreImpl6 *store_api = NULL;
    XStoreContextHandle store = NULL;
    CHECK( "runtime-store-abi",
           runtime_query( CLSID_XStoreImpl, IID_IXStoreImpl6, ( void ** )&store_api ) == S_OK && store_api );
    if ( store_api )
    {
        CHECK( "runtime-create-store-context", ( store_api )->XStoreCreateContext( NULL, &store ) == S_OK && store );
        IXThreadingImpl *threads = NULL;
        XTaskQueueHandle queue = NULL;
        XTaskQueueRegistrationToken game_token = { 0 };
        struct game_test_context context = { 0 };
        CHECK( "runtime-game-threading",
               runtime_query( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads ) == S_OK && threads );
        if ( threads )
        {
            CHECK( "runtime-game-queue",
                   ( threads )->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual,
                                                  &queue ) == S_OK );
            CHECK(
                "runtime-game-register-implemented",
                ( store_api )->XStoreRegisterGameLicenseChanged( store, queue, &context, game_changed, &game_token ) ==
                        S_OK &&
                    game_token.token );
            CHECK( "runtime-game-no-initial-event",
                   !( threads )->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) && !context.calls );
            ( threads )->XTaskQueueCloseHandle( queue ); /* Subscription owns a duplicate. */
            CHECK( "runtime-game-unregister",
                   ( store_api )->XStoreUnregisterGameLicenseChanged( store, game_token, TRUE ) );
            game_token.token = 123;
            CHECK( "runtime-game-invalid-context",
                   ( store_api )
                               ->XStoreRegisterGameLicenseChanged( ( void * )1, NULL, &context, game_changed,
                                                                   &game_token ) == E_INVALIDARG &&
                       !game_token.token );
            game_token.token = 123;
            CHECK( "runtime-game-null-callback",
                   ( store_api )->XStoreRegisterGameLicenseChanged( store, NULL, NULL, NULL, &game_token ) ==
                           E_POINTER &&
                       !game_token.token );
            CHECK( "runtime-game-register-close",
                   ( store_api )->XStoreRegisterGameLicenseChanged( store, NULL, NULL, game_changed, &game_token ) ==
                       S_OK );
            // No queue can run a request in this negative handle test. The
            // bridge-body builder is local XML only, even on the old code.
            XTaskQueueHandle previousQueue = nullptr;
            const auto hadQueue = threads->XTaskQueueGetCurrentProcessTaskQueue( &previousQueue );
            threads->XTaskQueueSetCurrentProcessTaskQueue( nullptr );
            XAsyncBlock invalidToken{};
            const char *ids[] = { "B00000000001" };
            CHECK( "runtime-token-rejects-foreign-store-context",
                   store_api->XStoreQueryLicenseTokenAsync( ( void * )1, ids, 1, "synthetic-negative-context",
                                                            &invalidToken ) == E_INVALIDARG );
            if ( hadQueue )
            {
                threads->XTaskQueueSetCurrentProcessTaskQueue( previousQueue );
                threads->XTaskQueueCloseHandle( previousQueue );
            }
            ( threads )->Release();
        }
        XAsyncBlock public_query = { 0 };
        const char *public_ids[] = { "B00000000002" };
        const char *bad_ids[] = { "bad/id" };
        CHECK( "runtime-public-invalid-context", store_api->XStoreQueryProductsAsync( ( void * )1,
            XStoreProductKind::Durable, public_ids, 1, NULL, 0, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-invalid-kind", store_api->XStoreQueryProductsAsync( store,
            ( XStoreProductKind )32, public_ids, 1, NULL, 0, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-empty-ids", store_api->XStoreQueryProductsAsync( store,
            XStoreProductKind::Durable, NULL, 0, NULL, 0, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-invalid-id", store_api->XStoreQueryProductsAsync( store,
            XStoreProductKind::Durable, bad_ids, 1, NULL, 0, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-over-limit", store_api->XStoreQueryProductsAsync( store,
            XStoreProductKind::Durable, public_ids, 101, NULL, 0, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-null-filters", store_api->XStoreQueryProductsAsync( store,
            XStoreProductKind::Durable, public_ids, 1, NULL, 1, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-null-result", store_api->XStoreQueryProductsResult( NULL, NULL ) == E_INVALIDARG );
        XStoreProductQueryHandle public_result = ( void * )1;
        CHECK( "runtime-public-clears-result", store_api->XStoreQueryProductsResult( &public_query,
            &public_result ) != S_OK && !public_result );
        CHECK( "runtime-public-package-invalid-context", store_api->XStoreQueryProductForPackageAsync( ( void * )1,
            XStoreProductKind::Durable, "00000001111122223333444444444444", &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-package-invalid-kind", store_api->XStoreQueryProductForPackageAsync( store,
            ( XStoreProductKind )32, "00000001111122223333444444444444", &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-package-null-identifier", store_api->XStoreQueryProductForPackageAsync( store,
            XStoreProductKind::Durable, NULL, &public_query ) == E_INVALIDARG );
        CHECK( "runtime-public-package-null-result", store_api->XStoreQueryProductForPackageResult( NULL, NULL ) == E_INVALIDARG );
        public_result = ( void * )1;
        CHECK( "runtime-public-package-clears-result", store_api->XStoreQueryProductForPackageResult( &public_query,
            &public_result ) == E_INVALIDARG && !public_result );
        XAsyncBlock invalid_license = { 0 };
        CHECK( "runtime-current-game-invalid-context",
               store_api->XStoreQueryGameLicenseAsync( ( void * )1, &invalid_license ) == E_INVALIDARG );
        CHECK( "runtime-current-game-no-missing-config-grant",
               store_api->XStoreQueryGameLicenseAsync( store, &invalid_license ) == E_GAME_MISSING_GAME_CONFIG );
        CHECK( "runtime-license-invalid-context",
               ( store_api )
                       ->XStoreAcquireLicenseForPackageAsync( ( void * )1, "00000001111122223333444444444444",
                                                              &invalid_license ) == E_INVALIDARG );
        CHECK( "runtime-durable-invalid-context",
               ( store_api )->XStoreAcquireLicenseForDurablesAsync( ( void * )1, "B00000000002", &invalid_license ) ==
                   E_INVALIDARG );
        CHECK( "runtime-durable-null-result",
               ( store_api )->XStoreAcquireLicenseForDurablesResult( NULL, NULL ) == E_INVALIDARG );
        CHECK( "runtime-addon-invalid-context",
               ( store_api )->XStoreQueryAddOnLicensesAsync( ( void * )1, &invalid_license ) == E_INVALIDARG );
        CHECK( "runtime-addon-null-count",
               ( store_api )->XStoreQueryAddOnLicensesResultCount( NULL, NULL ) == E_INVALIDARG );
        CHECK( "runtime-addon-invalid-result",
               ( store_api )->XStoreQueryAddOnLicensesResult( NULL, 0, NULL ) == E_INVALIDARG );
        CHECK( "runtime-license-invalid-handle", !( store_api )->XStoreIsLicenseValid( ( void * )1 ) );
        ( store_api )->XStoreCloseLicenseHandle( ( void * )1 );
        ( store_api )->XStoreCloseContextHandle( store );
        HRESULT query_hr = ( store_api )->XStoreEnumerateProductsQuery( ( void * )1, NULL, enumerate );
        printf( "STORE_ABI invalid_handle_hr=%08lx\n", query_hr );
        CHECK( "runtime-invalid-query-handle", query_hr == E_INVALIDARG );
        ( store_api )->Release();
    }
    bridge_started = CreateEventA( NULL, TRUE, FALSE, NULL );
    bridge_gate = CreateEventA( NULL, TRUE, FALSE, NULL );
    test_current_game_license();
    test_public_catalog();
    test_public_catalog_async();
    test_related_hints();
    test_receipts();
    test_async( test_metadata() );
    test_package_licenses();
    test_package_result_context();
    test_durable_acquisition();
    test_addon_licenses();
    test_game_licenses();
    test_current_game_result_lifetime();
    test_immediate_license_work_stays_on_submitting_thread();
    test_cancel_can_free_async_block_before_network_finishes();
    CloseHandle( bridge_started );
    CloseHandle( bridge_gate );
    if ( SUCCEEDED( hr ) ) RoUninitialize();
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
