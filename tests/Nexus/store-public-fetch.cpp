// SPDX-License-Identifier: MIT
#include "../../src/System/Store/PublicMetadata.h"
#include <stdio.h>
#include <string.h>
#include <initializer_list>

using namespace nexus::store;
static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; printf("FAIL line=%u\n", __LINE__); } } while (0)

static void policy_tests()
{
    for ( const DWORD error : { ERROR_WINHTTP_TIMEOUT, ERROR_WINHTTP_NAME_NOT_RESOLVED, ERROR_WINHTTP_CANNOT_CONNECT,
                                ERROR_WINHTTP_CONNECTION_ERROR, ERROR_WINHTTP_RESEND_REQUEST,
                                WSAETIMEDOUT, WSAECONNRESET, WSAECONNABORTED, WSAENETRESET, WSAEHOSTUNREACH,
                                WSAENETUNREACH, WSAECONNREFUSED } )
    {
        unsigned calls = 0, waits = 0;
        ULONGLONG clock = 0;
        const auto hr = PublicFetchWithRetry( [&] {
            return ++calls == 1 ? PublicFetchResult{ HRESULT_FROM_WIN32( error ), 0, error, 0 }
                                : PublicFetchResult{ S_OK };
        }, [&] { return clock; }, [&]( DWORD delay ) { clock += delay; ++waits; } );
        CHECK( hr == S_OK ); CHECK( calls == 2 ); CHECK( waits == 1 ); CHECK( clock == 250 );
    }
    for ( const DWORD status : { 408, 429, 500, 502, 503, 504 } )
    {
        unsigned calls = 0;
        const auto hr = PublicFetchWithRetry( [&] {
            return ++calls == 1 ? PublicFetchResult{ E_FAIL, status } : PublicFetchResult{ S_OK };
        }, [] { return ULONGLONG( 0 ); }, []( DWORD ) {} );
        CHECK( hr == S_OK ); CHECK( calls == 2 );
    }
    for ( const auto result : { PublicFetchResult{ E_FAIL, 401 }, PublicFetchResult{ E_FAIL, 403 },
                                PublicFetchResult{ E_FAIL, 404 }, PublicFetchResult{ E_FAIL, 200 },
                                PublicFetchResult{ E_OUTOFMEMORY }, PublicFetchResult{ E_ABORT },
                                PublicFetchResult{ HRESULT_FROM_WIN32( ERROR_WINHTTP_SECURE_FAILURE ), 503,
                                                   ERROR_WINHTTP_SECURE_FAILURE },
                                PublicFetchResult{ HRESULT_FROM_WIN32( ERROR_WINHTTP_OPERATION_CANCELLED ), 0,
                                                   ERROR_WINHTTP_OPERATION_CANCELLED } } )
    {
        unsigned calls = 0, waits = 0;
        const auto hr = PublicFetchWithRetry( [&] { ++calls; return result; }, [] { return ULONGLONG( 0 ); },
                                              [&]( DWORD ) { ++waits; } );
        CHECK( hr == result.hr ); CHECK( calls == 1 ); CHECK( waits == 0 );
    }
    {
        unsigned calls = 0;
        ULONGLONG clock = 0;
        const auto hr = PublicFetchWithRetry( [&] { ++calls; return PublicFetchResult{ E_FAIL, 503 }; },
                                              [&] { return clock; }, [&]( DWORD delay ) { clock += delay; } );
        CHECK( FAILED( hr ) ); CHECK( calls == 3 ); CHECK( clock == 750 );
    }
    for ( const ULONGLONG delay : { ULONGLONG( 120000 ), ~ULONGLONG( 0 ) } )
    {
        unsigned calls = 0;
        const auto hr = PublicFetchWithRetry( [&] { ++calls; return PublicFetchResult{ E_FAIL, 429, 0, delay }; },
                                              [] { return ULONGLONG( 0 ); }, []( DWORD ) { CHECK( false ); } );
        CHECK( FAILED( hr ) ); CHECK( calls == 1 );
    }
    {
        ULONGLONG clock = 0;
        unsigned calls = 0;
        const auto hr = PublicFetchWithRetry( [&] { ++calls; clock = 29900; return PublicFetchResult{ E_FAIL, 503 }; },
                                              [&] { return clock; }, []( DWORD ) { CHECK( false ); } );
        CHECK( FAILED( hr ) ); CHECK( calls == 1 );
    }
    {
        ULONGLONG clock = 0;
        unsigned calls = 0;
        const auto hr = PublicFetchWithRetry( [&] {
            return ++calls == 1 ? PublicFetchResult{ E_FAIL, 503, 0, 750 } : PublicFetchResult{ S_OK };
        }, [&] { return clock; }, [&]( DWORD delay ) { clock += delay; } );
        CHECK( hr == S_OK ); CHECK( clock == 750 );
    }
    BYTE *bytes = reinterpret_cast<BYTE *>( 1 ); SIZE_T size = 100;
    CHECK( FetchPublicMetadata( L"not-a-store.example.invalid", L"/", 1024, &bytes, &size ) == E_INVALIDARG );
    CHECK( bytes == nullptr ); CHECK( size == 0 );
}

static void transport_test( INTERNET_PORT port, const WCHAR *path, unsigned expectedCalls, bool success,
                            SIZE_T limit = 1024 )
{
    unsigned calls = 0;
    BYTE *bytes = nullptr;
    SIZE_T size = 0;
    const auto hr = PublicFetchWithRetry( [&] {
        ++calls;
        auto result = PublicFetchOnce( L"localhost", path, limit, &bytes, &size, port );
        printf( "ATTEMPT path=%ls http=%lu error=%lu hr=%08lx\n", path, result.status, result.error,
                static_cast<unsigned long>( result.hr ) );
        if ( FAILED( result.hr ) ) { CHECK( bytes == nullptr ); CHECK( size == 0 ); }
        return result;
    }, [] { return GetTickCount64(); }, []( DWORD delay ) { Sleep( delay ); } );
    printf( "FETCH path=%ls calls=%u hr=%08lx bytes=%llu\n", path, calls,
            static_cast<unsigned long>( hr ), static_cast<unsigned long long>( size ) );
    CHECK( calls == expectedCalls ); CHECK( !!SUCCEEDED( hr ) == success );
    if ( success ) { CHECK( size == 2 ); CHECK( bytes && !memcmp( bytes, "{}", 2 ) ); }
    free( bytes );
}

int main( int argc, char **argv )
{
    policy_tests();
    if ( argc == 3 )
    {
        const auto port = static_cast<INTERNET_PORT>( atoi( argv[1] ) );
        transport_test( port, L"/retry", 2, true );
        transport_test( port, L"/missing", 1, false );
        transport_test( port, L"/after", 1, false );
        transport_test( port, L"/after-date", 1, false );
        transport_test( port, L"/after-invalid", 1, false );
        transport_test( port, L"/empty", 1, false );
        transport_test( port, L"/oversize", 1, false, 8 );
        transport_test( port, L"/redirect", 1, false );
        transport_test( port, L"/partial", 2, true );
        transport_test( static_cast<INTERNET_PORT>( atoi( argv[2] ) ), L"/untrusted", 1, false );
    }
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
