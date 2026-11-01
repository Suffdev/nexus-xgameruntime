/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <wchar.h>

namespace nexus::store
{
struct PublicFetchResult
{
    HRESULT hr = E_FAIL;
    DWORD status = 0;
    DWORD error = 0;
    ULONGLONG retryAfterMilliseconds = 0;
};

inline bool RetryPublicFetch( const PublicFetchResult &result )
{
    if ( SUCCEEDED( result.hr ) ) return false;
    if ( result.error )
        return result.error == ERROR_WINHTTP_TIMEOUT || result.error == ERROR_WINHTTP_NAME_NOT_RESOLVED ||
               result.error == ERROR_WINHTTP_CANNOT_CONNECT || result.error == ERROR_WINHTTP_CONNECTION_ERROR ||
               result.error == ERROR_WINHTTP_RESEND_REQUEST ||
               /* Wine can surface the underlying Winsock error while reading
                * an already-started HTTPS response. These are still transient
                * transport failures, never certificate or cancellation errors. */
               result.error == WSAETIMEDOUT || result.error == WSAECONNRESET ||
               result.error == WSAECONNABORTED || result.error == WSAENETRESET ||
               result.error == WSAEHOSTUNREACH || result.error == WSAENETUNREACH ||
               result.error == WSAECONNREFUSED;
    return result.status == 408 || result.status == 429 || result.status == 500 || result.status == 502 ||
           result.status == 503 || result.status == 504;
}

template <typename Attempt, typename Clock, typename Wait>
HRESULT PublicFetchWithRetry( Attempt attempt, Clock clock, Wait wait )
{
    const ULONGLONG start = clock();
    for ( unsigned number = 0;; ++number )
    {
        const auto result = attempt();
        if ( !RetryPublicFetch( result ) || number == 2 ) return result.hr;
        const ULONGLONG elapsed = clock() - start;
        const ULONGLONG backoff = 250u << number;
        const ULONGLONG delay = result.retryAfterMilliseconds > backoff ? result.retryAfterMilliseconds : backoff;
        /* Bound retries, including Retry-After. Each attempt keeps its normal
         * transport timeouts; a deadline never changes a failure to success. */
        if ( elapsed >= 30000 || delay >= 30000 - elapsed ) return result.hr;
        wait( static_cast<DWORD>( delay ) );
    }
}

inline ULONGLONG PublicRetryAfter( HINTERNET request )
{
    WCHAR value[64];
    DWORD length = sizeof( value );
    ULONGLONG seconds = 0;
    bool digits = true;
    if ( !WinHttpQueryHeaders( request, WINHTTP_QUERY_CUSTOM, L"Retry-After", value, &length, NULL ) )
        return GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND ? 0 : ~ULONGLONG( 0 );
    if ( !value[0] ) return ~ULONGLONG( 0 );
    for ( unsigned i = 0; value[i]; ++i )
    {
        if ( value[i] < '0' || value[i] > '9' ) { digits = false; break; }
        if ( seconds > 86400 ) return ~ULONGLONG( 0 );
        seconds = seconds * 10 + value[i] - '0';
    }
    if ( digits ) return seconds * 1000;
    /* Some Wine versions accept arbitrary text in WinHttpTimeToSystemTime.
     * Validate the wire grammar before treating an HTTP date as a retry hint. */
    if ( wcslen( value ) != 29 || value[3] != ',' || value[4] != ' ' || value[7] != ' ' ||
         value[11] != ' ' || value[16] != ' ' || value[19] != ':' || value[22] != ':' ||
         value[25] != ' ' || wcsncmp( value + 26, L"GMT", 3 ) ) return ~ULONGLONG( 0 );
    static constexpr unsigned positions[] = { 5, 6, 12, 13, 14, 15, 17, 18, 20, 21, 23, 24 };
    for ( auto position : positions )
        if ( value[position] < '0' || value[position] > '9' ) return ~ULONGLONG( 0 );
    static constexpr WCHAR weekdays[][4] = { L"Sun", L"Mon", L"Tue", L"Wed", L"Thu", L"Fri", L"Sat" };
    static constexpr WCHAR months[][4] = { L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun",
                                           L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec" };
    bool weekday = false, month = false;
    for ( const auto &name : weekdays ) if ( !wcsncmp( value, name, 3 ) ) weekday = true;
    for ( const auto &name : months ) if ( !wcsncmp( value + 8, name, 3 ) ) month = true;
    if ( !weekday || !month ) return ~ULONGLONG( 0 );
    SYSTEMTIME date{};
    FILETIME target{}, now{};
    ULARGE_INTEGER targetTicks{}, nowTicks{};
    if ( !WinHttpTimeToSystemTime( value, &date ) || !SystemTimeToFileTime( &date, &target ) )
        return ~ULONGLONG( 0 );
    GetSystemTimeAsFileTime( &now );
    targetTicks.LowPart = target.dwLowDateTime; targetTicks.HighPart = target.dwHighDateTime;
    nowTicks.LowPart = now.dwLowDateTime; nowTicks.HighPart = now.dwHighDateTime;
    return targetTicks.QuadPart > nowTicks.QuadPart ? ( targetTicks.QuadPart - nowTicks.QuadPart ) / 10000 : 0;
}

/* Anonymous HTTPS only. The receipt caller restricts hosts to Microsoft's
 * catalog/certificate services. A fresh request never reuses partial data. */
inline PublicFetchResult PublicFetchOnce( const WCHAR *host, const WCHAR *path, SIZE_T limit, BYTE **out,
                                         SIZE_T *length, INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT )
{
    PublicFetchResult result;
    HINTERNET session = NULL, connection = NULL, request = NULL;
    DWORD size = sizeof( result.status ), available, read, redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    BYTE *buffer = NULL, *grown;
    const ULONGLONG start = GetTickCount64();
    *out = NULL;
    *length = 0;
    if ( !( session = WinHttpOpen( L"Xodus-Nexus-runtime/1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0 ) ) ||
         !WinHttpSetTimeouts( session, 5000, 5000, 10000, 10000 ) ||
         !( connection = WinHttpConnect( session, host, port, 0 ) ) ||
         !( request = WinHttpOpenRequest( connection, L"GET", path, NULL, NULL, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE ) ) ||
         !WinHttpSetOption( request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof( redirect ) ) ||
         !WinHttpSendRequest( request, NULL, 0, NULL, 0, 0, 0 ) || !WinHttpReceiveResponse( request, NULL ) ||
         !WinHttpQueryHeaders( request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL,
                               &result.status, &size, NULL ) )
        goto transport_error;
    if ( result.status != 200 )
    {
        result.hr = HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE );
        if ( RetryPublicFetch( result ) ) result.retryAfterMilliseconds = PublicRetryAfter( request );
        goto done;
    }
    for (;;)
    {
        if ( GetTickCount64() - start > 20000 )
        {
            result.error = ERROR_WINHTTP_TIMEOUT;
            result.hr = HRESULT_FROM_WIN32( result.error );
            goto done;
        }
        if ( !WinHttpQueryDataAvailable( request, &available ) ) goto transport_error;
        if ( !available ) break;
        if ( available > limit || *length > limit - available )
        {
            result.hr = HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
            goto done;
        }
        if ( !( grown = static_cast<BYTE *>( realloc( buffer, *length + available + 1 ) ) ) )
        {
            result.hr = E_OUTOFMEMORY;
            goto done;
        }
        buffer = grown;
        if ( !WinHttpReadData( request, buffer + *length, available, &read ) ) goto transport_error;
        if ( !read )
        {
            result.error = ERROR_WINHTTP_CONNECTION_ERROR;
            result.hr = HRESULT_FROM_WIN32( result.error );
            goto done;
        }
        *length += read;
        buffer[*length] = 0;
    }
    if ( !*length )
    {
        result.hr = HRESULT_FROM_WIN32( ERROR_WINHTTP_INVALID_SERVER_RESPONSE );
        goto done;
    }
    *out = buffer;
    buffer = NULL;
    result.hr = S_OK;
    goto done;
transport_error:
    result.error = GetLastError();
    if ( !result.error ) result.error = ERROR_WINHTTP_INTERNAL_ERROR;
    result.hr = HRESULT_FROM_WIN32( result.error );
done:
    free( buffer );
    if ( request ) WinHttpCloseHandle( request );
    if ( connection ) WinHttpCloseHandle( connection );
    if ( session ) WinHttpCloseHandle( session );
    if ( FAILED( result.hr ) ) *length = 0;
    return result;
}

inline HRESULT FetchPublicMetadata( const WCHAR *host, const WCHAR *path, SIZE_T limit, BYTE **out, SIZE_T *length )
{
    *out = NULL;
    *length = 0;
    if ( wcscmp( host, L"licensing.mp.microsoft.com" ) && wcscmp( host, L"displaycatalog.mp.microsoft.com" ) )
        return E_INVALIDARG;
    return PublicFetchWithRetry( [&] { return PublicFetchOnce( host, path, limit, out, length ); },
                                 [] { return GetTickCount64(); }, []( DWORD delay ) { Sleep( delay ); } );
}
}
