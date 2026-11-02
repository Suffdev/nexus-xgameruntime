// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright 2026 Olivia Ryan
#pragma once
#include <afunix.h>
#include <atomic>

static WCHAR *WineGetDosFileName( const char *path )
{
    using Convert = WCHAR *( CDECL * )( const char * );
    auto module = GetModuleHandleW( L"kernel32.dll" );
    auto convert = module ? reinterpret_cast<Convert>( GetProcAddress( module, "wine_get_dos_file_name" ) ) : nullptr;
    return convert ? convert( path ) : nullptr;
}

#define XODUS_XML_MAGIC 0x58445358
#define XODUS_MSA_TOKEN_REQUEST 3

static HRESULT xodus_socket_path( char *path, SIZE_T size )
{
    char unixPath[MAX_PATH];
    WCHAR *dosPath;
    DWORD len;

    if ( !( len = GetEnvironmentVariableA( "XODUS_SOCKET", unixPath, sizeof( unixPath ) ) ) ||
         len >= sizeof( unixPath ) )
    {
        if ( !( len = GetEnvironmentVariableA( "WINE_HOST_XDG_RUNTIME_DIR", unixPath, sizeof( unixPath ) ) ) ||
             len >= sizeof( unixPath ) )
            len = GetEnvironmentVariableA( "XDG_RUNTIME_DIR", unixPath, sizeof( unixPath ) );
        if ( !len || len + strlen( "/xodus.sock" ) >= sizeof( unixPath ) )
            return HRESULT_FROM_WIN32( ERROR_ENVVAR_NOT_FOUND );
        strcat( unixPath, "/xodus.sock" );
    }

    if ( !( dosPath = WineGetDosFileName( unixPath ) ) ) return HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND );
    len = WideCharToMultiByte( CP_ACP, 0, dosPath, -1, path, size, NULL, NULL );
    HeapFree( GetProcessHeap(), 0, dosPath );
    return len ? S_OK : HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
}

// One monotonic budget spans connection, bridge key, request, header and body.
// Nonblocking I/O is necessary: readiness alone cannot bound a large send on
// a blocking socket, and per-recv timeouts restart on every partial response.
class backend_deadline
{
    ULONGLONG started = GetTickCount64();
    DWORD budget;
    const std::atomic<bool> *cancel;
public:
    explicit backend_deadline( DWORD milliseconds, const std::atomic<bool> *cancellation = nullptr )
        : budget( milliseconds ), cancel( cancellation ) {}
    BOOL canceled() const { return cancel && cancel->load( std::memory_order_acquire ); }
    BOOL wait( SOCKET socket, bool writing, bool connecting = false ) const
    {
        for ( ;; )
        {
            if ( canceled() ) { WSASetLastError( WSA_OPERATION_ABORTED ); return FALSE; }
            ULONGLONG elapsed = GetTickCount64() - started;
            if ( elapsed >= budget ) { WSASetLastError( WSAETIMEDOUT ); return FALSE; }
            DWORD remaining = budget - static_cast<DWORD>( elapsed );
            // A request-local view, retained by its worker, interrupts readiness
            // without cross-thread socket closure or restarting the total budget.
            if ( cancel && remaining > 50 ) remaining = 50;
            timeval timeout = { static_cast<long>( remaining / 1000 ), static_cast<long>( remaining % 1000 * 1000 ) };
            fd_set ready, errors;
            FD_ZERO( &ready ); FD_SET( socket, &ready );
            FD_ZERO( &errors ); FD_SET( socket, &errors );
            int result = select( 0, writing ? NULL : &ready, writing ? &ready : NULL,
                                 connecting ? &errors : NULL, &timeout );
            if ( result == SOCKET_ERROR )
            {
                if ( WSAGetLastError() == WSAEINTR ) continue;
                return FALSE;
            }
            if ( !result )
            {
                if ( cancel ) continue;
                WSASetLastError( WSAETIMEDOUT ); return FALSE;
            }
            if ( canceled() ) { WSASetLastError( WSA_OPERATION_ABORTED ); return FALSE; }
            if ( connecting )
            {
                int error = 0, length = sizeof( error );
                if ( getsockopt( socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>( &error ), &length ) ) return FALSE;
                if ( !error && FD_ISSET( socket, &errors ) ) error = WSAECONNABORTED;
                if ( error ) { WSASetLastError( error ); return FALSE; }
            }
            return TRUE;
        }
    }
};

static BOOL xodus_connect( SOCKET socket, const sockaddr *address, int size, const backend_deadline &deadline )
{
    u_long nonblocking = 1;
    if ( ioctlsocket( socket, FIONBIO, &nonblocking ) ) return FALSE;
    if ( deadline.canceled() ) { WSASetLastError( WSA_OPERATION_ABORTED ); return FALSE; }
    if ( !connect( socket, address, size ) ) return TRUE;
    int error = WSAGetLastError();
    if ( error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEALREADY ) return FALSE;
    return deadline.wait( socket, true, true );
}

static BOOL xodus_send( SOCKET socket, const char *data, int size, const backend_deadline &deadline )
{
    while ( size > 0 )
    {
        if ( !deadline.wait( socket, true ) ) return FALSE;
        int sent = send( socket, data, size, 0 );
        if ( sent == SOCKET_ERROR && ( WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR ) ) continue;
        if ( sent <= 0 ) { if ( !sent ) WSASetLastError( WSAECONNABORTED ); return FALSE; }
        data += sent;
        size -= sent;
    }
    return TRUE;
}

static BOOL xodus_recv( SOCKET socket, char *data, int size, const backend_deadline &deadline )
{
    while ( size > 0 )
    {
        if ( !deadline.wait( socket, false ) ) return FALSE;
        int received = recv( socket, data, size, 0 );
        if ( received == SOCKET_ERROR && ( WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR ) ) continue;
        if ( received <= 0 ) { if ( !received ) WSASetLastError( WSAECONNABORTED ); return FALSE; }
        data += received;
        size -= received;
    }
    return TRUE;
}

static HRESULT xodus_request( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *responseSize, DWORD timeoutMilliseconds = 95000,
                               const std::atomic<bool> *cancellation = nullptr )
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    UINT32 magic = XODUS_XML_MAGIC;
    struct sockaddr_in bridge = { 0 };
    UINT16 responseType, receivedSize = 0;
    SOCKET s = INVALID_SOCKET;
    char bridgePort[8], bridgeKey[65], *end;
    char header[8];
    DWORD portLen, keyLen;
    unsigned long port;
    BOOL useBridge;
    WSADATA wsa;
    HRESULT hr;

    if ( !response || !responseSize || ( !body && size ) ) return E_INVALIDARG;
    *response = NULL;
    *responseSize = 0;
    backend_deadline deadline( timeoutMilliseconds, cancellation );
    if ( deadline.canceled() ) return E_ABORT;

    portLen = GetEnvironmentVariableA( "XODUS_BRIDGE_PORT", bridgePort, sizeof( bridgePort ) );
    keyLen = GetEnvironmentVariableA( "XODUS_BRIDGE_KEY", bridgeKey, sizeof( bridgeKey ) );
    useBridge = portLen || keyLen;
    if ( useBridge )
    {
        if ( !portLen || portLen >= sizeof( bridgePort ) || keyLen != 64 ) return E_INVALIDARG;
        port = strtoul( bridgePort, &end, 10 );
        if ( *end || !port || port > 65535 ) return E_INVALIDARG;
        bridge.sin_family = AF_INET;
        bridge.sin_port = htons( ( USHORT )port );
        bridge.sin_addr.s_addr = htonl( 0x7f000001 );
    }
    else if ( FAILED( hr = xodus_socket_path( addr.sun_path, sizeof( addr.sun_path ) ) ) )
        return hr;
    if ( WSAStartup( MAKEWORD( 2, 2 ), &wsa ) ) return E_FAIL;

    memcpy( header, &magic, 4 );
    memcpy( header + 4, &type, 2 );
    memcpy( header + 6, &size, 2 );

    if ( useBridge )
    {
        if ( ( s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) == INVALID_SOCKET ) goto error;
        if ( !xodus_connect( s, reinterpret_cast<sockaddr *>( &bridge ), sizeof( bridge ), deadline ) ) goto error;
        if ( !xodus_send( s, bridgeKey, 64, deadline ) ) goto error;
    }
    else
    {
        if ( ( s = socket( AF_UNIX, SOCK_STREAM, 0 ) ) == INVALID_SOCKET ) goto error;
        if ( !xodus_connect( s, reinterpret_cast<sockaddr *>( &addr ), sizeof( addr ), deadline ) ) goto error;
    }
    if ( !xodus_send( s, header, sizeof( header ), deadline ) || !xodus_send( s, body, size, deadline ) ) goto error;
    if ( !xodus_recv( s, header, sizeof( header ), deadline ) ) goto error;

    memcpy( &responseType, header + 4, 2 );
    memcpy( &receivedSize, header + 6, 2 );
    if ( memcmp( header, &magic, 4 ) || responseType != type + 1 || !receivedSize )
    {
        hr = E_UNEXPECTED;
        goto done;
    }
    if ( !( *response =
                static_cast<std::remove_reference_t<decltype( *response )>>( calloc( 1, receivedSize + 1 ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if ( !xodus_recv( s, *response, receivedSize, deadline ) )
    {
        hr = HRESULT_FROM_WIN32( WSAGetLastError() );
        if ( SUCCEEDED( hr ) ) hr = E_FAIL;
        free( *response );
        *response = NULL;
        goto done;
    }
    *responseSize = receivedSize;
    hr = S_OK;
    goto done;

error:
    hr = HRESULT_FROM_WIN32( WSAGetLastError() );
    if ( SUCCEEDED( hr ) ) hr = E_FAIL;
done:
    if ( deadline.canceled() )
    {
        free( *response ); *response = NULL; *responseSize = 0; hr = E_ABORT;
    }
    if ( s != INVALID_SOCKET ) closesocket( s );
    WSACleanup();
    return hr;
}

