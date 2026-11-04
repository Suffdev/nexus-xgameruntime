// SPDX-License-Identifier: MIT
// Real loopback sockets and the production backend framing implementation.
#include "../../src/private.h"
#include <afunix.h>
// Wine engines need not expose AF_UNIX. Exercise that protocol branch through
// an explicit loopback adapter; TCP timing/I/O remains real in both cases.
static SOCKET WSAAPI fixture_socket( int, int, int );
static int WSAAPI fixture_connect( SOCKET, const sockaddr *, int );
#define socket fixture_socket
#define connect fixture_connect
#include "../../src/System/User/BackendRequest.h"
#undef socket
#undef connect
#include <cstdio>
#include <string>
#include <vector>

static unsigned checks, failures;
static sockaddr_in unix_adapter;
static unsigned unix_connections;
static SOCKET WSAAPI fixture_socket( int family, int type, int protocol )
{
    return socket( family == AF_UNIX ? AF_INET : family, type, protocol );
}
static int WSAAPI fixture_connect( SOCKET value, const sockaddr *address, int size )
{
    if ( address->sa_family == AF_UNIX )
    {
        ++unix_connections;
        return connect( value, reinterpret_cast<sockaddr *>( &unix_adapter ), sizeof( unix_adapter ) );
    }
    return connect( value, address, size );
}
#define CHECK(label, expr) do { ++checks; if (!(expr)) { ++failures; printf("FAIL %s line %u\n", label, __LINE__); } } while (0)
enum class Reply { Complete, HeaderStall, BodyStall, Trickle, WrongType, Closed };
struct Server { SOCKET listener; Reply reply; UINT16 type; bool bridge; bool valid = false; };
static bool receive_all( SOCKET socket, char *bytes, int size )
{
    while ( size ) { int n = recv( socket, bytes, size, 0 ); if ( n <= 0 ) return false; bytes += n; size -= n; }
    return true;
}
static DWORD WINAPI serve( void *arg )
{
    auto server = static_cast<Server *>( arg );
    SOCKET socket = accept( server->listener, NULL, NULL );
    if ( socket == INVALID_SOCKET ) return 1;
    DWORD timeout = 2000;
    setsockopt( socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>( &timeout ), sizeof( timeout ) );
    char key[64], header[8], body[4];
    bool valid = !server->bridge || ( receive_all( socket, key, 64 ) && std::string( key, 64 ) == std::string( 64, 'a' ) );
    valid = valid && receive_all( socket, header, 8 ) && receive_all( socket, body, 4 );
    UINT32 magic = XODUS_XML_MAGIC; UINT16 type = server->type, size = 4;
    valid = valid && !memcmp( header, &magic, 4 ) && !memcmp( header + 4, &type, 2 ) &&
            !memcmp( header + 6, &size, 2 ) && !memcmp( body, "ping", 4 );
    server->valid = valid;
    if ( valid )
    {
        type += server->reply == Reply::WrongType ? 2 : 1;
        memcpy( header + 4, &type, 2 );
        if ( server->reply == Reply::HeaderStall ) Sleep( 700 );
        else if ( server->reply != Reply::Closed )
        {
            send( socket, header, 8, 0 );
            if ( server->reply == Reply::BodyStall ) Sleep( 700 );
            else if ( server->reply == Reply::Trickle )
            {
                for ( char c : std::string( "pong" ) ) { Sleep( 90 ); if ( send( socket, &c, 1, 0 ) != 1 ) break; }
            }
            else for ( char c : std::string( "pong" ) ) send( socket, &c, 1, 0 );
        }
    }
    closesocket( socket ); return 0;
}

static void run_case( UINT16 type, Reply reply, bool bridge )
{
    Server server{}; server.reply = reply; server.type = type; server.bridge = bridge;
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    sockaddr_un local{}; local.sun_family = AF_UNIX;
    char socketPath[MAX_PATH];
    snprintf( socketPath, sizeof( socketPath ), "/tmp/nexus-backend-%lu-%u-%u.sock", GetCurrentProcessId(), type, static_cast<unsigned>( reply ) );
    WCHAR *wide = WineGetDosFileName( socketPath );
    CHECK( "private-socket-path", wide != NULL );
    if ( !wide ) return;
    WideCharToMultiByte( CP_ACP, 0, wide, -1, local.sun_path, sizeof( local.sun_path ), NULL, NULL );
    server.listener = socket( AF_INET, SOCK_STREAM, 0 );
    CHECK( "listener-created", server.listener != INVALID_SOCKET );
    int result = bind( server.listener, reinterpret_cast<sockaddr *>( &address ), sizeof( address ) );
    CHECK( "private-listener-bound", result == 0 );
    if ( result ) { closesocket( server.listener ); HeapFree( GetProcessHeap(), 0, wide ); return; }
    CHECK( "listener-ready", listen( server.listener, 1 ) == 0 );
    int length = sizeof( address );
    CHECK( "ephemeral-port", getsockname( server.listener, reinterpret_cast<sockaddr *>( &address ), &length ) == 0 );
    unix_adapter = address;
    if ( bridge )
    {
        char port[8]; snprintf( port, sizeof( port ), "%u", ntohs( address.sin_port ) );
        SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", port );
        SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", std::string( 64, 'a' ).c_str() );
    }
    else
    {
        SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", NULL ); SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", NULL );
        SetEnvironmentVariableA( "XODUS_SOCKET", socketPath );
    }
    HANDLE thread = CreateThread( NULL, 0, serve, &server, 0, NULL );
    CHECK( "server-started", thread != NULL );
    if ( !thread ) { closesocket( server.listener ); HeapFree( GetProcessHeap(), 0, wide ); return; }
    char *response = NULL; UINT16 size = 0;
    ULONGLONG start = GetTickCount64();
    HRESULT hr = xodus_request( type, "ping", 4, &response, &size, 220 );
    ULONGLONG elapsed = GetTickCount64() - start;
    printf( "REQUEST type=%u bridge=%u reply=%u hr=%#lx elapsed=%I64u\n", type, bridge, static_cast<unsigned>( reply ), hr, elapsed );
    bool stalled = reply == Reply::HeaderStall || reply == Reply::BodyStall || reply == Reply::Trickle;
    if ( stalled )
    {
        CHECK( "whole-request-deadline", hr == HRESULT_FROM_WIN32( WSAETIMEDOUT ) && elapsed < 600 );
        CHECK( "partial-response-not-published", response == NULL && size == 0 );
    }
    else if ( reply == Reply::Complete ) CHECK( "complete-fragmented-response", hr == S_OK && size == 4 && response && !memcmp( response, "pong", 4 ) );
    else CHECK( "protocol-error-not-success", FAILED( hr ) && !response && !size );
    free( response );
    DWORD waited = WaitForSingleObject( thread, 3000 );
    CHECK( "server-finished", waited == WAIT_OBJECT_0 );
    // Do not destroy the stack-owned context while a failed fixture still runs.
    if ( waited != WAIT_OBJECT_0 ) ExitProcess( 2 );
    CHECK( "wire-request-preserved", server.valid );
    CloseHandle( thread ); closesocket( server.listener ); HeapFree( GetProcessHeap(), 0, wide );
}

static void refused_connection_and_send_stall()
{
    SOCKET listener = socket( AF_INET, SOCK_STREAM, 0 );
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    CHECK( "refusal-listener", listener != INVALID_SOCKET && bind( listener, reinterpret_cast<sockaddr *>( &address ), sizeof( address ) ) == 0 );
    int length = sizeof( address );
    CHECK( "refusal-port", getsockname( listener, reinterpret_cast<sockaddr *>( &address ), &length ) == 0 );
    char port[8]; snprintf( port, sizeof( port ), "%u", ntohs( address.sin_port ) );
    SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", port );
    SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", std::string( 64, 'a' ).c_str() );
    char *response = reinterpret_cast<char *>( 1 ); UINT16 size = 123;
    CHECK( "connection-error-preserved", xodus_request( 3, "ping", 4, &response, &size, 220 ) == HRESULT_FROM_WIN32( WSAECONNREFUSED ) );
    CHECK( "connection-error-clears-output", !response && !size );
    CHECK( "send-stall-listener", listen( listener, 1 ) == 0 );
    int bufferSize = 4096;
    CHECK( "send-stall-receive-buffer", setsockopt( listener, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>( &bufferSize ), sizeof( bufferSize ) ) == 0 );
    SOCKET client = socket( AF_INET, SOCK_STREAM, 0 );
    CHECK( "send-stall-small-buffer", setsockopt( client, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>( &bufferSize ), sizeof( bufferSize ) ) == 0 );
    backend_deadline connection( 2000 );
    CHECK( "send-stall-client", xodus_connect( client, reinterpret_cast<sockaddr *>( &address ), sizeof( address ), connection ) );
    SOCKET peer = accept( listener, NULL, NULL );
    CHECK( "send-stall-peer", peer != INVALID_SOCKET );
    std::vector<char> bytes( 4096, 'x' );
    backend_deadline deadline( 220 ); ULONGLONG started = GetTickCount64();
    BOOL sent = TRUE;
    for ( unsigned i = 0; sent && i < 16384; ++i ) sent = xodus_send( client, bytes.data(), bytes.size(), deadline );
    int error = WSAGetLastError();
    printf( "BACKPRESSURE sent=%d error=%d elapsed=%I64u\n", sent, error, GetTickCount64() - started );
    CHECK( "send-backpressure-honors-deadline", !sent && error == WSAETIMEDOUT && GetTickCount64() - started < 600 );
    closesocket( peer ); closesocket( client ); closesocket( listener );
    SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", "invalid" );
    response = reinterpret_cast<char *>( 1 ); size = 123;
    CHECK( "invalid-bridge-rejected", xodus_request( 3, "ping", 4, &response, &size ) == E_INVALIDARG );
    CHECK( "invalid-bridge-clears-output", !response && !size );
}

int main()
{
    WSADATA wsa; CHECK( "winsock-start", WSAStartup( MAKEWORD( 2, 2 ), &wsa ) == 0 );
    for ( bool bridge : { false, true } )
        for ( UINT16 type : { 3, 5, 9 } )
            for ( Reply reply : { Reply::Complete, Reply::HeaderStall, Reply::BodyStall, Reply::Trickle, Reply::WrongType, Reply::Closed } )
                run_case( type, reply, bridge );
    CHECK( "unix-protocol-branch-covered", unix_connections == 18 );
    refused_connection_and_send_stall();
    WSACleanup();
    printf( "CHECKS %u FAILURES %u\n", checks, failures ); return failures ? 1 : 0;
}
