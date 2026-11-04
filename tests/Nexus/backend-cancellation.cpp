// SPDX-License-Identifier: MIT
// Actual production socket code with event-controlled synthetic loopback peers.
#define main deadline_fixture_main
#include "backend-request.cpp"
#undef main
#include <atomic>
#include <type_traits>

// The unchanged before-state has no cancel argument. This adapter invokes that
// exact production signature; after the fix the identical fixture passes the
// operation token to the production request, without a fake socket transport.
template<typename Request> static HRESULT invoke_cancel_request( Request request, std::atomic<bool> &cancel,
                                                                char **out, UINT16 *size, DWORD budget = 3000 )
{
    if constexpr ( std::is_invocable_r_v<HRESULT, Request, UINT16, const char *, UINT16, char **, UINT16 *, DWORD,
                                         const std::atomic<bool> *> )
        return request( 3, "ping", 4, out, size, budget, &cancel );
    else return request( 3, "ping", 4, out, size, budget );
}
struct CancelPeer
{
    SOCKET listener = INVALID_SOCKET;
    HANDLE framed = NULL, release = NULL, closed = NULL, stop = NULL, full = NULL, thread = NULL;
    bool bridge = false, body = false, immediate = false, trickle = false;
    bool accepted = false, valid = false;
};
static DWORD WINAPI cancel_peer_thread( void *context )
{
    auto peer = static_cast<CancelPeer *>( context ); SOCKET socket = INVALID_SOCKET;
    for ( ;; )
    {
        if ( WaitForSingleObject( peer->stop, 0 ) == WAIT_OBJECT_0 ) goto done;
        fd_set ready; FD_ZERO( &ready ); FD_SET( peer->listener, &ready ); timeval slice{ 0, 50000 };
        int result = select( 0, &ready, NULL, NULL, &slice );
        if ( result == SOCKET_ERROR ) goto done;
        if ( result ) { socket = accept( peer->listener, NULL, NULL ); break; }
    }
    if ( socket == INVALID_SOCKET ) goto done;
    peer->accepted = true;
    {
        DWORD timeout = 1500; setsockopt( socket, SOL_SOCKET, SO_RCVTIMEO, ( const char * )&timeout, sizeof( timeout ) );
        char key[64], header[8], body[4]; UINT32 magic = XODUS_XML_MAGIC; UINT16 type = 3, count = 4;
        peer->valid = ( !peer->bridge || ( receive_all( socket, key, 64 ) && std::string( key, 64 ) == std::string( 64, 'a' ) ) ) &&
            receive_all( socket, header, 8 ) && receive_all( socket, body, 4 ) && !memcmp( header, &magic, 4 ) &&
            !memcmp( header + 4, &type, 2 ) && !memcmp( header + 6, &count, 2 ) && !memcmp( body, "ping", 4 );
        if ( !peer->valid ) goto done;
        type++; memcpy( header + 4, &type, 2 );
        if ( peer->body || peer->trickle ) send( socket, header, 8, 0 );
        if ( peer->body ) send( socket, "p", 1, 0 );
        SetEvent( peer->framed );
        bool replied = false; unsigned sent = 0; ULONGLONG started = GetTickCount64();
        for ( ;; )
        {
            if ( WaitForSingleObject( peer->stop, 0 ) == WAIT_OBJECT_0 ) break;
            if ( peer->trickle && !replied && GetTickCount64() - started >= 90 * ( sent + 1 ) )
            {
                if ( send( socket, "pong" + sent, 1, 0 ) != 1 ) break;
                if ( ++sent == 4 ) { replied = true; SetEvent( peer->full ); }
            }
            if ( !peer->trickle && !replied && ( peer->immediate || WaitForSingleObject( peer->release, 0 ) == WAIT_OBJECT_0 ) )
            {
                if ( peer->body ) send( socket, "ong", 3, 0 );
                else { send( socket, header, 8, 0 ); send( socket, "pong", 4, 0 ); }
                SetEvent( peer->full ); replied = true;
            }
            fd_set ready; FD_ZERO( &ready ); FD_SET( socket, &ready ); timeval slice{ 0, 50000 };
            int result = select( 0, &ready, NULL, NULL, &slice );
            if ( result == SOCKET_ERROR ) break;
            if ( result )
            {
                char byte; int count = recv( socket, &byte, 1, 0 );
                if ( count == 0 || count == SOCKET_ERROR ) { SetEvent( peer->closed ); break; }
            }
        }
    }
done:
    if ( socket != INVALID_SOCKET ) closesocket( socket );
    closesocket( peer->listener ); return 0;
}
static void start_peer( CancelPeer &peer, bool bridge, bool body, bool immediate = false )
{
    peer.bridge = bridge; peer.body = body; peer.immediate = immediate;
    peer.framed = CreateEventW( NULL, TRUE, FALSE, NULL ); peer.release = CreateEventW( NULL, TRUE, FALSE, NULL );
    peer.closed = CreateEventW( NULL, TRUE, FALSE, NULL ); peer.stop = CreateEventW( NULL, TRUE, FALSE, NULL );
    peer.full = CreateEventW( NULL, TRUE, FALSE, NULL );
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    peer.listener = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    CHECK( "cancel-listener-created", peer.listener != INVALID_SOCKET );
    CHECK( "cancel-listener-bound", bind( peer.listener, ( sockaddr * )&address, sizeof( address ) ) == 0 );
    CHECK( "cancel-listener-ready", listen( peer.listener, 2 ) == 0 );
    int length = sizeof( address ); getsockname( peer.listener, ( sockaddr * )&address, &length );
    char port[16]; snprintf( port, sizeof( port ), "%u", ntohs( address.sin_port ) );
    SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", bridge ? port : NULL );
    SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", bridge ? std::string( 64, 'a' ).c_str() : NULL );
    if ( !bridge ) { unix_adapter = address; SetEnvironmentVariableA( "XODUS_SOCKET", "/tmp/nexus-cancel-fixture.sock" ); }
    peer.thread = CreateThread( NULL, 0, cancel_peer_thread, &peer, 0, NULL ); CHECK( "cancel-peer-thread", peer.thread != NULL );
}
static void stop_peer( CancelPeer &peer )
{
    SetEvent( peer.stop ); SetEvent( peer.release );
    CHECK( "cancel-peer-joined", WaitForSingleObject( peer.thread, 3000 ) == WAIT_OBJECT_0 );
    for ( HANDLE handle : { peer.thread, peer.framed, peer.release, peer.closed, peer.stop, peer.full } ) CloseHandle( handle );
}
struct CancelCall
{
    std::atomic<bool> canceled{ false };
    char *response = NULL; UINT16 size = 0; HRESULT result = E_PENDING;
    HANDLE thread = NULL; DWORD budget = 3000; ULONGLONG elapsed = 0;
};
static DWORD WINAPI cancel_call_thread( void *context )
{
    auto call = static_cast<CancelCall *>( context );
    ULONGLONG started = GetTickCount64();
    call->result = invoke_cancel_request( &xodus_request, call->canceled, &call->response, &call->size, call->budget );
    call->elapsed = GetTickCount64() - started; return 0;
}
static void start_call( CancelCall &call ) { call.thread = CreateThread( NULL, 0, cancel_call_thread, &call, 0, NULL ); }
static void cleanup_call( CancelCall &call )
{
    CHECK( "cancel-call-finally-joined", WaitForSingleObject( call.thread, 4000 ) == WAIT_OBJECT_0 );
    CloseHandle( call.thread ); free( call.response );
}
static void blocked_cancel( bool bridge, bool body )
{
    printf( "CASE cancel blocked production socket bridge=%d body=%d\n", bridge, body );
    CancelPeer peer; start_peer( peer, bridge, body ); CancelCall call; start_call( call );
    CHECK( "cancel-request-framed", WaitForSingleObject( peer.framed, 2000 ) == WAIT_OBJECT_0 );
    call.canceled = true;
    CHECK( "cancel-worker-exits-without-server-release", WaitForSingleObject( call.thread, 1200 ) == WAIT_OBJECT_0 );
    CHECK( "cancel-peer-sees-eof-before-release", WaitForSingleObject( peer.closed, 300 ) == WAIT_OBJECT_0 );
    SetEvent( peer.release ); cleanup_call( call );
    CHECK( "cancel-result-is-abort", call.result == E_ABORT );
    CHECK( "cancel-publishes-no-output", !call.response && !call.size );
    CHECK( "cancel-preserves-request-framing", peer.valid ); stop_peer( peer );
}
static void precanceled( bool bridge )
{
    printf( "CASE precancel production socket bridge=%d\n", bridge );
    CancelPeer peer; start_peer( peer, bridge, false, true ); CancelCall call; call.canceled = true; start_call( call );
    CHECK( "precancel-client-returns", WaitForSingleObject( call.thread, 1200 ) == WAIT_OBJECT_0 ); cleanup_call( call );
    stop_peer( peer );
    CHECK( "precancel-no-connection", !peer.accepted ); CHECK( "precancel-result-is-abort", call.result == E_ABORT );
    CHECK( "precancel-no-output", !call.response && !call.size );
}
static void completion_race_and_independent( bool bridge )
{
    printf( "CASE completion race and independent request bridge=%d\n", bridge );
    CancelPeer old; start_peer( old, bridge, false ); CancelCall first; start_call( first );
    CHECK( "race-first-framed", WaitForSingleObject( old.framed, 2000 ) == WAIT_OBJECT_0 );
    CancelPeer next; start_peer( next, bridge, false ); CancelCall second; start_call( second );
    CHECK( "independent-request-framed-before-cancel", WaitForSingleObject( next.framed, 2000 ) == WAIT_OBJECT_0 );
    first.canceled = true;
    CHECK( "independent-canceled-worker-exits", WaitForSingleObject( first.thread, 1200 ) == WAIT_OBJECT_0 );
    SetEvent( old.release ); cleanup_call( first );
    CHECK( "independent-first-call-canceled-without-output", first.result == E_ABORT && !first.response && !first.size );
    CHECK( "independent-call-still-pending-after-other-cleanup", WaitForSingleObject( second.thread, 0 ) == WAIT_TIMEOUT );
    SetEvent( next.release );
    CHECK( "independent-request-completes-after-other-cancel", WaitForSingleObject( second.thread, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "independent-valid-output", second.result == S_OK && second.size == 4 && second.response && !memcmp( second.response, "pong", 4 ) );
    CHECK( "independent-operation-not-canceled", !second.canceled && second.result == S_OK );
    cleanup_call( second ); stop_peer( old ); stop_peer( next );
    CancelPeer later; start_peer( later, bridge, false, true ); CancelCall third; start_call( third );
    CHECK( "post-cancel-request-completes", WaitForSingleObject( third.thread, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "post-cancel-valid-output", third.result == S_OK && third.response && third.size == 4 && !memcmp( third.response, "pong", 4 ) );
    cleanup_call( third ); stop_peer( later );
}
static void completed_reply_race( bool bridge )
{
    printf( "CASE complete production response races cancellation bridge=%d\n", bridge );
    CancelPeer peer; start_peer( peer, bridge, false ); CancelCall call; start_call( call );
    CHECK( "complete-race-request-framed", WaitForSingleObject( peer.framed, 2000 ) == WAIT_OBJECT_0 );
    SetEvent( peer.release );
    CHECK( "complete-race-full-reply-sent", WaitForSingleObject( peer.full, 2000 ) == WAIT_OBJECT_0 );
    call.canceled = true;
    CHECK( "complete-race-client-finished", WaitForSingleObject( call.thread, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "complete-race-only-full-success-or-empty-abort", ( call.result == E_ABORT && !call.response && !call.size ) ||
        ( call.result == S_OK && call.response && call.size == 4 && !memcmp( call.response, "pong", 4 ) ) );
    cleanup_call( call ); stop_peer( peer );
}

static void active_token_deadline( bool bridge, unsigned mode )
{
    printf( "CASE uncanceled sliced total deadline bridge=%d mode=%u\n", bridge, mode );
    CancelPeer peer; peer.trickle = mode == 2; start_peer( peer, bridge, mode == 1 );
    CancelCall call; call.budget = 220; start_call( call );
    CHECK( "sliced-deadline-request-framed", WaitForSingleObject( peer.framed, 2000 ) == WAIT_OBJECT_0 );
    CHECK( "sliced-deadline-client-exits-without-peer-release", WaitForSingleObject( call.thread, 1500 ) == WAIT_OBJECT_0 );
    SetEvent( peer.release ); cleanup_call( call );
    CHECK( "sliced-deadline-preserves-timeout-result", call.result == HRESULT_FROM_WIN32( WSAETIMEDOUT ) );
    CHECK( "sliced-deadline-keeps-one-total-budget", call.elapsed >= 150 && call.elapsed < 1500 );
    CHECK( "sliced-deadline-no-partial-response", !call.response && !call.size ); stop_peer( peer );
}

int main()
{
    setvbuf( stdout, NULL, _IONBF, 0 ); WSADATA wsa;
    CHECK( "cancel-winsock-start", WSAStartup( MAKEWORD( 2, 2 ), &wsa ) == 0 );
    for ( bool bridge : { false, true } )
    { blocked_cancel( bridge, false ); blocked_cancel( bridge, true ); precanceled( bridge ); completion_race_and_independent( bridge ); completed_reply_race( bridge );
      for ( unsigned mode = 0; mode < 3; mode++ ) active_token_deadline( bridge, mode ); }
    WSACleanup(); printf( "CHECKS %u FAILURES %u\n", checks, failures ); return failures ? 1 : 0;
}
