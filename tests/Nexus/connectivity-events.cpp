// SPDX-License-Identifier: LGPL-2.1-or-later
// Synthetic device hints, real runtime queues. No game/account/network required.
#include "../../src/private.h"
#include <cstdio>
#include <atomic>

static SRWLOCK hint_lock = SRWLOCK_INIT;
static XNetworkingConnectivityHint device_hint{};
static HRESULT read_result = S_OK;
static HRESULT connectivity_read_hint( XNetworkingConnectivityHint *hint )
{
    AcquireSRWLockShared( &hint_lock );
    HRESULT hr = read_result;
    if ( SUCCEEDED( hr ) ) *hint = device_hint;
    ReleaseSRWLockShared( &hint_lock );
    return hr;
}
#include "../../src/System/Networking/ConnectivityEvents.h"

static unsigned checks, failures;
#define CHECK(label, expr) do { ++checks; if (!(expr)) { ++failures; printf("FAIL %s\n", label); } } while (0)
struct Seen
{
    SRWLOCK lock = SRWLOCK_INIT;
    unsigned count = 0;
    XNetworkingConnectivityHint hint{};
    XTaskQueueRegistrationToken token{};
    HANDLE entered = nullptr, release = nullptr;
    bool self_unregister = false;
    std::atomic<bool> self_result{false};
};
static void CALLBACK observe( void *context, const XNetworkingConnectivityHint *hint )
{
    auto seen = static_cast<Seen *>( context );
    AcquireSRWLockExclusive( &seen->lock );
    ++seen->count;
    seen->hint = *hint;
    ReleaseSRWLockExclusive( &seen->lock );
    if ( seen->self_unregister ) seen->self_result = connectivity_unregister( seen->token, TRUE );
    if ( seen->entered ) SetEvent( seen->entered );
    if ( seen->release ) WaitForSingleObject( seen->release, 5000 );
}
static unsigned count( Seen &seen )
{
    AcquireSRWLockShared( &seen.lock );
    unsigned value = seen.count;
    ReleaseSRWLockShared( &seen.lock );
    return value;
}
static XNetworkingConnectivityHint snapshot( Seen &seen )
{
    AcquireSRWLockShared( &seen.lock );
    auto value = seen.hint;
    ReleaseSRWLockShared( &seen.lock );
    return value;
}
static void set_hint( const XNetworkingConnectivityHint &hint, HRESULT hr = S_OK )
{
    AcquireSRWLockExclusive( &hint_lock );
    device_hint = hint;
    read_result = hr;
    ReleaseSRWLockExclusive( &hint_lock );
}
static void pump( XTaskQueueHandle q, DWORD duration )
{
    auto end = GetTickCount64() + duration;
    do
    {
        while ( x_threading_impl->XTaskQueueDispatch( q, XTaskQueuePort::Completion, 0 ) ) {}
        Sleep( 1 );
    } while ( GetTickCount64() < end );
}
static bool until( XTaskQueueHandle q, Seen &seen, unsigned desired )
{
    auto end = GetTickCount64() + 1800;
    do { pump( q, 2 ); if ( count( seen ) >= desired ) return true; } while ( GetTickCount64() < end );
    return false;
}
struct Waiter { XTaskQueueRegistrationToken token; HANDLE entered, done; BOOLEAN result; };
static DWORD WINAPI unregister_thread( void *context )
{
    auto waiter = static_cast<Waiter *>( context );
    SetEvent( waiter->entered );
    waiter->result = connectivity_unregister( waiter->token, TRUE );
    SetEvent( waiter->done );
    return 0;
}
int main()
{
    InitializeLogging();
    XTaskQueueHandle manual = nullptr, immediate = nullptr, threaded = nullptr;
    CHECK( "manual-queue", x_threading_impl->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &manual ) == S_OK );
    CHECK( "immediate-queue", x_threading_impl->XTaskQueueCreate( XTaskQueueDispatchMode::Immediate, XTaskQueueDispatchMode::Immediate, &immediate ) == S_OK );
    CHECK( "threaded-queue", x_threading_impl->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::ThreadPool, &threaded ) == S_OK );
    XTaskQueueRegistrationToken token{123};
    CHECK( "null-token", connectivity_register( manual, nullptr, observe, nullptr ) == E_POINTER );
    CHECK( "null-callback", connectivity_register( manual, nullptr, nullptr, &token ) == E_POINTER && token.token == 0 );
    CHECK( "unknown-unregister", !connectivity_unregister( {}, TRUE ) );
    XNetworkingConnectivityHint hint{};
    hint.networkInitialized = TRUE;
    hint.connectivityLevel = XNetworkingConnectivityLevelHint::None;
    set_hint( hint );
    Seen seen;
    CHECK( "register", connectivity_register( manual, &seen, observe, &seen.token ) == S_OK );
    CHECK( "manual-not-inline", count( seen ) == 0 );
    pump( manual, 10 );
    CHECK( "initial", count( seen ) == 1 && connectivity_equal( snapshot( seen ), hint ) );
    pump( manual, 650 );
    CHECK( "unchanged-not-duplicated", count( seen ) == 1 );
    hint.connectivityLevel = XNetworkingConnectivityLevelHint::InternetAccess;
    hint.ianaInterfaceType = 6;
    set_hint( hint );
    CHECK( "change-with-unpumped-work-port", until( manual, seen, 2 ) && connectivity_equal( snapshot( seen ), hint ) );
    hint.connectivityLevel = XNetworkingConnectivityLevelHint::None;
    set_hint( hint );
    CHECK( "disconnect", until( manual, seen, 3 ) && connectivity_equal( snapshot( seen ), hint ) );
    hint.networkInitialized = FALSE; set_hint( hint );
    CHECK( "initialization-change", until( manual, seen, 4 ) && !snapshot( seen ).networkInitialized );
    hint.connectivityCost = XNetworkingConnectivityCostHint::Fixed; set_hint( hint );
    CHECK( "cost-change", until( manual, seen, 5 ) && connectivity_equal( snapshot( seen ), hint ) );
    hint.roaming = TRUE; hint.overDataLimit = TRUE; hint.approachingDataLimit = TRUE; set_hint( hint );
    CHECK( "limits-change", until( manual, seen, 6 ) && connectivity_equal( snapshot( seen ), hint ) );
    set_hint( {}, E_FAIL ); pump( manual, 650 );
    CHECK( "read-error-preserves-valid-hint", count( seen ) == 6 && connectivity_equal( snapshot( seen ), hint ) );
    set_hint( hint ); pump( manual, 650 );
    CHECK( "read-recovery-unchanged", count( seen ) == 6 );
    CHECK( "unregister", connectivity_unregister( seen.token, TRUE ) );
    CHECK( "duplicate-unregister", !connectivity_unregister( seen.token, TRUE ) );
    set_hint( {} ); pump( manual, 650 );
    CHECK( "no-callback-after-unregister", count( seen ) == 6 );

    Seen coalesced; set_hint( hint );
    CHECK( "coalesce-register", connectivity_register( manual, &coalesced, observe, &coalesced.token ) == S_OK );
    hint.ianaInterfaceType = 71; set_hint( hint ); Sleep( 650 );
    hint.ianaInterfaceType = 6; hint.networkInitialized = TRUE; set_hint( hint ); Sleep( 650 );
    CHECK( "queued-no-inline", count( coalesced ) == 0 );
    pump( manual, 20 );
    CHECK( "queued-latest-hint", count( coalesced ) == 1 && connectivity_equal( snapshot( coalesced ), hint ) );
    CHECK( "coalesce-unregister", connectivity_unregister( coalesced.token, TRUE ) );

    Seen failed; set_hint( {}, E_FAIL );
    CHECK( "initial-failed-read-register", connectivity_register( manual, &failed, observe, &failed.token ) == S_OK );
    pump( manual, 10 );
    CHECK( "initial-failed-read-unknown", count( failed ) == 1 && !snapshot( failed ).networkInitialized );
    set_hint( hint );
    CHECK( "initial-failed-read-recovers", until( manual, failed, 2 ) && connectivity_equal( snapshot( failed ), hint ) );
    CHECK( "failed-read-unregister", connectivity_unregister( failed.token, TRUE ) );

    Seen canceled;
    CHECK( "queued-register", connectivity_register( manual, &canceled, observe, &canceled.token ) == S_OK );
    CHECK( "queued-unregister-without-pump", connectivity_unregister( canceled.token, TRUE ) );
    pump( manual, 650 ); CHECK( "queued-callback-suppressed", count( canceled ) == 0 );

    for ( auto q : {immediate, threaded} )
    {
        Seen self; self.self_unregister = true;
        self.entered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
        CHECK( "self-register", connectivity_register( q, &self, observe, &self.token ) == S_OK );
        CHECK( "self-callback-completes", WaitForSingleObject( self.entered, 1800 ) == WAIT_OBJECT_0 );
        CHECK( "self-unregister-succeeds", self.self_result );
        Sleep( 650 ); CHECK( "self-unregister-no-repeat", count( self ) == 1 );
        CloseHandle( self.entered );
    }
    Seen serial;
    serial.entered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    serial.release = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    CHECK( "serial-register", connectivity_register( threaded, &serial, observe, &serial.token ) == S_OK );
    CHECK( "serial-entered", WaitForSingleObject( serial.entered, 1800 ) == WAIT_OBJECT_0 );
    hint.ianaInterfaceType = 71; set_hint( hint ); Sleep( 650 );
    CHECK( "changed-while-running-no-overlap", count( serial ) == 1 );
    SetEvent( serial.release );
    CHECK( "changed-while-running-delivered", until( manual, serial, 2 ) && connectivity_equal( snapshot( serial ), hint ) );
    CHECK( "serial-unregister", connectivity_unregister( serial.token, TRUE ) );
    CloseHandle( serial.entered ); CloseHandle( serial.release );

    Seen nonwait;
    nonwait.entered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    nonwait.release = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    CHECK( "nonwait-register", connectivity_register( threaded, &nonwait, observe, &nonwait.token ) == S_OK );
    CHECK( "nonwait-entered", WaitForSingleObject( nonwait.entered, 1800 ) == WAIT_OBJECT_0 );
    CHECK( "nonwait-returns-during-callback", connectivity_unregister( nonwait.token, FALSE ) );
    hint.ianaInterfaceType = 6; set_hint( hint ); Sleep( 650 );
    CHECK( "nonwait-no-new-callback", count( nonwait ) == 1 );
    SetEvent( nonwait.release );
    // Drain the thread-pool title callback before closing its context handles.
    x_threading_impl->XTaskQueueTerminate( threaded, TRUE, nullptr, nullptr );
    CloseHandle( nonwait.entered ); CloseHandle( nonwait.release );
    x_threading_impl->XTaskQueueCloseHandle( threaded );
    threaded = nullptr;
    CHECK( "replacement-threaded-queue", x_threading_impl->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::ThreadPool, &threaded ) == S_OK );

    Seen blocked;
    blocked.entered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    blocked.release = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    CHECK( "blocking-register", connectivity_register( threaded, &blocked, observe, &blocked.token ) == S_OK );
    CHECK( "blocking-callback-entered", WaitForSingleObject( blocked.entered, 1800 ) == WAIT_OBJECT_0 );
    Waiter waiter{blocked.token, CreateEventW( nullptr, TRUE, FALSE, nullptr ), CreateEventW( nullptr, TRUE, FALSE, nullptr ), FALSE};
    HANDLE thread = CreateThread( nullptr, 0, unregister_thread, &waiter, 0, nullptr );
    CHECK( "unregister-thread", thread && WaitForSingleObject( waiter.entered, 1800 ) == WAIT_OBJECT_0 );
    CHECK( "wait-unregister-blocks", WaitForSingleObject( waiter.done, 80 ) == WAIT_TIMEOUT );
    set_hint( {} ); Sleep( 550 );
    CHECK( "running-callback-not-overlapped", count( blocked ) == 1 );
    SetEvent( blocked.release );
    CHECK( "wait-unregister-completes", WaitForSingleObject( waiter.done, 1800 ) == WAIT_OBJECT_0 && waiter.result );
    WaitForSingleObject( thread, 1800 );
    CloseHandle( thread ); CloseHandle( waiter.entered ); CloseHandle( waiter.done );
    CloseHandle( blocked.entered ); CloseHandle( blocked.release );
    for ( unsigned i = 0; i < 100; ++i )
    {
        Seen quick;
        CHECK( "cycle-register", connectivity_register( manual, &quick, observe, &quick.token ) == S_OK );
        CHECK( "cycle-unregister", connectivity_unregister( quick.token, FALSE ) );
        pump( manual, 1 ); CHECK( "cycle-suppressed", count( quick ) == 0 );
    }
    XTaskQueueHandle terminated = nullptr;
    CHECK( "terminated-queue-create", x_threading_impl->XTaskQueueCreate( XTaskQueueDispatchMode::Immediate, XTaskQueueDispatchMode::Immediate, &terminated ) == S_OK );
    CHECK( "terminate-queue", x_threading_impl->XTaskQueueTerminate( terminated, TRUE, nullptr, nullptr ) == S_OK );
    token.token = 123;
    CHECK( "terminated-register-fails-clears-token", FAILED( connectivity_register( terminated, nullptr, observe, &token ) ) && token.token == 0 );
    x_threading_impl->XTaskQueueCloseHandle( terminated );
    Sleep( 80 );
    AcquireSRWLockShared( &connectivity_lock );
    CHECK( "registration-list-empty", connectivity_registrations == nullptr );
    ReleaseSRWLockShared( &connectivity_lock );
    for ( auto q : {manual, immediate, threaded} ) x_threading_impl->XTaskQueueCloseHandle( q );
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
