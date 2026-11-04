// SPDX-License-Identifier: MIT
#include "../test_fixtures.h"
#include <xasyncprovider.h>
#include <atomic>
#include <thread>
#include <cstring>
#ifndef E_ILLEGAL_METHOD_CALL
#define E_ILLEGAL_METHOD_CALL _HRESULT_TYPEDEF_( 0x8000000E )
#endif

namespace
{
const char payloadIdentity = 0, wrongIdentity = 0;
struct Payload
{
    IXThreadingImpl *api;
    std::atomic<unsigned> reads{ 0 }, cleanups{ 0 };
};
HRESULT WINAPI PayloadProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    auto payload = static_cast<Payload *>( data->context );
    switch ( op )
    {
    case XAsyncOp::Begin:
        return payload->api->XAsyncSchedule( data->async, 0 );
    case XAsyncOp::DoWork:
        payload->api->XAsyncComplete( data->async, S_OK, sizeof( DWORD ) );
        return E_PENDING;
    case XAsyncOp::GetResult:
    {
        ++payload->reads;
        Sleep( 20 );
        const DWORD value = 0x1234;
        memcpy( data->buffer, &value, sizeof( value ) );
        return S_OK;
    }
    case XAsyncOp::Cleanup:
        ++payload->cleanups;
        return S_OK;
    default:
        return S_OK;
    }
}
struct Fixture
{
    HMODULE module = LoadLibraryW( L"xgameruntime.dll" );
    IXThreadingImpl *api = nullptr;
    XTaskQueueHandle queue = nullptr;
    ~Fixture()
    {
        if ( queue ) api->XTaskQueueCloseHandle( queue );
        if ( api ) api->Release();
        if ( module ) FreeLibrary( module );
    }
    HRESULT Initialize()
    {
        using Query = HRESULT( WINAPI * )( REFCLSID, REFIID, void ** );
        auto query = module ? reinterpret_cast<Query>( GetProcAddress( module, "QueryApiImpl" ) ) : nullptr;
        if ( !query ) return E_FAIL;
        auto hr = query( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &api ) );
        return FAILED( hr )
                   ? hr
                   : api->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue );
    }
};
}
TEST( NexusAsyncResults, BadArgumentsRetainThePayloadForACorrectedResultCall )
{
    Fixture fixture;
    ASSERT_EQ( fixture.Initialize(), S_OK );
    Payload payload{ fixture.api };
    XAsyncBlock async{};
    async.queue = fixture.queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &payload, &payloadIdentity, "Payload", PayloadProvider ), S_OK );
    ASSERT_TRUE( fixture.api->XTaskQueueDispatch( fixture.queue, XTaskQueuePort::Work, 5000 ) );
    ASSERT_EQ( fixture.api->XAsyncGetStatus( &async, TRUE ), S_OK );
    DWORD value = 0;
    EXPECT_TRUE( FAILED( fixture.api->XAsyncGetResult( &async, &payloadIdentity, 1, &value, nullptr ) ) );
    EXPECT_TRUE(
        FAILED( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), nullptr, nullptr ) ) );
    EXPECT_EQ( fixture.api->XAsyncGetResult( &async, &wrongIdentity, sizeof( value ), &value, nullptr ), E_INVALIDARG );
    EXPECT_EQ( payload.reads, 0u );
    EXPECT_EQ( payload.cleanups, 0u );
    ASSERT_EQ( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), &value, nullptr ), S_OK );
    EXPECT_EQ( value, 0x1234u );
    EXPECT_EQ( payload.reads, 1u );
    EXPECT_EQ( payload.cleanups, 1u );
    EXPECT_EQ( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), &value, nullptr ),
               E_ILLEGAL_METHOD_CALL );
}
TEST( NexusAsyncResults, ConcurrentResultReadersCannotConsumeTheSamePayloadTwice )
{
    Fixture fixture;
    ASSERT_EQ( fixture.Initialize(), S_OK );
    Payload payload{ fixture.api };
    XAsyncBlock async{};
    async.queue = fixture.queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &payload, &payloadIdentity, "Payload", PayloadProvider ), S_OK );
    ASSERT_TRUE( fixture.api->XTaskQueueDispatch( fixture.queue, XTaskQueuePort::Work, 5000 ) );
    HANDLE start = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    ASSERT_NE( start, nullptr );
    HRESULT results[2] = { E_PENDING, E_PENDING };
    DWORD values[2]{};
    auto read = [&]( unsigned i )
    {
        WaitForSingleObject( start, 5000 );
        results[i] = fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( DWORD ), &values[i], nullptr );
    };
    std::thread first( read, 0 ), second( read, 1 );
    SetEvent( start );
    first.join();
    second.join();
    CloseHandle( start );
    EXPECT_TRUE( ( results[0] == S_OK && results[1] == E_ILLEGAL_METHOD_CALL ) ||
                 ( results[1] == S_OK && results[0] == E_ILLEGAL_METHOD_CALL ) );
    EXPECT_EQ( payload.reads, 1u );
    EXPECT_EQ( payload.cleanups, 1u );
    EXPECT_EQ( values[0] + values[1], 0x1234u );
}

namespace
{
struct Deferred
{
    IXThreadingImpl *api;
    XAsyncBlock *async = nullptr;
    std::atomic<unsigned> cancels{ 0 }, cleanups{ 0 };
};
HRESULT WINAPI DeferredProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    auto deferred = static_cast<Deferred *>( data->context );
    switch ( op )
    {
    case XAsyncOp::Begin:
        deferred->async = data->async;
        return S_OK;
    case XAsyncOp::Cancel:
        // Counted only: the termination path completes the call itself.
        ++deferred->cancels;
        return S_OK;
    case XAsyncOp::GetResult:
        memset( data->buffer, 0x5A, data->bufferSize );
        return S_OK;
    case XAsyncOp::Cleanup:
        ++deferred->cleanups;
        return S_OK;
    default:
        return S_OK;
    }
}
}
namespace
{
// Fixture-only bounded query racer. The destructor always joins, so a failed
// assertion can never leave a joinable thread or hang the component run.
struct QueryRacer
{
    IXThreadingImpl *api;
    XAsyncBlock *block;
    std::atomic<bool> running{ true };
    std::atomic<unsigned> probes{ 0 };
    std::thread thread;

    QueryRacer( IXThreadingImpl *api_, XAsyncBlock *block_ ) : api( api_ ), block( block_ ),
        thread( [this] {
            while ( running.load( std::memory_order_acquire ) )
            {
                (void)api->XAsyncGetStatus( block, FALSE );
                probes.fetch_add( 1, std::memory_order_release );
                std::this_thread::yield();
            }
        } )
    {
        while ( probes.load( std::memory_order_acquire ) == 0 )
            std::this_thread::yield();
    }

    unsigned Stop()
    {
        running.store( false, std::memory_order_release );
        if ( thread.joinable() ) thread.join();
        return probes.load();
    }

    ~QueryRacer()
    {
        running.store( false, std::memory_order_release );
        if ( thread.joinable() ) thread.join();
    }
};
}

TEST( NexusAsyncResults, ReusedBlockLateCompletionLeavesANewerCallPending )
{
    // A caller zeroes its block and starts a new call on it while the first
    // call is still pending. The first call must not complete the second.
    Fixture fixture;
    ASSERT_EQ( fixture.Initialize(), S_OK );
    Deferred first{ fixture.api }, second{ fixture.api };
    XAsyncBlock async{};
    async.queue = fixture.queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &first, &payloadIdentity, "First", DeferredProvider ), S_OK );
    ASSERT_NE( first.async, nullptr );
    async = XAsyncBlock{};
    async.queue = fixture.queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &second, &payloadIdentity, "Second", DeferredProvider ), S_OK );
    ASSERT_NE( second.async, nullptr );

    fixture.api->XAsyncComplete( first.async, S_OK, 0 );
    EXPECT_EQ( first.cleanups, 1u );
    EXPECT_EQ( fixture.api->XAsyncGetStatus( &async, FALSE ), E_PENDING );

    fixture.api->XAsyncComplete( second.async, S_OK, sizeof( DWORD ) );
    ASSERT_EQ( fixture.api->XAsyncGetStatus( &async, TRUE ), S_OK );
    DWORD value = 0;
    ASSERT_EQ( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), &value, nullptr ), S_OK );
    EXPECT_EQ( value, 0x5A5A5A5Au );
    EXPECT_EQ( second.cleanups, 1u );
}
TEST( NexusAsyncResults, ReusedBlockHandoffRaceCancelsOnlyTheOldCall )
{
    // Query threads run only around API-visible work; the XAsyncBlock itself is
    // never overwritten while a query thread can touch it. Terminal reuse is
    // API-only (XAsyncBegin on a completed block). Cycles cover a terminal
    // transition during the caller to provider handoff and a raw reuse followed
    // by an old-queue termination racing queries of the newer call.
    Fixture fixture;
    ASSERT_EQ( fixture.Initialize(), S_OK );
    XAsyncBlock async{};
    async.queue = fixture.queue;

    // Terminal transition during the handoff while another thread queries.
    Deferred first{ fixture.api };
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &first, &payloadIdentity, "First", DeferredProvider ), S_OK );
    unsigned probes = 0;
    {
        QueryRacer racer( fixture.api, &async );
        fixture.api->XAsyncComplete( first.async, S_OK, 0 );
        probes = racer.Stop();
    }
    EXPECT_GT( probes, 0u );
    EXPECT_EQ( first.cleanups, 1u );

    // Reuse the completed block through the public API, without rewriting it.
    Deferred second{ fixture.api };
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &second, &payloadIdentity, "Second", DeferredProvider ), S_OK );
    EXPECT_EQ( fixture.api->XAsyncGetStatus( &async, FALSE ), E_PENDING );
    {
        QueryRacer racer( fixture.api, &async );
        fixture.api->XAsyncComplete( second.async, S_OK, sizeof( DWORD ) );
        probes = racer.Stop();
    }
    EXPECT_GT( probes, 0u );
    EXPECT_EQ( fixture.api->XAsyncGetStatus( &async, FALSE ), S_OK );
    DWORD value = 0;
    EXPECT_EQ( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), &value, nullptr ), S_OK );
    EXPECT_EQ( value, 0x5A5A5A5Au );
    EXPECT_EQ( second.cleanups, 1u );

    // Raw reuse is performed only while no query thread runs. The newer call is
    // then queried while the older queue terminates and completes.
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ( fixture.api->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ), S_OK );
    Deferred third{ fixture.api }, fourth{ fixture.api };
    async = XAsyncBlock{};
    async.queue = queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &third, &payloadIdentity, "Third", DeferredProvider ), S_OK );
    ASSERT_EQ( fixture.api->XAsyncSchedule( third.async, 0 ), S_OK );
    async = XAsyncBlock{};
    async.queue = fixture.queue;
    ASSERT_EQ( fixture.api->XAsyncBegin( &async, &fourth, &payloadIdentity, "Fourth", DeferredProvider ), S_OK );
    {
        QueryRacer racer( fixture.api, &async );
        EXPECT_EQ( fixture.api->XTaskQueueTerminate( queue, FALSE, nullptr, nullptr ), S_OK );
        for ( int i = 0; i < 10; ++i )
        {
            fixture.api->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 10 );
            fixture.api->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 10 );
        }
        probes = racer.Stop();
    }
    EXPECT_GT( probes, 0u );
    EXPECT_EQ( third.cancels, 1u );
    EXPECT_EQ( third.cleanups, 1u );
    EXPECT_EQ( fourth.cancels, 0u );
    EXPECT_EQ( fixture.api->XAsyncGetStatus( &async, FALSE ), E_PENDING );

    fixture.api->XAsyncComplete( fourth.async, S_OK, sizeof( DWORD ) );
    EXPECT_EQ( fixture.api->XAsyncGetStatus( &async, FALSE ), S_OK );
    value = 0;
    EXPECT_EQ( fixture.api->XAsyncGetResult( &async, &payloadIdentity, sizeof( value ), &value, nullptr ), S_OK );
    EXPECT_EQ( value, 0x5A5A5A5Au );
    EXPECT_EQ( fourth.cleanups, 1u );
    fixture.api->XTaskQueueCloseHandle( queue );
}
