/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Queue-bound connectivity notifications. The including translation unit
 * supplies connectivity_read_hint; production and notifications use the same
 * device-state query. No endpoint probes or authentication changes belong here.
 */
struct connectivity_registration
{
    struct connectivity_registration *next;
    LONG ref;
    UINT64 token, revision, delivered;
    XTaskQueueHandle queue, poll_queue;
    void *context;
    XNetworkingConnectivityHintChangedCallback *callback;
    XNetworkingConnectivityHint hint;
    BOOL removed, queued, running;
    DWORD callback_thread;
};
static SRWLOCK connectivity_lock = SRWLOCK_INIT;
static CONDITION_VARIABLE connectivity_changed = CONDITION_VARIABLE_INIT;
static struct connectivity_registration *connectivity_registrations;
static UINT64 connectivity_next_token;

static void connectivity_release( struct connectivity_registration *registration )
{
    if ( InterlockedDecrement( &registration->ref ) ) return;
    if ( registration->poll_queue ) ( x_threading_impl )->XTaskQueueCloseHandle( registration->poll_queue );
    if ( registration->queue ) ( x_threading_impl )->XTaskQueueCloseHandle( registration->queue );
    free( registration );
}

static BOOL connectivity_equal( const XNetworkingConnectivityHint &a, const XNetworkingConnectivityHint &b )
{
    return a.connectivityLevel == b.connectivityLevel && a.connectivityCost == b.connectivityCost &&
           a.ianaInterfaceType == b.ianaInterfaceType && a.networkInitialized == b.networkInitialized &&
           a.approachingDataLimit == b.approachingDataLimit && a.overDataLimit == b.overDataLimit &&
           a.roaming == b.roaming;
}

static void CALLBACK connectivity_callback( void *context, BOOLEAN canceled );

/* Reserve under connectivity_lock, submit outside it: Immediate queues may
 * call title code synchronously, including an unregister of this token. */
static BOOL connectivity_reserve( struct connectivity_registration *registration )
{
    if ( registration->removed || registration->queued || registration->revision == registration->delivered )
        return FALSE;
    registration->queued = TRUE;
    InterlockedIncrement( &registration->ref );
    return TRUE;
}

static HRESULT connectivity_submit( struct connectivity_registration *registration )
{
    HRESULT hr = ( x_threading_impl )->XTaskQueueSubmitCallback(
        registration->queue, XTaskQueuePort::Completion, registration, connectivity_callback );
    if ( FAILED( hr ) )
    {
        AcquireSRWLockExclusive( &connectivity_lock );
        registration->queued = FALSE;
        ReleaseSRWLockExclusive( &connectivity_lock );
        connectivity_release( registration );
    }
    return hr;
}

static void CALLBACK connectivity_callback( void *context, BOOLEAN canceled )
{
    auto registration = static_cast<connectivity_registration *>( context );
    XNetworkingConnectivityHint hint{};
    BOOL deliver, submit = FALSE;
    AcquireSRWLockExclusive( &connectivity_lock );
    deliver = !canceled && !registration->removed;
    if ( deliver )
    {
        hint = registration->hint;
        registration->delivered = registration->revision;
        registration->running = TRUE;
        registration->callback_thread = GetCurrentThreadId();
    }
    ReleaseSRWLockExclusive( &connectivity_lock );
    if ( deliver )
    {
        INFO( "connectivity token=%llu initialized=%u level=%u cost=%u interface=%u\n",
              ( unsigned long long )registration->token, ( unsigned )hint.networkInitialized,
              ( unsigned )hint.connectivityLevel, ( unsigned )hint.connectivityCost, hint.ianaInterfaceType );
        registration->callback( registration->context, &hint );
    }
    AcquireSRWLockExclusive( &connectivity_lock );
    registration->running = FALSE;
    registration->queued = FALSE;
    registration->callback_thread = 0;
    WakeAllConditionVariable( &connectivity_changed );
    if ( deliver ) submit = connectivity_reserve( registration );
    ReleaseSRWLockExclusive( &connectivity_lock );
    if ( submit ) connectivity_submit( registration );
    connectivity_release( registration );
}

static void CALLBACK connectivity_poll( void *context, BOOLEAN canceled );

static HRESULT connectivity_schedule( struct connectivity_registration *registration )
{
    AcquireSRWLockExclusive( &connectivity_lock );
    if ( registration->removed )
    {
        ReleaseSRWLockExclusive( &connectivity_lock );
        return E_ABORT;
    }
    InterlockedIncrement( &registration->ref );
    ReleaseSRWLockExclusive( &connectivity_lock );
    HRESULT hr = ( x_threading_impl )->XTaskQueueSubmitDelayedCallback(
        registration->poll_queue, XTaskQueuePort::Work, 500, registration, connectivity_poll );
    if ( FAILED( hr ) ) connectivity_release( registration );
    return hr;
}

static void CALLBACK connectivity_poll( void *context, BOOLEAN canceled )
{
    auto registration = static_cast<connectivity_registration *>( context );
    XNetworkingConnectivityHint hint{};
    BOOL active, submit = FALSE;
    AcquireSRWLockShared( &connectivity_lock );
    active = !canceled && !registration->removed;
    ReleaseSRWLockShared( &connectivity_lock );
    if ( active )
    {
        HRESULT hr = connectivity_read_hint( &hint );
        AcquireSRWLockExclusive( &connectivity_lock );
        /* A query failure is not evidence of disconnection. Keep the last
         * valid hint and retry; a successful read can also recover the initial
         * unknown/uninitialized notification after an initial query failure. */
        if ( SUCCEEDED( hr ) && !connectivity_equal( registration->hint, hint ) )
        {
            registration->hint = hint;
            ++registration->revision;
        }
        submit = connectivity_reserve( registration );
        ReleaseSRWLockExclusive( &connectivity_lock );
        if ( submit ) connectivity_submit( registration );
        connectivity_schedule( registration );
    }
    connectivity_release( registration );
}

static BOOLEAN connectivity_unregister( XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    struct connectivity_registration **cursor, *registration;
    AcquireSRWLockExclusive( &connectivity_lock );
    for ( cursor = &connectivity_registrations; *cursor && ( *cursor )->token != token.token;
          cursor = &( *cursor )->next )
        ;
    if ( !( registration = *cursor ) )
    {
        ReleaseSRWLockExclusive( &connectivity_lock );
        return FALSE;
    }
    *cursor = registration->next;
    registration->removed = TRUE;
    /* Suppress queued title calls. A Manual completion queue need not be
     * pumped to unregister; only an already running title callback can wait. */
    while ( wait && registration->running && registration->callback_thread != GetCurrentThreadId() )
        SleepConditionVariableSRW( &connectivity_changed, &connectivity_lock, INFINITE, 0 );
    ReleaseSRWLockExclusive( &connectivity_lock );
    /* Never terminate synchronously on the poll queue's own callback thread.
     * Scheduled/canceled work retains a ref until it has returned. */
    ( x_threading_impl )->XTaskQueueTerminate( registration->poll_queue, FALSE, NULL, NULL );
    connectivity_release( registration ); /* list */
    return TRUE;
}

static HRESULT connectivity_register( XTaskQueueHandle queue, void *context,
                                     XNetworkingConnectivityHintChangedCallback *callback,
                                     XTaskQueueRegistrationToken *token )
{
    struct connectivity_registration *registration;
    HRESULT hr;
    if ( !token ) return E_POINTER;
    token->token = 0;
    if ( !callback ) return E_POINTER;
    if ( !( registration = static_cast<connectivity_registration *>( calloc( 1, sizeof( *registration ) ) ) ) )
        return E_OUTOFMEMORY;
    registration->ref = 1; /* local */
    if ( queue )
        hr = ( x_threading_impl )->XTaskQueueDuplicateHandle( queue, &registration->queue );
    else
        hr = ( x_threading_impl )->XTaskQueueGetCurrentProcessTaskQueue( &registration->queue ) ? S_OK : E_FAIL;
    if ( SUCCEEDED( hr ) )
        hr = ( x_threading_impl )->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool,
                                                   XTaskQueueDispatchMode::ThreadPool, &registration->poll_queue );
    if ( FAILED( hr ) )
    {
        connectivity_release( registration );
        return hr;
    }
    registration->context = context;
    registration->callback = callback;
    connectivity_read_hint( &registration->hint );
    registration->revision = 1;
    registration->queued = TRUE;
    /* Local, list and initial notification refs. The initial callback may
     * unregister itself on an Immediate queue before Register returns. */
    InterlockedExchange( &registration->ref, 3 );
    AcquireSRWLockExclusive( &connectivity_lock );
    registration->token = token->token = ++connectivity_next_token;
    registration->next = connectivity_registrations;
    connectivity_registrations = registration;
    ReleaseSRWLockExclusive( &connectivity_lock );
    /* Polling is independent of the caller's Work dispatch mode. Titles often
     * pump only Completion while waiting for their first connectivity event. */
    hr = connectivity_schedule( registration );
    if ( SUCCEEDED( hr ) )
        hr = connectivity_submit( registration );
    else
        connectivity_release( registration ); /* initial notification not submitted */
    if ( FAILED( hr ) )
    {
        connectivity_unregister( *token, FALSE );
        token->token = 0;
    }
    INFO( "connectivity registration token=%llu hr=%08lx\n",
          ( unsigned long long )token->token, ( unsigned long )( UINT32 )hr );
    connectivity_release( registration ); /* local */
    return hr;
}
