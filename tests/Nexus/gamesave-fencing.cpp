/* SPDX-License-Identifier: MIT
 * Independent provider queues sharing one synthetic root and a closed transport.
 * Deliberately drain the older queue after a newer clean commit or deletion.
 */
#define main transfer_fixture_main
#include "gamesave-transfer.cpp"
#undef main
static HANDLE receive_entered, receive_resume;
static BOOL fencing_dialog_enabled;
static XGameSaveProvider *dialog_peer;
static HANDLE dialog_worker;
static HRESULT dialog_peer_result;
class FencingTransport final : public SaveTransport
{
public:
    bool CanResolveConflicts() const override { return fencing_dialog_enabled; }
    SaveConflictChoice ResolveConflict( const WCHAR * ) override;
    void CloseUser( XUserHandle u ) override { closedTransport.CloseUser( u ); }
    HRESULT Authorization( XUserHandle u, const char *a, char **out ) override { return closedTransport.Authorization( u, a, out ); }
    HRESULT DirectRequest( const WCHAR *m, const WCHAR *u, const WCHAR *h, const void *b, DWORD n, DWORD *s, BYTE **o, SIZE_T *z ) override
    { return closedTransport.DirectRequest( m, u, h, b, n, s, o, z ); }
    HRESULT SignedRequest( XUserHandle u, const char *method, const char *url, const char *auth, const char *headers,
                           const void *body, DWORD count, DWORD *status, BYTE **out, SIZE_T *size ) override
    {
        if ( !strcmp( method, "DELETE" ) && !strcmp( url, "https://fixture.invalid/Save,savedgame" ) )
        {
            ++remote.calls; *remote.metadata = 0; *remote.time = 0;
            *status = 204; *size = 2; *out = ( BYTE * )strdup( "{}" ); return *out ? S_OK : E_OUTOFMEMORY;
        }
        HRESULT hr = closedTransport.SignedRequest( u, method, url, auth, headers, body, count, status, out, size );
        if ( receive_entered && !strcmp( method, "GET" ) && !strcmp( url, "https://fixture.invalid/Save,savedgame" ) )
        { SetEvent( receive_entered ); if ( WaitForSingleObject( receive_resume, 5000 ) != WAIT_OBJECT_0 ) return E_ABORT; }
        return hr;
    }
};
static FencingTransport fencingTransport;
static void prepare_queue( XGameSaveProvider *p )
{
    p->transport = &fencingTransport; InitializeCriticalSection( &p->cloud_cs );
    p->upload_event = CreateEventW( NULL, FALSE, FALSE, NULL ); CHECK( "fence-queue-event", p->upload_event != NULL );
}
static void drain_queue( XGameSaveProvider *p )
{
    p->upload_stopping = TRUE;
    p->upload_thread = CreateThread( NULL, 0, upload_worker, p, 0, NULL ); CHECK( "fence-worker-created", p->upload_thread != NULL );
    CHECK( "fence-worker-drains", WaitForSingleObject( p->upload_thread, 15000 ) == WAIT_OBJECT_0 );
    CloseHandle( p->upload_thread ); p->upload_thread = NULL;
    CloseHandle( p->upload_event ); p->upload_event = NULL; DeleteCriticalSection( &p->cloud_cs );
}
static HRESULT write_progress( XGameSaveProvider *p, const char *value )
{
    XGameSaveContainer container = { p, const_cast<char *>( "Save" ) };
    update_op op = { const_cast<char *>( "progress" ), ( BYTE * )value, strlen( value ), FALSE };
    XGameSaveUpdate update{}; update.container = &container; update.count = 1; update.ops = &op;
    return submit_update( &update );
}
static void delayed_snapshot( unsigned scenario )
{
    printf( "CASE delayed other-provider snapshot scenario=%u\n", scenario ); memset( &remote, 0, sizeof( remote ) );
    auto a = device( FALSE, "fence-A" ), b = device( FALSE, "fence-B" ); strcpy( b->root, a->root );
    prepare_queue( a ); prepare_queue( b ); seed( a, "older", TRUE );
    queue_upload( a, "Save" ); CHECK( "fence-old-snapshot-pending", a->uploads && a->uploads->state.revision == 1 );
    if ( scenario ) CHECK( "fence-delete-succeeds", delete_container( b, "Save" ) == S_OK );
    if ( scenario != 2 )
    {
        const char *value = scenario == 3 ? "NEWER" : "recreated-progress";
        CHECK( "fence-newer-write", write_progress( b, value ) == S_OK );
        if ( scenario == 3 )
        {
            container_state recreated; CHECK( "fence-dirty-ABA-load", load_state( b, "Save", &recreated ) == S_OK );
            recreated.time = a->uploads->state.time;
            CHECK( "fence-dirty-ABA-persist-same-time", save_state( b, &recreated ) == S_OK ); free_state( &recreated );
            queue_upload( b, "Save" );
            CHECK( "fence-dirty-ABA-same-revision-time-size", b->uploads && b->uploads->state.dirty && b->uploads->state.revision == a->uploads->state.revision &&
                   b->uploads->state.time == a->uploads->state.time && b->uploads->state.blobs[0].size == a->uploads->state.blobs[0].size );
        }
        else drain_queue( b );
        container_state clean; CHECK( "fence-newer-index", load_state( b, "Save", &clean ) == S_OK );
        CHECK( "fence-newer-clean-or-pending", clean.dirty == ( scenario == 3 ) && clean.revision == ( scenario ? 1 : 2 ) ); free_state( &clean );
    }
    else { CloseHandle( b->upload_event ); b->upload_event = NULL; DeleteCriticalSection( &b->cloud_cs ); }
    const unsigned puts = remote.metadata_puts; char baseline[48]; strcpy( baseline, remote.time );
    drain_queue( a );
    CHECK( "fence-stale-snapshot-never-starts-metadata-put", remote.metadata_puts == puts );
    CHECK( "fence-stale-snapshot-does-not-rewrite-baseline", !strcmp( baseline, remote.time ) );
    if ( scenario != 2 )
    {
        const char *value = scenario == 3 ? "NEWER" : "recreated-progress";
        if ( scenario == 3 )
        {
            read_progress( b, value, TRUE ); drain_queue( b ); strcpy( baseline, remote.time );
        }
        read_progress( b, value, FALSE ); container_state current;
        CHECK( "fence-newer-revision-readable", load_state( b, "Save", &current ) == S_OK );
        CHECK( "fence-newer-visible-blob-size", current.count == 1 && current.blobs[0].size == strlen( value ) );
        CHECK( "fence-newer-remote-baseline-retained", !strcmp( current.remote, baseline ) ); free_state( &current );
        auto c = device( FALSE, "fence-cloud-reader" ); c->transport = &fencingTransport;
        CHECK( "fence-cloud-sync-readable", cloud_sync( c ) == S_OK ); read_progress( c, value, FALSE ); close_provider( c );
    }
    else
    {
        char directory[2048]; DWORD attributes; container_dir( a, "Save", directory, sizeof( directory ) );
        CHECK( "fence-delete-not-resurrected-locally", save_path_attributes( directory, &attributes ) == S_FALSE );
        CHECK( "fence-delete-not-resurrected-remotely", !*remote.metadata );
    }
    close_provider( a ); close_provider( b );
}
struct operation { XGameSaveProvider *provider; HRESULT hr; const char *value; };
static DWORD WINAPI sync_operation( void *context )
{ auto op = static_cast<operation *>( context ); op->hr = cloud_sync( op->provider ); return 0; }
static DWORD WINAPI write_operation( void *context )
{ auto op = static_cast<operation *>( context ); op->hr = write_progress( op->provider, op->value ); return 0; }
static void local_write_during_http( BOOL worker )
{
    printf( "CASE local mutation during blocked HTTP worker=%d\n", worker ); memset( &remote, 0, sizeof( remote ) );
    auto a = device( FALSE, "during-http-A" ), b = device( FALSE, "during-http-B" ); strcpy( b->root, a->root );
    a->transport = &fencingTransport; prepare_queue( b ); seed( a, "older", TRUE );
    remote.entered = CreateEventW( NULL, TRUE, FALSE, NULL ); remote.resume = CreateEventW( NULL, TRUE, FALSE, NULL );
    operation upload{ a }, write{ b, E_FAIL, "newest-local" }; HANDLE uploading;
    if ( worker ) { start_uploads( a ); queue_upload( a, "Save" ); uploading = NULL; }
    else uploading = CreateThread( NULL, 0, sync_operation, &upload, 0, NULL );
    CHECK( "fence-http-blocked", WaitForSingleObject( remote.entered, 2000 ) == WAIT_OBJECT_0 );
    HANDLE writing = CreateThread( NULL, 0, write_operation, &write, 0, NULL );
    BOOL wrote = WaitForSingleObject( writing, 1500 ) == WAIT_OBJECT_0;
    CHECK( "fence-local-submit-does-not-wait-on-network", wrote );
    container_state before_ack{};
    if ( wrote ) CHECK( "fence-newer-loaded-before-old-ack", load_state( b, "Save", &before_ack ) == S_OK );
    SetEvent( remote.resume ); CHECK( "fence-local-submit-completes", WaitForSingleObject( writing, 5000 ) == WAIT_OBJECT_0 && write.hr == S_OK );
    CloseHandle( writing );
    if ( worker )
    {
        EnterCriticalSection( &a->cs ); a->upload_stopping = TRUE; SetEvent( a->upload_event ); LeaveCriticalSection( &a->cs );
        CHECK( "fence-inflight-worker-completes", WaitForSingleObject( a->upload_thread, 5000 ) == WAIT_OBJECT_0 );
        CloseHandle( a->upload_thread ); a->upload_thread = NULL; CloseHandle( a->upload_event ); DeleteCriticalSection( &a->cloud_cs );
    }
    else { CHECK( "fence-sync-completes", WaitForSingleObject( uploading, 5000 ) == WAIT_OBJECT_0 && upload.hr == S_OK ); CloseHandle( uploading ); }
    CloseHandle( remote.entered ); CloseHandle( remote.resume ); remote.entered = remote.resume = NULL;
    read_progress( b, "newest-local", TRUE );
    if ( !worker && wrote )
    {
        CHECK( "fence-sync-snapshot-survives-baseline-only-advance", cloud_upload( b, &before_ack ) == S_OK );
        unsigned puts = remote.metadata_puts; drain_queue( b );
        CHECK( "fence-clean-queue-not-replayed-after-sync", remote.metadata_puts == puts );
    }
    else drain_queue( b );
    free_state( &before_ack ); read_progress( b, "newest-local", FALSE );
    auto c = device( FALSE, "during-http-reader" ); CHECK( "fence-newest-remote-readable", cloud_sync( c ) == S_OK );
    read_progress( c, "newest-local", FALSE ); close_provider( c ); close_provider( a ); close_provider( b );
}
static void local_write_during_receive( BOOL files )
{
    printf( "CASE staged receive races newer local files=%d\n", files ); memset( &remote, 0, sizeof( remote ) );
    auto source = device( files, "receive-source" ); seed( source, "download-old", TRUE );
    CHECK( "fence-receive-cloud-seed", cloud_sync( source ) == S_OK ); close_provider( source );
    auto a = device( files, "receive-A" ), b = device( files, "receive-B" ); strcpy( b->root, a->root );
    a->transport = &fencingTransport; prepare_queue( b ); seed( a, "local-old", FALSE );
    receive_entered = CreateEventW( NULL, TRUE, FALSE, NULL ); receive_resume = CreateEventW( NULL, TRUE, FALSE, NULL );
    operation receive{ a }, write{ b, E_FAIL, "newest-local" };
    HANDLE receiving = CreateThread( NULL, 0, sync_operation, &receive, 0, NULL );
    CHECK( "fence-receive-blocked", WaitForSingleObject( receive_entered, 2000 ) == WAIT_OBJECT_0 );
    HANDLE writing = CreateThread( NULL, 0, write_operation, &write, 0, NULL );
    CHECK( "fence-local-submit-during-receive", WaitForSingleObject( writing, 1500 ) == WAIT_OBJECT_0 );
    SetEvent( receive_resume ); CHECK( "fence-receive-local-write-completes", WaitForSingleObject( writing, 5000 ) == WAIT_OBJECT_0 && write.hr == S_OK );
    CHECK( "fence-stale-receive-rejected", WaitForSingleObject( receiving, 5000 ) == WAIT_OBJECT_0 && receive.hr == E_GS_CONTAINER_NOT_IN_SYNC );
    CloseHandle( writing ); CloseHandle( receiving ); CloseHandle( receive_entered ); CloseHandle( receive_resume ); receive_entered = receive_resume = NULL;
    read_progress( b, "newest-local", TRUE ); drain_queue( b ); read_progress( b, "newest-local", FALSE ); close_provider( a ); close_provider( b );
}
struct gate_operation { XGameSaveProvider *provider; HANDLE entered, resume; save_shared_lock *abandoned; HRESULT hr; BOOL data_lock = FALSE; };
static DWORD WINAPI hold_gate( void *context )
{
    auto op = static_cast<gate_operation *>( context ); op->abandoned = new save_shared_lock( op->provider, op->data_lock ? L"Local\\NexusGameSave-" : L"Local\\NexusGameSaveRemote-", 15000 );
    op->hr = op->abandoned->status; SetEvent( op->entered ); WaitForSingleObject( op->resume, 5000 );
    /* Deliberately emulate a stopped process: thread exit abandons its mutex. */
    return 0;
}
static void gate_timeout_and_abandonment()
{
    printf( "CASE bounded gate wait and abandoned owner\n" ); memset( &remote, 0, sizeof( remote ) );
    auto a = device( FALSE, "gate-root" ), b = device( FALSE, "gate-alias" );
    snprintf( b->root, sizeof( b->root ), "%s\\.\\", a->root );
    gate_operation op{ a, CreateEventW( NULL, TRUE, FALSE, NULL ), CreateEventW( NULL, TRUE, FALSE, NULL ) };
    HANDLE owner = CreateThread( NULL, 0, hold_gate, &op, 0, NULL );
    CHECK( "fence-gate-held", WaitForSingleObject( op.entered, 2000 ) == WAIT_OBJECT_0 && op.hr == S_OK );
    {
        save_remote_lock blocked( b, 40 );
        CHECK( "fence-gate-alias-bounded-timeout", blocked.status == HRESULT_FROM_WIN32( ERROR_TIMEOUT ) );
    }
    strcpy( b->root, a->root ); b->cloud = FALSE; CHECK( "fence-local-write-independent-of-remote-gate", write_progress( b, "newer-under-gate" ) == S_OK );
    SetEvent( op.resume ); CHECK( "fence-gate-owner-exits", WaitForSingleObject( owner, 2000 ) == WAIT_OBJECT_0 );
    { save_remote_lock recovered( b, 40 ); CHECK( "fence-abandoned-gate-recovered", recovered.status == S_OK ); }
    delete op.abandoned; CloseHandle( owner ); CloseHandle( op.entered ); CloseHandle( op.resume ); close_provider( a ); close_provider( b );
}
static void rejected_reacquire()
{
    printf( "CASE rejected lease after failed release\n" ); memset( &remote, 0, sizeof( remote ) );
    auto a = device( FALSE, "rejected-lease" ); seed( a, "retained", TRUE );
    CHECK( "fence-lease-initial-acquire", cloud_lock( a ) ); remote.fail_release = TRUE;
    CHECK( "fence-release-fails", FAILED( cloud_unlock( a, FALSE ) ) && a->locked );
    CHECK( "fence-rejected-reacquire-clears-stale-flag", !cloud_lock( a ) && !a->locked );
    container_state state{}; CHECK( "fence-rejected-load", load_state( a, "Save", &state ) == S_OK );
    CHECK( "fence-rejected-lease-does-not-upload", FAILED( cloud_upload( a, &state ) ) && !remote.metadata_puts && !remote.blob_puts );
    free_state( &state ); read_progress( a, "retained", TRUE ); remote.fail_release = FALSE; remote.locked = FALSE; close_provider( a );
}

static DWORD WINAPI dialog_peer_operation( void * )
{
    dialog_peer_result = write_progress( dialog_peer, "dialog-newest" );
    container_state state{};
    if ( SUCCEEDED( dialog_peer_result ) ) dialog_peer_result = load_state( dialog_peer, "Save", &state );
    if ( SUCCEEDED( dialog_peer_result ) ) dialog_peer_result = cloud_upload( dialog_peer, &state );
    free_state( &state ); return 0;
}
SaveConflictChoice FencingTransport::ResolveConflict( const WCHAR * )
{
    dialog_worker = CreateThread( NULL, 0, dialog_peer_operation, NULL, 0, NULL );
    CHECK( "fence-dialog-does-not-hold-data-or-remote-gate", WaitForSingleObject( dialog_worker, 2000 ) == WAIT_OBJECT_0 && dialog_peer_result == S_OK );
    return SaveConflictChoice::Cloud;
}
static void stale_conflict_choice()
{
    printf( "CASE conflict choice after other-provider commit\n" ); memset( &remote, 0, sizeof( remote ) );
    auto source = device( FALSE, "dialog-source" ); seed( source, "cloud-old", TRUE );
    CHECK( "fence-dialog-cloud-seed", cloud_sync( source ) == S_OK ); close_provider( source );
    auto a = device( FALSE, "dialog-A" ), b = device( FALSE, "dialog-B" ); strcpy( b->root, a->root );
    a->transport = &fencingTransport; prepare_queue( b ); seed( a, "local-old", TRUE );
    dialog_peer = b; dialog_peer_result = E_FAIL; fencing_dialog_enabled = TRUE;
    CHECK( "fence-stale-conflict-choice-rejected", cloud_sync( a ) == E_GS_CONTAINER_NOT_IN_SYNC );
    fencing_dialog_enabled = FALSE;
    CHECK( "fence-dialog-peer-finished", WaitForSingleObject( dialog_worker, 5000 ) == WAIT_OBJECT_0 ); CloseHandle( dialog_worker );
    read_progress( b, "dialog-newest", FALSE ); const unsigned puts = remote.metadata_puts;
    drain_queue( b ); CHECK( "fence-dialog-clean-snapshot-not-replayed", remote.metadata_puts == puts );
    read_progress( b, "dialog-newest", FALSE ); close_provider( a ); close_provider( b );
}

static void process_gate_abandonment()
{
    printf( "CASE separate process gate abandoned by external Stop\n" );
    auto provider = device( FALSE, "process-gate" ); provider->cloud = FALSE; seed( provider, "retained-progress", TRUE );
    char executable[2048], command[8192], event_name[128];
    GetModuleFileNameA( NULL, executable, sizeof( executable ) );
    snprintf( event_name, sizeof( event_name ), "Local\\NexusSaveFixtureReady-%lu", GetCurrentProcessId() );
    HANDLE ready = CreateEventA( NULL, TRUE, FALSE, event_name );
    snprintf( command, sizeof( command ), "\"%s\" --gate-child \"%s\" \"%s\"", executable, provider->root, event_name );
    STARTUPINFOA startup{}; startup.cb = sizeof( startup ); PROCESS_INFORMATION process{};
    BOOL created = CreateProcessA( NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process );
    CHECK( "fence-child-process-created", created );
    if ( created )
    {
        CHECK( "fence-child-process-owns-gate", WaitForSingleObject( ready, 3000 ) == WAIT_OBJECT_0 );
        { save_remote_lock blocked( provider, 40 ); CHECK( "fence-cross-process-gate-timeout", blocked.status == HRESULT_FROM_WIN32( ERROR_TIMEOUT ) ); }
        CHECK( "fence-external-stop-child", TerminateProcess( process.hProcess, 17 ) );
        CHECK( "fence-child-stopped", WaitForSingleObject( process.hProcess, 3000 ) == WAIT_OBJECT_0 );
        { save_remote_lock recovered( provider, 40 ); CHECK( "fence-cross-process-abandonment-recovers", recovered.status == S_OK ); }
        read_progress( provider, "retained-progress", TRUE ); CloseHandle( process.hThread ); CloseHandle( process.hProcess );
    }
    CloseHandle( ready ); close_provider( provider );
}

static void legacy_generation()
{
    printf( "CASE durable legacy generation and recreation\n" );
    auto provider = device( FALSE, "generation" ); provider->cloud = FALSE; seed( provider, "old", TRUE );
    container_state state{}; CHECK( "fence-legacy-read-no-invented-generation", load_state( provider, "Save", &state ) == S_OK && !state.incarnation[0] ); free_state( &state );
    auto first = snapshot_upload( provider, "Save" ); CHECK( "fence-legacy-snapshot-mints-generation", first && strlen( first->state.incarnation ) == 38 );
    auto second = snapshot_upload( provider, "Save" ); CHECK( "fence-generation-durable-not-per-read", first && second && !strcmp( first->state.incarnation, second->state.incarnation ) );
    CHECK( "fence-legacy-delete-local-success", delete_container( provider, "Save" ) == S_OK );
    CHECK( "fence-generation-recreate", write_progress( provider, "NEW" ) == S_OK );
    CHECK( "fence-recreation-new-generation", load_state( provider, "Save", &state ) == S_OK && first && strcmp( first->state.incarnation, state.incarnation ) );
    free_state( &state ); if ( first ) free_upload( first ); if ( second ) free_upload( second ); close_provider( provider );
}
static void files_revision_mutations()
{
    printf( "CASE Files zero-byte prune re-add and overflow preservation\n" );
    auto provider = device( TRUE, "files-mutation" ); provider->cloud = FALSE; seed( provider, "", FALSE );
    char folder[2048], directory[2048], raw[2048], cached[2048];
    snprintf( folder, sizeof( folder ), "%s\\.raw-view", provider->root );
    snprintf( directory, sizeof( directory ), "%s\\Save", folder ); files_mkdir( directory );
    snprintf( raw, sizeof( raw ), "%s\\progress", directory );
    files_cache_context prune{ folder, S_OK, TRUE };
    CHECK( "fence-files-prune", files_cache_visit( provider, "Save", &prune ) && prune.hr == S_OK );
    container_state state{}; CHECK( "fence-files-prune-revision", load_state( provider, "Save", &state ) == S_OK && state.revision == 2 && !state.count && state.incarnation[0] );
    state.dirty = FALSE; save_state( provider, &state ); free_state( &state );
    CHECK( "fence-files-raw-zero-created", files_write( raw, ( const BYTE * )"", 0 ) == S_OK );
    files_import_context context{ provider, 0 }; WIN32_FIND_DATAW info{};
    CHECK( "fence-files-zero-readd", files_import_one( folder, "Save", "progress", &info, &context ) == S_OK );
    CHECK( "fence-files-zero-readd-dirty-new-revision", load_state( provider, "Save", &state ) == S_OK && state.revision == 3 && state.dirty && state.count == 1 && !state.blobs[0].size );
    state.revision = ~(UINT64)0; state.dirty = FALSE; state.blobs[0].size = 3;
    CHECK( "fence-files-overflow-index-prepared", save_state( provider, &state ) == S_OK ); free_state( &state );
    blob_path( provider, "Save", "progress", cached, sizeof( cached ) );
    CHECK( "fence-files-old-cached-bytes", files_write( cached, ( const BYTE * )"old", 3 ) == S_OK );
    CHECK( "fence-files-new-raw-bytes", files_write( raw, ( const BYTE * )"new", 3 ) == S_OK ); info.nFileSizeLow = 3; context.total = 0;
    CHECK( "fence-files-overflow-fails-before-cache-write", files_import_one( folder, "Save", "progress", &info, &context ) == HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW ) );
    BYTE *bytes = NULL; SIZE_T size = 0;
    CHECK( "fence-files-overflow-keeps-old-bytes", read_file( cached, &bytes, &size ) == S_OK && size == 3 && !memcmp( bytes, "old", 3 ) ); free( bytes );
    CHECK( "fence-files-overflow-keeps-old-index", load_state( provider, "Save", &state ) == S_OK && state.revision == ~(UINT64)0 && !state.dirty && state.blobs[0].size == 3 );
    free_state( &state ); close_provider( provider );
}

static void missing_root_alias_identity()
{
    printf( "CASE missing root beneath directory alias keeps lock identity\n" );
    auto a = device( FALSE, "alias-owner" ), b = device( FALSE, "alias-peer" );
    char real[2048], alias[2048]; WCHAR real_w[4096], alias_w[4096];
    snprintf( real, sizeof( real ), "%s\\alias-real", root ); snprintf( alias, sizeof( alias ), "%s\\alias-link", root );
    CHECK( "fence-alias-real-parent-created", files_mkdir( real ) == S_OK );
    save_wide_path( real, real_w ); save_wide_path( alias, alias_w );
    CHECK( "fence-directory-alias-created", CreateSymbolicLinkW( alias_w, real_w, SYMBOLIC_LINK_FLAG_DIRECTORY | 2 ) );
    for ( unsigned data_lock = 0; data_lock < 2; data_lock++ )
    {
        snprintf( a->root, sizeof( a->root ), "%s\\missing-%u\\child", alias, data_lock );
        snprintf( b->root, sizeof( b->root ), "%s\\missing-%u\\child", real, data_lock );
        WCHAR before[4096], after[4096];
        CHECK( "fence-missing-alias-canonicalized", save_canonical_root( a->root, before ) == S_OK );
        gate_operation op{ a, CreateEventW( NULL, TRUE, FALSE, NULL ), CreateEventW( NULL, TRUE, FALSE, NULL ) };
        op.data_lock = data_lock;
        HANDLE owner = CreateThread( NULL, 0, hold_gate, &op, 0, NULL );
        CHECK( "fence-missing-root-lock-held", WaitForSingleObject( op.entered, 2000 ) == WAIT_OBJECT_0 && op.hr == S_OK );
        CHECK( "fence-missing-root-created-through-real-parent", files_mkdir( b->root ) == S_OK );
        CHECK( "fence-created-root-same-canonical-identity", save_canonical_root( b->root, after ) == S_OK && !wcscmp( before, after ) );
        {
            save_shared_lock blocked( b, data_lock ? L"Local\\NexusGameSave-" : L"Local\\NexusGameSaveRemote-", 40 );
            CHECK( "fence-create-does-not-bypass-existing-lock", blocked.status == HRESULT_FROM_WIN32( ERROR_TIMEOUT ) );
        }
        SetEvent( op.resume ); CHECK( "fence-alias-owner-exits", WaitForSingleObject( owner, 2000 ) == WAIT_OBJECT_0 );
        delete op.abandoned; CloseHandle( owner ); CloseHandle( op.entered ); CloseHandle( op.resume );
    }
    a->cloud = b->cloud = FALSE; close_provider( a ); close_provider( b );
}

int main( int argc, char **argv )
{
    if ( argc == 4 && !strcmp( argv[1], "--gate-child" ) )
    {
        XGameSaveProvider provider{}; lstrcpynA( provider.root, argv[2], sizeof( provider.root ) );
        save_remote_lock gate( &provider );
        if ( FAILED( gate.status ) ) return 2;
        HANDLE ready = OpenEventA( EVENT_MODIFY_STATE, FALSE, argv[3] );
        if ( !ready ) return 3;
        SetEvent( ready ); CloseHandle( ready ); Sleep( INFINITE ); return 4;
    }
    setvbuf( stdout, NULL, _IONBF, 0 );
    InitializeLogging(); INITIALIZE_OPTIONS options{}; options.isInlineConfig = TRUE;
    options.gameConfig = "<Game><Identity Name='Nexus.SaveFencingFixture' Publisher='CN=Fixture'/></Game>";
    CHECK( "fence-config", nexus::InitializeGameConfiguration( &options ) == S_OK );
    char temp[1024]; GetTempPathA( sizeof( temp ), temp ); snprintf( root, sizeof( root ), "%snexus-fencing-%lu-%I64u", temp, GetCurrentProcessId(), GetTickCount64() );
    create_directories( root ); SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    for ( unsigned scenario = 0; scenario < 4; scenario++ ) delayed_snapshot( scenario );
    legacy_generation(); files_revision_mutations();
    local_write_during_http( FALSE ); local_write_during_http( TRUE );
    local_write_during_receive( FALSE ); local_write_during_receive( TRUE ); gate_timeout_and_abandonment(); missing_root_alias_identity(); process_gate_abandonment(); rejected_reacquire(); stale_conflict_choice();
    printf( "CHECKS %u FAILURES %u\n", checks, failures ); return failures ? 1 : 0;
}
