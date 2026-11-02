/* SPDX-License-Identifier: MIT
 * Real filesystem/transaction implementation, injected OS failures and killed
 * child processes. All data is synthetic and the transport is closed. */
#include "../../src/private.h"
#include <string>
#include <vector>
static BOOL WINAPI atomic_write( HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED );
static BOOL WINAPI atomic_flush( HANDLE );
static BOOL WINAPI atomic_move( LPCWSTR, LPCWSTR, DWORD );
static BOOL WINAPI atomic_delete( LPCWSTR );
static BOOL WINAPI atomic_link( LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES );
static void *atomic_malloc( size_t );
static void *atomic_calloc( size_t, size_t );
static void *atomic_realloc( void *, size_t );
static char *atomic_strdup( const char * );
#define malloc atomic_malloc
#define calloc atomic_calloc
#define realloc atomic_realloc
#define strdup atomic_strdup
#define CreateHardLinkW atomic_link
#define WriteFile atomic_write
#define FlushFileBuffers atomic_flush
#define MoveFileExW atomic_move
#define DeleteFileW atomic_delete
#define main transfer_fixture_main
#include "gamesave-transfer.cpp"
#undef main
#undef WriteFile
#undef FlushFileBuffers
#undef MoveFileExW
#undef DeleteFileW
#undef CreateHardLinkW
#undef malloc
#undef calloc
#undef realloc
#undef strdup

static unsigned fault;
static unsigned allocation_fail_at, allocation_calls, links;
static bool allocation_failure() { return allocation_fail_at && ++allocation_calls == allocation_fail_at; }
static void *atomic_malloc( size_t size ) { return allocation_failure() ? NULL : malloc( size ); }
static void *atomic_calloc( size_t count, size_t size ) { return allocation_failure() ? NULL : calloc( count, size ); }
static void *atomic_realloc( void *value, size_t size ) { return allocation_failure() ? NULL : realloc( value, size ); }
static char *atomic_strdup( const char *value ) { return allocation_failure() ? NULL : strdup( value ); }
static BOOL WINAPI atomic_link( LPCWSTR to, LPCWSTR from, LPSECURITY_ATTRIBUTES security )
{
    if ( fault == 7 ) { SetLastError( ERROR_NOT_SUPPORTED ); return FALSE; }
    BOOL result = CreateHardLinkW( to, from, security );
    if ( result ) links++;
    return result;
}
static HANDLE index_flush;
static BOOL WINAPI atomic_write( HANDLE file, LPCVOID data, DWORD size, LPDWORD written, LPOVERLAPPED overlapped )
{
    WCHAR path[4096];
    bool staged = GetFinalPathNameByHandleW( file, path, ARRAY_SIZE( path ), 0 ) && wcsstr( path, L".local-update-" );
    if ( staged && fault == 1 && size == 5 && !memcmp( data, "new-B", 5 ) )
    { *written = 0; SetLastError( ERROR_DISK_FULL ); return FALSE; }
    if ( staged && ( fault == 2 || fault == 10 ) && wcsstr( path, L"index.tmp" ) &&
         std::string( static_cast<const char *>( data ), size ).find( "revision 2\n" ) != std::string::npos )
        index_flush = file;
    return WriteFile( file, data, size, written, overlapped );
}
static BOOL WINAPI atomic_flush( HANDLE file )
{
    if ( file == index_flush && fault == 2 ) { SetLastError( ERROR_DISK_FULL ); return FALSE; }
    BOOL ok = FlushFileBuffers( file );
    if ( ok && file == index_flush && fault == 10 ) TerminateProcess( GetCurrentProcess(), 77 );
    return ok;
}
static BOOL WINAPI atomic_move( LPCWSTR from, LPCWSTR to, DWORD flags )
{
    bool old = wcsstr( to, L".local-update-" ) && wcsstr( to, L"\\previous" );
    bool publish = wcsstr( from, L".local-update-" ) && wcsstr( from, L"\\next\\" ) && !wcsstr( to, L".local-update-" );
    bool rollback = wcsstr( from, L".local-update-" ) && wcsstr( from, L"\\previous" );
    if ( ( fault == 3 && old ) || ( ( fault == 4 || fault == 5 ) && publish ) || ( fault == 5 && rollback ) )
    { SetLastError( ERROR_ACCESS_DENIED ); return FALSE; }
    BOOL ok = MoveFileExW( from, to, flags );
    if ( ok && ( ( fault == 11 && old ) || ( fault == 12 && publish ) ) ) TerminateProcess( GetCurrentProcess(), 77 );
    return ok;
}
static BOOL WINAPI atomic_delete( LPCWSTR path )
{
    if ( fault == 6 && wcsstr( path, L".local-update-" ) && wcsstr( path, L"\\previous\\" ) )
    { SetLastError( ERROR_ACCESS_DENIED ); return FALSE; }
    return DeleteFileW( path );
}

static void seed_pair( XGameSaveProvider *p )
{
    seed( p, "old-A", FALSE );
    container_state state;
    CHECK( "pair-load", load_state( p, "Save", &state ) == S_OK );
    auto entry = add_blob( &state, "second" );
    CHECK( "pair-entry", entry != NULL );
    if ( entry ) entry->size = 5;
    char path[2048]; blob_path( p, "Save", "second", path, sizeof( path ) );
    CHECK( "pair-write", write_file( path, "old-B", 5 ) == S_OK );
    CHECK( "pair-index", save_state( p, &state ) == S_OK );
    free_state( &state );
}
static HRESULT update_pair( XGameSaveProvider *p, BOOL remove = FALSE, const char *a = "new-A", const char *b = "new-B" )
{
    XGameSaveContainer container = { p, const_cast<char *>( "Save" ) };
    update_op ops[] = { { const_cast<char *>( "progress" ), ( BYTE * )a, remove ? 0u : strlen( a ), remove },
                        { const_cast<char *>( "second" ), ( BYTE * )b, strlen( b ), FALSE } };
    XGameSaveUpdate update{}; update.container = &container; update.count = 2; update.ops = ops;
    return submit_update( &update );
}
static void expect_pair( XGameSaveProvider *p, const char *a, const char *b, UINT64 revision, BOOL dirty )
{
    container_state state;
    CHECK( "pair-index-readable", load_state( p, "Save", &state ) == S_OK );
    CHECK( "pair-whole-revision", state.count == 2 && state.revision == revision && state.dirty == dirty );
    free_state( &state );
    for ( unsigned i = 0; i < 2; i++ )
    {
        const char *value = i ? b : a;
        char path[2048]; BYTE *data = NULL; SIZE_T size = 0;
        blob_path( p, "Save", i ? "second" : "progress", path, sizeof( path ) );
        HRESULT hr = read_file( path, &data, &size );
        CHECK( "pair-whole-bytes", hr == S_OK && size == strlen( value ) && !memcmp( data, value, size ) );
        free( data );
    }
}
static void faults_retain_whole_save()
{
    for ( unsigned scenario = 1; scenario <= 6; scenario++ )
    {
        printf( "CASE atomic failure %u\n", scenario );
        auto p = device( FALSE, "atomic-fault" ); p->cloud = FALSE;
        seed_pair( p ); index_flush = NULL; fault = scenario;
        HRESULT hr = update_pair( p );
        CHECK( "failure-or-committed-cleanup", scenario == 6 ? hr == S_OK : FAILED( hr ) );
        if ( scenario == 5 )
        {
            container_state state;
            CHECK( "failed-rollback-not-empty-save", FAILED( load_state( p, "Save", &state ) ) );
            free_state( &state );
        }
        if ( scenario == 6 )
        {
            save_root_lock lock( p );
            CHECK( "cleanup-retains-discoverable-identity", recover_local_updates( p ) == S_OK );
        }
        fault = 0;
        expect_pair( p, scenario == 6 ? "new-A" : "old-A", scenario == 6 ? "new-B" : "old-B",
                     scenario == 6 ? 2 : 1, scenario == 6 );
        CHECK( "retry-after-fault", update_pair( p ) == S_OK );
        expect_pair( p, "new-A", "new-B", scenario == 6 ? 3 : 2, TRUE );
        close_provider( p );
    }
    auto p = device( FALSE, "delete-then-failure" ); p->cloud = FALSE;
    seed_pair( p ); fault = 1;
    CHECK( "failed-write-rolls-back-delete", FAILED( update_pair( p, TRUE ) ) );
    fault = 0;
    expect_pair( p, "old-A", "old-B", 1, FALSE );
    char path[2048]; WCHAR wide[4096];
    blob_path( p, "Save", "second", path, sizeof( path ) ); save_wide_path( path, wide );
    HANDLE blocked = CreateFileW( wide, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
    CHECK( "second-blob-locked", blocked != INVALID_HANDLE_VALUE );
    CHECK( "locked-second-fails-whole-update", FAILED( update_pair( p ) ) );
    CloseHandle( blocked );
    expect_pair( p, "old-A", "old-B", 1, FALSE );
    close_provider( p );
}

static void killed_writer_recovers( unsigned scenario )
{
    printf( "CASE killed writer %u\n", scenario );
    memset( &remote, 0, sizeof( remote ) );
    auto p = device( FALSE, "killed-writer" ); p->cloud = FALSE;
    seed_pair( p );
    WCHAR exe[4096], directory[4096], command[9000];
    GetModuleFileNameW( NULL, exe, ARRAY_SIZE( exe ) );
    MultiByteToWideChar( CP_UTF8, 0, p->root, -1, directory, ARRAY_SIZE( directory ) );
    swprintf( command, ARRAY_SIZE( command ), L"\"%ls\" --child %u \"%ls\"", exe, scenario, directory );
    STARTUPINFOW startup{}; PROCESS_INFORMATION process{}; startup.cb = sizeof( startup );
    BOOL launched = CreateProcessW( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process );
    CHECK( "kill-child-created", launched );
    if ( !launched ) { close_provider( p ); return; }
    DWORD wait = WaitForSingleObject( process.hProcess, 15000 );
    if ( wait != WAIT_OBJECT_0 ) { TerminateProcess( process.hProcess, 78 ); WaitForSingleObject( process.hProcess, 5000 ); }
    DWORD code = 0; GetExitCodeProcess( process.hProcess, &code );
    printf( "CHILD boundary=%u wait=%lu exit=%lu\n", scenario, wait, code );
    CHECK( "killed-at-injected-boundary", wait == WAIT_OBJECT_0 && code == 77 );
    CloseHandle( process.hThread ); CloseHandle( process.hProcess );
    // Synchronization must recover even if enumeration would otherwise miss
    // the active directory between the two commit renames.
    p->cloud = TRUE;
    CHECK( "restart-sync-recovers-first", cloud_sync( p ) == S_OK );
    expect_pair( p, scenario == 12 ? "new-A" : "old-A", scenario == 12 ? "new-B" : "old-B",
                 scenario == 12 ? 2 : 1, FALSE );
    auto other = device( FALSE, "cloud-after-kill" );
    CHECK( "recovered-whole-cloud-download", cloud_sync( other ) == S_OK );
    read_progress( other, scenario == 12 ? "new-A" : "old-A", FALSE );
    close_provider( other ); close_provider( p );
}

struct concurrent_case { XGameSaveProvider *p; LONG *finished; bool ok; unsigned writer; };
static DWORD WINAPI concurrent_write( void *context )
{
    auto c = static_cast<concurrent_case *>( context ); c->ok = true;
    for ( unsigned i = 0; i < 20; i++ )
    {
        char value[16]; snprintf( value, sizeof( value ), "%u-%04u", c->writer, i );
        if ( FAILED( update_pair( c->p, FALSE, value, value ) ) ) { c->ok = false; break; }
    }
    InterlockedIncrement( c->finished ); return 0;
}
static void concurrent_providers()
{
    auto a = device( FALSE, "concurrent-A" ), b = device( FALSE, "concurrent-B" ), reader = device( FALSE, "concurrent-reader" );
    a->cloud = b->cloud = reader->cloud = FALSE;
    strcpy( b->root, a->root ); strcpy( reader->root, a->root );
    seed_pair( a ); CHECK( "concurrent-initial-pair", update_pair( a, FALSE, "same", "same" ) == S_OK );
    LONG finished = 0; concurrent_case work[2] = { { a, &finished, false, 1 }, { b, &finished, false, 2 } };
    HANDLE threads[2] = { CreateThread( NULL, 0, concurrent_write, &work[0], 0, NULL ),
                          CreateThread( NULL, 0, concurrent_write, &work[1], 0, NULL ) };
    CHECK( "concurrent-writers-created", threads[0] && threads[1] );
    bool consistent = true; unsigned reads = 0;
    XGameSaveContainer container = { reader, const_cast<char *>( "Save" ) };
    while ( InterlockedCompareExchange( &finished, 0, 0 ) != 2 && reads < 2000 )
    {
        auto req = create_read_request( &container, NULL, 0 );
        if ( !req || FAILED( prepare_read( req ) ) || req->preparedCount != 2 ) consistent = false;
        else
        {
            std::vector<BYTE> bytes( req->preparedSize ); layout_read( req, bytes.data() );
            auto blobs = reinterpret_cast<XGameSaveBlob *>( bytes.data() );
            if ( blobs[0].info.size != blobs[1].info.size || memcmp( blobs[0].data, blobs[1].data, blobs[0].info.size ) )
                consistent = false;
        }
        free_read_request( req ); reads++; Sleep( 1 );
    }
    CHECK( "concurrent-readers-never-see-mixed-revisions", consistent && reads );
    CHECK( "concurrent-writers-finish", WaitForMultipleObjects( 2, threads, TRUE, 15000 ) == WAIT_OBJECT_0 );
    CHECK( "concurrent-writers-succeed", work[0].ok && work[1].ok );
    for ( HANDLE thread : threads ) CloseHandle( thread );
    container_state state;
    CHECK( "concurrent-final-index", load_state( a, "Save", &state ) == S_OK );
    CHECK( "concurrent-no-lost-updates", state.revision == 42 );
    free_state( &state ); close_provider( a ); close_provider( b ); close_provider( reader );
}

static void allocation_failures()
{
    unsigned covered = 0;
    for ( unsigned point = 1; point <= 100; point++ )
    {
        auto p = device( FALSE, "allocation-fault" ); p->cloud = FALSE;
        seed_pair( p ); allocation_calls = 0; allocation_fail_at = point;
        HRESULT hr = update_pair( p );
        const bool hit = allocation_calls >= point;
        allocation_fail_at = 0;
        CHECK( "allocation-error-visible", hit ? FAILED( hr ) : hr == S_OK );
        expect_pair( p, hit ? "old-A" : "new-A", hit ? "old-B" : "new-B", hit ? 1 : 2, !hit );
        close_provider( p );
        if ( !hit ) break;
        covered++;
    }
    printf( "ALLOCATION BOUNDARIES %u\n", covered );
    CHECK( "allocation-fault-coverage", covered >= 10 && covered < 100 );
}

static void preserve_files_and_copy_fallback()
{
    auto p = device( FALSE, "preserve-extra-files" ); p->cloud = FALSE; seed_pair( p );
    char dir[2048], extra[2048], readonly[2048]; WCHAR wide[4096];
    container_dir( p, "Save", dir, sizeof( dir ) );
    snprintf( extra, sizeof( extra ), "%s\\note-\xc4\x8d.tmp", dir );
    snprintf( readonly, sizeof( readonly ), "%s\\readonly-extra", dir );
    CHECK( "extra-unicode-temp-seed", write_file( extra, "KEEP", 4 ) == S_OK );
    CHECK( "readonly-extra-seed", write_file( readonly, "KEEP", 4 ) == S_OK );
    save_wide_path( readonly, wide ); CHECK( "readonly-extra-attribute", SetFileAttributesW( wide, FILE_ATTRIBUTE_READONLY ) );
    links = 0; fault = 1;
    CHECK( "extra-failed-update", FAILED( update_pair( p ) ) );
    CHECK( "readonly-original-attribute-retained", GetFileAttributesW( wide ) & FILE_ATTRIBUTE_READONLY );
    fault = 0; CHECK( "extra-commit", update_pair( p ) == S_OK );
    CHECK( "unchanged-files-share-blocks", links > 0 );
    CHECK( "readonly-committed-attribute-retained", GetFileAttributesW( wide ) & FILE_ATTRIBUTE_READONLY );
    for ( const char *path : { extra, readonly } )
    {
        BYTE *data = NULL; SIZE_T size = 0; HRESULT hr = read_file( path, &data, &size );
        CHECK( "extra-file-preserved", hr == S_OK && size == 4 && !memcmp( data, "KEEP", 4 ) ); free( data );
    }
    fault = 7; CHECK( "no-hardlinks-copy-fallback", update_pair( p ) == S_OK ); fault = 0;
    expect_pair( p, "new-A", "new-B", 3, TRUE );
    close_provider( p );
}

static BOOLEAN CALLBACK count_container( const XGameSaveContainerInfo *, void *context )
{
    ++*static_cast<unsigned *>( context ); return TRUE;
}
static void missing_index_is_not_new_save()
{
    memset( &remote, 0, sizeof( remote ) );
    auto p = device( FALSE, "orphaned-blobs" ); p->cloud = FALSE; seed_pair( p );
    char directory[2048], path[2048]; WCHAR wide[4096];
    container_dir( p, "Save", directory, sizeof( directory ) );
    snprintf( path, sizeof( path ), "%s\\index", directory ); save_wide_path( path, wide );
    CHECK( "missing-index-fixture", DeleteFileW( wide ) );
    CHECK( "missing-index-does-not-reinitialize", FAILED( update_pair( p ) ) );
    CHECK( "missing-index-not-authoritative-empty-cloud", FAILED( cloud_sync( p ) ) );
    CHECK( "missing-index-no-cloud-write", remote.metadata_puts == 0 );
    unsigned enumerated = 0;
    CHECK( "missing-index-enumeration-reports-error", FAILED( enumerate_containers( p, NULL, NULL, &enumerated, count_container ) ) );
    XGameSaveContainer container = { p, const_cast<char *>( "Save" ) };
    auto req = create_read_request( &container, NULL, 0 );
    CHECK( "missing-index-read-is-not-successful-empty", req && FAILED( prepare_read( req ) ) );
    free_read_request( req );
    for ( const char *name : { "progress", "second" } )
    {
        BYTE *data = NULL; SIZE_T size = 0; blob_path( p, "Save", name, path, sizeof( path ) );
        CHECK( "missing-index-retains-orphaned-bytes", read_file( path, &data, &size ) == S_OK && size == 5 && !memcmp( data, "old-", 4 ) );
        free( data );
    }
    close_provider( p );
    p = device( FALSE, "new-container-atomic" ); p->cloud = FALSE;
    fault = 1; CHECK( "new-container-aborted-write", FAILED( update_pair( p ) ) ); fault = 0;
    container_state state;
    HRESULT hr = load_state( p, "Save", &state );
    CHECK( "new-container-abort-leaves-no-visible-state", hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) );
    free_state( &state );
    CHECK( "new-container-retry-commits", update_pair( p ) == S_OK );
    expect_pair( p, "new-A", "new-B", 1, TRUE );
    close_provider( p );
}

int main( int argc, char **argv )
{
    InitializeLogging(); INITIALIZE_OPTIONS options{}; options.isInlineConfig = TRUE;
    options.gameConfig = "<Game><Identity Name='Nexus.AtomicSaveFixture' Publisher='CN=Fixture'/></Game>";
    CHECK( "atomic-config", nexus::InitializeGameConfiguration( &options ) == S_OK );
    char temp[1024]; GetTempPathA( sizeof( temp ), temp );
    snprintf( root, sizeof( root ), "%snexus-atomic-%lu-%I64u", temp, GetCurrentProcessId(), GetTickCount64() );
    create_directories( root ); SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    if ( argc == 4 && !strcmp( argv[1], "--child" ) )
    {
        auto p = device( FALSE, "child" ); p->cloud = FALSE; strcpy( p->root, argv[3] );
        fault = atoi( argv[2] );
        HRESULT result = update_pair( p );
        printf( "CHILD unexpected return boundary=%u hr=%#lx\n", fault, result );
        close_provider( p ); return 79;
    }
    faults_retain_whole_save();
    for ( unsigned scenario = 10; scenario <= 12; scenario++ ) killed_writer_recovers( scenario );
    concurrent_providers();
    allocation_failures();
    preserve_files_and_copy_fallback();
    missing_index_is_not_new_save();
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
