/* SPDX-License-Identifier: MIT
 * Actual index/read/update/sync paths and a closed in-memory transport.
 * Every payload and provider root is synthetic. No real account or network.
 */
#define main transfer_fixture_main
#include "gamesave-transfer.cpp"
#undef main
#include <string>
#include <vector>
static BOOLEAN CALLBACK count_index_container( const XGameSaveContainerInfo *, void *context )
{
    ++*static_cast<unsigned *>( context ); return TRUE;
}
static bool raw_equals( const char *path, const std::string &expected )
{
    BYTE *data = NULL; SIZE_T size = 0; HRESULT hr = read_file( path, &data, &size );
    bool same = hr == S_OK && size == expected.size() && !memcmp( data, expected.data(), size );
    free( data ); return same;
}
static void invalid_index( BOOL files, BOOL listed, const std::string &text )
{
    memset( &remote, 0, sizeof( remote ) );
    if ( listed )
    {
        auto source = device( files, "index-cloud" ); seed( source, "cloud-old", TRUE );
        CHECK( "index-prime-remote", cloud_sync( source ) == S_OK ); close_provider( source );
    }
    auto p = device( files, "index-local" ); seed( p, "local-new", TRUE );
    char directory[2048], index[2048], blob[2048];
    container_dir( p, "Save", directory, sizeof( directory ) ); snprintf( index, sizeof( index ), "%s\\index", directory );
    blob_path( p, "Save", "progress", blob, sizeof( blob ) );
    CHECK( "index-corrupt-fixture", write_file( index, text.data(), text.size() ) == S_OK );
    container_state state;
    CHECK( "invalid-index-load-fails-closed", load_state( p, "Save", &state ) == HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) ); free_state( &state );
    unsigned containers = 0;
    CHECK( "invalid-index-enumeration-reports-error", enumerate_containers( p, NULL, NULL, &containers, count_index_container ) == HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) );
    CHECK( "invalid-index-not-announced", containers == 0 );
    XGameSaveContainer container = { p, const_cast<char *>( "Save" ) };
    auto req = create_read_request( &container, NULL, 0 );
    CHECK( "invalid-index-read-fails-closed", req && prepare_read( req ) == HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) ); free_read_request( req );
    XGameSaveUpdate update{}; update.container = &container;
    p->cloud = FALSE;
    CHECK( "invalid-index-update-does-not-bless-state", submit_update( &update ) == HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) );
    CHECK( "invalid-index-update-preserves-index", raw_equals( index, text ) );
    CHECK( "invalid-index-update-preserves-progress", raw_equals( blob, "local-new" ) );
    // Reset corrupt input only to isolate cloud-sync's independent guard in the
    // before-state reproduction, where submit_update wrongly rewrites it.
    CHECK( "index-reset-fixture", write_file( index, text.data(), text.size() ) == S_OK );
    p->cloud = TRUE; const unsigned writes = remote.metadata_puts, downloads = p->downloaded;
    CHECK( "invalid-index-sync-fails-closed", cloud_sync( p ) == HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) );
    CHECK( "invalid-index-no-remote-write", remote.metadata_puts == writes );
    CHECK( "invalid-index-no-download", p->downloaded == downloads );
    CHECK( "invalid-index-sync-preserves-index", raw_equals( index, text ) );
    CHECK( "invalid-index-sync-preserves-progress", raw_equals( blob, "local-new" ) );
    close_provider( p );
}
static void malformed_indexes( BOOL files )
{
    const std::string base = "display 53617665\ntime 0\nremote -\ndirty 1\n";
    const std::string name = files ? "name 53617665\n" : "";
    std::vector<std::string> cases = {
        "", "junk\n", "display 53617665\ntime 0\nremote -\n" + name,
        base + name + "revision 1", base + name + "time 2\n",
        "display 53617665\ntime 18446744073709551616\nremote -\ndirty 1\n" + name,
        "display 53617665\ntime -1\nremote -\ndirty 1\n" + name,
        "display 0g\ntime 0\nremote -\ndirty 1\n" + name,
        "display 53617665\ntime 0\nremote -\ndirty 2\n" + name,
        base + name + "revision -1\n", base + name + "blob 70726f6772657373 nope -\n",
        base + name + "blob 70726f6772657373 4294967296 -\n", base + name + "blob 70726f6772657373 9\n",
        base + name + "blob 00 9 -\n", base + name + "blob 70726f6772657373 9 -\nblob 70726f6772657373 9 -\n",
        base + name + std::string( "\0hidden\n", 8 ), base + name + "future-unknown 1\n"
    };
    if ( files ) { cases.push_back( base ); cases.push_back( base + "name 4f74686572\n" ); cases.push_back( base + name + name ); }
    for ( unsigned i = 0; i < cases.size(); i++ ) for ( unsigned listed = 0; listed < 2; listed++ )
    { printf( "CASE invalid index files=%d listed=%u case=%u\n", files, listed, i ); invalid_index( files, listed, cases[i] ); }
}
static void valid_legacy_indexes( BOOL files )
{
    for ( unsigned revision = 0; revision < 2; revision++ )
    {
        auto p = device( files, "legacy-index" ); p->cloud = FALSE;
        char directory[2048], index[2048]; container_dir( p, "Save", directory, sizeof( directory ) ); create_directories( directory );
        snprintf( index, sizeof( index ), "%s\\index", directory );
        const std::string text = std::string( "display \ntime 0\nremote opaque:baseline\ndirty 0\n" ) + ( revision ? "revision 0\n" : "" ) +
                                 ( files ? "name 53617665\n" : "" ) + "blob 4a 0 opaque:atom\n";
        CHECK( "legacy-index-written", write_file( index, text.data(), text.size() ) == S_OK );
        container_state state; CHECK( "legacy-valid-index-readable", load_state( p, "Save", &state ) == S_OK );
        CHECK( "legacy-empty-display-zero-values", state.display && !*state.display && !state.time && !state.revision && !state.dirty && state.count == 1 );
        CHECK( "legacy-upper-hex-zero-blob-opaque-atom", state.count && !strcmp( state.blobs[0].name, "J" ) && !state.blobs[0].size && !strcmp( state.blobs[0].atom, "opaque:atom" ) );
        free_state( &state ); CHECK( "legacy-read-does-not-rewrite", raw_equals( index, text ) ); close_provider( p );
    }
}
int main()
{
    InitializeLogging(); INITIALIZE_OPTIONS options{}; options.isInlineConfig = TRUE;
    options.gameConfig = "<Game><Identity Name='Nexus.InvalidIndexFixture' Publisher='CN=Fixture'/></Game>";
    CHECK( "index-config", nexus::InitializeGameConfiguration( &options ) == S_OK );
    char temp[1024]; GetTempPathA( sizeof( temp ), temp ); snprintf( root, sizeof( root ), "%snexus-index-%lu-%I64u", temp, GetCurrentProcessId(), GetTickCount64() );
    create_directories( root ); SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    for ( unsigned files = 0; files < 2; files++ ) { malformed_indexes( files ); valid_legacy_indexes( files ); }
    printf( "CHECKS %u FAILURES %u\n", checks, failures ); return failures ? 1 : 0;
}
