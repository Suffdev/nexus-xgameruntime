/* SPDX-License-Identifier: MIT
 * A committed remote revision remains the baseline if releasing the session
 * fails. Reuse the actual upload implementation and closed two-device fixture.
 */
#define main transfer_fixture_main
#include "gamesave-transfer.cpp"
#undef main

static void committed_upload_then_release_failure( BOOL files, BOOL changed_elsewhere )
{
    struct XGameSaveProvider *a, *b;
    struct container_state s;
    char saved_root[2048];
    printf( "CASE committed metadata, failed release, relaunch files=%d other-device=%d\n", files,
            changed_elsewhere );
    memset( &remote, 0, sizeof( remote ) );
    a = device( files, "commit-A" );
    seed( a, "durable-local-progress", TRUE );
    strcpy( saved_root, a->root );
    CHECK( "commit-load-state", load_state( a, "Save", &s ) == S_OK );
    remote.fail_release = TRUE;
    CHECK( "commit-release-error-visible", FAILED( cloud_upload( a, &s ) ) );
    CHECK( "commit-actually-reached-server", remote.metadata_puts == 1 && *remote.metadata );
    CHECK( "commit-not-announced-as-complete", s.dirty && !remote.announced );
    free_state( &s );
    close_provider( a );
    /* Simulate lease expiry between sessions, with no clock changes or retry
     * that could accidentally repair the index before reopening it. */
    remote.locked = FALSE;
    remote.fail_release = FALSE;
    if ( changed_elsewhere )
    {
        b = device( files, "commit-B" );
        CHECK( "commit-B-download", cloud_sync( b ) == S_OK );
        seed( b, "newer-remote-progress", TRUE );
        CHECK( "commit-B-load", load_state( b, "Save", &s ) == S_OK );
        s.time += 2;
        strcpy( s.remote, remote.time );
        CHECK( "commit-B-later-time", save_state( b, &s ) == S_OK );
        free_state( &s );
        CHECK( "commit-B-upload", cloud_sync( b ) == S_OK );
        close_provider( b );
    }
    const unsigned writes = remote.metadata_puts;
    a = device( files, "commit-A-reopen" );
    strcpy( a->root, saved_root );
    read_progress( a, "durable-local-progress", TRUE );
    HRESULT hr = cloud_sync( a );
    if ( changed_elsewhere )
    {
        CHECK( "commit-real-conflict-preserved", hr == E_GS_CONTAINER_NOT_IN_SYNC );
        CHECK( "commit-real-conflict-no-write", remote.metadata_puts == writes );
        read_progress( a, "durable-local-progress", TRUE );
    }
    else
    {
        CHECK( "commit-relaunch-can-sync", hr == S_OK );
        read_progress( a, "durable-local-progress", FALSE );
        CHECK( "commit-relaunch-announces-upload", remote.announced == 1 );
    }
    close_provider( a );
}
static void older_commit_keeps_newer_local_revision( BOOL files )
{
    struct XGameSaveProvider *a;
    struct container_state state;
    char saved_root[2048];
    memset( &remote, 0, sizeof( remote ) );
    a = device( files, "older-commit" );
    seed( a, "older-snapshot", TRUE );
    strcpy( saved_root, a->root );
    struct save_upload *older = snapshot_upload( a, "Save" );
    CHECK( "older-snapshot-owned", older != NULL );
    if ( !older ) { close_provider( a ); return; }
    seed( a, "newer-local-progress", TRUE );
    CHECK( "newer-local-load", load_state( a, "Save", &state ) == S_OK );
    state.revision = 2;
    CHECK( "newer-local-revision-saved", save_state( a, &state ) == S_OK );
    free_state( &state );
    remote.fail_release = TRUE;
    CHECK( "older-release-failure-visible", FAILED( cloud_upload_data( a, &older->state, older->data, older->sizes ) ) );
    free_upload( older );
    CHECK( "newer-local-revision-load", load_state( a, "Save", &state ) == S_OK );
    CHECK( "newer-local-not-acknowledged", state.dirty && state.revision == 2 );
    CHECK( "acknowledged-remote-base-durable", !strcmp( state.remote, remote.time ) );
    free_state( &state );
    read_progress( a, "newer-local-progress", TRUE );
    close_provider( a );
    remote.locked = FALSE;
    remote.fail_release = FALSE;
    a = device( files, "newer-local-reopen" );
    strcpy( a->root, saved_root );
    CHECK( "newer-local-relaunch-upload", cloud_sync( a ) == S_OK );
    read_progress( a, "newer-local-progress", FALSE );
    CHECK( "newer-local-upload-announced", remote.announced == 1 );
    close_provider( a );
}
int main( void )
{
    InitializeLogging();
    INITIALIZE_OPTIONS options{};
    options.isInlineConfig = TRUE;
    options.gameConfig = "<Game><Identity Name='Nexus.SaveFixture' Publisher='CN=Fixture'/></Game>";
    CHECK( "actual-config", nexus::InitializeGameConfiguration( &options ) == S_OK );
    WCHAR temp[MAX_PATH];
    char path[1024];
    GetTempPathW( MAX_PATH, temp );
    WideCharToMultiByte( CP_UTF8, 0, temp, -1, path, sizeof( path ), NULL, NULL );
    snprintf( root, sizeof( root ), "%snexus-transfer-%lu-%I64u", path, GetCurrentProcessId(), GetTickCount64() );
    create_directories( root );
    SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    for ( unsigned files = 0; files < 2; files++ )
    {
        committed_upload_then_release_failure( files, FALSE );
        committed_upload_then_release_failure( files, TRUE );
        older_commit_keeps_newer_local_revision( files );
    }
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
