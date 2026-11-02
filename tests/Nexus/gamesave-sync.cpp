/* SPDX-License-Identifier: MIT
 * Compile the actual save implementation with a closed synthetic transport.
 * No runtime user, real credentials, network or production save directories. */

#include "../../src/private.h"
#include "../../src/System/GameSave/Transport.h"
#include "../../src/Runtime/Configuration.h"
#include "../../src/HttpClient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
static unsigned checks, failures, requests, blob_gets, writes;
static BOOL fail_second;
static BOOL fail_promote;
static unsigned metadata_case;
static unsigned listing_case;
static const char *listing_override;
static bool resolve_enabled, reject_lock, fail_backup_copy, fail_conflict_promote, fail_upload_atom, fail_release;
static unsigned dialog_calls, save_puts, atom_puts, mutation;
static SaveConflictChoice selected_choice = SaveConflictChoice::Cancel;
static std::string server_metadata, server_time;
static std::map<std::string, std::string> server_atoms;
static char backup_root[2048];
struct XGameSaveProvider;
static XGameSaveProvider *conflict_provider;
static const char *remote_time = "2026-10-22T12:00:00Z";
#define CHECK( name, expr )                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ++checks;                                                                                                      \
        if ( !( expr ) )                                                                                               \
        {                                                                                                              \
            ++failures;                                                                                                \
            printf( "FAIL %s line=%d\n", name, __LINE__ );                                                             \
        }                                                                                                              \
    } while ( 0 )

class ClosedSaveTransport final : public SaveTransport
{
public:
    HRESULT Authorization( XUserHandle, const char *, char ** ) override;
    HRESULT SignedRequest( XUserHandle, const char *, const char *, const char *, const char *, const void *, DWORD,
                           DWORD *, BYTE **, SIZE_T * ) override;
    HRESULT DirectRequest( const WCHAR *, const WCHAR *, const WCHAR *, const void *, DWORD, DWORD *, BYTE **,
                           SIZE_T * ) override;
    void CloseUser( XUserHandle ) override {}
    bool CanResolveConflicts() const override { return resolve_enabled; }
    SaveConflictChoice ResolveConflict( const WCHAR *details ) override;
};
static ClosedSaveTransport closedTransport;
HRESULT ClosedSaveTransport::Authorization( XUserHandle user, const char *relying, char **auth )
{
    *auth = strdup( "synthetic-not-a-token" );
    return *auth ? S_OK : E_OUTOFMEMORY;
}

HRESULT ClosedSaveTransport::DirectRequest( const WCHAR *method, const WCHAR *url, const WCHAR *headers,
                                            const void *body, DWORD count, DWORD *status, BYTE **out, SIZE_T *size )
{
    *status = 403;
    *out = NULL;
    *size = 0;
    return E_ACCESSDENIED;
}
HRESULT ClosedSaveTransport::SignedRequest( XUserHandle user, const char *method, const char *url, const char *auth,
                                            const char *headers, const void *body, DWORD count, DWORD *status,
                                            BYTE **out, SIZE_T *size )
{
    const char *response = NULL;
    char listing[512];
    ++requests;
    *out = NULL;
    *size = 0;
    *status = 500;
    if ( strcmp( method, "GET" ) )
    {
        ++writes;
        if ( !resolve_enabled ) return E_ACCESSDENIED;
        if ( strstr( url, "/lock?" ) )
        {
            *status = ( !strcmp( method, "PUT" ) && reject_lock ) || ( !strcmp( method, "DELETE" ) && fail_release ) ? 503 : 200;
            response = "{}";
        }
        else if ( !strcmp( method, "PUT" ) && strstr( url, "/Save,savedgame?" ) )
        {
            ++save_puts;
            server_metadata.assign( ( const char * )body, count );
            const char *time = strstr( url, "clientFileTime=" ) + 15;
            server_time.assign( time, strcspn( time, "&" ) ); remote_time = server_time.c_str();
            *status = 200; response = "{}";
        }
        else if ( !strcmp( method, "PUT" ) && strstr( url, ",binary" ) )
        {
            ++atom_puts;
            *status = fail_upload_atom ? 503 : 200; response = "{}";
            if ( !fail_upload_atom ) server_atoms[strrchr( url, '/' ) + 1].assign( ( const char * )body, count );
        }
        else return E_ACCESSDENIED;
        *size = strlen( response ); *out = ( BYTE * )strdup( response );
        return *out ? S_OK : E_OUTOFMEMORY;
    }
    if ( !strcmp( url, "https://fixture.invalid" ) )
    {
        snprintf( listing, sizeof( listing ),
                  "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"displayName\":\"Save\",\"clientFileTime\":\"%s\"}]}",
                  remote_time );
        response = listing;
        if ( listing_case )
        {
            const char *cases[] = { NULL,
                                    "{\"blobs\":[]",
                                    "{\"blobs\":[17]}",
                                    "{\"blobs\":[{\"fileName\":\"Save,savedgame\"},]}",
                                    "{\"blobs\":[{\"fileName\":\"Save,savedgame\"}{\"fileName\":\"Other,savedgame\"}]}",
                                    "{\"blobs\":[{}]}",
                                    "{\"blobs\":[{\"fileName\":\"Save,savedgame\"},{\"fileName\":\"Save,savedgame\"}]}",
                                    "{\"blobs\":[]}garbage" };
            response = cases[listing_case];
        }
        if ( listing_override ) response = listing_override;
    }
    else if ( !strcmp( url, "https://fixture.invalid/Save,savedgame" ) )
    {
        const char *cases[] = { "{\"atoms\":{\"one\":\"atom-A\",\"two\":\"atom-B\"}}",
                                "{\"atoms\":{\"one\":\"atom-A\",\"two\":\"atom-B\"",
                                "{\"atoms\":{\"one\":\"atom-A\",\"one\":\"atom-B\"}}",
                                "{\"atoms\":{\"one\":17}}",
                                "{\"atoms\":{\"one\":\"\"}}",
                                "{\"atoms\":{\"one\":\"atom-A\",}}" };
        response = resolve_enabled && !server_metadata.empty() ? server_metadata.c_str() : cases[metadata_case];
    }
    else if ( !strcmp( url, "https://fixture.invalid/atom-A" ) )
    {
        ++blob_gets;
        response = resolve_enabled && mutation == 1 && dialog_calls ? "changedA" : "remote-A";
    }
    else if ( !strcmp( url, "https://fixture.invalid/atom-B" ) )
    {
        ++blob_gets;
        if ( fail_second )
        {
            *status = 503;
            response = "unavailable";
        }
        else
            response = "remote-B";
    }
    else if ( resolve_enabled && server_atoms.count( strrchr( url, '/' ) + 1 ) )
        response = server_atoms[strrchr( url, '/' ) + 1].c_str();
    else
        return E_ACCESSDENIED;
    if ( *status != 503 ) *status = 200;
    *size = strlen( response );
    *out = static_cast<std::remove_reference_t<decltype( *out )>>( malloc( *size + 1 ) );
    if ( !*out ) return E_OUTOFMEMORY;
    memcpy( *out, response, *size + 1 );
    return S_OK;
}
static BOOL WINAPI test_move( const WCHAR *from, const WCHAR *to, DWORD flags )
{
    if ( ( fail_backup_copy && wcsstr( from, L"\\.conflict-" ) && wcsstr( from, L"\\local\\" ) ) ||
         ( fail_conflict_promote && !( flags & MOVEFILE_REPLACE_EXISTING ) && wcsstr( from, L"\\selected\\" ) ) )
    { SetLastError( ERROR_DISK_FULL ); return FALSE; }
    if ( fail_promote && !( flags & MOVEFILE_REPLACE_EXISTING ) && wcsstr( from, L"\\.incoming-" ) )
    {
        SetLastError( ERROR_ACCESS_DENIED );
        return FALSE;
    }
    return MoveFileExW( from, to, flags );
}
#define MoveFileExW test_move
#include "../../src/System/XGameSave.cpp"
#undef MoveFileExW
static void seed( struct XGameSaveProvider *provider, BOOL dirty )
{
    struct container_state state = { 0 };
    struct blob_entry *entry;
    char file[2048], dir[2048];
    state.name = strdup( "Save" );
    state.display = strdup( "Save" );
    state.dirty = dirty;
    state.time = parse_iso_time( "2026-10-20T12:00:00Z" );
    strcpy( state.remote, "2026-10-20T12:00:00Z" );
    container_dir( provider, "Save", dir, sizeof( dir ) );
    create_directories( dir );
    entry = add_blob( &state, "one" );
    entry->size = 7;
    strcpy( entry->atom, "old-A" );
    blob_path( provider, "Save", "one", file, sizeof( file ) );
    CHECK( "seed-one", write_file( file, "local-A", 7 ) == S_OK );
    entry = add_blob( &state, "two" );
    entry->size = 7;
    strcpy( entry->atom, "old-B" );
    blob_path( provider, "Save", "two", file, sizeof( file ) );
    CHECK( "seed-two", write_file( file, "local-B", 7 ) == S_OK );
    CHECK( "seed-state", save_state( provider, &state ) == S_OK );
    free_state( &state );
}
static void preserved( struct XGameSaveProvider *provider, BOOL dirty )
{
    struct container_state state;
    char file[2048];
    BYTE *bytes = NULL;
    SIZE_T size = 0;
    HRESULT hr;
    hr = load_state( provider, "Save", &state );
    CHECK( "original-index-preserved", hr == S_OK );
    if ( SUCCEEDED( hr ) )
    {
        CHECK( "original-metadata",
               state.dirty == dirty && !strcmp( state.remote, "2026-10-20T12:00:00Z" ) && state.count == 2 );
    }
    free_state( &state );
    blob_path( provider, "Save", "one", file, sizeof( file ) );
    hr = read_file( file, &bytes, &size );
    CHECK( "original-one-preserved", hr == S_OK && size == 7 && !memcmp( bytes, "local-A", 7 ) );
    free( bytes );
    bytes = NULL;
    blob_path( provider, "Save", "two", file, sizeof( file ) );
    hr = read_file( file, &bytes, &size );
    CHECK( "original-two-preserved", hr == S_OK && size == 7 && !memcmp( bytes, "local-B", 7 ) );
    free( bytes );
}
static BOOL count_local( struct XGameSaveProvider *provider, const char *name, void *context )
{
    unsigned *count = static_cast<unsigned *>( context );
    ++*count;
    CHECK( "only-live-container-enumerated", !strcmp( name, "Save" ) );
    return TRUE;
}
static void run_provider( BOOL files )
{
    WCHAR temp[MAX_PATH];
    char path[1024];
    struct XGameSaveProvider provider = { 0 };
    InitializeCriticalSection( &provider.cs );
    HRESULT hr;
    printf( "CASE provider %s\n", files ? "files" : "blobs" );
    provider.transport = &closedTransport;
    provider.files = files;
    CHECK( "temp", GetTempPathW( MAX_PATH, temp ) > 0 );
    CHECK( "utf8-temp", WideCharToMultiByte( CP_UTF8, 0, temp, -1, path, sizeof( path ), NULL, NULL ) > 0 );
    snprintf( provider.root, sizeof( provider.root ), "%snexus-sync-%lu-%I64u-%u", path, GetCurrentProcessId(),
              GetTickCount64(), files );
    strcpy( provider.base, "https://fixture.invalid" );
    provider.quota = SAVE_QUOTA;
    provider.user = reinterpret_cast<XUserHandle>( 1 );
    create_directories( provider.root );
    seed( &provider, FALSE );
    fail_second = TRUE;
    hr = cloud_download( &provider, "Save", "Save", remote_time );
    CHECK( "failed-download-reported", FAILED( hr ) );
    preserved( &provider, FALSE );
    fail_second = FALSE;
    for ( metadata_case = 1; metadata_case <= 5; metadata_case++ )
    {
        seed( &provider, FALSE );
        hr = cloud_download( &provider, "Save", "Save", remote_time );
        CHECK( "malformed-download-rejected", FAILED( hr ) );
        preserved( &provider, FALSE );
    }
    metadata_case = 0;
    seed( &provider, FALSE );
    fail_promote = TRUE;
    hr = cloud_download( &provider, "Save", "Save", remote_time );
    CHECK( "promotion-error-reported", FAILED( hr ) );
    preserved( &provider, FALSE );
    fail_promote = FALSE;
    SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    for ( listing_case = 1; listing_case <= 7; listing_case++ )
    {
        printf( "CASE invalid listing %u\n", listing_case );
        seed( &provider, FALSE );
        hr = cloud_sync( &provider );
        CHECK( "invalid-listing-fails-closed", FAILED( hr ) );
        preserved( &provider, FALSE );
        free( provider.auth );
        provider.auth = NULL;
    }
    listing_case = 0;
    /* An omitted container is deletion evidence only for an authoritative,
     * complete listing. Exercise the actual sync path before it touches data. */
    const char *partial[] = {
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":\"next-page\",\"totalItems\":1}}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":null,\"totalItems\":1}}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":\"\",\"totalItems\":1}}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":\"next-page\"}}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":17}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":-1}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":1.5}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":\"0\"}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":18446744073709551616}}",
        "{\"blobs\":[],\"pagingInfo\":[]}",
        "{\"blobs\":[],\"pagingInfo\":false}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":null,\"continuationToken\":\"next-page\"}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":0,\"totalItems\":1}}",
        "{\"blobs\":[],\"pagingInfo\":null,\"pagingInfo\":{\"continuationToken\":\"next\"}}",
        "{\"blobs\":[],\"blobs\":[]}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":0 \"continuationToken\":\"\"}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":0,}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":null}}",
        "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":false}}",
        "{\"blobs\":[],\"pagingInfo\":{\"totalItems\":0e0}}",
        "{\"blobs\":[] \"pagingInfo\":{\"totalItems\":0}}",
    };
    for ( const char *mode : { "auto", "download", "upload" } )
        for ( unsigned dirty = 0; dirty < 2; dirty++ )
            for ( unsigned i = 0; i < ARRAY_SIZE( partial ); i++ )
            {
                printf( "CASE incomplete listing %u dirty=%u mode=%s\n", i, dirty, mode );
                seed( &provider, dirty );
                listing_override = partial[i];
                blob_gets = writes = requests = 0;
                SetEnvironmentVariableA( "XODUS_SAVE_SYNC", mode );
                hr = cloud_sync( &provider );
                CHECK( "incomplete-listing-fails-closed", FAILED( hr ) );
                CHECK( "incomplete-listing-no-data-requests", requests == 1 && !blob_gets && !writes );
                preserved( &provider, dirty );
                free( provider.auth );
                provider.auth = NULL;
            }
    const char *complete[] = {
        "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"clientFileTime\":\"2026-10-20T12:00:00Z\"}],\"pagingInfo\":{\"continuationToken\":null,\"totalItems\":1}}",
        "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"clientFileTime\":\"2026-10-20T12:00:00Z\"}],\"pagingInfo\":{\"continuationToken\":\"\",\"totalItems\":1}}",
        "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"clientFileTime\":\"2026-10-20T12:00:00Z\"}],\"pagingInfo\":null}",
        "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"clientFileTime\":\"2026-10-20T12:00:00Z\"},{\"fileName\":\"Other,binary\"}],\"pagingInfo\":{\"totalItems\":2}}",
    };
    SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    for ( const char *listing : complete )
    {
        listing_override = listing;
        seed( &provider, FALSE );
        blob_gets = writes = requests = 0;
        CHECK( "complete-page-syncs", cloud_sync( &provider ) == S_OK );
        CHECK( "complete-page-no-mutations", requests == 1 && !blob_gets && !writes );
        preserved( &provider, FALSE );
        free( provider.auth );
        provider.auth = NULL;
    }
    listing_override = "{\"blobs\":[],\"pagingInfo\":{\"continuationToken\":null,\"totalItems\":0}}";
    seed( &provider, FALSE );
    CHECK( "complete-empty-syncs", cloud_sync( &provider ) == S_OK );
    {
        struct container_state removed;
        hr = load_state( &provider, "Save", &removed );
        CHECK( "complete-empty-honors-remote-deletion", FAILED( hr ) );
        free_state( &removed );
    }
    free( provider.auth );
    provider.auth = NULL;
    listing_override = NULL;
    seed( &provider, TRUE );
    fail_second = FALSE;
    blob_gets = writes = 0;
    SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "auto" );
    hr = cloud_sync( &provider );
    CHECK( "dirty-conflict-reported", hr == E_GS_CONTAINER_NOT_IN_SYNC );
    CHECK( "conflict-no-payload-or-upload", !blob_gets && !writes );
    preserved( &provider, TRUE );
    free( provider.auth );
    provider.auth = NULL;
    seed( &provider, FALSE );
    remote_time = "2026-10-20T12:00:00Z";
    blob_gets = writes = 0;
    hr = cloud_sync( &provider );
    CHECK( "unchanged-sync", hr == S_OK && !blob_gets && !writes );
    preserved( &provider, FALSE );
    free( provider.auth );
    provider.auth = NULL;
    seed( &provider, TRUE );
    remote_time = "2026-10-22T12:00:00Z";
    SetEnvironmentVariableA( "XODUS_SAVE_SYNC", "download" );
    hr = cloud_sync( &provider );
    CHECK( "explicit-download", hr == S_OK && !writes );
    {
        struct container_state state;
        CHECK( "download-state", load_state( &provider, "Save", &state ) == S_OK );
        CHECK( "download-metadata", !state.dirty && state.count == 2 && !strcmp( state.remote, remote_time ) );
        free_state( &state );
    }
    {
        char pattern[2048], file[2048], *key = files ? files_cache_key( "one" ) : hex_encode( "one" );
        WIN32_FIND_DATAA data;
        HANDLE find;
        BYTE *bytes = NULL;
        SIZE_T size = 0;
        unsigned count = 0;
        BOOL found = FALSE;
        snprintf( pattern, sizeof( pattern ), "%s\\*", provider.root );
        find = save_find_first( pattern, &data );
        if ( find != INVALID_HANDLE_VALUE )
        {
            do
            {
                if ( strncmp( data.cFileName, ".recovery-", 10 ) && !strstr( data.cFileName, ".backup-" ) ) continue;
                snprintf( file, sizeof( file ), "%s\\%s\\b_%s", provider.root, data.cFileName, key );
                if ( SUCCEEDED( read_file( file, &bytes, &size ) ) && size == 7 && !memcmp( bytes, "local-A", 7 ) )
                    found = TRUE;
                free( bytes );
                bytes = NULL;
            } while ( FindNextFileA( find, &data ) );
            FindClose( find );
        }
        free( key );
        CHECK( "recovery-copy-kept", found );
        enumerate_local( &provider, count_local, &count );
        CHECK( "recovery-not-in-cloud-set", count == 1 );
    }
    free( provider.auth );
    CHECK( "no-network-writes", writes == 0 );
    DeleteCriticalSection( &provider.cs );
}
static void check_bytes( XGameSaveProvider *provider, const char *name, const char *expected )
{
    char path[2048]; BYTE *data = NULL; SIZE_T size = 0;
    CHECK( "conflict-blob-path", blob_path( provider, "Save", name, path, sizeof( path ) ) );
    HRESULT hr = read_file( path, &data, &size );
    CHECK( "conflict-exact-progress", hr == S_OK && size == strlen( expected ) && !memcmp( data, expected, size ) );
    free( data );
}

SaveConflictChoice ClosedSaveTransport::ResolveConflict( const WCHAR *details )
{
    ++dialog_calls;
    CHECK( "conflict-explicit-choice-text", wcsstr( details, L"LOCAL:" ) && wcsstr( details, L"CLOUD:" ) &&
           wcsstr( details, L"Cancel" ) && wcsstr( details, L"Both versions are backed up" ) );
    const WCHAR *path = wcsstr( details, L"backed up in:\n" );
    CHECK( "conflict-backup-location-shown", path != NULL );
    if ( !path ) return SaveConflictChoice::Cancel;
    path += wcslen( L"backed up in:\n" );
    const WCHAR *end = wcsstr( path, L"\n\n" );
    CHECK( "conflict-backup-location-ended", end != NULL );
    if ( !end ) return SaveConflictChoice::Cancel;
    memset( backup_root, 0, sizeof( backup_root ) );
    CHECK( "conflict-backup-location-utf8", WideCharToMultiByte( CP_UTF8, 0, path, end - path,
            backup_root, sizeof( backup_root ) - 1, NULL, NULL ) > 0 );
    XGameSaveProvider local = { 0 }, cloud = { 0 };
    local.files = cloud.files = conflict_provider->files;
    snprintf( local.root, sizeof( local.root ), "%s\\local", backup_root );
    snprintf( cloud.root, sizeof( cloud.root ), "%s\\cloud", backup_root );
    // Consent is never requested before both real byte copies are durable.
    check_bytes( &local, "one", "local-A" ); check_bytes( &local, "two", "local-B" );
    check_bytes( &cloud, "one", "remote-A" ); check_bytes( &cloud, "two", "remote-B" );
    container_state state = { 0 };
    CHECK( "conflict-local-backup-index", load_state( &local, "Save", &state ) == S_OK && state.dirty );
    free_state( &state );
    CHECK( "conflict-cloud-backup-index", load_state( &cloud, "Save", &state ) == S_OK && !state.dirty );
    free_state( &state );
    if ( mutation == 2 ) remote_time = "2026-10-23T12:00:00Z";
    if ( mutation == 3 )
    {
        char file[2048]; blob_path( conflict_provider, "Save", "one", file, sizeof( file ) );
        CHECK( "conflict-simulated-local-edit", write_file( file, "changed", 7 ) == S_OK );
    }
    if ( mutation == 4 ) listing_override = "{\"blobs\":[]}";
    if ( mutation == 5 ) server_metadata = "{\"atoms\":{\"one\":\"atom-B\",\"two\":\"atom-A\"}}";
    if ( mutation == 6 ) listing_override = "{\"blobs\":[{\"fileName\":\"Save,savedgame\",\"displayName\":\"Save\",\"clientFileTime\":\"2026-10-22T12:00:00Z\"},{\"fileName\":\"Other,savedgame\",\"clientFileTime\":\"2026-10-22T12:00:00Z\"}]}";
    return selected_choice;
}

static void run_conflicts( BOOL files )
{
    for ( unsigned scenario = 0; scenario < 20; scenario++ )
    {
        WCHAR temp[MAX_PATH]; char path[1024]; XGameSaveProvider provider = { 0 };
        printf( "CASE conflict %s %u\n", files ? "files" : "blobs", scenario );
        resolve_enabled = true; reject_lock = fail_backup_copy = fail_conflict_promote = fail_upload_atom = fail_release = false;
        dialog_calls = save_puts = atom_puts = mutation = 0; backup_root[0] = 0;
        server_atoms.clear(); server_metadata.clear(); server_time.clear();
        remote_time = "2026-10-22T12:00:00Z"; listing_override = NULL; listing_case = metadata_case = 0;
        fail_second = fail_promote = FALSE; SetEnvironmentVariableA( "XODUS_SAVE_SYNC", NULL );
        selected_choice = scenario == 0 ? SaveConflictChoice::Cancel : scenario == 2 || scenario == 11 || scenario == 14 || scenario == 16 || scenario == 19 ? SaveConflictChoice::Cloud : SaveConflictChoice::Local;
        if ( scenario >= 3 && scenario <= 7 ) mutation = scenario - 2;
        if ( scenario == 8 ) reject_lock = true;
        if ( scenario == 9 ) fail_backup_copy = true;
        if ( scenario == 10 ) fail_second = TRUE;
        if ( scenario == 11 ) fail_conflict_promote = true;
        if ( scenario == 12 ) fail_upload_atom = true;
        if ( scenario == 13 || scenario == 14 || scenario == 18 ) fail_release = true;
        if ( scenario == 17 ) selected_choice = static_cast<SaveConflictChoice>( 99 );
        CHECK( "conflict-temp-path", GetTempPathW( MAX_PATH, temp ) > 0 );
        CHECK( "conflict-temp-utf8", WideCharToMultiByte( CP_UTF8, 0, temp, -1, path, sizeof( path ), NULL, NULL ) > 0 );
        snprintf( provider.root, sizeof( provider.root ), "%snexus-conflict-%lu-%I64u-%u-%u", path,
                  GetCurrentProcessId(), GetTickCount64(), files, scenario );
        provider.files = files; provider.cloud = TRUE; provider.user = reinterpret_cast<XUserHandle>( 1 );
        provider.transport = &closedTransport; provider.quota = SAVE_QUOTA;
        strcpy( provider.base, "https://fixture.invalid" );
        InitializeCriticalSection( &provider.cs ); create_directories( provider.root ); seed( &provider, TRUE );
        if ( scenario == 19 )
        {
            mutation = 6;
            container_state other = { 0 }; other.name = strdup( "Other" ); other.display = strdup( "Other" );
            strcpy( other.remote, "2026-10-22T12:00:00Z" );
            char folder[2048]; container_dir( &provider, "Other", folder, sizeof( folder ) ); files_mkdir( folder );
            CHECK( "conflict-other-container-seeded", save_state( &provider, &other ) == S_OK ); free_state( &other );
        }
        conflict_provider = &provider;
        provider.session_lock = scenario == 15 || scenario == 16 || scenario == 18;
        provider.locked = scenario == 18;
        HRESULT hr = cloud_sync( &provider );
        CHECK( "conflict-no-choice-before-backups", dialog_calls == ( scenario == 9 || scenario == 10 || scenario == 18 ? 0u : 1u ) );
        if ( scenario == 1 || scenario == 2 || scenario == 15 || scenario == 16 || scenario == 19 )
        {
            CHECK( "conflict-choice-applied", hr == S_OK );
            check_bytes( &provider, "one", selected_choice == SaveConflictChoice::Local ? "local-A" : "remote-A" );
            check_bytes( &provider, "two", selected_choice == SaveConflictChoice::Local ? "local-B" : "remote-B" );
            container_state state = { 0 };
            CHECK( "conflict-resolved-clean", load_state( &provider, "Save", &state ) == S_OK && !state.dirty );
            free_state( &state );
            CHECK( "conflict-cloud-write-only-for-local-choice", save_puts == ( selected_choice == SaveConflictChoice::Local ? 1u : 0u ) );
            CHECK( "conflict-upload-includes-all-local-blobs", atom_puts == ( selected_choice == SaveConflictChoice::Local ? 2u : 0u ) );
            if ( selected_choice == SaveConflictChoice::Local )
            {
                bool a = false, b = false;
                for ( const auto &item : server_atoms ) { a |= item.second == "local-A"; b |= item.second == "local-B"; }
                CHECK( "conflict-cloud-has-actual-local-progress", a && b );
            }
            CHECK( "conflict-next-start-no-loop", cloud_sync( &provider ) == S_OK && dialog_calls == 1 );
        }
        else if ( scenario == 13 || scenario == 14 )
        {
            CHECK( "conflict-release-failure-reported", FAILED( hr ) );
            CHECK( "conflict-release-retains-lock", provider.locked );
            CHECK( "conflict-release-retains-notification", provider.session_uploaded == ( scenario == 13 ) );
            check_bytes( &provider, "one", scenario == 13 ? "local-A" : "remote-A" );
            check_bytes( &provider, "two", scenario == 13 ? "local-B" : "remote-B" );
            container_state state = { 0 };
            CHECK( "conflict-release-retry-baseline", load_state( &provider, "Save", &state ) == S_OK &&
                   state.dirty == ( scenario == 13 ) && !strcmp( state.remote, remote_time ) );
            free_state( &state );
            fail_release = false;
            CHECK( "conflict-release-retry-succeeds", cloud_unlock( &provider, FALSE ) == S_OK && !provider.locked );
            CHECK( "conflict-release-retry-no-conflict", cloud_sync( &provider ) == S_OK && dialog_calls == 1 );
        }
        else
        {
            CHECK( "conflict-cancel-change-failure-rejected", FAILED( hr ) );
            CHECK( "conflict-failure-never-commits-cloud", save_puts == 0 );
            check_bytes( &provider, "one", mutation == 3 ? "changed" : "local-A" );
            check_bytes( &provider, "two", "local-B" );
            container_state state = { 0 };
            CHECK( "conflict-failure-keeps-dirty", load_state( &provider, "Save", &state ) == S_OK && state.dirty );
            free_state( &state );
        }
        if ( backup_root[0] )
        {
            XGameSaveProvider backup = { 0 }; backup.files = files;
            snprintf( backup.root, sizeof( backup.root ), "%s\\local", backup_root );
            check_bytes( &backup, "one", "local-A" ); check_bytes( &backup, "two", "local-B" );
            snprintf( backup.root, sizeof( backup.root ), "%s\\cloud", backup_root );
            check_bytes( &backup, "one", "remote-A" ); check_bytes( &backup, "two", "remote-B" );
        }
        CHECK( "conflict-session-contract-preserved", provider.session_lock ==
               ( scenario == 15 || scenario == 16 || scenario == 18 ) );
        if ( scenario == 15 || scenario == 16 )
        {
            CHECK( "conflict-session-still-owns-lock", provider.locked );
            CHECK( "conflict-session-defers-upload-notification", provider.session_uploaded == ( scenario == 15 ) );
            provider.session_lock = FALSE;
            CHECK( "conflict-session-final-release", cloud_unlock( &provider, FALSE ) == S_OK && !provider.locked );
        }
        unsigned count = 0;
        if ( scenario == 19 ) enumerate_local( &provider, []( XGameSaveProvider *, const char *, void *context ) -> BOOL {
            ++*( unsigned * )context; return TRUE;
        }, &count );
        else enumerate_local( &provider, count_local, &count );
        CHECK( "conflict-recovery-never-uploaded-as-container", count == ( scenario == 19 ? 2u : 1u ) );
        if ( scenario == 19 )
        {
            container_state other = { 0 };
            CHECK( "conflict-fresh-list-prevents-stale-deletion", load_state( &provider, "Other", &other ) == S_OK && !other.dirty );
            free_state( &other );
        }
        free( provider.auth ); DeleteCriticalSection( &provider.cs );
    }
    resolve_enabled = false; listing_override = NULL;
}

int main( void )
{
    InitializeLogging();
    INITIALIZE_OPTIONS options{};
    options.isInlineConfig = TRUE;
    options.gameConfig = "<Game><Identity Name='Nexus.SaveFixture' Publisher='CN=Fixture'/></Game>";
    CHECK( "actual-config", nexus::InitializeGameConfiguration( &options ) == S_OK );
    run_provider( FALSE );
    run_provider( TRUE );
    run_conflicts( FALSE );
    run_conflicts( TRUE );
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
