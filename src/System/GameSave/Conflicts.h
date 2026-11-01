/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Explicit conflict resolution during provider initialization. Never pick a
 * winner by timestamp, and never mutate live saves before both copies exist.
 * Recovery roots start with a dot and cannot enter the cloud container set. */
#include "ConflictDialog.h"

static HRESULT conflict_copy( XGameSaveProvider *from, XGameSaveProvider *to, const char *name )
{
    container_state state = { 0 };
    char source[2048], target[2048];
    HRESULT hr = load_state( from, name, &state );
    if ( SUCCEEDED( hr ) && !container_dir( to, name, target, sizeof( target ) ) ) hr = E_INVALIDARG;
    if ( SUCCEEDED( hr ) ) hr = files_mkdir( target );
    for ( UINT32 i = 0; SUCCEEDED( hr ) && i < state.count; i++ )
    {
        BYTE *data = NULL;
        SIZE_T size = 0;
        if ( !blob_path( from, name, state.blobs[i].name, source, sizeof( source ) ) ||
             !blob_path( to, name, state.blobs[i].name, target, sizeof( target ) ) )
            hr = E_INVALIDARG;
        else if ( SUCCEEDED( hr = read_file( source, &data, &size ) ) )
            hr = size == state.blobs[i].size ? write_file( target, data, size ) : HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
        free( data );
    }
    if ( SUCCEEDED( hr ) ) hr = save_state( to, &state );
    free_state( &state );
    return hr;
}

/* Compare full content as well as the index. Equal whole-second timestamps do
 * not prove that the cloud or another local provider still has the same data. */
static HRESULT conflict_equal( XGameSaveProvider *a, XGameSaveProvider *b, const char *name )
{
    container_state left = { 0 }, right = { 0 };
    HRESULT hr = load_state( a, name, &left );
    if ( SUCCEEDED( hr ) ) hr = load_state( b, name, &right );
    if ( SUCCEEDED( hr ) && ( left.count != right.count || left.time != right.time ||
         left.revision != right.revision || left.dirty != right.dirty || strcmp( left.remote, right.remote ) ||
         strcmp( left.display ? left.display : "", right.display ? right.display : "" ) ) )
        hr = E_GS_CONTAINER_NOT_IN_SYNC;
    for ( UINT32 i = 0; SUCCEEDED( hr ) && i < left.count; i++ )
    {
        blob_entry *entry = find_blob( &right, left.blobs[i].name );
        BYTE *first = NULL, *second = NULL;
        SIZE_T first_size = 0, second_size = 0;
        char source[2048], target[2048];
        if ( !entry || entry->size != left.blobs[i].size || strcmp( entry->atom, left.blobs[i].atom ) )
            hr = E_GS_CONTAINER_NOT_IN_SYNC;
        else if ( !blob_path( a, name, left.blobs[i].name, source, sizeof( source ) ) ||
                  !blob_path( b, name, left.blobs[i].name, target, sizeof( target ) ) ) hr = E_INVALIDARG;
        else
        {
            hr = read_file( source, &first, &first_size );
            if ( SUCCEEDED( hr ) ) hr = read_file( target, &second, &second_size );
            if ( SUCCEEDED( hr ) && ( first_size != second_size || memcmp( first, second, first_size ) ) )
                hr = E_GS_CONTAINER_NOT_IN_SYNC;
        }
        free( first );
        free( second );
    }
    free_state( &left );
    free_state( &right );
    return hr;
}

/* Verify the listing too: deleted containers and changed timestamps must not
 * be recreated using a stale selection. Incomplete lists remain fail-closed. */
static HRESULT conflict_remote_time( XGameSaveProvider *provider, const char *name, const char *expected )
{
    BYTE *buffer = NULL;
    SIZE_T size = 0;
    DWORD status = 0;
    UINT listed = 0, found = 0;
    const char *items;
    HRESULT hr = cloud_request( provider, "GET", "", NULL, NULL, 0, &status, &buffer, &size );
    if ( SUCCEEDED( hr ) && ( status != 200 || !save_json_object_complete( ( char * )buffer, size ) ||
         !( items = json_find( ( char * )buffer, "blobs" ) ) || *items != '[' ) ) hr = E_FAIL;
    if ( SUCCEEDED( hr ) )
    {
        for ( items = json_ws( items + 1 ); *items != ']'; )
        {
            const char *end = *items == '{' ? json_skip( items ) : NULL;
            char *file = NULL, *time = NULL;
            if ( !end || end <= items || end[-1] != '}' || !( file = json_find_string( items, "fileName" ) ) )
            { hr = E_FAIL; break; }
            listed++;
            SIZE_T len = strlen( name );
            if ( strlen( file ) == len + 10 && !strncmp( file, name, len ) && !strcmp( file + len, ",savedgame" ) )
            {
                time = json_find_string( items, "clientFileTime" );
                if ( ++found != 1 || !time || strcmp( time, expected ) ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
            }
            free( file ); free( time );
            if ( FAILED( hr ) ) break;
            items = json_ws( end );
            if ( *items == ',' && *json_ws( items + 1 ) == '{' ) items = json_ws( items + 1 );
            else if ( *items != ']' ) { hr = E_FAIL; break; }
        }
        if ( SUCCEEDED( hr ) ) hr = save_listing_complete( ( char * )buffer, listed );
        if ( SUCCEEDED( hr ) && found != 1 ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
    }
    free( buffer );
    return hr;
}

static HRESULT conflict_install( XGameSaveProvider *provider, XGameSaveProvider *copy, const char *name,
                                 const char *backup_root )
{
    XGameSaveProvider staging = { 0 };
    char target[2048], source[2048], recovery[2048];
    WCHAR target_w[4096], source_w[4096], recovery_w[4096];
    staging.files = provider->files;
    if ( snprintf( staging.root, sizeof( staging.root ), "%s\\selected", backup_root ) >= sizeof( staging.root ) ||
         snprintf( recovery, sizeof( recovery ), "%s\\replaced", backup_root ) >= sizeof( recovery ) ) return E_INVALIDARG;
    HRESULT hr = conflict_copy( copy, &staging, name );
    if ( FAILED( hr ) ) return hr;
    if ( !container_dir( provider, name, target, sizeof( target ) ) ||
         !container_dir( &staging, name, source, sizeof( source ) ) ||
         !save_wide_path( target, target_w ) || !save_wide_path( source, source_w ) ||
         !save_wide_path( recovery, recovery_w ) ) return E_INVALIDARG;
    if ( !MoveFileExW( target_w, recovery_w, MOVEFILE_WRITE_THROUGH ) ) return HRESULT_FROM_WIN32( GetLastError() );
    if ( !MoveFileExW( source_w, target_w, MOVEFILE_WRITE_THROUGH ) )
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        if ( !MoveFileExW( recovery_w, target_w, MOVEFILE_WRITE_THROUGH ) )
            ERR( "conflict rollback failed; original data remains in the recovery folder.\n" );
        return hr;
    }
    return S_OK;
}

static HRESULT resolve_cloud_conflict( XGameSaveProvider *provider, container_state *state,
                                       const char *display, const char *remote_time )
{
    if ( !GetSaveTransport( provider ).CanResolveConflicts() ) return E_GS_CONTAINER_NOT_IN_SYNC;
    if ( !remote_time || !*remote_time || strlen( remote_time ) >= sizeof( state->remote ) )
        return E_GS_CONTAINER_NOT_IN_SYNC;
    XGameSaveProvider local = { 0 }, cloud = { 0 }, current = { 0 };
    container_state remote_state = { 0 };
    WCHAR guid_w[40], root_w[4096], text[8192], label_w[256] = { 0 }, time_w[64], remote_w[64], path_w[4096];
    char guid_text[64], root[2048], local_time[48];
    GUID guid;
    HRESULT hr = CoCreateGuid( &guid );
    BOOL original_session = provider->session_lock;
    SaveConflictChoice choice = SaveConflictChoice::Cancel;
    const char *label;
    if ( FAILED( hr ) ) return hr;
    if ( !StringFromGUID2( guid, guid_w, ARRAY_SIZE( guid_w ) ) ||
         !WideCharToMultiByte( CP_UTF8, 0, guid_w, -1, guid_text, sizeof( guid_text ), NULL, NULL ) ||
         snprintf( root, sizeof( root ), "%s\\.conflict-%s", provider->root, guid_text ) >= sizeof( root ) ||
         !save_wide_path( root, root_w ) ) return E_INVALIDARG;
    if ( !CreateDirectoryW( root_w, NULL ) ) return HRESULT_FROM_WIN32( GetLastError() );
    if ( snprintf( local.root, sizeof( local.root ), "%s\\local", root ) >= sizeof( local.root ) ||
         snprintf( cloud.root, sizeof( cloud.root ), "%s\\cloud", root ) >= sizeof( cloud.root ) ||
         snprintf( current.root, sizeof( current.root ), "%s\\rechecked-cloud", root ) >= sizeof( current.root ) )
        return E_INVALIDARG;
    local.files = cloud.files = current.files = provider->files;
    cloud.transport = current.transport = provider->transport;
    cloud.user = current.user = provider->user;
    cloud.auth = current.auth = provider->auth;
    strcpy( cloud.base, provider->base ); strcpy( current.base, provider->base );

    EnterCriticalSection( &provider->cs );
    hr = conflict_copy( provider, &local, state->name );
    if ( SUCCEEDED( hr ) ) hr = conflict_equal( provider, &local, state->name );
    if ( SUCCEEDED( hr ) )
    {
        container_state captured = { 0 };
        hr = load_state( &local, state->name, &captured );
        if ( SUCCEEDED( hr ) ) { free_state( state ); *state = captured; }
        else free_state( &captured );
    }
    LeaveCriticalSection( &provider->cs );
    if ( SUCCEEDED( hr ) ) hr = cloud_download_into( &cloud, state->name, display, remote_time );
    if ( SUCCEEDED( hr ) ) hr = conflict_remote_time( provider, state->name, remote_time );
    if ( SUCCEEDED( hr ) ) hr = load_state( &cloud, state->name, &remote_state );
    if ( SUCCEEDED( hr ) && provider->files ) hr = files_validate_download( &remote_state );
    if ( FAILED( hr ) ) goto done;

    /* Never retain a lease while waiting indefinitely for user input. */
    provider->session_lock = FALSE;
    if ( FAILED( hr = cloud_unlock( provider, FALSE ) ) ) goto done;
    format_iso_time( state->time, local_time, sizeof( local_time ) );
    MultiByteToWideChar( CP_UTF8, 0, local_time, -1, time_w, ARRAY_SIZE( time_w ) );
    MultiByteToWideChar( CP_UTF8, 0, remote_time, -1, remote_w, ARRAY_SIZE( remote_w ) );
    MultiByteToWideChar( CP_UTF8, 0, root, -1, path_w, ARRAY_SIZE( path_w ) );
    label_w[0] = 0;
    label = state->display ? state->display : state->name;
    MultiByteToWideChar( CP_UTF8, 0, label, ( int )std::min( strlen( label ), ( size_t )200 ), label_w, ARRAY_SIZE( label_w ) - 1 );
    label_w[200] = 0;
    swprintf( text, ARRAY_SIZE( text ),
              L"Local and cloud progress differ. Choose the version to use. Cancel leaves synchronization unresolved.\n\n"
              L"Save: %ls\nLOCAL: %ls (%llu bytes)\nCLOUD: %ls (%llu bytes)\n\n"
              L"Both versions are backed up in:\n%ls\n\nIf either version changes while this dialog is open, your choice will not be applied.",
              label_w, time_w, ( unsigned long long )state_total_size( state ), remote_w,
              ( unsigned long long )state_total_size( &remote_state ), path_w );
    choice = GetSaveTransport( provider ).ResolveConflict( text );
    if ( choice != SaveConflictChoice::Local && choice != SaveConflictChoice::Cloud )
    { hr = E_GS_CONTAINER_NOT_IN_SYNC; goto done; }
    /* Reacquire, then re-read the listing AND all bytes. A same-second cloud
     * replacement, local edit, deleted container or failed lock invalidates consent. */
    provider->locked = FALSE;
    if ( !cloud_lock( provider ) ) { hr = E_GS_CONTAINER_NOT_IN_SYNC; goto done; }
    provider->session_lock = TRUE;
    hr = conflict_remote_time( provider, state->name, remote_time );
    if ( SUCCEEDED( hr ) ) hr = cloud_download_into( &current, state->name, display, remote_time );
    if ( SUCCEEDED( hr ) ) hr = conflict_equal( &cloud, &current, state->name );
    EnterCriticalSection( &provider->cs );
    if ( SUCCEEDED( hr ) ) hr = conflict_equal( provider, &local, state->name );
    if ( SUCCEEDED( hr ) )
    {
        if ( choice == SaveConflictChoice::Local ) hr = force_upload( provider, state );
        else
        {
            hr = conflict_install( provider, &cloud, state->name, root );
            if ( SUCCEEDED( hr ) ) provider->downloaded++;
        }
    }
    LeaveCriticalSection( &provider->cs );
done:
    free_state( &remote_state );
    provider->session_lock = FALSE;
    if ( !original_session || FAILED( hr ) )
    {
        HRESULT released = cloud_unlock( provider, FALSE );
        if ( SUCCEEDED( hr ) && FAILED( released ) && choice == SaveConflictChoice::Local )
        {
            // The remote commit is known, but final notification must retry.
            state->dirty = TRUE;
            HRESULT persisted = save_state( provider, state );
            hr = FAILED( persisted ) ? persisted : released;
        }
        else if ( SUCCEEDED( hr ) ) hr = released;
    }
    provider->session_lock = original_session;
    SaveStatus( "nexus-saves: conflict-resolution hr=%#lx backups=retained\n", hr );
    return hr;
}
