/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Local blob transactions retain the existing index/blob format. Publish a
 * complete directory and recover an interrupted swap before reading a save.
 * Remote lock order: cloud_cs, shared remote gate, provider cs, then root.
 * Local-only reads/updates need only provider cs and root; HTTP/dialog never
 * retains either local lock. */
/* Named objects coordinate cooperating processes in the same Windows object
 * namespace (the same Wineserver on Wine), not independent Wine prefixes. */
/* Resolve the nearest existing directory, then append the missing tail. The
 * identity cannot change merely because a caller creates its root after
 * taking the lock, including roots below a directory alias/junction. */
static HRESULT save_canonical_root( const char *root, WCHAR result[4096] )
{
    WCHAR path[4096], absolute[4096], ancestor[4096], resolved[4096];
    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, root, -1, path, ARRAY_SIZE( path ) ) ) return E_INVALIDARG;
    if ( !wcsncmp( path, L"\\\\?\\UNC\\", 8 ) )
    {
        memmove( path + 2, path + 8, ( wcslen( path ) - 7 ) * sizeof( WCHAR ) ); path[0] = path[1] = L'\\';
    }
    else if ( !wcsncmp( path, L"\\\\?\\", 4 ) )
        memmove( path, path + 4, ( wcslen( path ) - 3 ) * sizeof( WCHAR ) );
    DWORD length = GetFullPathNameW( path, ARRAY_SIZE( absolute ), absolute, NULL );
    if ( !length || length >= ARRAY_SIZE( absolute ) ) return E_INVALIDARG;
    while ( length > 3 && ( absolute[length - 1] == L'\\' || absolute[length - 1] == L'/' ) ) absolute[--length] = 0;
    wcscpy( ancestor, absolute );
    DWORD prefix = length;
    for ( ;; )
    {
        const WCHAR *open_path = ancestor;
        if ( ancestor[1] == L':' )
        {
            if ( wcslen( ancestor ) + 4 >= ARRAY_SIZE( path ) ) return E_INVALIDARG;
            wcscpy( path, L"\\\\?\\" ); wcscat( path, ancestor ); open_path = path;
        }
        else if ( ancestor[0] == L'\\' && ancestor[1] == L'\\' )
        {
            if ( wcslen( ancestor ) + 6 >= ARRAY_SIZE( path ) ) return E_INVALIDARG;
            wcscpy( path, L"\\\\?\\UNC\\" ); wcscat( path, ancestor + 2 ); open_path = path;
        }
        HANDLE directory = CreateFileW( open_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL );
        if ( directory != INVALID_HANDLE_VALUE )
        {
            BY_HANDLE_FILE_INFORMATION information;
            if ( !GetFileInformationByHandle( directory, &information ) )
            { DWORD error = GetLastError(); CloseHandle( directory ); return HRESULT_FROM_WIN32( error ); }
            if ( !( information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
            { CloseHandle( directory ); return HRESULT_FROM_WIN32( ERROR_DIRECTORY ); }
            DWORD count = GetFinalPathNameByHandleW( directory, resolved, ARRAY_SIZE( resolved ), FILE_NAME_NORMALIZED );
            CloseHandle( directory );
            if ( !count || count >= ARRAY_SIZE( resolved ) ) return E_INVALIDARG;
            break;
        }
        DWORD error = GetLastError();
        if ( error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND ) return HRESULT_FROM_WIN32( error );
        if ( prefix <= 3 ) return HRESULT_FROM_WIN32( error );
        WCHAR *slash = wcsrchr( ancestor, L'\\' );
        if ( !slash || slash - ancestor < 2 ) return HRESULT_FROM_WIN32( error );
        prefix = slash - ancestor;
        if ( prefix == 2 && ancestor[1] == L':' ) prefix = 3;
        ancestor[prefix] = 0;
    }
    if ( !wcsncmp( resolved, L"\\\\?\\UNC\\", 8 ) )
    {
        memmove( resolved + 2, resolved + 8, ( wcslen( resolved ) - 7 ) * sizeof( WCHAR ) );
        resolved[0] = resolved[1] = L'\\';
    }
    else if ( !wcsncmp( resolved, L"\\\\?\\", 4 ) )
        memmove( resolved, resolved + 4, ( wcslen( resolved ) - 3 ) * sizeof( WCHAR ) );
    SIZE_T count = wcslen( resolved );
    const WCHAR *tail = absolute + prefix;
    if ( count && resolved[count - 1] == L'\\' && *tail == L'\\' ) tail++;
    BOOL separator = count && resolved[count - 1] != L'\\' && *tail && *tail != L'\\';
    if ( count + separator + wcslen( tail ) >= 4096 ) return E_INVALIDARG;
    wcscpy( result, resolved ); if ( separator ) wcscat( result, L"\\" ); wcscat( result, tail );
    count = wcslen( result );
    while ( count > 3 && result[count - 1] == L'\\' ) result[--count] = 0;
    CharUpperBuffW( result, count ); return S_OK;
}
class save_shared_lock
{
    HANDLE mutex = NULL;
    bool owned = false;
    DWORD timeout;
public:
    HRESULT status = E_OUTOFMEMORY;
    save_shared_lock( const XGameSaveProvider *provider, const WCHAR *prefix, DWORD wait ) : timeout( wait )
    {
        WCHAR absolute[4096], name[128];
        char utf8[16384];
        HRESULT canonical = save_canonical_root( provider->root, absolute );
        if ( FAILED( canonical ) ) { status = canonical; return; }
        if ( !WideCharToMultiByte( CP_UTF8, 0, absolute, -1, utf8, sizeof( utf8 ), NULL, NULL ) ) return;
        char *key = files_cache_key( utf8 );
        if ( !key ) return;
        swprintf( name, ARRAY_SIZE( name ), L"%ls%hs", prefix, key ); free( key );
        mutex = CreateMutexW( NULL, FALSE, name );
        if ( !mutex ) { status = HRESULT_FROM_WIN32( GetLastError() ); return; }
        acquire();
    }
    HRESULT acquire()
    {
        if ( owned ) return status;
        if ( !mutex ) return status;
        DWORD result = WaitForSingleObject( mutex, timeout );
        owned = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
        return status = owned ? S_OK : HRESULT_FROM_WIN32( result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError() );
    }
    void release() { if ( owned ) { ReleaseMutex( mutex ); owned = false; } }
    ~save_shared_lock() { release(); if ( mutex ) CloseHandle( mutex ); }
    save_shared_lock( const save_shared_lock & ) = delete;
    save_shared_lock &operator=( const save_shared_lock & ) = delete;
};
class save_root_lock : public save_shared_lock
{
public:
    explicit save_root_lock( const XGameSaveProvider *p ) : save_shared_lock( p, L"Local\\NexusGameSave-", INFINITE ) {}
};
class save_remote_lock : public save_shared_lock
{
public:
    explicit save_remote_lock( const XGameSaveProvider *p, DWORD timeout = 15000 )
        : save_shared_lock( p, L"Local\\NexusGameSaveRemote-", timeout ) {}
};

class save_cs_lock
{
    CRITICAL_SECTION *cs;
public:
    explicit save_cs_lock( CRITICAL_SECTION *value ) : cs( value ) { if ( cs ) EnterCriticalSection( cs ); }
    ~save_cs_lock() { if ( cs ) LeaveCriticalSection( cs ); }
    save_cs_lock( const save_cs_lock & ) = delete;
};

static HRESULT save_path_attributes( const char *path, DWORD *attributes )
{
    WCHAR wide[4096];
    if ( !save_wide_path( path, wide ) ) return E_INVALIDARG;
    *attributes = GetFileAttributesW( wide );
    if ( *attributes != INVALID_FILE_ATTRIBUTES )
        return *attributes & FILE_ATTRIBUTE_REPARSE_POINT ? E_ACCESSDENIED : S_OK;
    DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? S_FALSE : HRESULT_FROM_WIN32( error );
}

static HRESULT save_move_directory( const char *from, const char *to )
{
    WCHAR source[4096], target[4096];
    if ( !save_wide_path( from, source ) || !save_wide_path( to, target ) ) return E_INVALIDARG;
    return MoveFileExW( source, target, MOVEFILE_WRITE_THROUGH ) ? S_OK : HRESULT_FROM_WIN32( GetLastError() );
}

// Only owned journal trees are removed here, never the active save directory.
static HRESULT save_remove_journal( const char *path )
{
    DWORD attributes;
    HRESULT hr = save_path_attributes( path, &attributes );
    if ( hr != S_OK ) return hr == S_FALSE ? S_OK : hr;
    WCHAR wide[4096];
    if ( !save_wide_path( path, wide ) ) return E_INVALIDARG;
    if ( attributes & FILE_ATTRIBUTE_DIRECTORY )
    {
        WCHAR pattern[4096];
        WIN32_FIND_DATAW data;
        if ( wcslen( wide ) + 3 >= ARRAY_SIZE( pattern ) ) return E_INVALIDARG;
        wcscpy( pattern, wide ); wcscat( pattern, L"\\*" );
        HANDLE find = FindFirstFileW( pattern, &data );
        if ( find == INVALID_HANDLE_VALUE ) return HRESULT_FROM_WIN32( GetLastError() );
        do
        {
            if ( !wcscmp( data.cFileName, L"." ) || !wcscmp( data.cFileName, L".." ) || !wcscmp( data.cFileName, L"name" ) ) continue;
            char name[1024], child[2048];
            if ( !WideCharToMultiByte( CP_UTF8, 0, data.cFileName, -1, name, sizeof( name ), NULL, NULL ) ||
                 snprintf( child, sizeof( child ), "%s\\%s", path, name ) >= sizeof( child ) )
                hr = E_INVALIDARG;
            else hr = save_remove_journal( child );
            if ( FAILED( hr ) ) break;
        } while ( FindNextFileW( find, &data ) );
        if ( SUCCEEDED( hr ) && GetLastError() != ERROR_NO_MORE_FILES ) hr = HRESULT_FROM_WIN32( GetLastError() );
        FindClose( find );
        if ( FAILED( hr ) ) return hr;
        // The recovery identity is removed last. A failed or interrupted
        // backup cleanup must remain discoverable on the next startup.
        char identity[2048];
        if ( snprintf( identity, sizeof( identity ), "%s\\name", path ) >= sizeof( identity ) ) return E_INVALIDARG;
        if ( FAILED( hr = save_remove_journal( identity ) ) ) return hr;
        return RemoveDirectoryW( wide ) ? S_OK : HRESULT_FROM_WIN32( GetLastError() );
    }
    if ( attributes & FILE_ATTRIBUTE_READONLY )
        if ( !SetFileAttributesW( wide, attributes & ~FILE_ATTRIBUTE_READONLY ) ) return HRESULT_FROM_WIN32( GetLastError() );
    return DeleteFileW( wide ) ? S_OK : HRESULT_FROM_WIN32( GetLastError() );
}

static HRESULT local_update_paths( XGameSaveProvider *provider, const char *name, char target[2048], char journal[2048] )
{
    if ( !container_dir( provider, name, target, 2048 ) ||
         snprintf( journal, 2048, "%s\\.local-update-%s", provider->root, strrchr( target, '\\' ) + 1 ) >= 2048 )
        return E_GS_INVALID_CONTAINER_NAME;
    return S_OK;
}

static HRESULT missing_local_index( const char *directory, HRESULT missing )
{
    DWORD attributes;
    HRESULT hr = save_path_attributes( directory, &attributes );
    if ( hr == S_FALSE ) return missing;
    if ( FAILED( hr ) ) return hr;
    if ( !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ) return HRESULT_FROM_WIN32( ERROR_DIRECTORY );
    char pattern[2048]; WIN32_FIND_DATAA entry;
    if ( snprintf( pattern, sizeof( pattern ), "%s\\*", directory ) >= sizeof( pattern ) ) return E_INVALIDARG;
    HANDLE find = save_find_first( pattern, &entry );
    if ( find == INVALID_HANDLE_VALUE ) return HRESULT_FROM_WIN32( GetLastError() );
    hr = missing;
    do
    {
        if ( strcmp( entry.cFileName, "." ) && strcmp( entry.cFileName, ".." ) )
        { hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA ); break; }
    } while ( FindNextFileA( find, &entry ) );
    if ( hr == missing && GetLastError() != ERROR_NO_MORE_FILES ) hr = HRESULT_FROM_WIN32( GetLastError() );
    FindClose( find );
    return hr;
}

// Caller owns the root mutex. Journal creation precedes all mutations of the
// active directory. A missing active directory with a backup means rollback;
// active + backup means the final rename committed the complete new revision.
static HRESULT recover_local_update( XGameSaveProvider *provider, const char *name )
{
    char target[2048], journal[2048], previous[2048], next[2048];
    DWORD attributes;
    HRESULT hr = local_update_paths( provider, name, target, journal );
    if ( FAILED( hr ) ) return hr;
    hr = save_path_attributes( journal, &attributes );
    if ( hr != S_OK ) return hr == S_FALSE ? S_OK : hr;
    if ( !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ) return E_ACCESSDENIED;
    if ( snprintf( previous, sizeof( previous ), "%s\\previous", journal ) >= sizeof( previous ) ||
         snprintf( next, sizeof( next ), "%s\\next\\%s", journal, strrchr( target, '\\' ) + 1 ) >= sizeof( next ) )
        return E_INVALIDARG;
    HRESULT active = save_path_attributes( target, &attributes );
    if ( FAILED( active ) ) return active;
    if ( active == S_OK && !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ) return E_ACCESSDENIED;
    HRESULT old = save_path_attributes( previous, &attributes );
    if ( FAILED( old ) ) return old;
    if ( old == S_OK )
    {
        if ( !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ) return E_ACCESSDENIED;
        if ( active == S_FALSE )
        {
            if ( FAILED( hr = save_move_directory( previous, target ) ) ) return hr;
        }
        else
        {
            hr = save_path_attributes( next, &attributes );
            if ( hr != S_FALSE ) return FAILED( hr ) ? hr : HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
        }
    }
    // Cleanup is retryable. It cannot turn an already committed revision into
    // a failed update, nor authorize removal of the active data.
    if ( FAILED( hr = save_remove_journal( journal ) ) )
        WARN( "local save journal cleanup retained for retry, hr %#lx\n", hr );
    return S_OK;
}

static HRESULT recover_local_updates( XGameSaveProvider *provider )
{
    char pattern[2048], journal[2048], path[2048];
    WIN32_FIND_DATAA entry;
    if ( snprintf( pattern, sizeof( pattern ), "%s\\.local-update-*", provider->root ) >= sizeof( pattern ) )
        return E_INVALIDARG;
    HANDLE find = save_find_first( pattern, &entry );
    if ( find == INVALID_HANDLE_VALUE )
    {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32( error );
    }
    HRESULT hr = S_OK;
    do
    {
        BYTE *data = NULL;
        SIZE_T size = 0;
        if ( !( entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) || entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT )
        { hr = E_ACCESSDENIED; break; }
        if ( snprintf( journal, sizeof( journal ), "%s\\%s", provider->root, entry.cFileName ) >= sizeof( journal ) ||
             snprintf( path, sizeof( path ), "%s\\name", journal ) >= sizeof( path ) )
        { hr = E_INVALIDARG; break; }
        hr = read_file( path, &data, &size );
        if ( hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) )
        {
            DWORD attrs;
            snprintf( path, sizeof( path ), "%s\\previous", journal );
            if ( save_path_attributes( path, &attrs ) == S_FALSE ) hr = save_remove_journal( journal );
        }
        else if ( SUCCEEDED( hr ) )
        {
            char expected[2048], target[2048];
            if ( !size || size > 256 || strlen( ( char * )data ) != size ||
                 FAILED( local_update_paths( provider, ( char * )data, target, expected ) ) || strcmp( journal, expected ) )
                hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            else hr = recover_local_update( provider, ( char * )data );
        }
        free( data );
        if ( FAILED( hr ) ) break;
    } while ( FindNextFileA( find, &entry ) );
    if ( SUCCEEDED( hr ) && GetLastError() != ERROR_NO_MORE_FILES ) hr = HRESULT_FROM_WIN32( GetLastError() );
    FindClose( find );
    return hr;
}

static HRESULT copy_local_container( const char *source, const char *target )
{
    char pattern[2048];
    WCHAR pattern_wide[4096];
    WIN32_FIND_DATAW entry;
    HRESULT hr = files_mkdir( target );
    if ( FAILED( hr ) ) return hr;
    if ( snprintf( pattern, sizeof( pattern ), "%s\\*", source ) >= sizeof( pattern ) ) return E_INVALIDARG;
    if ( !save_wide_path( pattern, pattern_wide ) ) return E_INVALIDARG;
    HANDLE find = FindFirstFileW( pattern_wide, &entry );
    if ( find == INVALID_HANDLE_VALUE ) return HRESULT_FROM_WIN32( GetLastError() );
    do
    {
        if ( !wcscmp( entry.cFileName, L"." ) || !wcscmp( entry.cFileName, L".." ) ) continue;
        char from[2048], to[2048], filename[1024];
        BYTE *bytes = NULL; SIZE_T size = 0;
        if ( entry.dwFileAttributes & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ) ||
             !WideCharToMultiByte( CP_UTF8, 0, entry.cFileName, -1, filename, sizeof( filename ), NULL, NULL ) ||
             snprintf( from, sizeof( from ), "%s\\%s", source, filename ) >= sizeof( from ) ||
             snprintf( to, sizeof( to ), "%s\\%s", target, filename ) >= sizeof( to ) )
        { hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA ); break; }
        WCHAR from_wide[4096], to_wide[4096];
        if ( !save_wide_path( from, from_wide ) || !save_wide_path( to, to_wide ) ) { hr = E_INVALIDARG; break; }
        // Every mutation below replaces/unlinks a file, never edits an inode.
        // Share unchanged blobs instead of copying the entire save each time.
        // Readonly files are copied so journal cleanup cannot alter attributes
        // of the active file. Filesystems without hardlinks use flushed copies.
        if ( !( entry.dwFileAttributes & FILE_ATTRIBUTE_READONLY ) && CreateHardLinkW( to_wide, from_wide, NULL ) ) continue;
        hr = read_file( from, &bytes, &size );
        if ( SUCCEEDED( hr ) ) hr = write_file( to, bytes, size );
        free( bytes );
        WCHAR wide[4096];
        if ( SUCCEEDED( hr ) && ( !save_wide_path( to, wide ) || !SetFileAttributesW( wide, entry.dwFileAttributes ) ) )
            hr = HRESULT_FROM_WIN32( GetLastError() );
        if ( FAILED( hr ) ) break;
    } while ( FindNextFileW( find, &entry ) );
    if ( SUCCEEDED( hr ) && GetLastError() != ERROR_NO_MORE_FILES ) hr = HRESULT_FROM_WIN32( GetLastError() );
    FindClose( find );
    return hr;
}

class local_save_transaction
{
    XGameSaveProvider *provider;
    const char *name;
    char target[2048], journal[2048], previous[2048], source[2048];
    bool prepared = false;
public:
    XGameSaveProvider staged{};
    local_save_transaction( XGameSaveProvider *value, const char *container ) : provider( value ), name( container ) {}
    HRESULT prepare()
    {
        HRESULT hr = local_update_paths( provider, name, target, journal );
        if ( FAILED( hr ) ) return hr;
        if ( FAILED( hr = recover_local_update( provider, name ) ) || FAILED( hr = files_mkdir( provider->root ) ) ) return hr;
        if ( snprintf( previous, sizeof( previous ), "%s\\previous", journal ) >= sizeof( previous ) ||
             snprintf( staged.root, sizeof( staged.root ), "%s\\next", journal ) >= sizeof( staged.root ) ) return E_INVALIDARG;
        staged.files = provider->files;
        if ( !container_dir( &staged, name, source, sizeof( source ) ) ) return E_INVALIDARG;
        WCHAR wide[4096];
        if ( !save_wide_path( journal, wide ) ) return E_INVALIDARG;
        if ( !CreateDirectoryW( wide, NULL ) ) return HRESULT_FROM_WIN32( GetLastError() );
        prepared = true;
        char record[2048];
        if ( snprintf( record, sizeof( record ), "%s\\name", journal ) >= sizeof( record ) ) return E_INVALIDARG;
        if ( FAILED( hr = write_file( record, name, strlen( name ) ) ) ) return hr;
        DWORD attributes;
        hr = save_path_attributes( target, &attributes );
        if ( hr == S_FALSE ) return files_mkdir( source );
        if ( FAILED( hr ) ) return hr;
        return attributes & FILE_ATTRIBUTE_DIRECTORY ? copy_local_container( target, source ) : E_ACCESSDENIED;
    }
    HRESULT commit()
    {
        DWORD attributes;
        HRESULT hr = save_path_attributes( target, &attributes );
        if ( FAILED( hr ) ) return hr;
        if ( hr == S_OK && FAILED( hr = save_move_directory( target, previous ) ) ) return hr;
        if ( FAILED( hr = save_move_directory( source, target ) ) ) return hr;
        prepared = false;
        if ( FAILED( hr = save_remove_journal( journal ) ) ) WARN( "committed save journal retained, hr %#lx\n", hr );
        return S_OK;
    }
    ~local_save_transaction()
    {
        if ( prepared && FAILED( recover_local_update( provider, name ) ) )
            ERR( "local update rollback pending; previous save retained in journal\n" );
    }
};
