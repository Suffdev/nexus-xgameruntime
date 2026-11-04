/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Licensed content mounts use a private projection of the package layout.
 * Installed files, public metadata and a package identifier never grant rights. */
#include <bcrypt.h>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <xstore.h>

struct package_mount_file
{
    std::wstring source, destination;
    UINT64 bytes;
};
struct package_mount_less
{
    bool operator()( const std::wstring &a, const std::wstring &b ) const
    {
        return CompareStringOrdinal( a.c_str(), a.size(), b.c_str(), b.size(), TRUE ) == CSTR_LESS_THAN;
    }
};
struct package_mount_plan
{
    std::vector<package_mount_file> files;
    std::map<std::wstring, SIZE_T, package_mount_less> destinations;
    UINT64 bytes = 0;
    UINT groups = 0;
};
struct package_mount_find
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ~package_mount_find()
    {
        if ( value != INVALID_HANDLE_VALUE )
            FindClose( value );
    }
};

/* DestinationPath is rooted in the package image, not in the host filesystem.
 * Source paths remain relative to the already validated extracted package. */
static BOOL package_mount_relative( const char *text, BOOL destination, std::wstring &out )
{
    out.clear();
    if ( !text || strlen( text ) >= MAX_PATH )
        return FALSE;
    WCHAR wide[MAX_PATH];
    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, MAX_PATH ) )
        return FALSE;
    const WCHAR *p = wide;
    if ( destination && ( *p == L'\\' || *p == L'/' ) )
        ++p;
    if ( *p == L'\\' || *p == L'/' )
        return FALSE;
    while ( *p )
    {
        const WCHAR *end = p;
        while ( *end && *end != L'\\' && *end != L'/' )
            ++end;
        std::wstring part( p, end );
        if ( part == L".." )
            return FALSE;
        if ( !part.empty() && part != L"." )
        {
            if ( part.back() == L'.' || part.back() == L' ' )
                return FALSE;
            for ( WCHAR c : part )
                if ( c < 32 || wcschr( L":*?\"<>|", c ) )
                    return FALSE;
            if ( !out.empty() )
                out += L'\\';
            out += part;
        }
        p = *end ? end + 1 : end;
    }
    return out.size() < MAX_PATH;
}

/* The package root is host-supplied and must be a real directory. Components
 * below it use the shared bounded no-reparse walk from Content.h. */
static BOOL package_mount_directory( const WCHAR *root, const std::wstring &relative, std::wstring &out )
{
    WCHAR path[MAX_PATH];
    DWORD attributes = GetFileAttributesW( root );
    if ( attributes == INVALID_FILE_ATTRIBUTES || !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ||
         ( attributes & FILE_ATTRIBUTE_REPARSE_POINT ) )
        return FALSE;
    if ( !content_directory( root, relative.c_str(), path ) )
        return FALSE;
    out = path;
    return TRUE;
}

static HRESULT package_mount_collect( const WCHAR *root, xmlNodePtr node, UINT depth, package_mount_plan &plan,
                                      enum content_layout_coordinate coordinate )
{
    if ( depth > 16 )
        return HRESULT_FROM_WIN32( ERROR_MORE_DATA );
    for ( ; node; node = node->next )
    {
        if ( node->type != XML_ELEMENT_NODE )
            continue;
        if ( !strcmp( ( char * )node->name, "FileGroup" ) )
        {
            char source[MAX_PATH], include[MAX_PATH];
            std::unique_ptr<xmlChar, xmlFreeFunc> destination( xmlGetProp( node, BAD_CAST "DestinationPath" ),
                                                               xmlFree );
            std::unique_ptr<xmlChar, xmlFreeFunc> exclude( xmlGetProp( node, BAD_CAST "Exclude" ), xmlFree );
            std::wstring source_relative, destination_relative, include_directory, directory;
            if ( ++plan.groups > 256 )
                return HRESULT_FROM_WIN32( ERROR_MORE_DATA );
            if ( exclude )
                return E_NOTIMPL;
            if ( !content_text( node, "Include", include, sizeof( include ) ) ||
                 !content_relative( include, TRUE ) )
                return E_INVALIDARG;
            if ( destination )
            {
                if ( !*destination.get() ||
                     !package_mount_relative( ( char * )destination.get(), TRUE, destination_relative ) )
                    return E_INVALIDARG;
            }
            else if ( content_text( node, "SourcePath", source, sizeof( source ) ) )
            {
                /* No destination was declared: the deployed tree is the declared
                 * source location, matching package chunk readiness. */
                if ( !package_mount_relative( source, TRUE, destination_relative ) ) return E_INVALIDARG;
            }
            else
                return E_INVALIDARG;
            if ( coordinate == CONTENT_LAYOUT_DESTINATION )
            {
                /* An already deployed tree is projected onto its own destination
                 * paths; SourcePath is the build-machine coordinate then. */
                source_relative = destination_relative;
            }
            else if ( !content_text( node, "SourcePath", source, sizeof( source ) ) ||
                      !package_mount_relative( source, TRUE, source_relative ) )
                return E_INVALIDARG;
            char *last = strrchr( include, '\\' ), *slash = strrchr( include, '/' );
            if ( !last || ( slash && slash > last ) )
                last = slash;
            const char *pattern = include;
            if ( last )
            {
                *last = 0;
                pattern = last + 1;
                if ( !package_mount_relative( include, FALSE, include_directory ) )
                    return E_INVALIDARG;
                if ( !source_relative.empty() && !include_directory.empty() )
                    source_relative += L'\\';
                source_relative += include_directory;
            }
            WCHAR wide_pattern[MAX_PATH];
            if ( !*pattern || strchr( pattern, '%' ) ||
                 !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, pattern, -1, wide_pattern, MAX_PATH ) ||
                 !package_mount_directory( root, source_relative, directory ) )
                return E_INVALIDARG;
            std::wstring search = directory + L"\\" + wide_pattern;
            if ( search.size() >= MAX_PATH )
                return E_INVALIDARG;
            WIN32_FIND_DATAW found;
            package_mount_find find;
            find.value = FindFirstFileW( search.c_str(), &found );
            if ( find.value == INVALID_HANDLE_VALUE )
                return HRESULT_FROM_WIN32( GetLastError() );
            BOOL any = FALSE;
            do
            {
                if ( found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                    continue;
                if ( found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT )
                    return E_ACCESSDENIED;
                std::wstring target = destination_relative;
                if ( !target.empty() )
                    target += L'\\';
                target += found.cFileName;
                std::wstring path = directory + L"\\" + found.cFileName;
                if ( target.size() >= MAX_PATH || path.size() >= MAX_PATH )
                    return E_INVALIDARG;
                UINT64 size = ( ( UINT64 )found.nFileSizeHigh << 32 ) | found.nFileSizeLow;
                auto previous = plan.destinations.find( target );
                if ( previous != plan.destinations.end() )
                {
                    const auto &file = plan.files[previous->second];
                    if ( file.source != path || file.bytes != size )
                        return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
                }
                else
                {
                    if ( plan.files.size() == 65536 || UINT64_MAX - plan.bytes < size )
                        return HRESULT_FROM_WIN32( ERROR_MORE_DATA );
                    plan.destinations.emplace( target, plan.files.size() );
                    plan.files.push_back( { path, target, size } );
                    plan.bytes += size;
                }
                any = TRUE;
            } while ( FindNextFileW( find.value, &found ) );
            if ( GetLastError() != ERROR_NO_MORE_FILES )
                return HRESULT_FROM_WIN32( GetLastError() );
            if ( !any )
                return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND );
        }
        HRESULT hr = package_mount_collect( root, node->children, depth + 1, plan, coordinate );
        if ( FAILED( hr ) )
            return hr;
    }
    return S_OK;
}

static HRESULT package_mount_read_plan( const content_package &package, package_mount_plan &plan )
{
    WCHAR pattern[MAX_PATH], file[MAX_PATH];
    if ( !content_join( package.path, L"layout_*.xml", pattern ) )
        return E_INVALIDARG;
    WIN32_FIND_DATAW found;
    package_mount_find find;
    find.value = FindFirstFileW( pattern, &found );
    if ( find.value == INVALID_HANDLE_VALUE )
        return HRESULT_FROM_WIN32( GetLastError() );
    char id[33];
    if ( found.dwFileAttributes & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ) ||
         !content_layout_id( found.cFileName, id ) || strcmp( id, package.identifier ) ||
         !content_join( package.path, found.cFileName, file ) )
        return E_INVALIDARG;
    if ( FindNextFileW( find.value, &found ) )
        return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
    if ( GetLastError() != ERROR_NO_MORE_FILES )
        return HRESULT_FROM_WIN32( GetLastError() );
    std::unique_ptr<xmlDoc, decltype( &xmlFreeDoc )> document( content_read_xml( file ), &xmlFreeDoc );
    xmlNodePtr root = document ? xmlDocGetRootElement( document.get() ) : NULL;
    if ( !root || strcmp( ( char * )root->name, "Package" ) )
        return E_INVALIDARG;
    try
    {
        enum content_layout_coordinate coordinate;
        UINT groups = 0;
        if ( !content_layout_coordinate( package.path, root->children, &coordinate, &groups ) )
            return E_INVALIDARG;
        HRESULT hr = package_mount_collect( package.path, root->children, 0, plan, coordinate );
        return FAILED( hr ) ? hr : plan.groups && !plan.files.empty() ? S_OK : E_INVALIDARG;
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}

static BOOL package_mount_remove( const std::wstring &path, UINT depth = 0 )
{
    if ( depth > 128 || path.size() + 3 >= MAX_PATH )
        return FALSE;
    DWORD attributes = GetFileAttributesW( path.c_str() );
    if ( attributes == INVALID_FILE_ATTRIBUTES )
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    if ( attributes & FILE_ATTRIBUTE_REPARSE_POINT )
        return attributes & FILE_ATTRIBUTE_DIRECTORY ? RemoveDirectoryW( path.c_str() ) : DeleteFileW( path.c_str() );
    if ( !( attributes & FILE_ATTRIBUTE_DIRECTORY ) )
        return SetFileAttributesW( path.c_str(), FILE_ATTRIBUTE_NORMAL ) && DeleteFileW( path.c_str() );
    WIN32_FIND_DATAW found;
    package_mount_find find;
    find.value = FindFirstFileW( ( path + L"\\*" ).c_str(), &found );
    if ( find.value == INVALID_HANDLE_VALUE )
        return FALSE;
    BOOL ok = TRUE;
    UINT count = 0;
    do
    {
        if ( !wcscmp( found.cFileName, L"." ) || !wcscmp( found.cFileName, L".." ) )
            continue;
        if ( ++count > 65536 )
        {
            ok = FALSE;
            break;
        }
        ok = package_mount_remove( path + L"\\" + found.cFileName, depth + 1 ) && ok;
    } while ( FindNextFileW( find.value, &found ) );
    if ( GetLastError() != ERROR_NO_MORE_FILES )
        ok = FALSE;
    return RemoveDirectoryW( path.c_str() ) && ok;
}

struct package_mount_right
{
    void *context = NULL;
    BOOL ( *valid )( void * ) = NULL;
    void ( *close )( void * ) = NULL;
};
struct package_mount_record
{
    LONG refs = 1;
    package_mount_record *next = NULL;
    package_mount_right right;
    std::wstring directory;
    std::string path;
    HANDLE anchor = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION identity{};
};
static SRWLOCK package_mount_lock = SRWLOCK_INIT;
static package_mount_record *package_mounts;

static BOOL package_mount_same_directory( const package_mount_record &record )
{
    DWORD attributes = GetFileAttributesW( record.directory.c_str() );
    if ( attributes == INVALID_FILE_ATTRIBUTES || ( attributes & FILE_ATTRIBUTE_REPARSE_POINT ) )
        return FALSE;
    HANDLE check = CreateFileW( record.directory.c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL );
    if ( check == INVALID_HANDLE_VALUE )
        return FALSE;
    BY_HANDLE_FILE_INFORMATION info{};
    BOOL ok = GetFileInformationByHandle( check, &info ) &&
              info.dwVolumeSerialNumber == record.identity.dwVolumeSerialNumber &&
              info.nFileIndexHigh == record.identity.nFileIndexHigh &&
              info.nFileIndexLow == record.identity.nFileIndexLow;
    CloseHandle( check );
    return ok;
}

static void package_mount_release( package_mount_record *record )
{
    if ( InterlockedDecrement( &record->refs ) )
        return;
    try
    {
        if ( !record->directory.empty() && record->anchor != INVALID_HANDLE_VALUE &&
             package_mount_same_directory( *record ) )
            package_mount_remove( record->directory );
    }
    catch ( const std::bad_alloc & )
    { /* Retain only this private temporary view on cleanup OOM. */
    }
    if ( record->anchor != INVALID_HANDLE_VALUE )
        CloseHandle( record->anchor );
    if ( record->right.context && record->right.close )
        record->right.close( record->right.context );
    delete record;
}
struct package_mount_owner
{
    package_mount_record *p;
    ~package_mount_owner()
    {
        if ( p )
            package_mount_release( p );
    }
};

static HRESULT package_mount_make_directory( const std::wstring &root, const std::wstring &relative )
{
    std::wstring path = root;
    SIZE_T offset = 0;
    while ( offset < relative.size() )
    {
        SIZE_T end = relative.find( L'\\', offset );
        if ( end == std::wstring::npos )
            end = relative.size();
        path += L'\\';
        path.append( relative, offset, end - offset );
        if ( path.size() >= MAX_PATH )
            return E_INVALIDARG;
        if ( !CreateDirectoryW( path.c_str(), NULL ) && GetLastError() != ERROR_ALREADY_EXISTS )
            return HRESULT_FROM_WIN32( GetLastError() );
        DWORD attributes = GetFileAttributesW( path.c_str() );
        if ( attributes == INVALID_FILE_ATTRIBUTES || !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ||
             ( attributes & FILE_ATTRIBUTE_REPARSE_POINT ) )
            return E_ACCESSDENIED;
        offset = end + 1;
    }
    return S_OK;
}

/* Consumes the independently obtained license on both success and failure.
 * The internal callback form lets closed, account-free fixtures exercise the
 * exact projection code without an alternate production licensing provider. */
static HRESULT package_mount_create( const content_package &package, package_mount_right right,
                                     XPackageMountHandle *out )
{
    package_mount_owner owner{ new ( std::nothrow ) package_mount_record };
    if ( !owner.p )
    {
        if ( right.context && right.close )
            right.close( right.context );
        return E_OUTOFMEMORY;
    }
    owner.p->right = right;
    if ( !out )
        return E_INVALIDARG;
    *out = NULL;
    if ( !package.content )
        return E_ACCESSDENIED;
    if ( !right.context || !right.valid || !right.close || !right.valid( right.context ) )
        return E_ACCESSDENIED;
    try
    {
        package_mount_plan plan;
        HRESULT hr = package_mount_read_plan( package, plan );
        if ( FAILED( hr ) )
            return hr;
        WCHAR temporary[MAX_PATH], name[64];
        DWORD length = GetEnvironmentVariableW( L"XODUS_MOUNT_ROOT", temporary, MAX_PATH );
        /* The host session owns cleanup, including crashes and Windows files
         * opened without FILE_SHARE_DELETE. Do not strand large copies in an
         * unmanaged prefix Temp directory when an older host lacks this root. */
        if ( !length )
            return E_NOTIMPL;
        std::wstring managed;
        if ( length >= MAX_PATH || !content_absolute( temporary ) ||
             !package_mount_directory( temporary, L"", managed ) )
            return E_INVALIDARG;
        BYTE nonce[16];
        if ( BCryptGenRandom( NULL, nonce, sizeof( nonce ), BCRYPT_USE_SYSTEM_PREFERRED_RNG ) )
            return E_FAIL;
        wcscpy( name, L"XodusDlcMount-" );
        for ( UINT i = 0; i < sizeof( nonce ); ++i )
            swprintf( name + 14 + i * 2, 3, L"%02x", nonce[i] );
        WCHAR projected[MAX_PATH];
        if ( !content_join( temporary, name, projected ) )
            return E_INVALIDARG;
        owner.p->directory = projected;
        if ( !CreateDirectoryW( owner.p->directory.c_str(), NULL ) )
            return HRESULT_FROM_WIN32( GetLastError() );
        owner.p->anchor = CreateFileW( owner.p->directory.c_str(), FILE_READ_ATTRIBUTES,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL );
        if ( owner.p->anchor == INVALID_HANDLE_VALUE ||
             !GetFileInformationByHandle( owner.p->anchor, &owner.p->identity ) )
        {
            RemoveDirectoryW( owner.p->directory.c_str() );
            return E_FAIL;
        }
        ULARGE_INTEGER available;
        if ( !GetDiskFreeSpaceExW( owner.p->directory.c_str(), &available, NULL, NULL ) )
            return HRESULT_FROM_WIN32( GetLastError() );
        if ( available.QuadPart < plan.bytes )
            return HRESULT_FROM_WIN32( ERROR_DISK_FULL );
        for ( const auto &file : plan.files )
        {
            if ( !right.valid( right.context ) )
                return E_ACCESSDENIED;
            SIZE_T separator = file.destination.rfind( L'\\' );
            if ( separator != std::wstring::npos &&
                 FAILED( hr = package_mount_make_directory( owner.p->directory,
                                                            file.destination.substr( 0, separator ) ) ) )
                return hr;
            std::wstring target = owner.p->directory + L"\\" + file.destination;
            if ( target.size() >= MAX_PATH )
                return E_INVALIDARG;
            DWORD attributes = GetFileAttributesW( file.source.c_str() );
            if ( attributes == INVALID_FILE_ATTRIBUTES ||
                 ( attributes & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ) ) )
                return E_ACCESSDENIED;
            if ( !CopyFileW( file.source.c_str(), target.c_str(), TRUE ) )
                return HRESULT_FROM_WIN32( GetLastError() );
            WIN32_FILE_ATTRIBUTE_DATA data{};
            if ( !GetFileAttributesExW( target.c_str(), GetFileExInfoStandard, &data ) ||
                 ( ( ( UINT64 )data.nFileSizeHigh << 32 ) | data.nFileSizeLow ) != file.bytes )
                return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            if ( !SetFileAttributesW( target.c_str(), FILE_ATTRIBUTE_READONLY ) )
                return HRESULT_FROM_WIN32( GetLastError() );
        }
        if ( !right.valid( right.context ) )
            return E_ACCESSDENIED;
        int size =
            WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, owner.p->directory.c_str(), -1, NULL, 0, NULL, NULL );
        if ( size <= 0 )
            return E_INVALIDARG;
        owner.p->path.resize( size );
        if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, owner.p->directory.c_str(), -1, owner.p->path.data(),
                                   size, NULL, NULL ) )
            return E_INVALIDARG;
        owner.p->path.resize( size - 1 );
        AcquireSRWLockExclusive( &package_mount_lock );
        owner.p->next = package_mounts;
        package_mounts = owner.p;
        ReleaseSRWLockExclusive( &package_mount_lock );
        *out = ( XPackageMountHandle )owner.p;
        owner.p = NULL;
        return S_OK;
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}

static package_mount_record *package_mount_acquire( XPackageMountHandle handle )
{
    AcquireSRWLockShared( &package_mount_lock );
    package_mount_record *record = package_mounts;
    while ( record && record != ( void * )handle )
        record = record->next;
    if ( record )
        InterlockedIncrement( &record->refs );
    ReleaseSRWLockShared( &package_mount_lock );
    return record;
}

static HRESULT package_mount_path_size( XPackageMountHandle handle, SIZE_T *size )
{
    if ( !size )
        return E_INVALIDARG;
    *size = 0;
    package_mount_owner owner{ package_mount_acquire( handle ) };
    if ( !owner.p )
        return E_INVALIDARG;
    if ( !owner.p->right.valid( owner.p->right.context ) || !package_mount_same_directory( *owner.p ) )
        return E_ACCESSDENIED;
    *size = owner.p->path.size() + 1;
    return S_OK;
}

static HRESULT package_mount_path( XPackageMountHandle handle, SIZE_T size, char *path )
{
    if ( path && size )
        path[0] = 0;
    if ( !path )
        return E_INVALIDARG;
    package_mount_owner owner{ package_mount_acquire( handle ) };
    if ( !owner.p )
        return E_INVALIDARG;
    if ( !owner.p->right.valid( owner.p->right.context ) || !package_mount_same_directory( *owner.p ) )
        return E_ACCESSDENIED;
    if ( size < owner.p->path.size() + 1 )
        return E_NOT_SUFFICIENT_BUFFER;
    memcpy( path, owner.p->path.c_str(), owner.p->path.size() + 1 );
    return S_OK;
}

static void package_mount_close( XPackageMountHandle handle )
{
    AcquireSRWLockExclusive( &package_mount_lock );
    package_mount_record **link = &package_mounts;
    while ( *link && *link != ( void * )handle )
        link = &( *link )->next;
    package_mount_record *record = *link;
    if ( record )
        *link = record->next;
    ReleaseSRWLockExclusive( &package_mount_lock );
    if ( record )
        package_mount_release( record );
}

struct package_mount_store_right
{
    IXStoreImpl *api;
    XStoreLicenseHandle license;
};
static BOOL package_mount_store_valid( void *context )
{
    auto right = static_cast<package_mount_store_right *>( context );
    return right->api->XStoreIsLicenseValid( right->license );
}
static void package_mount_store_close( void *context )
{
    auto right = static_cast<package_mount_store_right *>( context );
    right->api->XStoreCloseLicenseHandle( right->license );
    right->api->Release();
    delete right;
}

static HRESULT package_mount_request_license( const char *identifier, package_mount_right *out )
{
    *out = {};
    IXStoreImpl *store = NULL;
    IXThreadingImpl *threads = NULL;
    XTaskQueueHandle queue = NULL;
    XStoreContextHandle context = NULL;
    XStoreLicenseHandle license = NULL;
    XAsyncBlock async{};
    HRESULT hr = QueryApiImpl( CLSID_XStoreImpl, IID_IXStoreImpl, ( void ** )&store );
    if ( FAILED( hr ) )
        return hr;
    hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threads );
    if ( SUCCEEDED( hr ) )
        hr =
            threads->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::ThreadPool, &queue );
    if ( SUCCEEDED( hr ) )
        hr = store->XStoreCreateContext( NULL, &context );
    if ( SUCCEEDED( hr ) )
    {
        async.queue = queue;
        hr = store->XStoreAcquireLicenseForPackageAsync( context, identifier, &async );
        if ( SUCCEEDED( hr ) )
            hr = threads->XAsyncGetStatus( &async, TRUE );
        if ( SUCCEEDED( hr ) )
            hr = store->XStoreAcquireLicenseForPackageResult( &async, &license );
        if ( SUCCEEDED( hr ) && ( !license || !store->XStoreIsLicenseValid( license ) ) )
            hr = E_ACCESSDENIED;
    }
    if ( context )
        store->XStoreCloseContextHandle( context );
    if ( queue )
        threads->XTaskQueueCloseHandle( queue );
    if ( threads )
        threads->Release();
    if ( SUCCEEDED( hr ) )
    {
        auto right = new ( std::nothrow ) package_mount_store_right{ store, license };
        if ( right )
        {
            *out = { right, package_mount_store_valid, package_mount_store_close };
            return S_OK;
        }
        hr = E_OUTOFMEMORY;
    }
    if ( license )
        store->XStoreCloseLicenseHandle( license );
    store->Release();
    return hr;
}

static HRESULT package_mount_legacy( const char *identifier, XPackageMountHandle *out )
{
    if ( !out )
        return E_INVALIDARG;
    *out = NULL;
    if ( !chunks_identifier( identifier ) )
        return E_INVALIDARG;
    WCHAR root[MAX_PATH];
    HRESULT hr = chunks_resolve( identifier, root );
    if ( FAILED( hr ) )
        return hr;
    content_package package{};
    if ( !content_load( root, &package ) )
        return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    if ( !package.content )
        return E_ACCESSDENIED;
    if ( strcmp( package.identifier, identifier ) )
        return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    package_mount_right right;
    hr = package_mount_request_license( identifier, &right );
    if ( FAILED( hr ) )
        return hr;
    return package_mount_create( package, right, out );
}
