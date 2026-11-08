/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Enumerate real extracted content packages, not catalog or license entries.
 * Installation metadata is not evidence of ownership. Store licensing remains
 * independent. Shared by the C++ package provider. */
#include <libxml/parser.h>
#include <libxml/tree.h>

#define CONTENT_MAX_PACKAGES 128
#define CONTENT_MAX_DIRECTORIES 512
#define CONTENT_MAX_IDS 256
#define CONTENT_XML_LIMIT ( 1024 * 1024 )

struct content_game
{
    char identity[256], publisher[256], store[13];
    char related[CONTENT_MAX_IDS][13];
    UINT32 related_count;
};

static BOOL content_id( const char *text )
{
    UINT i;
    if ( !text || strlen( text ) != 12 ) return FALSE;
    for ( i = 0; i < 12; i++ )
        if ( !( ( text[i] >= 'A' && text[i] <= 'Z' ) || ( text[i] >= '0' && text[i] <= '9' ) ) ) return FALSE;
    return TRUE;
}

/* Require single direct children. Nested/unrelated elements must not supply
 * package identity, dependencies or application declarations. */
static xmlNodePtr content_child( xmlNodePtr parent, const char *name )
{
    xmlNodePtr node, result = NULL;
    if ( !parent ) return NULL;
    for ( node = parent->children; node; node = node->next )
        if ( node->type == XML_ELEMENT_NODE && !strcmp( ( char * )node->name, name ) )
        {
            if ( result ) return NULL;
            result = node;
        }
    return result;
}

static BOOL content_text( xmlNodePtr node, const char *attribute, char *out, SIZE_T size )
{
    xmlChar *value;
    BOOL ok;
    out[0] = 0;
    if ( !node ) return FALSE;
    value = attribute ? xmlGetProp( node, ( xmlChar * )attribute ) : xmlNodeGetContent( node );
    ok = value && value[0] && strlen( ( char * )value ) < size;
    if ( ok ) strcpy( out, ( char * )value );
    xmlFree( value );
    return ok;
}

static content_game GetContentConfiguration()
{
    content_game current{};
    const auto config = nexus::GetGameConfiguration();
    if ( !config ) return current;
    const auto identity = config->game.child( "Identity" );
    const auto copy = []( std::string_view value, char *out, SIZE_T size )
    {
        if ( value.size() < size )
        {
            if ( !value.empty() ) memcpy( out, value.data(), value.size() );
            out[value.size()] = 0;
        }
    };
    if ( identity )
    {
        copy( identity->attribute( "Name" ), current.identity, sizeof( current.identity ) );
        copy( identity->attribute( "Publisher" ), current.publisher, sizeof( current.publisher ) );
    }
    copy( config->storeId, current.store, sizeof( current.store ) );
    for ( const auto &id : config->relatedProducts )
        if ( current.related_count < CONTENT_MAX_IDS && content_id( id.c_str() ) )
            copy( id, current.related[current.related_count++], 13 );
    return current;
}

struct content_package
{
    WCHAR path[MAX_PATH];
    char identifier[33], identity[256], publisher_id[256], store[13];
    char dependency[256], allowed[CONTENT_MAX_IDS][13];
    UINT32 allowed_count;
    XVersion version;
    char display[256], description[1024], publisher[256];
    BOOL content;
};
struct content_snapshot
{
    struct content_game current;
    struct content_package packages[CONTENT_MAX_PACKAGES];
    UINT32 count, directories;
};

static BOOL content_join( const WCHAR *root, const WCHAR *name, WCHAR *out )
{
    SIZE_T a = wcslen( root ), b = wcslen( name );
    if ( a + b + 2 > MAX_PATH ) return FALSE;
    wcscpy( out, root );
    if ( a && out[a - 1] != '\\' ) wcscat( out, L"\\" );
    wcscat( out, name );
    return TRUE;
}

static xmlDocPtr content_read_xml( const WCHAR *path )
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD read;
    char *bytes;
    xmlDocPtr doc = NULL;
    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL );
    if ( file == INVALID_HANDLE_VALUE ) return NULL;
    if ( !GetFileSizeEx( file, &size ) || size.QuadPart <= 0 || size.QuadPart > CONTENT_XML_LIMIT ||
         !( bytes = static_cast<std::remove_reference_t<decltype( bytes )>>( malloc( size.QuadPart ) ) ) )
    {
        CloseHandle( file );
        return NULL;
    }
    if ( ReadFile( file, bytes, size.QuadPart, &read, NULL ) && read == size.QuadPart )
    {
        doc = xmlReadMemory( bytes, read, NULL, NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING );
        if ( doc && ( doc->intSubset || doc->extSubset ) )
        {
            xmlFreeDoc( doc );
            doc = NULL;
        }
    }
    free( bytes );
    CloseHandle( file );
    return doc;
}

static BOOL content_version( const char *text, XVersion *version )
{
    unsigned v[4], i;
    const char *p = text;
    for ( i = 0; i < 4; i++ )
    {
        if ( *p < '0' || *p > '9' ) return FALSE;
        v[i] = 0;
        do
        {
            v[i] = v[i] * 10 + *p++ - '0';
            if ( v[i] > 65535 ) return FALSE;
        } while ( *p >= '0' && *p <= '9' );
        if ( i < 3 && *p++ != '.' ) return FALSE;
    }
    if ( *p ) return FALSE;
    version->major = v[0];
    version->minor = v[1];
    version->build = v[2];
    version->revision = v[3];
    return TRUE;
}

static BOOL content_layout_id( const WCHAR *name, char *out )
{
    UINT i, n = 0;
    if ( wcslen( name ) != 47 || wcsncmp( name, L"layout_", 7 ) || wcscmp( name + 43, L".xml" ) ) return FALSE;
    for ( i = 0; i < 36; i++ )
    {
        WCHAR c = name[7 + i];
        if ( i == 8 || i == 13 || i == 18 || i == 23 )
        {
            if ( c != '-' ) return FALSE;
            continue;
        }
        if ( c >= 'A' && c <= 'F' ) c += 'a' - 'A';
        if ( !( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ) ) ) return FALSE;
        out[n++] = c;
    }
    out[n] = 0;
    return n == 32;
}

/* FileGroup paths stay relative to the extracted root. Do not advertise a
 * registration-only directory with missing declared payload as installed. */
static BOOL content_relative( const char *text, BOOL pattern )
{
    const char *p = text;
    if ( !*p || *p == '/' || *p == '\\' || strchr( p, ':' ) ) return FALSE;
    for ( ; *p; p++ )
    {
        if ( ( unsigned char )*p < 32 || ( !pattern && ( *p == '*' || *p == '?' ) ) ) return FALSE;
        if ( *p == '.' && ( p == text || p[-1] == '/' || p[-1] == '\\' ) && p[1] == '.' &&
             ( !p[2] || p[2] == '/' || p[2] == '\\' ) )
            return FALSE;
    }
    return TRUE;
}

/* Literal package component rules shared with Mount: Win32 trims trailing dots
 * and spaces and resolves "..", so a literal location or include prefix must
 * reject those forms plus invalid Windows characters. Valid Unicode bytes and
 * case are preserved; "." is handled by the caller and canonicalizes to empty. */
static BOOL content_component( const char *text, SIZE_T length )
{
    SIZE_T i;
    if ( !length || ( length == 2 && text[0] == '.' && text[1] == '.' ) ) return FALSE;
    if ( text[length - 1] == '.' || text[length - 1] == ' ' ) return FALSE;
    for ( i = 0; i < length; ++i )
    {
        unsigned char c = ( unsigned char )text[i];
        if ( c < 32 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' )
            return FALSE;
    }
    return TRUE;
}

/* Package layout locations and include prefixes are relative to the package
 * image, never the host filesystem. One leading separator still names the
 * package root; every literal component follows content_component. */
static BOOL content_package_relative( const char *text, char *out, SIZE_T size )
{
    const char *p;
    SIZE_T used = 0;
    if ( !text || !out || !size ) return FALSE;
    p = text;
    if ( *p == '/' || *p == '\\' ) ++p;
    if ( *p == '/' || *p == '\\' ) return FALSE;
    while ( *p )
    {
        const char *end = p;
        SIZE_T length;
        while ( *end && *end != '/' && *end != '\\' ) ++end;
        length = ( SIZE_T )( end - p );
        if ( length && !( length == 1 && *p == '.' ) )
        {
            if ( !content_component( p, length ) ) return FALSE;
            if ( used && used + 1 >= size ) return FALSE;
            if ( used ) out[used++] = '\\';
            if ( used + length >= size ) return FALSE;
            memmove( out + used, p, length );
            used += length;
        }
        p = end;
        if ( *p ) ++p;
    }
    out[used] = 0;
    return TRUE;
}

/* Canonical package-relative location without empty or "." components. */
static BOOL content_layout_location( xmlNodePtr node, const char *attribute, char *out, SIZE_T size )
{
    char value[MAX_PATH];
    const char *p;
    SIZE_T used = 0;
    if ( !out || !size || !content_text( node, attribute, value, sizeof( value ) ) ) return FALSE;
    if ( !content_package_relative( value, value, sizeof( value ) ) ) return FALSE;
    for ( p = value; ; )
    {
        const char *end = p;
        SIZE_T length;
        while ( *end && *end != '/' && *end != '\\' ) ++end;
        length = ( SIZE_T )( end - p );
        if ( length && !( length == 1 && *p == '.' ) )
        {
            if ( used && used + 1 >= size ) return FALSE;
            if ( used ) out[used++] = '\\';
            if ( used + length >= size ) return FALSE;
            memmove( out + used, p, length );
            used += length;
        }
        if ( !*end ) break;
        p = end + 1;
    }
    out[used] = 0;
    return TRUE;
}

/* Include may carry one literal directory prefix; wildcards are leaf-only. */
static BOOL content_include_parts( const char *include, char *prefix, SIZE_T size, const char **leaf )
{
    const char *last = strrchr( include, '\\' ), *slash = strrchr( include, '/' );
    if ( !last || ( slash && slash > last ) ) last = slash;
    *leaf = last ? last + 1 : include;
    prefix[0] = 0;
    if ( !last ) return TRUE;
    if ( ( SIZE_T )( last - include ) >= size ) return FALSE;
    memcpy( prefix, include, ( SIZE_T )( last - include ) );
    prefix[last - include] = 0;
    return content_package_relative( prefix, prefix, size );
}

/* Every path component below the package root must be a real directory.
 * Reparse points are never followed, so a layout cannot redirect the payload
 * outside the extracted tree. The root itself is host-supplied. */
static BOOL content_directory( const WCHAR *root, const WCHAR *relative, WCHAR *out )
{
    DWORD attributes;
    SIZE_T used;
    if ( !root || !relative || !out ) return FALSE;
    used = wcslen( root );
    if ( !used || used >= MAX_PATH ) return FALSE;
    wcscpy( out, root );
    attributes = GetFileAttributesW( out );
    if ( attributes == INVALID_FILE_ATTRIBUTES || !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ) return FALSE;
    while ( *relative )
    {
        const WCHAR *end = relative;
        SIZE_T length;
        while ( *end && *end != L'\\' && *end != L'/' ) ++end;
        length = ( SIZE_T )( end - relative );
        if ( length )
        {
            if ( used + length + 2 > MAX_PATH ) return FALSE;
            out[used++] = L'\\';
            memcpy( out + used, relative, length * sizeof( WCHAR ) );
            used += length;
            out[used] = 0;
            attributes = GetFileAttributesW( out );
            if ( attributes == INVALID_FILE_ATTRIBUTES || !( attributes & FILE_ATTRIBUTE_DIRECTORY ) ||
                 ( attributes & FILE_ATTRIBUTE_REPARSE_POINT ) )
                return FALSE;
        }
        relative = *end ? end + 1 : end;
    }
    return TRUE;
}

/* A downloaded tree can be deployed at its declared destination or still hold
 * the declared source coordinate. Exactly one interpretation is used for the
 * whole package, so payload is never advertised from mixed coordinates. */
enum content_layout_coordinate
{
    CONTENT_LAYOUT_SOURCE = 0,
    CONTENT_LAYOUT_DESTINATION = 1
};

/* Validate every declared declaration before any tree is inspected, so an
 * invalid path cannot hide behind the other coordinate. */
static BOOL content_layout_declarations( xmlNodePtr node, UINT depth, UINT *groups )
{
    char include[MAX_PATH], prefix[MAX_PATH];
    const char *leaf;
    BOOL source, destination;
    if ( depth > 16 ) return FALSE;
    for ( ; node; node = node->next )
    {
        if ( node->type != XML_ELEMENT_NODE ) continue;
        if ( !strcmp( ( char * )node->name, "FileGroup" ) )
        {
            source = xmlHasProp( node, ( xmlChar * )"SourcePath" ) != NULL;
            destination = xmlHasProp( node, ( xmlChar * )"DestinationPath" ) != NULL;
            if ( ++*groups > 256 || ( !source && !destination ) ||
                 !content_text( node, "Include", include, sizeof( include ) ) ||
                 !content_relative( include, TRUE ) ||
                 !content_include_parts( include, prefix, sizeof( prefix ), &leaf ) || !*leaf ||
                 ( source && !content_layout_location( node, "SourcePath", prefix, sizeof( prefix ) ) ) ||
                 ( destination && !content_layout_location( node, "DestinationPath", prefix, sizeof( prefix ) ) ) )
                return FALSE;
        }
        if ( !content_layout_declarations( node->children, depth + 1, groups ) ) return FALSE;
    }
    return TRUE;
}

static BOOL content_layout_files( const WCHAR *root, xmlNodePtr node, UINT depth, UINT *groups,
                                  enum content_layout_coordinate coordinate )
{
    char include[MAX_PATH], prefix[MAX_PATH], location[MAX_PATH];
    WCHAR relative[MAX_PATH], leaf[MAX_PATH], directory[MAX_PATH], pattern[MAX_PATH], *part;
    WIN32_FIND_DATAW data;
    HANDLE find;
    BOOL found;
    if ( depth > 16 ) return FALSE;
    for ( ; node; node = node->next )
    {
        const char *suffix;
        if ( node->type != XML_ELEMENT_NODE ) continue;
        if ( !strcmp( ( char * )node->name, "FileGroup" ) )
        {
            if ( ++*groups > 256 || !content_text( node, "Include", include, sizeof( include ) ) ||
                 !content_relative( include, TRUE ) ||
                 !content_include_parts( include, prefix, sizeof( prefix ), &suffix ) || !*suffix )
                return FALSE;
            if ( coordinate == CONTENT_LAYOUT_SOURCE )
            {
                if ( !xmlHasProp( node, ( xmlChar * )"SourcePath" ) ||
                     !content_layout_location( node, "SourcePath", location, sizeof( location ) ) )
                    return FALSE;
            }
            else if ( xmlHasProp( node, ( xmlChar * )"DestinationPath" ) )
            {
                if ( !content_layout_location( node, "DestinationPath", location, sizeof( location ) ) )
                    return FALSE;
            }
            else if ( xmlHasProp( node, ( xmlChar * )"SourcePath" ) )
            {
                /* No destination was declared: the deployed tree is the declared
                 * source location, matching package chunk readiness. */
                if ( !content_layout_location( node, "SourcePath", location, sizeof( location ) ) ) return FALSE;
            }
            else
                return FALSE;
            if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, location, -1, relative, MAX_PATH ) ) return FALSE;
            for ( part = relative; *part; ++part )
                if ( *part == '/' ) *part = '\\';
            if ( prefix[0] )
            {
                WCHAR literal[MAX_PATH];
                if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, prefix, -1, literal, MAX_PATH ) ) return FALSE;
                for ( part = literal; *part; ++part )
                    if ( *part == '/' ) *part = '\\';
                if ( relative[0] && wcslen( relative ) + wcslen( literal ) + 2 > MAX_PATH ) return FALSE;
                if ( relative[0] ) wcscat( relative, L"\\" );
                wcscat( relative, literal );
            }
            if ( !content_directory( root, relative, directory ) ) return FALSE;
            if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, suffix, -1, leaf, MAX_PATH ) ) return FALSE;
            for ( part = leaf; *part; ++part )
                if ( *part == '/' ) *part = '\\';
            if ( !content_join( directory, leaf, pattern ) ) return FALSE;
            if ( ( find = FindFirstFileW( pattern, &data ) ) == INVALID_HANDLE_VALUE ) return FALSE;
            found = FALSE;
            do
            {
                if ( !( data.dwFileAttributes & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT ) ) )
                {
                    found = TRUE;
                    break;
                }
            } while ( FindNextFileW( find, &data ) );
            FindClose( find );
            if ( !found ) return FALSE;
        }
        if ( !content_layout_files( root, node->children, depth + 1, groups, coordinate ) ) return FALSE;
    }
    return TRUE;
}

/* The deployed destination coordinate is authoritative because the installer
 * materializes exactly those paths and package chunk readiness reads them.
 * The declared source coordinate is only a fallback for a tree that was not
 * remapped. */
static BOOL content_layout_coordinate( const WCHAR *root, xmlNodePtr node,
                                       enum content_layout_coordinate *coordinate, UINT *groups )
{
    UINT declared = 0, visited = 0;
    if ( !content_layout_declarations( node, 0, &declared ) || !declared ) return FALSE;
    if ( content_layout_files( root, node, 0, &visited, CONTENT_LAYOUT_DESTINATION ) && visited )
    {
        *coordinate = CONTENT_LAYOUT_DESTINATION;
        if ( groups ) *groups = visited;
        return TRUE;
    }
    visited = 0;
    if ( content_layout_files( root, node, 0, &visited, CONTENT_LAYOUT_SOURCE ) && visited )
    {
        *coordinate = CONTENT_LAYOUT_SOURCE;
        if ( groups ) *groups = visited;
        return TRUE;
    }
    return FALSE;
}

static BOOL content_load_layout( struct content_package *package )
{
    WCHAR pattern[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW data;
    HANDLE find;
    xmlDocPtr doc;
    xmlNodePtr root;
    enum content_layout_coordinate coordinate;
    UINT groups = 0, layouts = 0;
    BOOL valid = FALSE;
    if ( !content_join( package->path, L"layout_*.xml", pattern ) ||
         ( find = FindFirstFileW( pattern, &data ) ) == INVALID_HANDLE_VALUE )
        return FALSE;
    do
    {
        if ( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) continue;
        if ( ++layouts != 1 || !content_layout_id( data.cFileName, package->identifier ) ||
             !content_join( package->path, data.cFileName, path ) )
        {
            valid = FALSE;
            break;
        }
        doc = content_read_xml( path );
        root = doc ? xmlDocGetRootElement( doc ) : NULL;
        valid = root && !strcmp( ( char * )root->name, "Package" ) &&
                content_layout_coordinate( package->path, root->children, &coordinate, &groups ) && groups;
        if ( doc ) xmlFreeDoc( doc );
        if ( !valid ) break;
    } while ( FindNextFileW( find, &data ) );
    FindClose( find );
    return valid;
}

static BOOL content_load( const WCHAR *path, struct content_package *package )
{
    WCHAR file[MAX_PATH];
    xmlDocPtr config = NULL, manifest = NULL;
    xmlNodePtr game, appx, identity, other, dependency, node;
    char value[256], version[64];
    BOOL ok = FALSE;
    memset( package, 0, sizeof( *package ) );
    if ( wcslen( path ) >= MAX_PATH ) return FALSE;
    wcscpy( package->path, path );
    if ( !content_join( path, L"MicrosoftGame.config", file ) || !( config = content_read_xml( file ) ) ||
         !content_join( path, L"appxmanifest.xml", file ) || !( manifest = content_read_xml( file ) ) )
        goto done;
    game = xmlDocGetRootElement( config );
    appx = xmlDocGetRootElement( manifest );
    if ( !game || strcmp( ( char * )game->name, "Game" ) || !appx || strcmp( ( char * )appx->name, "Package" ) )
        goto done;
    identity = content_child( game, "Identity" );
    other = content_child( appx, "Identity" );
    if ( !content_text( identity, "Name", package->identity, sizeof( package->identity ) ) ||
         !content_text( other, "Name", value, sizeof( value ) ) || strcmp( package->identity, value ) ||
         !content_text( identity, "Publisher", package->publisher_id, sizeof( package->publisher_id ) ) ||
         !content_text( other, "Publisher", value, sizeof( value ) ) || strcmp( package->publisher_id, value ) ||
         !content_text( identity, "Version", version, sizeof( version ) ) ||
         !content_version( version, &package->version ) || !content_text( other, "Version", value, sizeof( value ) ) ||
         strcmp( version, value ) ||
         !content_text( content_child( game, "StoreId" ), NULL, package->store, sizeof( package->store ) ) ||
         !content_id( package->store ) )
        goto done;
    dependency = content_child( content_child( game, "DesktopRegistration" ), "MainPackageDependency" );
    other = content_child( content_child( appx, "Dependencies" ), "MainPackageDependency" );
    if ( dependency || other )
    {
        if ( !content_text( dependency, "Name", package->dependency, sizeof( package->dependency ) ) ||
             !content_text( other, "Name", value, sizeof( value ) ) || strcmp( package->dependency, value ) ||
             content_child( game, "Executables" ) || content_child( appx, "Applications" ) )
            goto done;
        package->content = TRUE;
        node = content_child( game, "AllowedProducts" );
        for ( node = node ? node->children : NULL; node; node = node->next )
            if ( node->type == XML_ELEMENT_NODE && !strcmp( ( char * )node->name, "AllowedProduct" ) )
            {
                if ( package->allowed_count == CONTENT_MAX_IDS || !content_text( node, NULL, value, sizeof( value ) ) ||
                     !content_id( value ) )
                    goto done;
                strcpy( package->allowed[package->allowed_count++], value );
            }
        if ( !package->allowed_count || !content_load_layout( package ) ) goto done;
    }
    else if ( !content_child( game, "Executables" ) && !content_child( appx, "Applications" ) )
        goto done;
    node = content_child( game, "ShellVisuals" );
    content_text( node, "DefaultDisplayName", package->display, sizeof( package->display ) );
    content_text( node, "Description", package->description, sizeof( package->description ) );
    content_text( node, "PublisherDisplayName", package->publisher, sizeof( package->publisher ) );
    ok = TRUE;
done:
    if ( config ) xmlFreeDoc( config );
    if ( manifest ) xmlFreeDoc( manifest );
    return ok;
}

static HRESULT content_add( struct content_snapshot *snapshot, const WCHAR *path )
{
    struct content_package *package;
    UINT i;
    if ( ++snapshot->directories > CONTENT_MAX_DIRECTORIES ) return HRESULT_FROM_WIN32( ERROR_MORE_DATA );
    for ( i = 0; i < snapshot->count; i++ )
        if ( !wcsicmp( snapshot->packages[i].path, path ) ) return S_OK;
    if ( !( package = static_cast<std::remove_reference_t<decltype( package )>>( calloc( 1, sizeof( *package ) ) ) ) )
        return E_OUTOFMEMORY;
    if ( content_load( path, package ) )
    {
        for ( i = 0; i < snapshot->count; i++ )
            if ( package->content && snapshot->packages[i].content &&
                 !strcmp( package->identifier, snapshot->packages[i].identifier ) )
            {
                BOOL same = !strcmp( package->identity, snapshot->packages[i].identity ) &&
                            !strcmp( package->store, snapshot->packages[i].store ) &&
                            !memcmp( &package->version, &snapshot->packages[i].version, sizeof( package->version ) );
                free( package );
                return same ? S_OK : HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            }
        if ( snapshot->count == CONTENT_MAX_PACKAGES )
        {
            free( package );
            return HRESULT_FROM_WIN32( ERROR_MORE_DATA );
        }
        snapshot->packages[snapshot->count++] = *package;
    }
    free( package );
    return S_OK;
}

/* Bounded direct-child discovery only. Additional installation locations may
 * be supplied as semicolon-separated absolute Windows paths. Never scan an
 * entire drive, recurse into prefixes or derive installation from a receipt. */
static HRESULT content_scan( struct content_snapshot *snapshot, const WCHAR *path )
{
    WCHAR pattern[MAX_PATH], child[MAX_PATH];
    WIN32_FIND_DATAW data;
    HANDLE find;
    HRESULT hr = content_add( snapshot, path );
    UINT entries = 0;
    if ( FAILED( hr ) || !content_join( path, L"*", pattern ) ) return hr;
    if ( ( find = FindFirstFileW( pattern, &data ) ) == INVALID_HANDLE_VALUE ) return S_OK;
    do
    {
        if ( ++entries > CONTENT_MAX_DIRECTORIES )
        {
            hr = HRESULT_FROM_WIN32( ERROR_MORE_DATA );
            break;
        }
        if ( data.cFileName[0] == '.' || !( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) ||
             ( data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ) )
            continue;
        if ( content_join( path, data.cFileName, child ) && FAILED( hr = content_add( snapshot, child ) ) ) break;
    } while ( FindNextFileW( find, &data ) );
    FindClose( find );
    return hr;
}

static BOOL content_absolute( const WCHAR *path )
{
    return wcslen( path ) >= 3 && ( ( path[0] >= 'A' && path[0] <= 'Z' ) || ( path[0] >= 'a' && path[0] <= 'z' ) ) &&
           path[1] == ':' && ( path[2] == '\\' || path[2] == '/' );
}

static HRESULT content_discover( struct content_snapshot *snapshot )
{
    WCHAR path[MAX_PATH], file[MAX_PATH], *sep, *roots, *next;
    DWORD length;
    UINT i;
    HRESULT hr = S_OK;
    if ( GetModuleFileNameW( NULL, path, MAX_PATH ) && ( sep = wcsrchr( path, '\\' ) ) )
    {
        *sep = 0;
        while ( content_join( path, L"MicrosoftGame.config", file ) )
        {
            if ( GetFileAttributesW( file ) != INVALID_FILE_ATTRIBUTES )
            {
                hr = content_scan( snapshot, path );
                if ( SUCCEEDED( hr ) && content_join( path, L"DLC", file ) ) hr = content_scan( snapshot, file );
                if ( SUCCEEDED( hr ) && ( sep = wcsrchr( path, '\\' ) ) && sep > path + 2 )
                {
                    *sep = 0;
                    hr = content_scan( snapshot, path );
                }
                break;
            }
            if ( !( sep = wcsrchr( path, '\\' ) ) || sep <= path + 2 ) break;
            *sep = 0;
        }
    }
    if ( FAILED( hr ) ) return hr;
    length = GetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", NULL, 0 );
    if ( !length ) return S_OK;
    if ( length > 32768 ) return E_INVALIDARG;
    if ( !( roots = static_cast<std::remove_reference_t<decltype( roots )>>( malloc( length * sizeof( *roots ) ) ) ) )
        return E_OUTOFMEMORY;
    roots[0] = 0;
    if ( GetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", roots, length ) >= length )
    {
        free( roots );
        return E_INVALIDARG;
    }
    for ( sep = roots, i = 0; sep && *sep; sep = next )
    {
        next = wcschr( sep, ';' );
        if ( next ) *next++ = 0;
        if ( ++i > 64 || !content_absolute( sep ) )
        {
            hr = E_INVALIDARG;
            break;
        }
        if ( FAILED( hr = content_scan( snapshot, sep ) ) ) break;
    }
    free( roots );
    return hr;
}

static BOOL content_parent_allowed( const struct content_package *package, const char *identity, const char *store )
{
    UINT i;
    if ( strcmp( package->dependency, identity ) ) return FALSE;
    for ( i = 0; i < package->allowed_count; i++ )
        if ( !strcmp( package->allowed[i], store ) ) return TRUE;
    return FALSE;
}

static BOOL content_matches( const struct content_snapshot *snapshot, const struct content_package *package,
                             XPackageEnumerationScope scope )
{
    UINT i, j;
    const struct content_game *current = &snapshot->current;
    if ( !package->content ) return FALSE;
    if ( content_parent_allowed( package, current->identity, current->store ) ) return TRUE;
    if ( scope == XPackageEnumerationScope::ThisOnly ) return FALSE;
    for ( i = 0; i < snapshot->count; i++ )
    {
        const struct content_package *parent = &snapshot->packages[i];
        if ( parent->content || !content_parent_allowed( package, parent->identity, parent->store ) ) continue;
        if ( scope == XPackageEnumerationScope::ThisPublisher && !strcmp( parent->publisher_id, current->publisher ) )
            return TRUE;
        if ( scope == XPackageEnumerationScope::ThisAndRelated )
            for ( j = 0; j < current->related_count; j++ )
                if ( !strcmp( current->related[j], parent->store ) ) return TRUE;
    }
    return FALSE;
}

static HRESULT enumerate_content_packages( XPackageEnumerationScope scope, void *context,
                                           XPackageEnumerationCallback *callback )
{
    struct content_snapshot *snapshot;
    XPackageDetails details;
    UINT i, count = 0, index = 0;
    HRESULT hr;
    if ( !( snapshot =
                static_cast<std::remove_reference_t<decltype( snapshot )>>( calloc( 1, sizeof( *snapshot ) ) ) ) )
        return E_OUTOFMEMORY;
    snapshot->current = GetContentConfiguration();
    if ( !content_id( snapshot->current.store ) || !snapshot->current.identity[0] )
    {
        free( snapshot );
        return S_OK;
    }
    if ( SUCCEEDED( hr = content_discover( snapshot ) ) )
    {
        for ( i = 0; i < snapshot->count; i++ )
            if ( content_matches( snapshot, &snapshot->packages[i], scope ) ) count++;
        for ( i = 0; i < snapshot->count; i++ )
        {
            const struct content_package *package = &snapshot->packages[i];
            if ( !content_matches( snapshot, package, scope ) ) continue;
            memset( &details, 0, sizeof( details ) );
            details.packageIdentifier = package->identifier;
            details.version = package->version;
            details.kind = XPackageKind::Content;
            details.displayName = package->display;
            details.description = package->description;
            details.publisher = package->publisher;
            details.storeId = package->store;
            details.index = index++;
            details.count = count;
            if ( !callback( context, &details ) ) break;
        }
    }
    free( snapshot );
    return hr;
}

struct content_identifier_query
{
    const char *store;
    char identifier[33];
    BOOL found, ambiguous;
};

static BOOLEAN WINAPI content_identifier_match( void *arg, const XPackageDetails *details )
{
    auto query = static_cast<content_identifier_query *>( arg );
    if ( strcmp( query->store, details->storeId ) ) return TRUE;
    if ( query->found && strcmp( query->identifier, details->packageIdentifier ) )
        query->ambiguous = TRUE;
    else
    {
        memcpy( query->identifier, details->packageIdentifier, sizeof( query->identifier ) );
        query->found = TRUE;
    }
    return TRUE;
}

/* This is installation lookup only. No license or online request is involved.
 * Unknown or ambiguous products are not mapped to another package. */
static HRESULT content_query_identifier( const char *store, SIZE_T size, char *identifier )
{
    struct content_identifier_query query = { 0 };
    HRESULT hr;
    if ( identifier && size ) identifier[0] = 0;
    if ( !content_id( store ) || !identifier ) return E_INVALIDARG;
    if ( size < sizeof( query.identifier ) ) return E_NOT_SUFFICIENT_BUFFER;
    query.store = store;
    if ( FAILED( hr = enumerate_content_packages( XPackageEnumerationScope::ThisAndRelated, &query,
                                                  content_identifier_match ) ) )
        return hr;
    if ( !query.found || query.ambiguous ) return E_INVALIDARG;
    memcpy( identifier, query.identifier, sizeof( query.identifier ) );
    return S_OK;
}

struct content_store_query
{
    const char *identifier;
    char store[13];
    BOOL found, ambiguous;
};

static BOOLEAN WINAPI content_store_match( void *arg, const XPackageDetails *details )
{
    auto query = static_cast<content_store_query *>( arg );
    if ( strcmp( query->identifier, details->packageIdentifier ) ) return TRUE;
    if ( query->found && strcmp( query->store, details->storeId ) )
        query->ambiguous = TRUE;
    else
    {
        memcpy( query->store, details->storeId, sizeof( query->store ) );
        query->found = TRUE;
    }
    return TRUE;
}

HRESULT xpackage_query_content_store( const char *identifier, SIZE_T size, char *store )
{
    struct content_store_query query = { 0 };
    HRESULT hr;
    UINT i;
    if ( store && size ) store[0] = 0;
    if ( !store || !identifier || strlen( identifier ) != 32 ) return E_INVALIDARG;
    for ( i = 0; i < 32; i++ )
        if ( !( ( identifier[i] >= '0' && identifier[i] <= '9' ) || ( identifier[i] >= 'a' && identifier[i] <= 'f' ) ) )
            return E_INVALIDARG;
    if ( size < sizeof( query.store ) ) return E_NOT_SUFFICIENT_BUFFER;
    query.identifier = identifier;
    if ( FAILED( hr = enumerate_content_packages( XPackageEnumerationScope::ThisAndRelated, &query,
                                                  content_store_match ) ) )
        return hr;
    if ( !query.found || query.ambiguous ) return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    memcpy( store, query.store, sizeof( query.store ) );
    return S_OK;
}
