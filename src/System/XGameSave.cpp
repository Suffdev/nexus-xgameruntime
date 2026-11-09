/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XGameSave and XGameSaveFiles
 *
 * Copyright 2026 Olivia Ryan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <ctype.h>
#include <stdio.h>
#include "XGameSave.h"
#include "GameSave/Transport.h"
#include "User/XUser.h"
#include "../Runtime/Configuration.h"
#include "../HttpClient.h"
#include <cstdarg>
#include <type_traits>

#include <bcrypt.h>

static const char *GetSavePackageFamilyName()
{
    auto config = nexus::GetGameConfiguration();
    return config && !config->packageFamilyName.empty() ? config->packageFamilyName.c_str() : nullptr;
}
static const char *GetSaveMsaAppId()
{
    auto config = nexus::GetGameConfiguration();
    return config && !config->msaAppId.empty() ? config->msaAppId.c_str() : nullptr;
}
static UINT32 GetSaveTitleId()
{
    auto config = nexus::GetGameConfiguration();
    return config ? config->titleId : 0;
}
static bool GetSaveFullTrust()
{
    auto config = nexus::GetGameConfiguration();
    return config && config->fullTrust;
}
static void SaveStatus( const char *format, ... )
{
    va_list args;
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
}

#define E_GS_INVALID_CONTAINER_NAME ( ( HRESULT )0x80830001 )
#define E_GS_PROVIDED_BUFFER_TOO_SMALL ( ( HRESULT )0x80830007 )
#define E_GS_BLOB_NOT_FOUND ( ( HRESULT )0x80830008 )
#define E_GS_NO_SERVICE_CONFIGURATION ( ( HRESULT )0x80830009 )
#define E_GS_CONTAINER_NOT_IN_SYNC ( ( HRESULT )0x8083000A )
#define E_GS_UPDATE_TOO_BIG ( ( HRESULT )0x80830005 )

#define SAVE_QUOTA ( 256 * 1024 * 1024 )
static BOOL save_json_object_complete( const char *, SIZE_T );

struct blob_entry
{
    char *name;
    UINT32 size;
    char atom[48];
};

struct container_state
{
    char *name;
    char *display;
    UINT64 time;
    char remote[48];
    BOOL dirty;
    UINT64 revision;
    char incarnation[40];
    UINT32 count;
    struct blob_entry *blobs;
};

struct save_upload
{
    struct save_upload *next;
    struct container_state state;
    BYTE **data;
    SIZE_T *sizes;
};

struct XGameSaveProvider
{
    SaveTransport *transport;
    XUserHandle user;
    char *scid;
    char root[2048];
    char base[512];
    char *auth;
    BOOL cloud;
    BOOL locked;
    BOOL files;
    BOOL session_lock;
    BOOL session_uploaded;
    INT64 quota;
    UINT32 downloaded;
    UINT32 uploaded;
    CRITICAL_SECTION cs;
    CRITICAL_SECTION cloud_cs;
    HANDLE upload_event;
    HANDLE upload_thread;
    BOOL upload_stopping;
    struct save_upload *uploads;
};

static SaveConflictChoice show_save_conflict( const WCHAR *details );

class DefaultSaveTransport final : public SaveTransport
{
public:
    HRESULT Authorization( XUserHandle user, const char *audience, char **authorization ) override
    {
        return xuser_device_authorization( user, audience, authorization );
    }
    HRESULT SignedRequest( XUserHandle user, const char *method, const char *url, const char *authorization,
                           const char *headers, const void *body, DWORD bodySize, DWORD *status, BYTE **output,
                           SIZE_T *size ) override
    {
        return xuser_signed_request( user, method, url, authorization, headers, body, bodySize, status, output, size );
    }
    HRESULT DirectRequest( const WCHAR *method, const WCHAR *url, const WCHAR *headers, const void *body,
                           DWORD bodySize, DWORD *status, BYTE **output, SIZE_T *size ) override
    {
        return http_request_raw( method, url, headers, body, bodySize, status, output, size );
    }
    void CloseUser( XUserHandle user ) override
    {
        x_user_impl->XUserCloseHandle( user );
    }
    bool CanResolveConflicts() const override { return true; }
    SaveConflictChoice ResolveConflict( const WCHAR *details ) override { return show_save_conflict( details ); }
};
static SaveTransport &GetSaveTransport( XGameSaveProvider *provider )
{
    static DefaultSaveTransport transport;
    return provider->transport ? *provider->transport : transport;
}

struct XGameSaveContainer
{
    struct XGameSaveProvider *provider;
    char *name;
};

struct update_op
{
    char *name;
    BYTE *data;
    SIZE_T size;
    BOOL remove;
};

struct XGameSaveUpdate
{
    struct XGameSaveContainer *container;
    char *display;
    UINT32 count;
    UINT32 capacity;
    struct update_op *ops;
};

static char *hex_encode( const char *str )
{
    static const char digits[] = "0123456789abcdef";
    SIZE_T len = strlen( str );
    char *out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( 1, len * 2 + 1 ) );
    if ( !out ) return NULL;
    for ( SIZE_T i = 0; i < len; i++ )
    {
        out[2 * i] = digits[( BYTE )str[i] >> 4];
        out[2 * i + 1] = digits[( BYTE )str[i] & 15];
    }
    return out;
}

static char *hex_decode( const char *hex )
{
    SIZE_T len = strlen( hex ) / 2;
    char *out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( 1, len + 1 ) );
    if ( !out ) return NULL;
    for ( SIZE_T i = 0; i < len; i++ )
    {
        char pair[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        out[i] = ( char )strtoul( pair, NULL, 16 );
    }
    return out;
}

static char *url_encode( const char *str )
{
    static const char digits[] = "0123456789ABCDEF";
    char *out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( 1, strlen( str ) * 3 + 1 ) ), *p = out;
    if ( !out ) return NULL;
    for ( ; *str; str++ )
    {
        BYTE c = *str;
        if ( isalnum( c ) || c == '-' || c == '.' || c == '_' || c == '~' )
            *p++ = c;
        else
        {
            *p++ = '%';
            *p++ = digits[c >> 4];
            *p++ = digits[c & 15];
        }
    }
    return out;
}

static char *json_escape( const char *str )
{
    char *out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( 1, strlen( str ) * 6 + 1 ) ), *p = out;
    if ( !out ) return NULL;
    for ( ; *str; str++ )
    {
        BYTE c = *str;
        if ( c == '"' || c == '\\' )
        {
            *p++ = '\\';
            *p++ = c;
        }
        else if ( c < 0x20 )
            p += sprintf( p, "\\u%04x", c );
        else
            *p++ = c;
    }
    return out;
}

static const char *json_ws( const char *p )
{
    while ( *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' )
        p++;
    return p;
}

static const char *json_string( const char *p, char **out )
{
    char *buf, *q;
    const char *start;

    if ( *p != '"' ) return NULL;
    start = ++p;
    while ( *p && *p != '"' )
        p += ( *p == '\\' && p[1] ) ? 2 : 1;
    if ( !*p || !( buf = static_cast<std::remove_reference_t<decltype( buf )>>( calloc( 1, p - start + 1 ) ) ) )
        return NULL;
    for ( q = buf, p = start; *p != '"'; p++ )
    {
        if ( *p != '\\' )
        {
            *q++ = *p;
            continue;
        }
        switch ( *++p )
        {
        case 'n':
            *q++ = '\n';
            break;
        case 't':
            *q++ = '\t';
            break;
        case 'r':
            *q++ = '\r';
            break;
        case 'b':
            *q++ = '\b';
            break;
        case 'f':
            *q++ = '\f';
            break;
        case 'u':
        {
            char hex[5] = { 0 };
            WCHAR wc;
            memcpy( hex, p + 1, 4 );
            wc = ( WCHAR )strtoul( hex, NULL, 16 );
            q += WideCharToMultiByte( CP_UTF8, 0, &wc, 1, q, 4, NULL, NULL );
            p += 4;
            break;
        }
        default:
            *q++ = *p;
            break;
        }
    }
    *out = buf;
    return p + 1;
}

static const char *json_skip( const char *p )
{
    int depth = 0;
    char *tmp;

    p = json_ws( p );
    do
    {
        if ( !*p ) return NULL;
        if ( *p == '"' )
        {
            if ( !( p = json_string( p, &tmp ) ) ) return NULL;
            free( tmp );
            continue;
        }
        if ( *p == '{' || *p == '[' )
            depth++;
        else if ( *p == '}' || *p == ']' )
        {
            if ( !depth ) return NULL;
            if ( !--depth ) return p + 1;
        }
        else if ( !depth && ( *p == ',' ) )
            return p;
        p++;
    } while ( depth > 0 || ( *p && *p != ',' && *p != '}' && *p != ']' ) );
    return p;
}

static BOOL json_object_next( const char **p, char **key, const char **value )
{
    const char *q = json_ws( *p );

    if ( *q == '{' || *q == ',' ) q = json_ws( q + 1 );
    if ( *q != '"' ) return FALSE;
    if ( !( q = json_string( q, key ) ) ) return FALSE;
    q = json_ws( q );
    if ( *q != ':' )
    {
        free( *key );
        return FALSE;
    }
    *value = json_ws( q + 1 );
    if ( !( q = json_skip( *value ) ) )
    {
        free( *key );
        return FALSE;
    }
    *p = q;
    return TRUE;
}

static const char *json_find( const char *object, const char *name )
{
    const char *p = object, *value;
    char *key;

    while ( json_object_next( &p, &key, &value ) )
    {
        BOOL match = !strcmp( key, name );
        free( key );
        if ( match ) return value;
    }
    return NULL;
}

static char *json_find_string( const char *object, const char *name )
{
    const char *value = json_find( object, name );
    char *out = NULL;
    if ( value && *value == '"' ) json_string( value, &out );
    return out;
}

static UINT64 filetime_to_unix( const FILETIME *ft )
{
    ULARGE_INTEGER li = { .LowPart = ft->dwLowDateTime, .HighPart = ft->dwHighDateTime };
    return li.QuadPart / 10000000 - 11644473600ULL;
}

static UINT64 parse_iso_time( const char *str )
{
    SYSTEMTIME st = { 0 };
    FILETIME ft;
    if ( !str || sscanf( str, "%hu-%hu-%huT%hu:%hu:%hu", &st.wYear, &st.wMonth, &st.wDay, &st.wHour, &st.wMinute,
                         &st.wSecond ) != 6 )
        return 0;
    if ( !SystemTimeToFileTime( &st, &ft ) ) return 0;
    return filetime_to_unix( &ft );
}

static void format_iso_time( UINT64 unixTime, char *out, SIZE_T size )
{
    ULARGE_INTEGER li = { .QuadPart = ( unixTime + 11644473600ULL ) * 10000000 };
    FILETIME ft = { li.LowPart, li.HighPart };
    SYSTEMTIME st;
    FileTimeToSystemTime( &ft, &st );
    snprintf( out, size, "%04u-%02u-%02uT%02u:%02u:%02u.0000000Z", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
              st.wSecond );
}

static UINT64 unix_now( void )
{
    FILETIME ft;
    GetSystemTimeAsFileTime( &ft );
    return filetime_to_unix( &ft );
}

static BOOL save_wide_path( const char *path, WCHAR out[4096] )
{
    if ( path[0] && path[1] == ':' )
    {
        wcscpy( out, L"\\\\?\\" );
        return MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out + 4, 4092 ) != 0;
    }
    return MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, 4096 ) != 0;
}

static HANDLE save_find_first( const char *path, WIN32_FIND_DATAA *out )
{
    WCHAR wide[4096];
    WIN32_FIND_DATAW data;
    HANDLE find;
    if ( !save_wide_path( path, wide ) ) return INVALID_HANDLE_VALUE;
    find = FindFirstFileW( wide, &data );
    if ( find != INVALID_HANDLE_VALUE )
    {
        memcpy( out, &data, offsetof( WIN32_FIND_DATAA, cFileName ) );
        WideCharToMultiByte( CP_UTF8, 0, data.cFileName, -1, out->cFileName, sizeof( out->cFileName ), NULL, NULL );
    }
    return find;
}

static HRESULT read_file( const char *path, BYTE **data, SIZE_T *size )
{
    WCHAR wide[4096];
    HANDLE file;
    LARGE_INTEGER li;
    DWORD error = ERROR_SUCCESS;

    *data = NULL;
    *size = 0;
    if ( !save_wide_path( path, wide ) ) return HRESULT_FROM_WIN32( GetLastError() );
    file = CreateFileW( wide, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
    if ( file == INVALID_HANDLE_VALUE ) return HRESULT_FROM_WIN32( GetLastError() );
    if ( !GetFileSizeEx( file, &li ) ) error = GetLastError();
    else if ( li.QuadPart < 0 || static_cast<UINT64>( li.QuadPart ) >= SIZE_MAX ) error = ERROR_FILE_TOO_LARGE;
    else if ( !( *data = static_cast<BYTE *>( calloc( 1, static_cast<SIZE_T>( li.QuadPart ) + 1 ) ) ) )
        error = ERROR_NOT_ENOUGH_MEMORY;
    if ( error )
    {
        CloseHandle( file );
        return HRESULT_FROM_WIN32( error );
    }
    SIZE_T offset = 0, length = static_cast<SIZE_T>( li.QuadPart );
    while ( offset < length )
    {
        DWORD read = 0, chunk = static_cast<DWORD>( std::min<SIZE_T>( length - offset, MAXDWORD ) );
        if ( !ReadFile( file, *data + offset, chunk, &read, NULL ) ) error = GetLastError();
        else if ( !read ) error = ERROR_HANDLE_EOF;
        if ( error ) break;
        offset += read;
    }
    CloseHandle( file );
    if ( error )
    {
        free( *data );
        *data = NULL;
        return HRESULT_FROM_WIN32( error );
    }
    *size = length;
    return S_OK;
}

static HRESULT write_file( const char *path, const void *data, SIZE_T size )
{
    char tmp[2048 + 64], suffix[64];
    WCHAR wide[4096], temporary[4096], guid_text[40];
    HANDLE file;
    DWORD error = ERROR_SUCCESS;

    GUID guid;
    HRESULT hr = CoCreateGuid( &guid );
    if ( FAILED( hr ) ) return hr;
    if ( !StringFromGUID2( guid, guid_text, ARRAY_SIZE( guid_text ) ) ||
         !WideCharToMultiByte( CP_UTF8, 0, guid_text, -1, suffix, sizeof( suffix ), NULL, NULL ) ||
         snprintf( tmp, sizeof( tmp ), "%s.tmp-%s", path, suffix ) >= sizeof( tmp ) ) return E_INVALIDARG;
    if ( !save_wide_path( path, wide ) || !save_wide_path( tmp, temporary ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    file = CreateFileW( temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL );
    if ( file == INVALID_HANDLE_VALUE ) return HRESULT_FROM_WIN32( GetLastError() );
    SIZE_T offset = 0;
    while ( offset < size )
    {
        DWORD written = 0, chunk = static_cast<DWORD>( std::min<SIZE_T>( size - offset, MAXDWORD ) );
        if ( !WriteFile( file, static_cast<const BYTE *>( data ) + offset, chunk, &written, NULL ) ) error = GetLastError();
        else if ( !written ) error = ERROR_WRITE_FAULT;
        if ( error ) break;
        offset += written;
    }
    if ( !error && !FlushFileBuffers( file ) ) error = GetLastError();
    CloseHandle( file );
    if ( !error && !MoveFileExW( temporary, wide, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH ) )
        error = GetLastError();
    if ( error )
    {
        DeleteFileW( temporary );
        return HRESULT_FROM_WIN32( error );
    }
    return S_OK;
}

static HRESULT files_mkdir( const char *path );
static void create_directories( const char *path )
{
    files_mkdir( path );
}

static void delete_directory( const char *path )
{
    char pattern[2048], child[2048];
    WIN32_FIND_DATAA data;
    HANDLE find;

    snprintf( pattern, sizeof( pattern ), "%s\\*", path );
    if ( ( find = save_find_first( pattern, &data ) ) != INVALID_HANDLE_VALUE )
    {
        do
        {
            if ( !strcmp( data.cFileName, "." ) || !strcmp( data.cFileName, ".." ) ) continue;
            snprintf( child, sizeof( child ), "%s\\%s", path, data.cFileName );
            if ( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                delete_directory( child );
            else
                DeleteFileA( child );
        } while ( FindNextFileA( find, &data ) );
        FindClose( find );
    }
    RemoveDirectoryA( path );
}

static char *files_cache_key( const char *name )
{
    BCRYPT_ALG_HANDLE algorithm;
    BYTE digest[32];
    char *hex;
    NTSTATUS status;
    if ( BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0 ) ) return NULL;
    status = BCryptHash( algorithm, NULL, 0, ( BYTE * )name, strlen( name ), digest, sizeof( digest ) );
    BCryptCloseAlgorithmProvider( algorithm, 0 );
    if ( status || !( hex = static_cast<std::remove_reference_t<decltype( hex )>>( malloc( 65 ) ) ) ) return NULL;
    for ( UINT i = 0; i < 32; i++ )
        sprintf( hex + i * 2, "%02x", digest[i] );
    return hex;
}

static BOOL container_dir( struct XGameSaveProvider *provider, const char *name, char *out, SIZE_T size )
{
    char *hex = provider->files ? files_cache_key( name ) : hex_encode( name );
    if ( !hex ) return FALSE;
    if ( snprintf( out, size, "%s\\%s", provider->root, hex ) >= size )
    {
        free( hex );
        return FALSE;
    }
    free( hex );
    return TRUE;
}

static BOOL blob_path( struct XGameSaveProvider *provider, const char *container, const char *blob, char *out,
                       SIZE_T size )
{
    char dir[2048], *hex = provider->files ? files_cache_key( blob ) : hex_encode( blob );
    BOOL ok = hex && container_dir( provider, container, dir, sizeof( dir ) );
    if ( ok ) ok = snprintf( out, size, "%s\\b_%s", dir, hex ) < size;
    free( hex );
    return ok;
}

static void free_state( struct container_state *state )
{
    for ( UINT32 i = 0; i < state->count; i++ )
        free( state->blobs[i].name );
    free( state->blobs );
    free( state->name );
    free( state->display );
    memset( state, 0, sizeof( *state ) );
}

static struct blob_entry *find_blob( struct container_state *state, const char *name )
{
    for ( UINT32 i = 0; i < state->count; i++ )
        if ( !strcmp( state->blobs[i].name, name ) ) return &state->blobs[i];
    return NULL;
}

static struct blob_entry *add_blob( struct container_state *state, const char *name )
{
    struct blob_entry *blobs, *entry;
    if ( ( entry = find_blob( state, name ) ) ) return entry;
    if ( !( blobs = static_cast<std::remove_reference_t<decltype( blobs )>>(
                realloc( state->blobs, ( state->count + 1 ) * sizeof( *blobs ) ) ) ) )
        return NULL;
    state->blobs = blobs;
    entry = &blobs[state->count];
    memset( entry, 0, sizeof( *entry ) );
    if ( !( entry->name = strdup( name ) ) ) return NULL;
    state->count++;
    return entry;
}

static void remove_blob( struct container_state *state, const char *name )
{
    struct blob_entry *entry = find_blob( state, name );
    if ( !entry ) return;
    free( entry->name );
    memmove( entry, entry + 1, ( state->blobs + state->count - entry - 1 ) * sizeof( *entry ) );
    state->count--;
}

static UINT64 state_total_size( const struct container_state *state )
{
    UINT64 total = 0;
    for ( UINT32 i = 0; i < state->count; i++ )
        total += state->blobs[i].size;
    return total;
}

#include "GameSave/LocalTransactions.h"
#include "GameSave/Index.h"

static HRESULT load_state( struct XGameSaveProvider *provider, const char *name, struct container_state *state )
{
    char dir[2048], path[2048];
    SIZE_T size;
    BYTE *data;
    HRESULT hr;

    memset( state, 0, sizeof( *state ) );
    save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return lock.status;
    if ( FAILED( hr = recover_local_update( provider, name ) ) ) return hr;
    if ( !( state->name = strdup( name ) ) ) return E_OUTOFMEMORY;
    if ( !container_dir( provider, name, dir, sizeof( dir ) ) ) return E_OUTOFMEMORY;
    snprintf( path, sizeof( path ), "%s\\index", dir );
    if ( FAILED( hr = read_file( path, &data, &size ) ) )
    {
        if ( hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) )
            hr = missing_local_index( dir, hr );
        return hr;
    }
    hr = parse_local_index( ( char * )data, size, provider->files, name, state );
    free( data );
    return hr;
}

static HRESULT save_state( struct XGameSaveProvider *provider, const struct container_state *state )
{
    save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return lock.status;
    HRESULT recovery = recover_local_update( provider, state->name );
    if ( FAILED( recovery ) ) return recovery;
    char dir[2048], path[2048], *hex, *text;
    SIZE_T size = 256 + ( provider->files ? strlen( state->name ) * 2 + 8 : 0 ) +
                  ( state->display ? strlen( state->display ) * 2 : 0 ),
           len = 0;
    HRESULT hr;

    for ( UINT32 i = 0; i < state->count; i++ )
        size += strlen( state->blobs[i].name ) * 2 + 80;
    if ( !container_dir( provider, state->name, dir, sizeof( dir ) ) ) return E_OUTOFMEMORY;
    create_directories( dir );
    if ( !( text = static_cast<std::remove_reference_t<decltype( text )>>( calloc( 1, size ) ) ) ) return E_OUTOFMEMORY;
    hex = hex_encode( state->display ? state->display : "" );
    if ( !hex ) { free( text ); return E_OUTOFMEMORY; }
    len += snprintf( text + len, size - len, "display %s\ntime %I64u\nremote %s\ndirty %d\n", hex ? hex : "",
                     state->time, state->remote[0] ? state->remote : "-", state->dirty );
    free( hex );
    len += snprintf( text + len, size - len, "revision %I64u\n", state->revision );
    if ( state->incarnation[0] ) len += snprintf( text + len, size - len, "incarnation %s\n", state->incarnation );
    if ( provider->files )
    {
        hex = hex_encode( state->name );
        if ( !hex )
        {
            free( text );
            return E_OUTOFMEMORY;
        }
        /* Persist file-provider metadata separately from the exposed files. */
        len += snprintf( text + len, size - len, "name %s\n", hex );
        free( hex );
    }
    for ( UINT32 i = 0; i < state->count; i++ )
    {
        hex = hex_encode( state->blobs[i].name );
        if ( !hex ) { free( text ); return E_OUTOFMEMORY; }
        len += snprintf( text + len, size - len, "blob %s %u %s\n", hex ? hex : "", state->blobs[i].size,
                         state->blobs[i].atom[0] ? state->blobs[i].atom : "-" );
        free( hex );
    }
    snprintf( path, sizeof( path ), "%s\\index", dir );
    hr = write_file( path, text, len );
    free( text );
    return hr;
}

/* A generation is minted durably before a legacy container can enter a
 * remote queue. Reads never invent identity; deleting/recreating changes it. */
static HRESULT ensure_incarnation( container_state *state )
{
    if ( state->incarnation[0] ) return S_OK;
    GUID guid; WCHAR text[40];
    HRESULT hr = CoCreateGuid( &guid );
    if ( FAILED( hr ) ) return hr;
    if ( !StringFromGUID2( guid, text, ARRAY_SIZE( text ) ) ||
         !WideCharToMultiByte( CP_UTF8, 0, text, -1, state->incarnation, sizeof( state->incarnation ), NULL, NULL ) )
        return E_FAIL;
    return S_OK;
}
static BOOL same_save_version( const container_state *a, const container_state *b )
{
    return a->revision == b->revision && !strcmp( a->incarnation, b->incarnation ) && a->dirty == b->dirty &&
           !strcmp( a->remote, b->remote );
}
static HRESULT current_save_version( XGameSaveProvider *provider, const container_state *expected )
{
    container_state current{};
    HRESULT hr = load_state( provider, expected->name, &current );
    if ( SUCCEEDED( hr ) && !same_save_version( expected, &current ) ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
    free_state( &current ); return hr;
}

/* A missing target is a version too. Capture before receiving bytes and
 * compare under the promotion lock; no download may overwrite an intervening
 * creation, deletion, or local transaction. */
class save_version_guard
{
    XGameSaveProvider *provider;
    container_state captured{};
    HRESULT initial;
    BOOL observed = FALSE;
public:
    save_version_guard( XGameSaveProvider *p, const char *name, const container_state *expected = NULL,
                        BOOL expected_exists = FALSE ) : provider( p )
    {
        save_cs_lock local( &p->cs ); save_root_lock root( p );
        initial = root.status;
        if ( SUCCEEDED( initial ) ) { observed = TRUE; initial = load_state( p, name, &captured ); }
        if ( expected && ( expected_exists != SUCCEEDED( initial ) ||
             ( expected_exists && !same_save_version( expected, &captured ) ) ) ) initial = E_GS_CONTAINER_NOT_IN_SYNC;
    }
    HRESULT status() const
    {
        if ( !observed || !captured.name ) return FAILED( initial ) ? initial : E_FAIL;
        return initial == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) ||
               initial == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) ? S_OK : initial;
    }
    HRESULT check() const
    {
        if ( FAILED( status() ) ) return status();
        container_state current{};
        HRESULT now = load_state( provider, captured.name, &current );
        BOOL absent = now == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || now == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND );
        HRESULT hr = SUCCEEDED( initial ) ?
            ( SUCCEEDED( now ) && same_save_version( &captured, &current ) ? S_OK : E_GS_CONTAINER_NOT_IN_SYNC ) :
            ( absent ? S_OK : E_GS_CONTAINER_NOT_IN_SYNC );
        free_state( &current ); return hr;
    }
    ~save_version_guard() { free_state( &captured ); }
};

typedef BOOL ( *container_callback )( struct XGameSaveProvider *provider, const char *name, void *context );

static HRESULT enumerate_local_locked( struct XGameSaveProvider *provider, container_callback callback, void *context )
{
    save_cs_lock local( &provider->cs );
    save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return lock.status;
    HRESULT recovery = recover_local_updates( provider );
    if ( FAILED( recovery ) ) return recovery;
    char pattern[2048], index[2048];
    WIN32_FIND_DATAA data;
    HANDLE find;
    HRESULT hr = S_OK;
    BOOL stopped = FALSE;

    snprintf( pattern, sizeof( pattern ), "%s\\*", provider->root );
    if ( ( find = save_find_first( pattern, &data ) ) == INVALID_HANDLE_VALUE )
    {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32( error );
    }
    do
    {
        char *name;
        BOOL more;
        if ( !( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) || data.cFileName[0] == '.' ) continue;
        snprintf( index, sizeof( index ), "%s\\%s\\index", provider->root, data.cFileName );
        if ( provider->files )
        {
            BYTE *text;
            SIZE_T size;
            /* Hash directories are indexes, not container names. Validate
             * the entire index and its identity before invoking any callback. */
            if ( strlen( data.cFileName ) != 64 || strspn( data.cFileName, "0123456789abcdef" ) != 64 ) continue;
            if ( FAILED( hr = read_file( index, &text, &size ) ) ) break;
            container_state state{};
            hr = parse_local_index( ( char * )text, size, TRUE, NULL, &state );
            free( text );
            if ( SUCCEEDED( hr ) )
            {
                char expected[2048];
                if ( !container_dir( provider, state.name, expected, sizeof( expected ) ) ) hr = E_OUTOFMEMORY;
                else if ( strcmp( strrchr( expected, '\\' ) + 1, data.cFileName ) ) hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            }
            name = state.name; state.name = NULL; free_state( &state );
            if ( FAILED( hr ) ) { free( name ); break; }
        }
        else
        {
            SIZE_T length = strlen( data.cFileName );
            if ( !length || length % 2 || length > 512 ||
                 strspn( data.cFileName, "0123456789abcdefABCDEF" ) != length ) continue;
            if ( !( name = hex_decode( data.cFileName ) ) ) continue;
            if ( strlen( name ) * 2 != length ) { free( name ); continue; }
        }
        more = callback( provider, name, context );
        free( name );
        if ( !more )
        {
            stopped = TRUE;
            break;
        }
    } while ( FindNextFileA( find, &data ) );
    if ( !stopped && SUCCEEDED( hr ) )
    {
        DWORD error = GetLastError();
        if ( error != ERROR_NO_MORE_FILES ) hr = HRESULT_FROM_WIN32( error );
    }
    FindClose( find );
    return hr;
}

struct save_name { save_name *next; char *name; };
struct save_names { save_name *first = NULL, **tail = &first; HRESULT status = S_OK; };
static BOOL collect_save_name( XGameSaveProvider *, const char *name, void *context )
{
    save_names *names = static_cast<save_names *>( context );
    save_name *item = static_cast<save_name *>( calloc( 1, sizeof( *item ) ) );
    if ( !item ) { names->status = E_OUTOFMEMORY; return FALSE; }
    if ( !( item->name = strdup( name ) ) ) { free( item ); names->status = E_OUTOFMEMORY; return FALSE; }
    *names->tail = item; names->tail = &item->next; return TRUE;
}
/* Collect a validated name list under the data mutex. Callbacks may do HTTP,
 * so none is invoked while enumeration owns the data lock or provider cs. */
static HRESULT enumerate_local( XGameSaveProvider *provider, container_callback callback, void *context )
{
    save_names names;
    HRESULT hr = enumerate_local_locked( provider, collect_save_name, &names );
    if ( SUCCEEDED( hr ) ) hr = names.status;
    BOOL more = TRUE;
    while ( names.first )
    {
        save_name *item = names.first; names.first = item->next;
        if ( SUCCEEDED( hr ) && more ) more = callback( provider, item->name, context );
        free( item->name ); free( item );
    }
    return hr;
}

static HRESULT cloud_request( struct XGameSaveProvider *provider, const char *method, const char *path,
                              const char *extraHeaders, const void *body, DWORD bodySize, DWORD *status, BYTE **buffer,
                              SIZE_T *bufferSize )
{
    char url[2048], headers[1024];
    HRESULT hr;

    snprintf( url, sizeof( url ), "%s%s", provider->base, path );
    snprintf( headers, sizeof( headers ), "x-xbl-contract-version: 107\r\nx-xbl-pfn: %s\r\n%s",
              GetSavePackageFamilyName(), extraHeaders ? extraHeaders : "" );
    hr = GetSaveTransport( provider )
             .SignedRequest( provider->user, method, url, provider->auth, headers, body, bodySize, status, buffer,
                             bufferSize );

    if ( SUCCEEDED( hr ) && *status >= 400 ) WARN( "save request failed with status %lu\n", *status );
    return hr;
}

static BOOL cloud_lock( struct XGameSaveProvider *provider )
{
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return FALSE;
    const char *quota;
    SIZE_T size;
    BYTE *buffer;
    DWORD status;
    HRESULT hr;

    if ( provider->session_lock && provider->locked ) return TRUE;
    provider->locked = FALSE;
    hr = cloud_request( provider, "PUT", "/lock?friendlyName=Xodus",
                        "x-xbl-lock-ver: 1\r\nContent-Type: application/json\r\n", NULL, 0, &status, &buffer, &size );
    if ( FAILED( hr ) ) return FALSE;
    if ( status == 200 || status == 201 )
    {
        if ( ( quota = json_find( ( char * )buffer, "quotaBytes" ) ) ) provider->quota = _strtoi64( quota, NULL, 10 );
        provider->locked = TRUE;
    }
    else
        WARN( "could not acquire the cloud save lock (status %lu), another device may be using it.\n", status );
    free( buffer );
    return provider->locked;
}

static HRESULT cloud_unlock( struct XGameSaveProvider *provider, BOOL uploaded )
{
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return gate.status;
    SIZE_T size = 0;
    BYTE *buffer = NULL;
    DWORD status = 0;
    HRESULT hr;

    if ( uploaded ) provider->session_uploaded = TRUE;
    if ( !provider->locked || provider->session_lock ) return S_OK;
    hr = cloud_request( provider, "DELETE",
                        provider->session_uploaded ? "/lock?newSavesUploaded=true" : "/lock?newSavesUploaded=false",
                        NULL, NULL, 0, &status, &buffer, &size );
    free( buffer );
    if ( SUCCEEDED( hr ) && ( status < 200 || status >= 300 ) ) hr = E_FAIL;
    if ( FAILED( hr ) )
    {
        WARN( "cloud save session release failed, hr %#lx, status %lu; upload notification retained for retry.\n", hr,
              status );
        return hr;
    }
    provider->locked = FALSE;
    provider->session_uploaded = FALSE;
    return S_OK;
}

static void cloud_disable( struct XGameSaveProvider *provider )
{
    provider->cloud = FALSE;
    ERR( "cloud saves disabled for this session, continuing with local saves only.\n" );
}

static HRESULT cloud_download_into( struct XGameSaveProvider *provider, const char *name, const char *display,
                                    const char *remoteTime )
{
    struct container_state state = { 0 };
    char path[1024], dir[2048], blob[2048], *enc, *key;
    SIZE_T size, dataSize;
    BYTE *buffer, *data;
    const char *atoms, *value;
    DWORD status;
    HRESULT hr;

    if ( !( enc = url_encode( name ) ) ) return E_OUTOFMEMORY;
    snprintf( path, sizeof( path ), "/%s,savedgame", enc );
    free( enc );
    if ( FAILED( hr = cloud_request( provider, "GET", path, NULL, NULL, 0, &status, &buffer, &size ) ) ) return hr;
    if ( status != 200 || !save_json_object_complete( ( char * )buffer, size ) ||
         !( atoms = json_find( ( char * )buffer, "atoms" ) ) || *atoms != '{' )
    {
        free( buffer );
        return E_FAIL;
    }

    if ( !container_dir( provider, name, dir, sizeof( dir ) ) )
        hr = E_OUTOFMEMORY;
    else
        hr = files_mkdir( dir );
    if ( !( state.name = strdup( name ) ) ) hr = E_OUTOFMEMORY;
    state.display = strdup( display ? display : name );
    state.time = parse_iso_time( remoteTime );
    lstrcpynA( state.remote, remoteTime ? remoteTime : "", sizeof( state.remote ) );

    while ( SUCCEEDED( hr ) && json_object_next( &atoms, &key, &value ) )
    {
        char *atom = NULL;
        struct blob_entry *entry;
        if ( *value == '"' ) json_string( value, &atom );
        if ( !atom || !*atom || !*key || strlen( atom ) >= sizeof( state.blobs[0].atom ) || find_blob( &state, key ) ||
             state.count >= 16384 )
        {
            free( atom );
            free( key );
            hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            break;
        }
        if ( !( entry = add_blob( &state, key ) ) )
        {
            free( atom );
            free( key );
            hr = E_OUTOFMEMORY;
            break;
        }
        snprintf( path, sizeof( path ), "/%s", atom );
        data = NULL;
        dataSize = 0;
        if ( SUCCEEDED( hr = cloud_request( provider, "GET", path, NULL, NULL, 0, &status, &data, &dataSize ) ) &&
             status == 200 )
        {
            if ( dataSize > UINT_MAX )
                hr = E_GS_UPDATE_TOO_BIG;
            else if ( !blob_path( provider, name, key, blob, sizeof( blob ) ) )
                hr = E_OUTOFMEMORY;
            else
            {
                hr = write_file( blob, data, dataSize );
                entry->size = dataSize;
                lstrcpynA( entry->atom, atom, sizeof( entry->atom ) );
            }
        }
        else if ( SUCCEEDED( hr ) )
            hr = E_FAIL;
        free( data );
        free( atom );
        free( key );
    }
    /* The iterator also stops on malformed/truncated JSON. Only a real closing
     * brace permits committing the new index, including an empty atoms object. */
    value = json_ws( atoms );
    if ( *value == '{' ) value = json_ws( value + 1 );
    if ( SUCCEEDED( hr ) && *value != '}' ) hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
    free( buffer );
    if ( SUCCEEDED( hr ) ) hr = save_state( provider, &state );

    free_state( &state );
    return hr;
}

#include "GameSave/Transactions.h"

#define LARGE_BLOB_SIZE ( 4 * 1024 * 1024 )

static HRESULT upload_large_atom( struct XGameSaveProvider *provider, const char *atom, const BYTE *data, SIZE_T size )
{
    char path[128], body[64], *blobUri = NULL, *commit = NULL, *p;
    UINT32 blocks = ( size + LARGE_BLOB_SIZE - 1 ) / LARGE_BLOB_SIZE;
    SIZE_T responseSize, commitSize;
    BYTE *response;
    DWORD status;
    HRESULT hr;

    snprintf( path, sizeof( path ), "/atoms/%.36s", atom );
    snprintf( body, sizeof( body ), "{\"size\":%Iu}", size );
    if ( FAILED( hr = cloud_request( provider, "POST", path,
                                     "Content-Type: application/json\r\nAccept: application/json\r\n", body,
                                     strlen( body ), &status, &response, &responseSize ) ) )
        return hr;
    if ( status == 200 ) blobUri = json_find_string( ( char * )response, "blobUri" );
    free( response );
    if ( !blobUri ) return E_FAIL;

    commitSize = 64 + blocks * 24;
    if ( !( commit = static_cast<std::remove_reference_t<decltype( commit )>>( calloc( 1, commitSize ) ) ) )
    {
        free( blobUri );
        return E_OUTOFMEMORY;
    }
    p = commit + sprintf( commit, "{\"blockIds\":[" );

    for ( UINT32 i = 0; i < blocks && SUCCEEDED( hr ); i++ )
    {
        char id[16], encoded[32], *url;
        WCHAR *urlW;
        SIZE_T chunk = std::min<SIZE_T>( LARGE_BLOB_SIZE, size - ( SIZE_T )i * LARGE_BLOB_SIZE ), urlSize;
        int len;

        snprintf( id, sizeof( id ), "%08u", i );
        encode_base64( 8, ( const BYTE * )id, sizeof( encoded ) - 1, encoded, TRUE );
        encoded[12] = 0;
        p += sprintf( p, "%s\"%s\"", i ? "," : "", encoded );

        urlSize = strlen( blobUri ) + 64;
        if ( !( url = static_cast<std::remove_reference_t<decltype( url )>>( calloc( 1, urlSize ) ) ) )
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        {
            char *q = url + snprintf( url, urlSize, "%s&comp=block&blockid=", blobUri );
            for ( const char *c = encoded; *c; c++ )
                q += ( *c == '=' ) ? sprintf( q, "%%3D" ) : ( *q = *c, 1 );
            *q = 0;
        }
        len = MultiByteToWideChar( CP_UTF8, 0, url, -1, NULL, 0 );
        if ( !( urlW = static_cast<std::remove_reference_t<decltype( urlW )>>( calloc( len, sizeof( WCHAR ) ) ) ) )
        {
            free( url );
            hr = E_OUTOFMEMORY;
            break;
        }
        MultiByteToWideChar( CP_UTF8, 0, url, -1, urlW, len );
        hr = GetSaveTransport( provider )
                 .DirectRequest( L"PUT", urlW, L"x-ms-version: 2015-04-05\r\n", data + ( SIZE_T )i * LARGE_BLOB_SIZE,
                                 chunk, &status, &response, &responseSize );
        if ( SUCCEEDED( hr ) && status != 201 )
        {
            WARN( "save block upload failed with status %lu\n", status );
            hr = E_FAIL;
        }
        free( response );
        free( urlW );
        free( url );
    }
    free( blobUri );

    if ( SUCCEEDED( hr ) )
    {
        sprintf( p, "],\"size\":%Iu}", size );
        snprintf( path, sizeof( path ), "/atoms/%.36s?commit=true", atom );
        hr = cloud_request( provider, "POST", path, "Content-Type: application/json\r\nAccept: application/json\r\n",
                            commit, strlen( commit ), &status, &response, &responseSize );
        free( response );
        if ( SUCCEEDED( hr ) && ( status < 200 || status >= 300 ) ) hr = E_FAIL;
    }
    free( commit );

    return hr;
}

/* The metadata PUT acknowledges a new remote baseline independently of the
 * session-release notification. Persist only that baseline, keeping dirty
 * data and the current local revision until the entire upload succeeds. An
 * older in-flight snapshot must never acknowledge a newer local write. */
static HRESULT record_cloud_commit( struct XGameSaveProvider *provider, const struct container_state *uploaded,
                                    BOOL completed )
{
    save_cs_lock local( &provider->cs ); save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return lock.status;
    container_state current{};
    HRESULT hr = load_state( provider, uploaded->name, &current );
    if ( SUCCEEDED( hr ) && strcmp( current.incarnation, uploaded->incarnation ) ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
    if ( SUCCEEDED( hr ) )
    {
        if ( current.revision == uploaded->revision && current.dirty )
        {
            container_state acknowledged = *uploaded;
            acknowledged.dirty = !completed;
            hr = save_state( provider, &acknowledged );
        }
        else if ( current.dirty && current.revision > uploaded->revision )
        {
            /* A newer local write may proceed during HTTP. Acknowledge only
             * the remote baseline, retaining its new payload and dirty state. */
            lstrcpynA( current.remote, uploaded->remote, sizeof( current.remote ) );
            hr = save_state( provider, &current );
        }
        else hr = E_GS_CONTAINER_NOT_IN_SYNC;
    }
    free_state( &current ); return hr;
}

static HRESULT cloud_upload_data( struct XGameSaveProvider *provider, struct container_state *state, BYTE **snapshot,
                                  SIZE_T *snapshot_sizes )
{
    char path[2048], blob[2048], timestamp[48], *enc, *encDisplay, *json, *p;
    SIZE_T size, jsonSize = 32;
    BYTE *buffer, *data;
    DWORD status;
    HRESULT hr = S_OK;

    if ( !provider->cloud ) return S_FALSE;
    save_remote_lock remote( provider );
    if ( FAILED( remote.status ) ) return remote.status;
    {
        save_cs_lock local( &provider->cs ); save_root_lock lock( provider );
        if ( FAILED( lock.status ) ) return lock.status;
        container_state current{};
        hr = load_state( provider, state->name, &current );
        if ( SUCCEEDED( hr ) && ( !current.dirty || !state->dirty || current.revision != state->revision ||
             strcmp( current.incarnation, state->incarnation ) ) ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
        /* A completed older upload may only advance this queued write's
         * remote baseline; that does not invalidate its immutable payload. */
        if ( SUCCEEDED( hr ) ) lstrcpynA( state->remote, current.remote, sizeof( state->remote ) );
        free_state( &current ); if ( FAILED( hr ) ) return hr;
    }
    if ( !cloud_lock( provider ) ) return E_FAIL;

    for ( UINT32 i = 0; i < state->count && SUCCEEDED( hr ); i++ )
    {
        struct blob_entry *entry = &state->blobs[i];
        GUID guid;
        if ( entry->atom[0] ) continue;
        if ( !blob_path( provider, state->name, entry->name, blob, sizeof( blob ) ) )
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        if ( snapshot )
        {
            data = snapshot[i];
            size = snapshot_sizes[i];
        }
        else if ( FAILED( hr = read_file( blob, &data, &size ) ) )
            break;
        CoCreateGuid( &guid );
        snprintf( entry->atom, sizeof( entry->atom ), "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X,binary",
                  guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                  guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7] );
        if ( size > LARGE_BLOB_SIZE )
        {
            hr = upload_large_atom( provider, entry->atom, data, size );
            if ( !snapshot ) free( data );
        }
        else
        {
            snprintf( path, sizeof( path ), "/%s", entry->atom );
            hr = cloud_request( provider, "PUT", path, "Content-Type: application/octet-stream\r\n", data, size,
                                &status, &buffer, &size );
            if ( !snapshot ) free( data );
            free( buffer );
            if ( SUCCEEDED( hr ) && ( status < 200 || status >= 300 ) ) hr = E_FAIL;
        }
        if ( FAILED( hr ) ) entry->atom[0] = 0;
    }
    if ( FAILED( hr ) )
    {
        cloud_unlock( provider, FALSE );
        return hr;
    }

    for ( UINT32 i = 0; i < state->count; i++ )
        jsonSize += strlen( state->blobs[i].name ) * 6 + strlen( state->blobs[i].atom ) + 8;
    if ( !( json = static_cast<std::remove_reference_t<decltype( json )>>( calloc( 1, jsonSize ) ) ) )
    {
        cloud_unlock( provider, FALSE );
        return E_OUTOFMEMORY;
    }
    p = json + sprintf( json, "{\"atoms\":{" );
    for ( UINT32 i = 0; i < state->count; i++ )
    {
        char *escaped = json_escape( state->blobs[i].name );
        p += sprintf( p, "%s\"%s\":\"%s\"", i ? "," : "", escaped ? escaped : "", state->blobs[i].atom );
        free( escaped );
    }
    strcpy( p, "}}" );

    format_iso_time( state->time ? state->time : unix_now(), timestamp, sizeof( timestamp ) );
    enc = url_encode( state->name );
    encDisplay = url_encode( state->display ? state->display : state->name );
    snprintf( path, sizeof( path ), "/%s,savedgame?clientFileTime=%s&displayName=%s", enc ? enc : "", timestamp,
              encDisplay ? encDisplay : "" );
    free( enc );
    free( encDisplay );
    hr = cloud_request( provider, "PUT", path, "Content-Type: application/json\r\n", json, strlen( json ), &status,
                        &buffer, &size );
    free( json );
    free( buffer );
    if ( SUCCEEDED( hr ) && ( status < 200 || status >= 300 ) ) hr = E_FAIL;
    if ( SUCCEEDED( hr ) )
    {
        lstrcpynA( state->remote, timestamp, sizeof( state->remote ) );
        HRESULT persisted = record_cloud_commit( provider, state, FALSE );
        HRESULT released = cloud_unlock( provider, TRUE );
        hr = FAILED( persisted ) ? persisted : released;
        if ( SUCCEEDED( hr ) ) hr = record_cloud_commit( provider, state, TRUE );
    }
    else
        cloud_unlock( provider, FALSE );
    if ( SUCCEEDED( hr ) )
    {
        state->dirty = FALSE;
        lstrcpynA( state->remote, timestamp, sizeof( state->remote ) );
    }

    return hr;
}

static struct save_upload *snapshot_upload( XGameSaveProvider *, const char * );
static void free_upload( save_upload * );
static HRESULT cloud_upload( struct XGameSaveProvider *provider, struct container_state *state )
{
    save_cs_lock cloud( provider->upload_thread ? &provider->cloud_cs : NULL );
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return gate.status;
    save_upload *upload;
    {
        save_cs_lock local( &provider->cs ); save_root_lock root( provider );
        if ( FAILED( root.status ) ) return root.status;
        container_state current{};
        HRESULT hr = load_state( provider, state->name, &current );
        if ( SUCCEEDED( hr ) && ( current.revision != state->revision || current.dirty != state->dirty ||
             strcmp( current.incarnation, state->incarnation ) ||
             ( !state->dirty && strcmp( current.remote, state->remote ) ) ) ) hr = E_GS_CONTAINER_NOT_IN_SYNC;
        free_state( &current );
        if ( FAILED( hr ) ) return hr;
        upload = snapshot_upload( provider, state->name );
    }
    if ( !upload ) return E_OUTOFMEMORY;
    HRESULT hr = cloud_upload_data( provider, &upload->state, upload->data, upload->sizes );
    if ( SUCCEEDED( hr ) )
    {
        free_state( state ); *state = upload->state;
        for ( UINT32 i = 0; i < upload->state.count; i++ ) free( upload->data[i] );
        free( upload->data ); upload->data = NULL;
        memset( &upload->state, 0, sizeof( upload->state ) );
    }
    free_upload( upload ); return hr;
}

static void free_upload( struct save_upload *upload )
{
    if ( upload->data )
        for ( UINT32 i = 0; i < upload->state.count; i++ )
            free( upload->data[i] );
    free( upload->data );
    free( upload->sizes );
    free_state( &upload->state );
    free( upload );
}

/* Called under cs. Own every dirty blob before releasing the local lock: the
 * game is free to overwrite or delete the live files while HTTP is in flight. */
static struct save_upload *snapshot_upload( struct XGameSaveProvider *provider, const char *name )
{
    save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return NULL;
    struct save_upload *upload =
        static_cast<std::remove_reference_t<decltype( upload )>>( calloc( 1, sizeof( *upload ) ) );
    char path[2048];
    if ( !upload ) return NULL;
    if ( FAILED( load_state( provider, name, &upload->state ) ) ) goto failed;
    {
        BOOL changed = !upload->state.incarnation[0] || ( !upload->state.dirty && !upload->state.remote[0] );
        if ( FAILED( ensure_incarnation( &upload->state ) ) ) goto failed;
        /* A valid never-uploaded legacy container may be locally clean. Make
         * its first publication durable dirty intent before starting HTTP. */
        if ( !upload->state.remote[0] ) upload->state.dirty = TRUE;
        if ( changed && FAILED( save_state( provider, &upload->state ) ) ) goto failed;
    }
    if ( upload->state.count )
    {
        upload->data = static_cast<std::remove_reference_t<decltype( upload->data )>>(
            calloc( upload->state.count, sizeof( *upload->data ) ) );
        upload->sizes = static_cast<std::remove_reference_t<decltype( upload->sizes )>>(
            calloc( upload->state.count, sizeof( *upload->sizes ) ) );
        if ( !upload->data || !upload->sizes ) goto failed;
    }
    for ( UINT32 i = 0; i < upload->state.count; i++ )
    {
        if ( upload->state.blobs[i].atom[0] ) continue;
        if ( !blob_path( provider, name, upload->state.blobs[i].name, path, sizeof( path ) ) ||
             FAILED( read_file( path, &upload->data[i], &upload->sizes[i] ) ) )
            goto failed;
    }
    return upload;
failed:
    free_upload( upload );
    return NULL;
}

/* cs protects the queue/local index, cloud_cs serializes remote writes/deletes.
 * At most the latest pending snapshot per container is retained. No network
 * operation holds cs, and completion never changes the caller's task queue. */
static void cancel_pending_upload( struct XGameSaveProvider *provider, const char *name )
{
    struct save_upload **entry = &provider->uploads, *old;
    while ( *entry )
    {
        if ( strcmp( ( *entry )->state.name, name ) )
        {
            entry = &( *entry )->next;
            continue;
        }
        old = *entry;
        *entry = old->next;
        free_upload( old );
    }
}

static void queue_upload( struct XGameSaveProvider *provider, const char *name )
{
    struct save_upload *upload, **tail;
    cancel_pending_upload( provider, name );
    if ( !( upload = snapshot_upload( provider, name ) ) )
    {
        WARN( "cannot snapshot cloud upload; durable dirty index retained for retry.\n" );
        return;
    }
    for ( tail = &provider->uploads; *tail; tail = &( *tail )->next )
        ;
    *tail = upload;
    SetEvent( provider->upload_event );
}

static DWORD WINAPI upload_worker( void *context )
{
    struct XGameSaveProvider *provider = static_cast<XGameSaveProvider *>( context );
    HRESULT com = CoInitializeEx( NULL, COINIT_MULTITHREADED );
    for ( ;; )
    {
        struct save_upload *upload;
        struct container_state current;
        BOOL stopping;
        HRESULT hr;
        WaitForSingleObject( provider->upload_event, INFINITE );
        for ( ;; )
        {
            save_cs_lock cloud( &provider->cloud_cs );
            save_remote_lock gate( provider );
            {
                save_cs_lock local( &provider->cs );
                upload = provider->uploads;
                if ( upload ) provider->uploads = upload->next;
                stopping = provider->upload_stopping;
            }
            if ( !upload )
            {
                if ( stopping ) goto done;
                break;
            }
            hr = FAILED( gate.status ) ? gate.status :
                 cloud_upload_data( provider, &upload->state, upload->data, upload->sizes );
            if ( FAILED( hr ) ) WARN( "background upload failed, hr %#lx; dirty save retained for retry.\n", hr );
            free_upload( upload );
        }
    }
done:
    if ( SUCCEEDED( com ) ) CoUninitialize();
    return 0;
}

static HRESULT cloud_delete( struct XGameSaveProvider *provider, const char *name )
{
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return gate.status;
    char path[1024], *enc = url_encode( name );
    SIZE_T size;
    BYTE *buffer;
    DWORD status;
    HRESULT hr;

    if ( !provider->cloud )
    {
        free( enc );
        return S_FALSE;
    }
    if ( !enc ) return E_OUTOFMEMORY;
    if ( !cloud_lock( provider ) )
    {
        free( enc );
        return E_FAIL;
    }
    snprintf( path, sizeof( path ), "/%s,savedgame", enc );
    free( enc );
    hr = cloud_request( provider, "DELETE", path, NULL, NULL, 0, &status, &buffer, &size );
    free( buffer );
    if ( SUCCEEDED( hr ) && status != 200 && status != 204 && status != 404 ) hr = E_FAIL;
    HRESULT released = cloud_unlock( provider, SUCCEEDED( hr ) );
    return FAILED( hr ) ? hr : released;
}

struct remote_container
{
    char *name;
    char *display;
    char *time;
};

enum sync_mode
{
    SYNC_AUTO,
    SYNC_DOWNLOAD,
    SYNC_UPLOAD,
};

static enum sync_mode sync_mode( void )
{
    char value[32];
    if ( !GetEnvironmentVariableA( "XODUS_SAVE_SYNC", value, sizeof( value ) ) ) return SYNC_AUTO;
    if ( !_stricmp( value, "download" ) ) return SYNC_DOWNLOAD;
    if ( !_stricmp( value, "upload" ) ) return SYNC_UPLOAD;
    return SYNC_AUTO;
}

static HRESULT force_upload( struct XGameSaveProvider *provider, struct container_state *state );

struct local_sync_context
{
    struct remote_container *remote;
    HRESULT hr;
};

static BOOL sync_local_callback( struct XGameSaveProvider *provider, const char *name, void *context )
{
    struct local_sync_context *sync = static_cast<local_sync_context *>( context );
    struct remote_container *remote = sync->remote;
    struct container_state state;
    char dir[2048];

    for ( ; remote->name; remote++ )
        if ( !strcmp( remote->name, name ) ) return TRUE;
    if ( FAILED( sync->hr = load_state( provider, name, &state ) ) )
    {
        free_state( &state );
        return FALSE;
    }
    if ( sync_mode() == SYNC_UPLOAD )
        sync->hr = force_upload( provider, &state );
    else if ( state.dirty || !state.remote[0] )
    {
        sync->hr = cloud_upload( provider, &state );
        if ( SUCCEEDED( sync->hr ) )
        {
            provider->uploaded++;
        }
    }
    else if ( container_dir( provider, name, dir, sizeof( dir ) ) )
    {

        save_cs_lock local( &provider->cs ); save_root_lock root( provider );
        sync->hr = root.status;
        if ( SUCCEEDED( sync->hr ) ) sync->hr = current_save_version( provider, &state );
        if ( SUCCEEDED( sync->hr ) ) delete_directory( dir );
    }
    free_state( &state );
    return SUCCEEDED( sync->hr );
}

static HRESULT force_upload( struct XGameSaveProvider *provider, struct container_state *state )
{
    {
        save_cs_lock local( &provider->cs ); save_root_lock root( provider );
        if ( FAILED( root.status ) ) return root.status;
        HRESULT hr = current_save_version( provider, state );
        if ( FAILED( hr ) ) return hr;
        if ( state->revision == ~(UINT64)0 ) return HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW );
        if ( FAILED( hr = ensure_incarnation( state ) ) ) return hr;
        for ( UINT32 i = 0; i < state->count; i++ ) state->blobs[i].atom[0] = 0;
        state->dirty = TRUE; state->revision++;
        if ( FAILED( hr = save_state( provider, state ) ) ) return hr;
    }
    HRESULT hr = cloud_upload( provider, state );
    if ( SUCCEEDED( hr ) ) provider->uploaded++;
    return hr;
}

static HRESULT files_cloud_download( struct XGameSaveProvider *, const char *, const char *, const char *,
                                     const container_state * = NULL, BOOL = FALSE );

static HRESULT files_validate_download( const container_state *state );

#include "GameSave/Conflicts.h"

static HRESULT cloud_sync( struct XGameSaveProvider *provider )
{
    save_cs_lock cloud( provider->upload_thread ? &provider->cloud_cs : NULL );
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return gate.status;
    {
        save_cs_lock local( &provider->cs ); save_root_lock root( provider );
        if ( FAILED( root.status ) ) return root.status;
        HRESULT recovery = recover_local_updates( provider );
        if ( FAILED( recovery ) ) return recovery;
    }
    struct remote_container *remote = NULL;
    enum sync_mode mode;
    const char *blobs, *item;
    UINT32 count = 0, capacity = 0, listed = 0;
    SIZE_T size;
    BYTE *buffer;
    DWORD status;
    HRESULT hr;
    BOOL refresh = FALSE;

    if ( FAILED( hr = GetSaveTransport( provider )
                          .Authorization( provider->user, "http://xboxlive.com", &provider->auth ) ) )
        return hr;

list_again:
    if ( FAILED( hr = cloud_request( provider, "GET", "", NULL, NULL, 0, &status, &buffer, &size ) ) ) return hr;
    if ( status == 404 )
    {
        free( buffer );
        buffer = ( BYTE * )strdup( "{\"blobs\":[]}" );
        size = buffer ? strlen( ( char * )buffer ) : 0;
        status = 200;
    }
    if ( status != 200 || !save_json_object_complete( ( char * )buffer, size ) ||
         !( blobs = json_find( ( char * )buffer, "blobs" ) ) || *blobs != '[' )
    {
        free( buffer );
        return E_FAIL;
    }
    for ( item = json_ws( blobs + 1 ); *item != ']'; )
    {
        const char *end;
        char *fileName, *comma;
        struct remote_container *tmp;
        if ( *item != '{' || !( end = json_skip( item ) ) || end <= item || end[-1] != '}' )
        {
            hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            break;
        }
        if ( !( fileName = json_find_string( item, "fileName" ) ) )
        {
            hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            break;
        }
        listed++;
        if ( ( comma = strstr( fileName, ",savedgame" ) ) && !comma[10] )
        {
            *comma = 0;
            if ( !*fileName || count == 16384 )
            {
                free( fileName );
                hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
                break;
            }
            for ( UINT32 j = 0; j < count; j++ )
                if ( !strcmp( remote[j].name, fileName ) ) hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            if ( FAILED( hr ) )
            {
                free( fileName );
                break;
            }
            if ( count + 1 >= capacity )
            {
                capacity = capacity ? capacity * 2 : 16;
                if ( !( tmp = static_cast<std::remove_reference_t<decltype( tmp )>>(
                            realloc( remote, capacity * sizeof( *remote ) ) ) ) )
                {
                    free( fileName );
                    hr = E_OUTOFMEMORY;
                    break;
                }
                remote = tmp;
            }
            remote[count].name = fileName;
            remote[count].display = json_find_string( item, "displayName" );
            remote[count].time = json_find_string( item, "clientFileTime" );
            remote[++count].name = NULL;
            fileName = NULL;
        }
        free( fileName );
        item = json_ws( end );
        if ( *item == ',' )
        {
            item = json_ws( item + 1 );
            if ( *item == ']' )
            {
                hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
                break;
            }
        }
        else if ( *item != ']' )
        {
            hr = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            break;
        }
    }
    if ( SUCCEEDED( hr ) ) hr = save_listing_complete( ( char * )buffer, listed );
    free( buffer );
    if ( FAILED( hr ) )
    {
        WARN( "cloud save listing is incomplete or invalid; local saves retained, hr %#lx\n", hr );
        goto done;
    }

    mode = sync_mode();
    for ( UINT32 i = 0; i < count; i++ )
    {
        struct container_state state;
        HRESULT local = load_state( provider, remote[i].name, &state );
        BOOL exists = SUCCEEDED( local );
        if ( FAILED( local ) && local != HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) &&
             local != HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) )
        {
            free_state( &state );
            hr = local;
            goto done;
        }
        BOOL remoteChanged = !exists || strcmp( state.remote, remote[i].time ? remote[i].time : "" );
        if ( exists && state.dirty && remoteChanged && mode == SYNC_AUTO )
        {
            /* Only an explicit choice with recovery copies can replace either
             * side. A cancelled/stale/failed resolution retains local data. */
            hr = resolve_cloud_conflict( provider, &state, remote[i].display, remote[i].time, gate );
            free_state( &state );
            refresh = SUCCEEDED( hr );
            goto done;
        }
        if ( mode == SYNC_UPLOAD )
        {
            if ( exists ) hr = force_upload( provider, &state );
        }
        else if ( mode == SYNC_DOWNLOAD || !exists || ( remoteChanged && !state.dirty ) ||
                  ( remoteChanged && state.dirty && parse_iso_time( remote[i].time ) > state.time ) )
        {
            hr = provider->files ? files_cloud_download( provider, remote[i].name, remote[i].display, remote[i].time, &state, exists )
                                 : cloud_download( provider, remote[i].name, remote[i].display, remote[i].time, &state, exists );
            if ( SUCCEEDED( hr ) ) provider->downloaded++;
        }
        else if ( state.dirty )
        {
            hr = cloud_upload( provider, &state );
            if ( SUCCEEDED( hr ) ) provider->uploaded++;
        }
        free_state( &state );
        if ( FAILED( hr ) ) goto done;
    }
done:
    if ( remote )
    {
        if ( SUCCEEDED( hr ) && !refresh )
        {
            struct local_sync_context sync = { remote, S_OK };
            hr = enumerate_local( provider, sync_local_callback, &sync );
            if ( SUCCEEDED( hr ) ) hr = sync.hr;
        }
        for ( UINT32 i = 0; i < count; i++ )
        {
            free( remote[i].name );
            free( remote[i].display );
            free( remote[i].time );
        }
        free( remote );
    }
    else if ( SUCCEEDED( hr ) )
    {
        struct remote_container empty = { 0 };
        struct local_sync_context sync = { &empty, S_OK };
        hr = enumerate_local( provider, sync_local_callback, &sync );
        if ( SUCCEEDED( hr ) ) hr = sync.hr;
    }
    if ( refresh )
    {
        // The choice may have taken minutes. Never delete or upload other
        // containers using the listing from before the user made a choice.
        remote = NULL; count = capacity = listed = 0; refresh = FALSE;
        goto list_again;
    }
    return hr;
}

static HRESULT initialize_provider( XUserHandle user, const char *configurationId, XGameSaveProviderHandle *out )
{
    struct XGameSaveProvider *provider;
    char localAppData[2048], scid[128];
    UINT64 xuid;
    HRESULT hr;

    if ( !user || !configurationId || !out ) return E_INVALIDARG;
    if ( !( provider =
                static_cast<std::remove_reference_t<decltype( provider )>>( calloc( 1, sizeof( *provider ) ) ) ) )
        return E_OUTOFMEMORY;
    InitializeCriticalSection( &provider->cs );
    provider->quota = SAVE_QUOTA;
    if ( FAILED( hr = ( x_user_impl )->XUserDuplicateHandle( user, &provider->user ) ) ||
         !( provider->scid = strdup( configurationId ) ) )
    {
        DeleteCriticalSection( &provider->cs );
        free( provider );
        return FAILED( hr ) ? hr : E_OUTOFMEMORY;
    }
    xuid = xuser_get_xuid( user );
    lstrcpynA( scid, configurationId, sizeof( scid ) );
    for ( char *p = scid; *p; p++ )
        if ( !isalnum( ( BYTE )*p ) && *p != '-' ) *p = '_';
    if ( !GetEnvironmentVariableA( "LOCALAPPDATA", localAppData, sizeof( localAppData ) ) )
        strcpy( localAppData, "C:\\users\\Public\\AppData\\Local" );
    snprintf( provider->root, sizeof( provider->root ), "%s\\XodusGameSave\\%I64u\\%s", localAppData, xuid, scid );
    create_directories( provider->root );
    snprintf( provider->base, sizeof( provider->base ),
              "https://titlestorage.xboxlive.com/connectedstorage/users/xuid(%I64u)/scids/%s", xuid, configurationId );

    provider->cloud = GetSavePackageFamilyName() != NULL;
    if ( provider->cloud )
    {
        hr = cloud_sync( provider );
        if ( FAILED( hr ) )
        {
            ERR( "cloud sync failed, hr %#lx.\n", hr );
            cloud_disable( provider );
        }
    }

    if ( provider->cloud )
    {
        InitializeCriticalSection( &provider->cloud_cs );
        provider->upload_event = CreateEventW( NULL, FALSE, FALSE, NULL );
        if ( provider->upload_event )
            provider->upload_thread = CreateThread( NULL, 0, upload_worker, provider, 0, NULL );
        if ( !provider->upload_thread )
        {
            hr = HRESULT_FROM_WIN32( GetLastError() );
            if ( provider->upload_event ) CloseHandle( provider->upload_event );
            DeleteCriticalSection( &provider->cloud_cs );
            cloud_unlock( provider, FALSE );
            GetSaveTransport( provider ).CloseUser( provider->user );
            DeleteCriticalSection( &provider->cs );
            free( provider->auth );
            free( provider->scid );
            free( provider );
            return hr;
        }
    }

    if ( GetEnvironmentVariableA( "XODUS_SAVE_SYNC", NULL, 0 ) )
        SaveStatus( "xodus-savesync: cloud %d downloaded %u uploaded %u\n", provider->cloud, provider->downloaded,
                    provider->uploaded );
    *out = provider;
    return S_OK;
}

static BOOL flush_dirty_upload( struct XGameSaveProvider *provider, const char *name, void *context )
{
    struct container_state state;
    HRESULT hr = load_state( provider, name, &state );
    if ( SUCCEEDED( hr ) && state.dirty )
    {
        hr = cloud_upload( provider, &state );
        if ( FAILED( hr ) ) WARN( "final cloud upload failed, hr %#lx; dirty save retained.\n", hr );
    }
    free_state( &state );
    return TRUE;
}

static void close_provider( struct XGameSaveProvider *provider )
{
    if ( !provider ) return;
    if ( provider->upload_thread )
    {
        EnterCriticalSection( &provider->cs );
        provider->upload_stopping = TRUE;
        SetEvent( provider->upload_event );
        LeaveCriticalSection( &provider->cs );
        /* Keep the user, provider and remote session alive until all queued
         * snapshots finish. Abrupt process termination is not a cloud ack. */
        WaitForSingleObject( provider->upload_thread, INFINITE );
        /* Includes snapshots that could not be allocated and genuine upload
         * failures. One final attempt, never a busy retry loop. */
        enumerate_local( provider, flush_dirty_upload, NULL );
        CloseHandle( provider->upload_thread );
        CloseHandle( provider->upload_event );
        DeleteCriticalSection( &provider->cloud_cs );
    }
    cloud_unlock( provider, FALSE );
    GetSaveTransport( provider ).CloseUser( provider->user );
    DeleteCriticalSection( &provider->cs );
    free( provider->auth );
    free( provider->scid );
    free( provider );
}

struct usage_context
{
    UINT64 total;
};

static BOOL usage_callback( struct XGameSaveProvider *provider, const char *name, void *context )
{
    struct usage_context *usage = static_cast<usage_context *>( context );
    struct container_state state;
    if ( SUCCEEDED( load_state( provider, name, &state ) ) ) usage->total += state_total_size( &state );
    free_state( &state );
    return TRUE;
}

static INT64 remaining_quota( struct XGameSaveProvider *provider )
{
    struct usage_context usage = { 0 };
    enumerate_local( provider, usage_callback, &usage );
    return std::max<INT64>( 0, provider->quota - ( INT64 )usage.total );
}

static HRESULT delete_container( struct XGameSaveProvider *provider, const char *name )
{
    if ( !provider || !name || !*name ) return E_INVALIDARG;
    save_cs_lock cloud( provider->upload_thread ? &provider->cloud_cs : NULL );
    save_remote_lock gate( provider );
    if ( FAILED( gate.status ) ) return gate.status;
    HRESULT hr;
    {
        save_cs_lock local( &provider->cs ); save_root_lock root( provider );
        if ( FAILED( root.status ) ) return root.status;
        if ( FAILED( hr = recover_local_update( provider, name ) ) ) return hr;
        container_state state{};
        hr = load_state( provider, name, &state ); free_state( &state );
        if ( FAILED( hr ) && hr != HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) &&
             hr != HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) ) return hr;
        char dir[2048];
        if ( !container_dir( provider, name, dir, sizeof( dir ) ) ) return E_OUTOFMEMORY;
        delete_directory( dir ); cancel_pending_upload( provider, name );
    }
    hr = provider->cloud ? cloud_delete( provider, name ) : S_OK;
    if ( FAILED( hr ) ) WARN( "cloud delete failed, hr %#lx.\n", hr );
    return hr;
}

struct info_context
{
    const char *prefix;
    const char *exact;
    void *context;
    XGameSaveContainerInfoCallback *callback;
    BOOL found;
    HRESULT hr = S_OK;
};

static BOOL info_callback( struct XGameSaveProvider *provider, const char *name, void *context )
{
    struct info_context *ctx = static_cast<info_context *>( context );
    struct container_state state;
    XGameSaveContainerInfo info;
    BOOL more;

    if ( ctx->exact && strcmp( ctx->exact, name ) ) return TRUE;
    if ( ctx->prefix && strncmp( ctx->prefix, name, strlen( ctx->prefix ) ) ) return TRUE;
    if ( FAILED( ctx->hr = load_state( provider, name, &state ) ) )
    {
        free_state( &state );
        return FALSE;
    }
    info.name = state.name;
    info.displayName = state.display ? state.display : state.name;
    info.blobCount = state.count;
    info.totalSize = state_total_size( &state );
    info.lastModifiedTime = state.time;
    /* needsSync describes an on-demand download, not a pending upload. This
     * provider eagerly downloads its containers during initialization. */
    info.needsSync = FALSE;
    ctx->found = TRUE;
    more = ctx->callback( &info, ctx->context );
    free_state( &state );
    return more && !ctx->exact;
}

static HRESULT enumerate_containers( struct XGameSaveProvider *provider, const char *prefix, const char *exact,
                                     void *context, XGameSaveContainerInfoCallback *callback )
{
    struct info_context ctx = { prefix, exact, context, callback, FALSE };
    if ( !provider || !callback ) return E_INVALIDARG;
    EnterCriticalSection( &provider->cs );
    HRESULT hr = enumerate_local( provider, info_callback, &ctx );
    LeaveCriticalSection( &provider->cs );
    return FAILED( hr ) ? hr : ctx.hr;
}

static HRESULT enumerate_blobs( struct XGameSaveContainer *container, const char *prefix, void *context,
                                XGameSaveBlobInfoCallback *callback )
{
    struct container_state state;
    HRESULT hr;

    if ( !container || !callback ) return E_INVALIDARG;
    EnterCriticalSection( &container->provider->cs );
    if ( SUCCEEDED( hr = load_state( container->provider, container->name, &state ) ) )
    {
        for ( UINT32 i = 0; i < state.count; i++ )
        {
            XGameSaveBlobInfo info = { state.blobs[i].name, state.blobs[i].size };
            if ( prefix && strncmp( prefix, info.name, strlen( prefix ) ) ) continue;
            if ( !callback( &info, context ) ) break;
        }
    }
    free_state( &state );
    LeaveCriticalSection( &container->provider->cs );
    return hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) ? S_OK
                                                                                                                : hr;
}

struct read_request
{
    struct XGameSaveContainer *container;
    char **names;
    UINT32 count;
    BYTE *prepared;
    SIZE_T preparedSize;
    UINT32 preparedCount;
};

static HRESULT prepare_read( struct read_request *req )
{
    save_cs_lock local( &req->container->provider->cs );
    save_root_lock lock( req->container->provider );
    if ( FAILED( lock.status ) ) return lock.status;
    struct container_state state;
    char path[2048];
    SIZE_T size = 0, offset;
    UINT32 count;
    HRESULT hr;

    EnterCriticalSection( &req->container->provider->cs );
    if ( FAILED( hr = load_state( req->container->provider, req->container->name, &state ) ) )
    {
        free_state( &state );
        LeaveCriticalSection( &req->container->provider->cs );
        if ( hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) )
            hr = req->names ? E_GS_BLOB_NOT_FOUND : ( req->preparedCount = 0, req->preparedSize = 0, S_OK );
        return hr;
    }
    count = req->names ? req->count : state.count;
    for ( UINT32 i = 0; i < count; i++ )
    {
        struct blob_entry *entry = req->names ? find_blob( &state, req->names[i] ) : &state.blobs[i];
        if ( !entry )
        {
            free_state( &state );
            LeaveCriticalSection( &req->container->provider->cs );
            return E_GS_BLOB_NOT_FOUND;
        }
        size += sizeof( XGameSaveBlob ) + strlen( entry->name ) + 1 + entry->size;
    }
    if ( !( req->prepared = static_cast<std::remove_reference_t<decltype( req->prepared )>>( calloc( 1, size + 1 ) ) ) )
        hr = E_OUTOFMEMORY;
    offset = count * sizeof( XGameSaveBlob );
    for ( UINT32 i = 0; SUCCEEDED( hr ) && i < count; i++ )
    {
        struct blob_entry *entry = req->names ? find_blob( &state, req->names[i] ) : &state.blobs[i];
        XGameSaveBlob *blob = ( XGameSaveBlob * )req->prepared + i;
        SIZE_T dataSize;
        BYTE *data;
        blob->info.name = ( const char * )( ULONG_PTR )offset;
        strcpy( ( char * )req->prepared + offset, entry->name );
        offset += strlen( entry->name ) + 1;
        blob_path( req->container->provider, req->container->name, entry->name, path, sizeof( path ) );
        if ( FAILED( hr = read_file( path, &data, &dataSize ) ) ) break;
        blob->info.size = std::min<SIZE_T>( dataSize, entry->size );
        blob->data = ( UINT8 * )( ULONG_PTR )offset;
        memcpy( req->prepared + offset, data, blob->info.size );
        offset += entry->size;
        free( data );
    }
    free_state( &state );
    LeaveCriticalSection( &req->container->provider->cs );
    req->preparedSize = size;
    req->preparedCount = count;
    return hr;
}

static void layout_read( struct read_request *req, void *buffer )
{
    if ( req->preparedSize ) memcpy( buffer, req->prepared, req->preparedSize );
    for ( UINT32 i = 0; i < req->preparedCount; i++ )
    {
        XGameSaveBlob *blob = ( XGameSaveBlob * )buffer + i;
        blob->info.name = ( const char * )buffer + ( ULONG_PTR )blob->info.name;
        blob->data = ( UINT8 * )buffer + ( ULONG_PTR )blob->data;
    }
}

static void free_read_request( struct read_request *req )
{
    if ( !req ) return;
    for ( UINT32 i = 0; req->names && i < req->count; i++ )
        free( req->names[i] );
    free( req->names );
    free( req->prepared );
    free( req );
}

static struct read_request *create_read_request( struct XGameSaveContainer *container, const char **names,
                                                 UINT32 count )
{
    struct read_request *req = static_cast<std::remove_reference_t<decltype( req )>>( calloc( 1, sizeof( *req ) ) );
    if ( !req ) return NULL;
    req->container = container;
    req->count = count;
    if ( names && count )
    {
        if ( !( req->names = static_cast<std::remove_reference_t<decltype( req->names )>>(
                    calloc( count, sizeof( char * ) ) ) ) )
        {
            free( req );
            return NULL;
        }
        for ( UINT32 i = 0; i < count; i++ )
            if ( !( req->names[i] = strdup( names[i] ) ) )
            {
                free_read_request( req );
                return NULL;
            }
    }
    return req;
}

static HRESULT submit_update( struct XGameSaveUpdate *update )
{
    struct XGameSaveProvider *provider = update->container->provider;
    save_cs_lock local( &provider->cs );
    save_root_lock lock( provider );
    if ( FAILED( lock.status ) ) return lock.status;
    local_save_transaction transaction( provider, update->container->name );
    struct container_state state;
    char path[2048];
    UINT64 total = 0;
    HRESULT hr = S_OK;

    for ( UINT32 i = 0; i < update->count; i++ )
    {
        if ( update->ops[i].size > 16 * 1024 * 1024 - total ) return E_GS_UPDATE_TOO_BIG;
        total += update->ops[i].size;
    }

    hr = load_state( provider, update->container->name, &state );
    if ( hr == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND ) || hr == HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND ) )
    {
        free_state( &state );
        hr = ( state.name = strdup( update->container->name ) ) ? S_OK : E_OUTOFMEMORY;
    }
    if ( SUCCEEDED( hr ) && update->display )
    {
        free( state.display );
        state.display = strdup( update->display );
        if ( !state.display ) hr = E_OUTOFMEMORY;
    }
    else if ( SUCCEEDED( hr ) && !state.display && !( state.display = strdup( update->container->name ) ) )
        hr = E_OUTOFMEMORY;
    // Check sharing/readonly restrictions on every destination before staging.
    // Replacing the whole directory must not bypass a locked blob or index.
    for ( UINT32 i = 0; SUCCEEDED( hr ) && i <= update->count; i++ )
    {
        WCHAR wide[4096];
        if ( i == update->count )
        {
            char dir[2048];
            if ( !container_dir( provider, state.name, dir, sizeof( dir ) ) ||
                 snprintf( path, sizeof( path ), "%s\\index", dir ) >= sizeof( path ) ) { hr = E_INVALIDARG; break; }
        }
        else if ( !blob_path( provider, state.name, update->ops[i].name, path, sizeof( path ) ) )
        { hr = E_INVALIDARG; break; }
        if ( !save_wide_path( path, wide ) ) { hr = E_INVALIDARG; break; }
        DWORD attributes;
        hr = save_path_attributes( path, &attributes );
        if ( hr == S_FALSE ) { hr = S_OK; continue; }
        if ( FAILED( hr ) ) break;
        if ( attributes & ( FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY ) ) { hr = E_ACCESSDENIED; break; }
        HANDLE probe = CreateFileW( wide, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, 0, NULL );
        if ( probe == INVALID_HANDLE_VALUE ) hr = HRESULT_FROM_WIN32( GetLastError() );
        else CloseHandle( probe );
    }
    if ( SUCCEEDED( hr ) ) hr = transaction.prepare();

    for ( UINT32 i = 0; SUCCEEDED( hr ) && i < update->count; i++ )
    {
        struct update_op *op = &update->ops[i];
        if ( !blob_path( &transaction.staged, state.name, op->name, path, sizeof( path ) ) )
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        if ( op->remove )
        {
            WCHAR wide[4096];
            if ( !save_wide_path( path, wide ) ) hr = HRESULT_FROM_WIN32( GetLastError() );
            else if ( !DeleteFileW( wide ) )
            {
                DWORD error = GetLastError();
                if ( error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND ) hr = HRESULT_FROM_WIN32( error );
            }
            if ( FAILED( hr ) ) break;
            remove_blob( &state, op->name );
        }
        else
        {
            struct blob_entry *entry;
            if ( FAILED( hr = write_file( path, op->data, op->size ) ) ) break;
            if ( !( entry = add_blob( &state, op->name ) ) )
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            entry->size = op->size;
            entry->atom[0] = 0;
        }
    }
    if ( SUCCEEDED( hr ) )
    {
        state.time = unix_now();
        state.dirty = TRUE;
        if ( state.revision == ~(UINT64)0 ) hr = HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW );
        else { state.revision++; hr = ensure_incarnation( &state ); }
        if ( SUCCEEDED( hr ) ) hr = save_state( &transaction.staged, &state );
    }
    if ( SUCCEEDED( hr ) ) hr = transaction.commit();
    if ( SUCCEEDED( hr ) && provider->cloud )
    {
        queue_upload( provider, state.name );
    }
    free_state( &state );
    return hr;
}

enum async_kind
{
    ASYNC_INITIALIZE,
    ASYNC_QUOTA,
    ASYNC_DELETE,
    ASYNC_READ,
    ASYNC_SUBMIT,
};

struct save_async
{
    enum async_kind kind;
    XUserHandle user;
    char *text;
    struct XGameSaveProvider *provider;
    struct read_request *read;
    struct XGameSaveUpdate *update;
    XGameSaveProviderHandle result;
    INT64 quota;
};

static const char saveOperationIdentities[5] = {};
static void ReleaseSaveAsync( save_async *context )
{
    if ( context->result ) close_provider( context->result );
    if ( context->user ) x_user_impl->XUserCloseHandle( context->user );
    free_read_request( context->read );
    free( context->text );
    free( context );
}

// GetResult is synchronous on its calling thread. Keep its caller-owned count
// output in a scoped result target, never interpret opaque XAsyncBlock bytes.
static thread_local UINT32 *readResultCountOutput = nullptr;
struct ReadResultScope
{
    UINT32 *previous;
    explicit ReadResultScope( UINT32 *output ) : previous( readResultCountOutput )
    {
        readResultCountOutput = output;
    }
    ~ReadResultScope()
    {
        readResultCountOutput = previous;
    }
};
static HRESULT WINAPI save_async_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    struct save_async *ctx = static_cast<save_async *>( data->context );
    if ( op == XAsyncOp::Cleanup )
    {
        ReleaseSaveAsync( ctx );
        return S_OK;
    }
    IXThreadingImpl *xthreading;
    SIZE_T size = 0;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = ( xthreading )->XAsyncSchedule( data->async, 0 );
        break;

    case XAsyncOp::DoWork:
        switch ( ctx->kind )
        {
        case ASYNC_INITIALIZE:
            hr = initialize_provider( ctx->user, ctx->text, &ctx->result );
            size = sizeof( XGameSaveProviderHandle );
            break;
        case ASYNC_QUOTA:
            EnterCriticalSection( &ctx->provider->cs );
            ctx->quota = remaining_quota( ctx->provider );
            LeaveCriticalSection( &ctx->provider->cs );
            hr = S_OK;
            size = sizeof( INT64 );
            break;
        case ASYNC_DELETE:
            hr = delete_container( ctx->provider, ctx->text );
            break;
        case ASYNC_READ:
            hr = prepare_read( ctx->read );
            size = std::max<SIZE_T>( ctx->read->preparedSize, 1 );
            break;
        case ASYNC_SUBMIT:
            hr = submit_update( ctx->update );
            break;
        }
        ( xthreading )->XAsyncComplete( data->async, hr, SUCCEEDED( hr ) ? size : 0 );
        hr = S_OK;
        break;

    case XAsyncOp::GetResult:
        switch ( ctx->kind )
        {
        case ASYNC_INITIALIZE:
            memcpy( data->buffer, &ctx->result, sizeof( ctx->result ) );
            ctx->result = NULL;
            break;
        case ASYNC_QUOTA:
            memcpy( data->buffer, &ctx->quota, sizeof( ctx->quota ) );
            break;
        case ASYNC_READ:
            layout_read( ctx->read, data->buffer );
            if ( readResultCountOutput ) *readResultCountOutput = ctx->read->preparedCount;
            break;
        default:
            break;
        }
        break;

    case XAsyncOp::Cleanup:
        break;

    case XAsyncOp::Cancel:
        break;
    }
    ( xthreading )->Release();
    return hr;
}

static HRESULT begin_save_async( save_async *context, XAsyncBlock *async, const char *name )
{
    if ( !async )
    {
        ReleaseSaveAsync( context );
        return E_INVALIDARG;
    }
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) )
    {
        ReleaseSaveAsync( context );
        return hr;
    }
    hr = threading->XAsyncBegin( async, context, &saveOperationIdentities[context->kind], name, save_async_provider );
    threading->Release();
    if ( FAILED( hr ) ) ReleaseSaveAsync( context );
    return hr;
}
static HRESULT get_save_result( XAsyncBlock *async, async_kind kind, SIZE_T size, void *buffer )
{
    if ( !async ) return E_INVALIDARG;
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    hr = threading->XAsyncGetResult( async, &saveOperationIdentities[kind], size, buffer, nullptr );
    threading->Release();
    return hr;
}

HRESULT WINAPI XGameSaveImpl::XGameSaveInitializeProvider( XUserHandle requestingUser, const char *configurationId,
                                                           BOOLEAN syncOnDemand, XGameSaveProviderHandle *provider )
{

    return initialize_provider( requestingUser, configurationId, provider );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveInitializeProviderAsync( XUserHandle requestingUser, const char *configurationId,
                                                                BOOLEAN syncOnDemand, XAsyncBlock *async )
{
    struct save_async *ctx;
    HRESULT hr;

    if ( !requestingUser || !configurationId ) return E_INVALIDARG;
    if ( !( ctx = static_cast<std::remove_reference_t<decltype( ctx )>>( calloc( 1, sizeof( *ctx ) ) ) ) )
        return E_OUTOFMEMORY;
    ctx->kind = ASYNC_INITIALIZE;
    ctx->text = strdup( configurationId );
    if ( !ctx->text )
    {
        ReleaseSaveAsync( ctx );
        return E_OUTOFMEMORY;
    }
    hr = x_user_impl->XUserDuplicateHandle( requestingUser, &ctx->user );
    if ( FAILED( hr ) )
    {
        ReleaseSaveAsync( ctx );
        return hr;
    }
    return begin_save_async( ctx, async, "XGameSaveInitializeProviderAsync" );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveInitializeProviderResult( XAsyncBlock *async, XGameSaveProviderHandle *provider )
{

    if ( !provider ) return E_INVALIDARG;
    *provider = nullptr;
    return get_save_result( async, ASYNC_INITIALIZE, sizeof( *provider ), provider );
}

void WINAPI XGameSaveImpl::XGameSaveCloseProvider( XGameSaveProviderHandle provider )
{

    close_provider( provider );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveGetRemainingQuota( XGameSaveProviderHandle provider, INT64 *remainingQuota )
{

    if ( !provider || !remainingQuota ) return E_INVALIDARG;
    EnterCriticalSection( &provider->cs );
    *remainingQuota = remaining_quota( provider );
    LeaveCriticalSection( &provider->cs );
    return S_OK;
}

HRESULT WINAPI XGameSaveImpl::XGameSaveGetRemainingQuotaAsync( XGameSaveProviderHandle provider, XAsyncBlock *async )
{
    struct save_async *ctx;

    if ( !provider ) return E_INVALIDARG;
    if ( !( ctx = static_cast<std::remove_reference_t<decltype( ctx )>>( calloc( 1, sizeof( *ctx ) ) ) ) )
        return E_OUTOFMEMORY;
    ctx->kind = ASYNC_QUOTA;
    ctx->provider = provider;
    return begin_save_async( ctx, async, "XGameSaveGetRemainingQuotaAsync" );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveGetRemainingQuotaResult( XAsyncBlock *async, INT64 *remainingQuota )
{

    if ( !remainingQuota ) return E_INVALIDARG;
    return get_save_result( async, ASYNC_QUOTA, sizeof( *remainingQuota ), remainingQuota );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveDeleteContainer( XGameSaveProviderHandle provider, const char *containerName )
{

    return delete_container( provider, containerName );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveDeleteContainerAsync( XGameSaveProviderHandle provider,
                                                             const char *containerName, XAsyncBlock *async )
{
    struct save_async *ctx;

    if ( !provider || !containerName ) return E_INVALIDARG;
    if ( !( ctx = static_cast<std::remove_reference_t<decltype( ctx )>>( calloc( 1, sizeof( *ctx ) ) ) ) )
        return E_OUTOFMEMORY;
    ctx->kind = ASYNC_DELETE;
    ctx->provider = provider;
    if ( !( ctx->text = strdup( containerName ) ) )
    {
        free( ctx );
        return E_OUTOFMEMORY;
    }
    return begin_save_async( ctx, async, "XGameSaveDeleteContainerAsync" );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveDeleteContainerResult( XAsyncBlock *async )
{

    return get_save_result( async, ASYNC_DELETE, 0, NULL );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveGetContainerInfo( XGameSaveProviderHandle provider, const char *containerName,
                                                         void *context, XGameSaveContainerInfoCallback *callback )
{

    if ( !containerName ) return E_INVALIDARG;
    return enumerate_containers( provider, NULL, containerName, context, callback );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveEnumerateContainerInfo( XGameSaveProviderHandle provider, void *context,
                                                               XGameSaveContainerInfoCallback *callback )
{

    return enumerate_containers( provider, NULL, NULL, context, callback );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveEnumerateContainerInfoByName( XGameSaveProviderHandle provider,
                                                                     const char *containerNamePrefix, void *context,
                                                                     XGameSaveContainerInfoCallback *callback )
{

    return enumerate_containers( provider, containerNamePrefix, NULL, context, callback );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveCreateContainer( XGameSaveProviderHandle provider, const char *containerName,
                                                        XGameSaveContainerHandle *containerContext )
{
    struct XGameSaveContainer *container;

    if ( !provider || !containerContext ) return E_INVALIDARG;
    if ( !containerName || !*containerName || strlen( containerName ) > 256 ) return E_GS_INVALID_CONTAINER_NAME;
    if ( !( container =
                static_cast<std::remove_reference_t<decltype( container )>>( calloc( 1, sizeof( *container ) ) ) ) )
        return E_OUTOFMEMORY;
    container->provider = provider;
    if ( !( container->name = strdup( containerName ) ) )
    {
        free( container );
        return E_OUTOFMEMORY;
    }
    *containerContext = container;
    return S_OK;
}

void WINAPI XGameSaveImpl::XGameSaveCloseContainer( XGameSaveContainerHandle context )
{

    if ( !context ) return;
    free( context->name );
    free( context );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveEnumerateBlobInfo( XGameSaveContainerHandle container, void *context,
                                                          XGameSaveBlobInfoCallback *callback )
{

    return enumerate_blobs( container, NULL, context, callback );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveEnumerateBlobInfoByName( XGameSaveContainerHandle container,
                                                                const char *blobNamePrefix, void *context,
                                                                XGameSaveBlobInfoCallback *callback )
{

    return enumerate_blobs( container, blobNamePrefix, context, callback );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveReadBlobData( XGameSaveContainerHandle container, const char **blobNames,
                                                     UINT32 *countOfBlobs, SIZE_T blobsSize, XGameSaveBlob *blobData )
{
    struct read_request *req;
    HRESULT hr;

    if ( !container || !countOfBlobs || ( !blobData && blobsSize ) ) return E_INVALIDARG;
    if ( !( req = create_read_request( container, blobNames, blobNames ? *countOfBlobs : 0 ) ) ) return E_OUTOFMEMORY;
    if ( SUCCEEDED( hr = prepare_read( req ) ) )
    {
        if ( blobsSize < req->preparedSize )
            hr = E_GS_PROVIDED_BUFFER_TOO_SMALL;
        else
        {
            layout_read( req, blobData );
            *countOfBlobs = req->preparedCount;
        }
    }
    free_read_request( req );
    return hr;
}

HRESULT WINAPI XGameSaveImpl::XGameSaveReadBlobDataAsync( XGameSaveContainerHandle container, const char **blobNames,
                                                          UINT32 countOfBlobs, XAsyncBlock *async )
{
    struct save_async *ctx;

    if ( !container ) return E_INVALIDARG;
    if ( !( ctx = static_cast<std::remove_reference_t<decltype( ctx )>>( calloc( 1, sizeof( *ctx ) ) ) ) )
        return E_OUTOFMEMORY;
    ctx->kind = ASYNC_READ;
    if ( !( ctx->read = create_read_request( container, blobNames, blobNames ? countOfBlobs : 0 ) ) )
    {
        free( ctx );
        return E_OUTOFMEMORY;
    }
    return begin_save_async( ctx, async, "XGameSaveReadBlobDataAsync" );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveReadBlobDataResult( XAsyncBlock *async, SIZE_T blobsSize,
                                                           XGameSaveBlob *blobData, UINT32 *countOfBlobs )
{
    if ( !async || !countOfBlobs || ( !blobData && blobsSize ) ) return E_INVALIDARG;
    *countOfBlobs = 0;
    ReadResultScope result( countOfBlobs );
    // A one-byte private result keeps the empty read context until GetResult.
    // It is not a blob and must never require a dummy buffer from the title.
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    SIZE_T required = 0;
    hr = threading->XAsyncGetResultSize( async, &required );
    threading->Release();
    if ( FAILED( hr ) ) return hr;
    BYTE empty = 0;
    return required == 1 ? get_save_result( async, ASYNC_READ, 1, &empty )
                         : get_save_result( async, ASYNC_READ, blobsSize, blobData );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveCreateUpdate( XGameSaveContainerHandle container,
                                                     const char *containerDisplayName,
                                                     XGameSaveUpdateHandle *updateContext )
{
    struct XGameSaveUpdate *update;

    if ( !container || !updateContext ) return E_INVALIDARG;
    if ( !( update = static_cast<std::remove_reference_t<decltype( update )>>( calloc( 1, sizeof( *update ) ) ) ) )
        return E_OUTOFMEMORY;
    update->container = container;
    if ( containerDisplayName && !( update->display = strdup( containerDisplayName ) ) )
    {
        free( update );
        return E_OUTOFMEMORY;
    }
    *updateContext = update;
    return S_OK;
}

void WINAPI XGameSaveImpl::XGameSaveCloseUpdate( XGameSaveUpdateHandle context )
{

    if ( !context ) return;
    for ( UINT32 i = 0; i < context->count; i++ )
    {
        free( context->ops[i].name );
        free( context->ops[i].data );
    }
    free( context->ops );
    free( context->display );
    free( context );
}

static HRESULT add_update_op( struct XGameSaveUpdate *update, const char *name, const UINT8 *data, SIZE_T size,
                              BOOL remove )
{
    struct update_op *op;

    if ( !update || !name || !*name ) return E_INVALIDARG;
    for ( UINT32 i = 0; i < update->count; i++ )
        if ( !strcmp( update->ops[i].name, name ) ) return E_INVALIDARG;
    if ( update->count == update->capacity )
    {
        UINT32 capacity = update->capacity ? update->capacity * 2 : 8;
        if ( !( op = static_cast<std::remove_reference_t<decltype( op )>>(
                    realloc( update->ops, capacity * sizeof( *op ) ) ) ) )
            return E_OUTOFMEMORY;
        update->ops = op;
        update->capacity = capacity;
    }
    op = &update->ops[update->count];
    memset( op, 0, sizeof( *op ) );
    if ( !( op->name = strdup( name ) ) ) return E_OUTOFMEMORY;
    op->remove = remove;
    if ( !remove )
    {
        if ( !( op->data = static_cast<std::remove_reference_t<decltype( op->data )>>(
                    malloc( std::max<SIZE_T>( size, 1 ) ) ) ) )
        {
            free( op->name );
            return E_OUTOFMEMORY;
        }
        if ( size ) memcpy( op->data, data, size );
        op->size = size;
    }
    update->count++;
    return S_OK;
}

HRESULT WINAPI XGameSaveImpl::XGameSaveSubmitBlobWrite( XGameSaveUpdateHandle updateContext, const char *blobName,
                                                        UINT8 *data, SIZE_T byteCount )
{

    if ( !data && byteCount ) return E_INVALIDARG;
    return add_update_op( updateContext, blobName, data, byteCount, FALSE );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveSubmitBlobDelete( XGameSaveUpdateHandle updateContext, const char *blobName )
{

    return add_update_op( updateContext, blobName, NULL, 0, TRUE );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveSubmitUpdate( XGameSaveUpdateHandle updateContext )
{

    if ( !updateContext ) return E_INVALIDARG;
    return submit_update( updateContext );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveSubmitUpdateAsync( XGameSaveUpdateHandle updateContext, XAsyncBlock *async )
{
    struct save_async *ctx;

    if ( !updateContext ) return E_INVALIDARG;
    if ( !( ctx = static_cast<std::remove_reference_t<decltype( ctx )>>( calloc( 1, sizeof( *ctx ) ) ) ) )
        return E_OUTOFMEMORY;
    ctx->kind = ASYNC_SUBMIT;
    ctx->update = updateContext;
    return begin_save_async( ctx, async, "XGameSaveSubmitUpdateAsync" );
}

HRESULT WINAPI XGameSaveImpl::XGameSaveSubmitUpdateResult( XAsyncBlock *async )
{

    return get_save_result( async, ASYNC_SUBMIT, 0, NULL );
}

#include "GameSave/Files.h"

/*
 * Explicit IXGameSaveImpl3 compatibility view.
 *
 * The installer-only observed legacy caller asks for IID3 and passes a null
 * configurationId to InitializeProviderAsync. Only this view resolves null
 * from the already parsed current package manifest. Explicit non-null values,
 * the flat IXGameSaveImpl path, all other IIDs, async/state/cloud behavior and
 * the real HRESULT path are unchanged and forwarded to the shared owner.
 *
 * The owner is the process-static XGameSaveImpl singleton from
 * GetGameSaveInterface(). This view is intentionally retained for the owner's
 * lifetime; AddRef/Release still follow normal COM reference accounting.
 */
class XGameSaveLegacyView final : public IXGameSaveImpl3
{
public:
    explicit XGameSaveLegacyView( XGameSaveImpl *owner ) noexcept : owner_( owner ) {}

    HRESULT WINAPI QueryInterface( REFIID iid, void **out ) noexcept override
    {
        if ( !out ) return E_POINTER;
        *out = nullptr;
        // QI(IID3) twice returns this same view. All other interfaces belong to
        // the shared owner, preserving its COM identity/refcount.
        if ( iid == __uuidof( IXGameSaveImpl3 ) )
        {
            *out = static_cast<IXGameSaveImpl3 *>( this );
            AddRef();
            return S_OK;
        }
        return owner_->QueryInterface( iid, out );
    }
    ULONG WINAPI AddRef() noexcept override { return owner_->AddRef(); }
    ULONG WINAPI Release() noexcept override { return owner_->Release(); }

    HRESULT WINAPI XGameSaveInitializeProvider( XUserHandle user, const char *configurationId, BOOLEAN syncOnDemand,
                                                XGameSaveProviderHandle *provider ) override
    {
        if ( configurationId ) return owner_->XGameSaveInitializeProvider( user, configurationId, syncOnDemand, provider );
        if ( provider ) *provider = nullptr;
        std::string scid;
        HRESULT hr = nexus::GetGameScid( scid );
        if ( FAILED( hr ) ) return hr;
        return owner_->XGameSaveInitializeProvider( user, scid.c_str(), syncOnDemand, provider );
    }
    HRESULT WINAPI XGameSaveInitializeProviderAsync( XUserHandle user, const char *configurationId, BOOLEAN syncOnDemand,
                                                     XAsyncBlock *async ) override
    {
        if ( configurationId ) return owner_->XGameSaveInitializeProviderAsync( user, configurationId, syncOnDemand, async );
        std::string scid;
        HRESULT hr = nexus::GetGameScid( scid );
        if ( FAILED( hr ) ) return hr;
        return owner_->XGameSaveInitializeProviderAsync( user, scid.c_str(), syncOnDemand, async );
    }
    HRESULT WINAPI XGameSaveInitializeProviderResult( XAsyncBlock *async, XGameSaveProviderHandle *provider ) override
    {
        return owner_->XGameSaveInitializeProviderResult( async, provider );
    }
    void WINAPI XGameSaveCloseProvider( XGameSaveProviderHandle provider ) override
    {
        owner_->XGameSaveCloseProvider( provider );
    }
    HRESULT WINAPI XGameSaveGetRemainingQuota( XGameSaveProviderHandle provider, INT64 *remainingQuota ) override
    {
        return owner_->XGameSaveGetRemainingQuota( provider, remainingQuota );
    }
    HRESULT WINAPI XGameSaveGetRemainingQuotaAsync( XGameSaveProviderHandle provider, XAsyncBlock *async ) override
    {
        return owner_->XGameSaveGetRemainingQuotaAsync( provider, async );
    }
    HRESULT WINAPI XGameSaveGetRemainingQuotaResult( XAsyncBlock *async, INT64 *remainingQuota ) override
    {
        return owner_->XGameSaveGetRemainingQuotaResult( async, remainingQuota );
    }
    HRESULT WINAPI XGameSaveDeleteContainer( XGameSaveProviderHandle provider, const char *containerName ) override
    {
        return owner_->XGameSaveDeleteContainer( provider, containerName );
    }
    HRESULT WINAPI XGameSaveDeleteContainerAsync( XGameSaveProviderHandle provider, const char *containerName,
                                                  XAsyncBlock *async ) override
    {
        return owner_->XGameSaveDeleteContainerAsync( provider, containerName, async );
    }
    HRESULT WINAPI XGameSaveDeleteContainerResult( XAsyncBlock *async ) override
    {
        return owner_->XGameSaveDeleteContainerResult( async );
    }
    HRESULT WINAPI XGameSaveGetContainerInfo( XGameSaveProviderHandle provider, const char *containerName, void *context,
                                              XGameSaveContainerInfoCallback *callback ) override
    {
        return owner_->XGameSaveGetContainerInfo( provider, containerName, context, callback );
    }
    HRESULT WINAPI XGameSaveEnumerateContainerInfo( XGameSaveProviderHandle provider, void *context,
                                                    XGameSaveContainerInfoCallback *callback ) override
    {
        return owner_->XGameSaveEnumerateContainerInfo( provider, context, callback );
    }
    HRESULT WINAPI XGameSaveEnumerateContainerInfoByName( XGameSaveProviderHandle provider, const char *containerNamePrefix,
                                                          void *context,
                                                          XGameSaveContainerInfoCallback *callback ) override
    {
        return owner_->XGameSaveEnumerateContainerInfoByName( provider, containerNamePrefix, context, callback );
    }
    HRESULT WINAPI XGameSaveCreateContainer( XGameSaveProviderHandle provider, const char *containerName,
                                             XGameSaveContainerHandle *containerContext ) override
    {
        return owner_->XGameSaveCreateContainer( provider, containerName, containerContext );
    }
    void WINAPI XGameSaveCloseContainer( XGameSaveContainerHandle context ) override
    {
        owner_->XGameSaveCloseContainer( context );
    }
    HRESULT WINAPI XGameSaveEnumerateBlobInfo( XGameSaveContainerHandle container, void *context,
                                               XGameSaveBlobInfoCallback *callback ) override
    {
        return owner_->XGameSaveEnumerateBlobInfo( container, context, callback );
    }
    HRESULT WINAPI XGameSaveEnumerateBlobInfoByName( XGameSaveContainerHandle container, const char *blobNamePrefix,
                                                     void *context, XGameSaveBlobInfoCallback *callback ) override
    {
        return owner_->XGameSaveEnumerateBlobInfoByName( container, blobNamePrefix, context, callback );
    }
    HRESULT WINAPI XGameSaveReadBlobData( XGameSaveContainerHandle container, const char **blobNames, UINT32 *countOfBlobs,
                                          SIZE_T blobsSize, XGameSaveBlob *blobData ) override
    {
        return owner_->XGameSaveReadBlobData( container, blobNames, countOfBlobs, blobsSize, blobData );
    }
    HRESULT WINAPI XGameSaveReadBlobDataAsync( XGameSaveContainerHandle container, const char **blobNames,
                                               UINT32 countOfBlobs, XAsyncBlock *async ) override
    {
        return owner_->XGameSaveReadBlobDataAsync( container, blobNames, countOfBlobs, async );
    }
    HRESULT WINAPI XGameSaveReadBlobDataResult( XAsyncBlock *async, SIZE_T blobsSize, XGameSaveBlob *blobData,
                                                UINT32 *countOfBlobs ) override
    {
        return owner_->XGameSaveReadBlobDataResult( async, blobsSize, blobData, countOfBlobs );
    }
    HRESULT WINAPI XGameSaveCreateUpdate( XGameSaveContainerHandle container, const char *containerDisplayName,
                                          XGameSaveUpdateHandle *updateContext ) override
    {
        return owner_->XGameSaveCreateUpdate( container, containerDisplayName, updateContext );
    }
    void WINAPI XGameSaveCloseUpdate( XGameSaveUpdateHandle context ) override
    {
        owner_->XGameSaveCloseUpdate( context );
    }
    HRESULT WINAPI XGameSaveSubmitBlobWrite( XGameSaveUpdateHandle updateContext, const char *blobName, UINT8 *data,
                                             SIZE_T byteCount ) override
    {
        return owner_->XGameSaveSubmitBlobWrite( updateContext, blobName, data, byteCount );
    }
    HRESULT WINAPI XGameSaveSubmitBlobDelete( XGameSaveUpdateHandle updateContext, const char *blobName ) override
    {
        return owner_->XGameSaveSubmitBlobDelete( updateContext, blobName );
    }
    HRESULT WINAPI XGameSaveSubmitUpdate( XGameSaveUpdateHandle updateContext ) override
    {
        return owner_->XGameSaveSubmitUpdate( updateContext );
    }
    HRESULT WINAPI XGameSaveSubmitUpdateAsync( XGameSaveUpdateHandle updateContext, XAsyncBlock *async ) override
    {
        return owner_->XGameSaveSubmitUpdateAsync( updateContext, async );
    }
    HRESULT WINAPI XGameSaveSubmitUpdateResult( XAsyncBlock *async ) override
    {
        return owner_->XGameSaveSubmitUpdateResult( async );
    }
    HRESULT WINAPI XGameSaveFilesGetFolderWithUiAsync( XUserHandle user, const char *scid, XAsyncBlock *async ) override
    {
        return owner_->XGameSaveFilesGetFolderWithUiAsync( user, scid, async );
    }
    HRESULT WINAPI XGameSaveFilesGetFolderWithUiResult( XAsyncBlock *async, SIZE_T size, char *folder ) override
    {
        return owner_->XGameSaveFilesGetFolderWithUiResult( async, size, folder );
    }
    HRESULT WINAPI XGameSaveFilesGetRemainingQuota( XUserHandle user, const char *scid, INT64 *quota ) override
    {
        return owner_->XGameSaveFilesGetRemainingQuota( user, scid, quota );
    }

    // The legacy IID3 pointer historically exposed the owner's defensive
    // extension slots beyond the declared interface. Preserve the exact
    // unknown0..unknown15 signatures/order and honest E_NOTIMPL behavior.
    virtual HRESULT WINAPI Unknown0( void *a, void *b, void *c, void *d ) { return owner_->Unknown0( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown1( void *a, void *b, void *c, void *d ) { return owner_->Unknown1( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown2( void *a, void *b, void *c, void *d ) { return owner_->Unknown2( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown3( void *a, void *b, void *c, void *d ) { return owner_->Unknown3( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown4( void *a, void *b, void *c, void *d ) { return owner_->Unknown4( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown5( void *a, void *b, void *c, void *d ) { return owner_->Unknown5( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown6( void *a, void *b, void *c, void *d ) { return owner_->Unknown6( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown7( void *a, void *b, void *c, void *d ) { return owner_->Unknown7( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown8( void *a, void *b, void *c, void *d ) { return owner_->Unknown8( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown9( void *a, void *b, void *c, void *d ) { return owner_->Unknown9( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown10( void *a, void *b, void *c, void *d ) { return owner_->Unknown10( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown11( void *a, void *b, void *c, void *d ) { return owner_->Unknown11( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown12( void *a, void *b, void *c, void *d ) { return owner_->Unknown12( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown13( void *a, void *b, void *c, void *d ) { return owner_->Unknown13( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown14( void *a, void *b, void *c, void *d ) { return owner_->Unknown14( a, b, c, d ); }
    virtual HRESULT WINAPI Unknown15( void *a, void *b, void *c, void *d ) { return owner_->Unknown15( a, b, c, d ); }

private:
    XGameSaveImpl *owner_;
};

XGameSaveImpl::XGameSaveImpl() noexcept = default;
XGameSaveImpl::~XGameSaveImpl() noexcept = default;

HRESULT WINAPI XGameSaveImpl::QueryInterface( REFIID iid, void **out ) noexcept
{
    if ( !out ) return E_POINTER;
    *out = nullptr;
    if ( iid == __uuidof( IXGameSaveImpl3 ) )
    {
        // One stable, owner-owned view per XGameSaveImpl instance. The view
        // owns no independent reference: AddRef/Release delegate to this owner,
        // preserving COM identity and accounting without a cycle.
        try
        {
            std::lock_guard<std::mutex> lock( legacyMutex_ );
            if ( !legacyView_ ) legacyView_ = std::make_unique<XGameSaveLegacyView>( this );
            *out = static_cast<IXGameSaveImpl3 *>( legacyView_.get() );
            AddRef();
            return S_OK;
        }
        catch ( const std::bad_alloc & )
        {
            *out = nullptr;
            return E_OUTOFMEMORY;
        }
        catch ( ... )
        {
            *out = nullptr;
            return E_FAIL;
        }
    }
    if ( iid != __uuidof( IUnknown ) && iid != __uuidof( IXGameSaveImpl ) && iid != __uuidof( IXGameSaveImpl2 ) &&
         iid != __uuidof( IXGameSaveImpl4 ) )
        return E_NOINTERFACE;
    *out = static_cast<IXGameSaveImpl4 *>( this );
    AddRef();
    return S_OK;
}

IXGameSaveImpl *GetGameSaveInterface() noexcept
{
    static XGameSaveImpl save;
    return &save;
}
