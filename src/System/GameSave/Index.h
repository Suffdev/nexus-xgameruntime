/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Validate the existing index grammar before a successful read can authorize
 * replacing local progress. Legacy indexes may omit revision, but not the
 * four serializer headers. No count/footer exists in that legacy format.
 */
static BOOL save_index_hex( const char *text, BOOL empty )
{
    SIZE_T length = strlen( text );
    if ( ( !empty && !length ) || length % 2 || strspn( text, "0123456789abcdefABCDEF" ) != length ) return FALSE;
    for ( SIZE_T i = 0; i < length; i += 2 ) if ( text[i] == '0' && text[i + 1] == '0' ) return FALSE;
    return TRUE;
}
static BOOL save_index_number( const char *text, UINT64 limit, UINT64 *value )
{
    UINT64 number = 0;
    if ( !*text ) return FALSE;
    for ( ; *text; text++ )
    {
        if ( *text < '0' || *text > '9' ) return FALSE;
        unsigned digit = *text - '0';
        if ( number > ( limit - digit ) / 10 || digit > limit ) return FALSE;
        number = number * 10 + digit;
    }
    *value = number; return TRUE;
}
static BOOL save_index_token( const char *text, SIZE_T capacity )
{
    SIZE_T length = strlen( text );
    if ( !length || length >= capacity ) return FALSE;
    for ( const unsigned char *p = ( const unsigned char * )text; *p; p++ ) if ( *p <= 32 || *p == 127 ) return FALSE;
    return TRUE;
}
static HRESULT parse_local_index( char *data, SIZE_T size, BOOL files, const char *expected_name,
                                  container_state *state )
{
    const HRESULT invalid = HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
    enum { DISPLAY = 1, TIME = 2, REMOTE = 4, DIRTY = 8, REVISION = 16, NAME = 32, INCARNATION = 64 };
    unsigned seen = 0;
    if ( !size || data[size - 1] != '\n' || memchr( data, 0, size ) ) return invalid;
    for ( char *line = data, *next; *line; line = next )
    {
        next = strchr( line, '\n' );
        if ( !next ) return invalid;
        *next++ = 0;
        unsigned field = 0; UINT64 number;
        if ( !strncmp( line, "display ", 8 ) )
        {
            field = DISPLAY;
            if ( seen & field || !save_index_hex( line + 8, TRUE ) ) return invalid;
            if ( !( state->display = hex_decode( line + 8 ) ) ) return E_OUTOFMEMORY;
        }
        else if ( !strncmp( line, "time ", 5 ) )
        {
            field = TIME;
            if ( !save_index_number( line + 5, ~(UINT64)0, &number ) ) return invalid;
            state->time = number;
        }
        else if ( !strncmp( line, "remote ", 7 ) )
        {
            field = REMOTE;
            if ( !save_index_token( line + 7, sizeof( state->remote ) ) ) return invalid;
            strcpy( state->remote, strcmp( line + 7, "-" ) ? line + 7 : "" );
        }
        else if ( !strncmp( line, "dirty ", 6 ) )
        {
            field = DIRTY;
            if ( strcmp( line + 6, "0" ) && strcmp( line + 6, "1" ) ) return invalid;
            state->dirty = line[6] == '1';
        }
        else if ( !strncmp( line, "revision ", 9 ) )
        {
            field = REVISION;
            if ( !save_index_number( line + 9, ~(UINT64)0, &number ) ) return invalid;
            state->revision = number;
        }
        else if ( !strncmp( line, "incarnation ", 12 ) )
        {
            field = INCARNATION;
            const char *id = line + 12;
            if ( strlen( id ) != 38 || id[0] != '{' || id[37] != '}' ) return invalid;
            for ( unsigned i = 1; i < 37; i++ )
                if ( i == 9 || i == 14 || i == 19 || i == 24 ? id[i] != '-' :
                     !strchr( "0123456789abcdefABCDEF", id[i] ) ) return invalid;
            strcpy( state->incarnation, line + 12 );
        }
        else if ( !strncmp( line, "name ", 5 ) )
        {
            field = NAME;
            if ( !files || seen & field || !save_index_hex( line + 5, FALSE ) ) return invalid;
            char *name = hex_decode( line + 5 );
            if ( !name ) return E_OUTOFMEMORY;
            if ( expected_name && strcmp( expected_name, name ) ) { free( name ); return invalid; }
            if ( expected_name ) free( name ); else state->name = name;
        }
        else if ( !strncmp( line, "blob ", 5 ) )
        {
            char *hex = line + 5, *size_text = strchr( hex, ' ' ), *atom;
            if ( !size_text ) return invalid;
            *size_text++ = 0; atom = strchr( size_text, ' ' );
            if ( !atom ) return invalid;
            *atom++ = 0;
            if ( !save_index_hex( hex, FALSE ) || !save_index_number( size_text, UINT_MAX, &number ) ||
                 !save_index_token( atom, sizeof( state->blobs[0].atom ) ) ) return invalid;
            char *name = hex_decode( hex );
            if ( !name ) return E_OUTOFMEMORY;
            if ( find_blob( state, name ) ) { free( name ); return invalid; }
            blob_entry *entry = add_blob( state, name ); free( name );
            if ( !entry ) return E_OUTOFMEMORY;
            entry->size = static_cast<UINT32>( number );
            strcpy( entry->atom, strcmp( atom, "-" ) ? atom : "" );
        }
        else return invalid;
        if ( field && seen & field ) return invalid;
        seen |= field;
    }
    const unsigned required = DISPLAY | TIME | REMOTE | DIRTY | ( files ? NAME : 0 );
    return ( seen & required ) == required ? S_OK : invalid;
}
