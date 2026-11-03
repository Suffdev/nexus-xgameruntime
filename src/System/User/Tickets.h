// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
static HRESULT get_rps_tickets( XUser *owner, BOOLEAN allowUi, char **userTicket, char **deviceTicket,
                                char xbox_msa_id[17], char store_msa_id[17],
                                const std::atomic<bool> *cancel = nullptr )
{
    /* The xodus platform's own MSA client id (the hosting app the service
     * signs the account in with). Titles without an MSAAppId in
     * MicrosoftGame.config (Deep Rock Galactic, RequiresXboxLive=false)
     * still need a signed-in local user for GDK input routing, so their
     * token is requested as the platform app, never as another title. */
    static const char platform_client_id[] = "0000000040159362";
    UINT16 responseSize = 0;
    char *response = NULL;
    xmlChar *body = NULL;
    xmlNodePtr root;
    xmlDocPtr doc;
    int bodySize;
    HRESULT hr;

    /* Schema 0 permits an absent MSAAppId, including full-trust titles.
     * Use the existing platform account request in that case, not a guessed
     * title client id. Keep the declared full-trust scope and all real server
     * authentication results. This does not grant a title token or ownership.
     * An incomplete newer/unknown full-trust configuration still fails. */
    if ( !GetMsaAppId() && GetFullTrust() && !GetLegacyFullTrust() ) return E_GAME_MISSING_GAME_CONFIG;

    if ( !( doc = xmlNewDoc( BAD_CAST "1.0" ) ) ) return E_OUTOFMEMORY;
    root = xmlNewNode( NULL, BAD_CAST "MSATokenRequest" );
    xmlDocSetRootElement( doc, root );
    xmlNewTextChild( root, NULL, BAD_CAST "ClientId", BAD_CAST( GetMsaAppId() ? GetMsaAppId() : platform_client_id ) );
    xmlNewTextChild( root, NULL, BAD_CAST "AllowUi", BAD_CAST( allowUi ? "true" : "false" ) );
    xmlNewTextChild( root, NULL, BAD_CAST "MSAFullTrust", BAD_CAST( GetFullTrust() ? "true" : "false" ) );
    xmlDocDumpMemory( doc, &body, &bodySize );
    xmlFreeDoc( doc );
    if ( !body ) return E_OUTOFMEMORY;
    if ( bodySize > 0xffff )
    {
        xmlFree( body );
        return E_INVALIDARG;
    }

    hr = owner->transport.BackendCancellable( XODUS_MSA_TOKEN_REQUEST, ( const char * )body, bodySize, &response, &responseSize, cancel ? *cancel : owner->cancelled );
    xmlFree( body );
    if ( FAILED( hr ) )
    {
        if ( hr != E_ABORT ) ERR( "xodus-service request failed, hr %#lx. Is xodus-service running?\n", hr );
        return hr;
    }

    nexus::XmlNode payload;
    hr = nexus::ParseXml( std::string_view( response, responseSize ), payload );
    free( response );
    if ( FAILED( hr ) || payload.name != "MSATokenResponse" ) return E_UNEXPECTED;
    auto unique = [&]( const char *name ) -> const nexus::XmlNode *
    {
        const nexus::XmlNode *found = nullptr;
        for ( const auto &child : payload.children )
        {
            if ( child.name != name ) continue;
            if ( found || !child.children.empty() ) return nullptr;
            found = &child;
        }
        return found;
    };
    auto token = unique( "Token" ), device = unique( "DeviceRps" );
    auto validTicket = []( const nexus::XmlNode *node )
    {
        return node && !node->text.empty() &&
               std::all_of( node->text.begin(), node->text.end(),
                            []( unsigned char c ) { return c >= 0x21 && c != '"' && c != 0x5c; } );
    };
    if ( !validTicket( token ) || !validTicket( device ) ) return E_UNEXPECTED;
    *userTicket = strdup( token->text.c_str() );
    *deviceTicket = strdup( device->text.c_str() );
    auto xbox = unique( "XboxMsaAccountId" ), store = unique( "StoreMsaAccountId" );
    account_metadata_pair( xbox ? xbox->text.c_str() : nullptr, store ? store->text.c_str() : nullptr, xbox_msa_id,
                           store_msa_id );

    if ( !*userTicket || !**userTicket || !*deviceTicket || !**deviceTicket )
    {
        ERR( "xodus-service returned incomplete tickets.\n" );
        free( *userTicket );
        free( *deviceTicket );
        *userTicket = *deviceTicket = NULL;
        return E_UNEXPECTED;
    }

    return S_OK;
}


// Only a silent request may overlap public endpoint discovery. The child owns
// its unpublished outputs and is always drained before its owner can unwind.
class SilentUserTickets
{
    XUser *owner;
    HANDLE thread = nullptr;
    std::atomic<bool> cancelled{ false };
    HRESULT result = E_PENDING;
    char *user = nullptr, *device = nullptr;
    char xbox[17]{}, store[17]{};
    static DWORD WINAPI Run( void *value )
    {
        auto self = static_cast<SilentUserTickets *>( value );
        auth_metadata( "init-tickets-begin", self->owner, E_PENDING, 0, FALSE, FALSE );
        const auto com = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
        self->result = FAILED( com ) ? com : self->owner->cancelled ? E_ABORT :
            get_rps_tickets( self->owner, FALSE, &self->user, &self->device, self->xbox, self->store, &self->cancelled );
        if ( SUCCEEDED( com ) ) CoUninitialize();
        auth_metadata( "init-tickets-end", self->owner, self->result, 0, FALSE, FALSE );
        return 0;
    }
public:
    explicit SilentUserTickets( XUser *owner ) : owner( owner ) {}
    SilentUserTickets( const SilentUserTickets & ) = delete;
    SilentUserTickets &operator=( const SilentUserTickets & ) = delete;
    ~SilentUserTickets()
    {
        cancelled = true;
        if ( thread )
        {
            WaitForSingleObject( thread, INFINITE );
            CloseHandle( thread );
            owner->Release();
        }
        free( user ); free( device );
    }
    bool Start() noexcept
    {
        if ( owner->cancelled ) return false;
        owner->AddRef();
        try { thread = owner->transport.StartSilentTicketThread( Run, this ); }
        catch ( ... ) { thread = nullptr; }
        if ( !thread ) owner->Release(); // Preserve the sequential fallback.
        return thread != nullptr;
    }
    void Cancel() noexcept { cancelled = true; }
    HRESULT Take( char **userTicket, char **deviceTicket, char xboxId[17], char storeId[17] ) noexcept
    {
        DWORD waited;
        while ( ( waited = WaitForSingleObject( thread, 25 ) ) == WAIT_TIMEOUT )
            if ( owner->cancelled ) cancelled = true;
        if ( waited != WAIT_OBJECT_0 )
        {
            const auto error = GetLastError();
            return error ? HRESULT_FROM_WIN32( error ) : E_UNEXPECTED;
        }
        if ( owner->cancelled ) return E_ABORT;
        if ( FAILED( result ) ) return result;
        *userTicket = user; user = nullptr;
        *deviceTicket = device; device = nullptr;
        memcpy( xboxId, xbox, sizeof( xbox ) ); memcpy( storeId, store, sizeof( store ) );
        return result;
    }
};
