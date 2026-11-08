// SPDX-License-Identifier: LGPL-2.1-or-later
#include "Presence.h"
#include "../GameInvite/Bridge.h"
#include "../../Runtime/Configuration.h"
#include "../Threading/Atomic64.h"
#include <memory>
#include <new>

namespace nexus::presence
{
namespace
{
Atomic64<UINT64> generation{ 0 };
struct Worker
{
    XUserHandle user;
    HMODULE module;
    UINT64 generation;
    UINT32 title;
    ~Worker() { user->Release(); }
};
void Erase( std::vector<std::string> &fields ) noexcept
{
    for ( auto &field : fields ) SecureZeroMemory( field.data(), field.size() );
    fields.clear();
}
DWORD WINAPI Run( void *context )
{
    std::unique_ptr<Worker> worker( static_cast<Worker *>( context ) );
    const auto com = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
    while ( SUCCEEDED( com ) && generation == worker->generation && xuser_is_current_user( worker->user ) )
    {
        std::vector<std::string> fields, reply;
        // An older launcher must not cause background token requests for a
        // feature it cannot publish or clean up.
        if ( FAILED( invites::GetBridge().Exchange( { "presence-ready" }, reply ) ) ) break;
        const auto hr = Prepare( worker->user, worker->title, fields );
        if ( SUCCEEDED( hr ) && generation == worker->generation && xuser_is_current_user( worker->user ) )
            invites::GetBridge().Exchange( fields, reply );
        Erase( fields );
        // Renew signatures as well as presence. Never hold up XUserAddResult or
        // a title callback, and stop promptly when runtime shutdown is requested.
        for ( unsigned i = 0; i < 60 && generation == worker->generation; ++i ) Sleep( 1000 );
    }
    if ( SUCCEEDED( com ) ) CoUninitialize();
    const auto module = worker->module;
    worker.reset();
    FreeLibraryAndExitThread( module, 0 );
}
}
HRESULT Prepare( XUserHandle user, UINT32 title, std::vector<std::string> &fields ) noexcept
{
    fields.clear();
    if ( !user || !title || !user->xuid || user->cancelled ) return E_INVALIDARG;
    char *authorization = nullptr;
    HRESULT result = E_FAIL;
    try
    {
        const auto url = "https://userpresence.xboxlive.com/users/xuid(" + std::to_string( user->xuid ) + ")/devices/current/titles/current";
        constexpr char body[] = "{\"state\":\"active\"}";
        UINT32 version = 0;
        result = user->GetPresenceAuthorization( url.c_str(), &authorization, &version, title );
        if ( SUCCEEDED( result ) )
        {
            char post[104]{}, remove[104]{};
            result = user->GetSignature( version, "POST", url.c_str(), authorization, sizeof( body ) - 1, body, post );
            if ( SUCCEEDED( result ) ) result = user->GetSignature( version, "DELETE", url.c_str(), authorization, 0, nullptr, remove );
            if ( SUCCEEDED( result ) ) fields = { "presence", std::to_string( user->xuid ), std::to_string( title ), authorization, std::string( post, 104 ), std::string( remove, 104 ) };
            SecureZeroMemory( post, sizeof( post ) ); SecureZeroMemory( remove, sizeof( remove ) );
        }
    }
    catch ( ... ) { result = E_OUTOFMEMORY; }
    if ( authorization ) { SecureZeroMemory( authorization, strlen( authorization ) ); free( authorization ); }
    if ( FAILED( result ) ) Erase( fields );
    return result;
}
void Start( XUserHandle user ) noexcept
{
    const auto *config = GetGameConfiguration();
    if ( !user || !config || !config->titleId || !invites::BridgeAvailable() ) return;
    HMODULE module = nullptr;
    if ( !GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<const WCHAR *>( &Run ), &module ) ) return;
    auto worker = new ( std::nothrow ) Worker{ user, module, ++generation, config->titleId };
    if ( !worker ) { FreeLibrary( module ); return; }
    user->AddRef();
    const auto thread = CreateThread( nullptr, 0, Run, worker, 0, nullptr );
    if ( thread ) CloseHandle( thread );
    else { delete worker; FreeLibrary( module ); }
}
void Stop() noexcept { ++generation; }
}
