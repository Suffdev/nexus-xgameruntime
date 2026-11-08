// SPDX-License-Identifier: LGPL-2.1-or-later
// Authentication protocol and identity handling adapted from Olivia Ryan's
// XUser implementation and the tested Nexus session corrections.
#pragma once
#include "../../private.h"
#include <bcrypt.h>
#include <atomic>
#include "Transport.h"
#include "AuthorizationCache.h"

struct policy
{
    UINT32 version{};
    UINT32 maxBodyBytes{};
};

struct endpoint
{
    HSTRING protocol, host, path, relyingParty, tokenType;
    struct policy policyValue{};
    struct policy *policy{};
    BOOL wildcard;
};

class XUser
{
public:
    UserTransport &transport;
    nexus::user::AuthorizationCache authorizationCache;
    SRWLOCK privilegeLock{};
    BYTE grantedPrivileges[256]{};
    BOOL privilegesKnown{};
    ULONGLONG privilegesCheckedAt{};
    LONG ref{};
    std::atomic<bool> cancelled{ false };

    BCRYPT_ALG_HANDLE signingAlgorithm{};
    BCRYPT_KEY_HANDLE key{};
    char *proofKey{};
    char *userToken{};
    char *deviceToken{};
    char *titleToken{};
    /* Title id asserted by the title token's server claims. Zero means no
     * token is bound to this launch's configured title. */
    UINT32 titleTokenTitleId{};
    char *deviceAuth{};
    char *deviceAuthAudience{};
    ULONGLONG deviceAuthTime{};
    CRITICAL_SECTION deviceAuthSection;
    CONDITION_VARIABLE initCv{};
    LONG initDone{};
    HRESULT initResult{};
    UINT64 xuid{};
    char xbox_msa_id[17]{}, store_msa_id[17]{};
    XUserAgeGroup age_group{};
    UINT32 policiesLen{};
    UINT32 endpointsLen{};
    struct policy *policies{};
    struct endpoint *endpoints{};

    char gamertag[16]{};
    char modernGamertag[97]{};
    char modernGamertagSuffix[15]{};
    char uniqueModernGamertag[101]{};
    /* Signed in from the offline identity cache: no tokens exist, and token
     * requests report Microsoft as unreachable (User/OfflineIdentity.h). */
    bool offline{};
    XUser() : XUser( GetUserTransport() ) {}
    explicit XUser( UserTransport &transport ) : transport( transport )
    {
        InitializeCriticalSection( &deviceAuthSection );
    }
    HRESULT InitializeNetwork( XUserAddOptions options );
    HRESULT LoadEndpoints( const BYTE *buffer, SIZE_T size );
    void ResetNetworkState() noexcept;
    void RememberOfflineIdentity( const BYTE *defaults, SIZE_T defaultsSize, const BYTE *current,
                                  SIZE_T currentSize ) noexcept;
    HRESULT SignInOffline( HRESULT failure ) noexcept;
    HRESULT CachePrivileges( const WCHAR *xid, UINT32 xidSize, const WCHAR *privileges, UINT32 privilegesSize );
    HRESULT CheckPrivilege( XUserPrivilege privilege, BOOLEAN *granted, XUserPrivilegeDenyReason *reason );
    BOOLEAN IsStoreUser();
    ULONG WINAPI AddRef();
    ULONG WINAPI Release();
    HRESULT WINAPI Initialize( const XUserAddOptions options );
    HRESULT WINAPI GetEndpointInfo( const char *url, struct endpoint *info );
    HRESULT WINAPI GetAuthorization( const WCHAR *relyingParty, WCHAR **auth, bool forceRefresh = false );
    HRESULT GetPresenceAuthorization( const char *url, char **auth, UINT32 *signatureVersion, UINT32 expectedTitle );
    HRESULT WINAPI GetSignature( UINT32 version, const char *method, const char *url, const char *auth, UINT32 bodySize,
                                 const void *body, char signature[104] );
};

HRESULT WaitForUserSignInWorkers( DWORD timeout ) noexcept;
