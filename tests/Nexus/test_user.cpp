// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "../../src/System/User/XUserImpl.h"
#include "../../src/System/User/Presence.h"
#include "../../src/System/User/OfflineIdentity.h"
#include <wincrypt.h>
#include <string>
#include <vector>
#include <memory>
#include <cstring>

namespace
{
class RuntimeEnvironment final : public testing::Environment
{
public:
    void SetUp() override
    {
        InitializeLogging();
    }
};
const auto environment = testing::AddGlobalTestEnvironment( new RuntimeEnvironment );
NTSTATUS HashForVerification( BYTE *bytes, ULONG size, BYTE output[32] )
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    auto status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0 );
    if ( status < 0 ) return status;
    status = BCryptHash( algorithm, nullptr, 0, bytes, size, output, 32 );
    BCryptCloseAlgorithmProvider( algorithm, 0 );
    return status;
}
class Apartment
{
    HRESULT status = CoInitializeEx( nullptr, COINIT_MULTITHREADED );

public:
    ~Apartment()
    {
        if ( SUCCEEDED( status ) ) CoUninitialize();
    }
};
class SyntheticTransport final : public UserTransport
{
public:
    unsigned backendCalls = 0, httpCalls = 0, rawCalls = 0, unexpected = 0;
    unsigned defaultFailures = 0, retryMilliseconds = 0, retryCalls = 0;
    bool unreachable = false;
    void WaitForSignInRetry( DWORD milliseconds ) noexcept override
    {
        retryMilliseconds += milliseconds;
        ++retryCalls;
    }
    bool currentFails = false, titleToken = true;
    std::string currentEndpoints = Endpoints();
    bool blockBackend = false;
    bool blockAuthorization = false, refuseAuthorization = false;
    DWORD authorizationThread = 0;
    HANDLE authorizationEntered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    HANDLE authorizationContinue = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    HANDLE backendEntered = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    HANDLE backendContinue = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    ~SyntheticTransport()
    {
        CloseHandle( authorizationEntered );
        CloseHandle( authorizationContinue );
        CloseHandle( backendEntered );
        CloseHandle( backendContinue );
    }
    std::string xml = "<MSATokenResponse><Token>synthetic-rps</Token><DeviceRps>synthetic-device-rps</DeviceRps>"
                      "<XboxMsaAccountId>0123456789ABCDEF</XboxMsaAccountId><StoreMsaAccountId>fedcba9876543210</"
                      "StoreMsaAccountId></MSATokenResponse>";
    std::string xid = "1234567890123456";
    std::string claimXid = "1234567890123456", privilegeText = "209 254";
    DWORD xstsStatus = 200;
    std::vector<std::string> signedBodies;
    static std::string Endpoints()
    {
        return R"({"SignaturePolicies":[{"Version":1,"MaxBodyBytes":1024}],"EndPoints":[{"Protocol":"https","Host":"service.example.invalid","Path":"/api","RelyingParty":"https://service.example.invalid/","TokenType":"JWT","SignaturePolicyIndex":0}]})";
    }
    static HRESULT Reply( std::string_view text, BYTE **output, SIZE_T *length )
    {
        *output = static_cast<BYTE *>( malloc( text.size() + 1 ) );
        if ( !*output ) return E_OUTOFMEMORY;
        memcpy( *output, text.data(), text.size() );
        ( *output )[text.size()] = 0;
        *length = text.size();
        return S_OK;
    }
    HRESULT Backend( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *length ) override
    {
        ++backendCalls;
        if ( blockBackend )
        {
            SetEvent( backendEntered );
            if ( WaitForSingleObject( backendContinue, 5000 ) != WAIT_OBJECT_0 ) return E_ABORT;
        }
        if ( type != 3 || !body || !size || !strstr( body, "<MSATokenRequest>" ) )
        {
            ++unexpected;
            return E_FAIL;
        }
        SIZE_T count = 0;
        HRESULT hr = Reply( xml, reinterpret_cast<BYTE **>( response ), &count );
        *length = static_cast<UINT16>( count );
        return hr;
    }
    HRESULT Http( const WCHAR *method, const WCHAR *url, char *, const WCHAR *, const WCHAR **, BYTE **output,
                  SIZE_T *length ) override
    {
        ++httpCalls;
        *output = nullptr;
        *length = 0;
        if ( unreachable ) return HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT );
        if ( !wcscmp( url, L"https://title.mgt.xboxlive.com/titles/default/endpoints?type=1" ) )
        {
            if ( defaultFailures )
            {
                --defaultFailures;
                return E_ACCESSDENIED;
            }
            return Reply( Endpoints(), output, length );
        }
        if ( !wcscmp( url, L"https://device.auth.xboxlive.com/device/authenticate" ) && !wcscmp( method, L"POST" ) )
            return Reply( R"({"Token":"synthetic-device-token"})", output, length );
        if ( !wcscmp( url, L"https://sisu.xboxlive.com/authorize" ) && !wcscmp( method, L"POST" ) )
        {
            std::string response = R"({"UserToken":{"Token":"synthetic-user-token"},)";
            if ( titleToken ) response += R"("TitleToken":{"Token":"synthetic-title-token"},)";
            response += R"("AuthorizationToken":{"Token":"synthetic-authorization","DisplayClaims":{"xui":[{"xid":")" +
                        xid + R"(","gtg":"Synthetic","mgt":"Synthetic","mgs":"","umg":"Synthetic","agg":"Adult"}]}}})";
            return Reply( response, output, length );
        }
        if ( !wcscmp( url, L"https://title.mgt.xboxlive.com/titles/current/endpoints" ) )
        {
            if ( currentFails ) return E_FAIL;
            return Reply( currentEndpoints, output, length );
        }
        ++unexpected;
        return E_FAIL; // There is deliberately no network fallback.
    }
    HRESULT HttpRaw( const WCHAR *method, const WCHAR *url, const WCHAR *, const void *body, DWORD size, DWORD *status,
                     BYTE **output, SIZE_T *length ) override
    {
        ++rawCalls;
        *output = nullptr;
        *length = 0;
        *status = 0;
        if ( wcscmp( method, L"POST" ) || wcscmp( url, L"https://xsts.auth.xboxlive.com/xsts/authorize" ) )
        {
            ++unexpected;
            return E_FAIL;
        }
        if ( blockAuthorization )
        {
            authorizationThread = GetCurrentThreadId();
            SetEvent( authorizationEntered );
            if ( WaitForSingleObject( authorizationContinue, 5000 ) != WAIT_OBJECT_0 ) return E_ABORT;
        }
        if ( refuseAuthorization ) return E_FAIL;
        signedBodies.emplace_back( static_cast<const char *>( body ), size );
        *status = xstsStatus;
        std::string response = R"({"Token":"synthetic-xsts","DisplayClaims":{"xui":[{"xid":")" + claimXid +
                               R"(","uhs":"synthetic-user-hash","prv":")" + privilegeText + R"("}]}})";
        return Reply( response, output, length );
    }
};
struct ReleaseUser
{
    void operator()( XUser *user ) const
    {
        user->Release();
    }
};
using User = std::unique_ptr<XUser, ReleaseUser>;
User CreateUser( UserTransport &transport )
{
    User user( new XUser( transport ) );
    user->ref = 1;
    EXPECT_EQ( user->Initialize( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    return user;
}
}

static std::string PresenceEndpoints()
{
    return R"({"SignaturePolicies":[{"Version":1,"MaxBodyBytes":8192}],"EndPoints":[{"Protocol":"https","Host":"userpresence.xboxlive.com","RelyingParty":"http://xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0}]})";
}
TEST( NexusPresence, UsesGenuineTitleDeviceAndMatchingUserAndSignsOnlyCurrentTitle )
{
    Apartment apartment; SyntheticTransport transport; transport.currentEndpoints = PresenceEndpoints();
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    user->initDone = 1; user->initResult = S_OK;
    std::vector<std::string> fields;
    ASSERT_EQ( nexus::presence::Prepare( user.get(), 123, fields ), S_OK );
    ASSERT_EQ( fields.size(), 6u );
    EXPECT_EQ( fields[0], "presence" ); EXPECT_EQ( fields[1], transport.xid ); EXPECT_EQ( fields[2], "123" );
    EXPECT_EQ( fields[3], "XBL3.0 x=synthetic-user-hash;synthetic-xsts" );
    ASSERT_EQ( transport.signedBodies.size(), 1u );
    for ( const auto field : { "\"TitleToken\":\"synthetic-title-token\"", "\"DeviceToken\":\"synthetic-device-token\"", "\"UserTokens\":[\"synthetic-user-token\"]", "\"RelyingParty\":\"http://xboxlive.com\"", "\"SandboxId\":\"RETAIL\"" } )
        EXPECT_NE( transport.signedBodies[0].find( field ), std::string::npos );
    for ( unsigned index : { 4u, 5u } )
    {
        const char *method = index == 4 ? "POST" : "DELETE", *body = index == 4 ? "{\"state\":\"active\"}" : "";
        BYTE decoded[76]; DWORD size = sizeof( decoded );
        ASSERT_TRUE( CryptStringToBinaryA( fields[index].data(), fields[index].size(), CRYPT_STRING_BASE64, decoded, &size, nullptr, nullptr ) );
        ASSERT_EQ( size, 76u );
        std::vector<BYTE> payload( decoded, decoded + 4 ); payload.push_back( 0 );
        payload.insert( payload.end(), decoded + 4, decoded + 12 ); payload.push_back( 0 );
        const auto route = "/users/xuid(" + transport.xid + ")/devices/current/titles/current";
        for ( const auto &text : { std::string( method ), route, fields[3], std::string( body ) } )
        { payload.insert( payload.end(), text.begin(), text.end() ); payload.push_back( 0 ); }
        BYTE digest[32]; ASSERT_EQ( HashForVerification( payload.data(), payload.size(), digest ), 0 );
        EXPECT_EQ( BCryptVerifySignature( user->key, nullptr, digest, sizeof( digest ), decoded + 12, 64, 0 ), 0 );
        payload.back() = 'x'; ASSERT_EQ( HashForVerification( payload.data(), payload.size(), digest ), 0 );
        EXPECT_NE( BCryptVerifySignature( user->key, nullptr, digest, sizeof( digest ), decoded + 12, 64, 0 ), 0 );
    }
    EXPECT_EQ( transport.unexpected, 0u );
}
TEST( NexusPresence, MissingTitleTokenNeverFallsBackToOrdinaryUserAuthorization )
{
    Apartment apartment; SyntheticTransport transport; transport.titleToken = false; transport.currentEndpoints = PresenceEndpoints();
    auto user = CreateUser( transport ); ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    user->initDone = 1; user->initResult = S_OK;
    std::vector<std::string> fields{ "must-clear" };
    EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 123, fields ) ) );
    EXPECT_TRUE( fields.empty() ); EXPECT_EQ( transport.rawCalls, 0u );
    EXPECT_STREQ( user->userToken, "synthetic-user-token" ); EXPECT_EQ( user->initResult, S_OK );
}
TEST( NexusPresence, WrongMalformedOrMissingAuthenticatedIdentityNeverPublishes )
{
    Apartment apartment;
    for ( const auto identity : { "", "0", "43", "-1", "18446744073709551616", "1234567890123456\\u0000" } )
    {
        SyntheticTransport transport; transport.currentEndpoints = PresenceEndpoints(); transport.claimXid = identity;
        auto user = CreateUser( transport ); ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1; user->initResult = S_OK;
        std::vector<std::string> fields{ "must-clear" };
        EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 123, fields ) ) ); EXPECT_TRUE( fields.empty() );
        EXPECT_EQ( user->initResult, S_OK ); EXPECT_STREQ( user->userToken, "synthetic-user-token" );
    }
}
TEST( NexusPresence, MissingEndpointOrUnsupportedPolicyFailsClosedWithoutBreakingLogin )
{
    Apartment apartment;
    for ( const auto metadata : { SyntheticTransport::Endpoints(), std::string( R"({"EndPoints":[{"Protocol":"https","Host":"userpresence.xboxlive.com","RelyingParty":"http://xboxlive.com","TokenType":"JWT"}]})" ) } )
    {
        SyntheticTransport transport; transport.currentEndpoints = metadata;
        auto user = CreateUser( transport ); ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1; user->initResult = S_OK;
        std::vector<std::string> fields; EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 123, fields ) ) );
        EXPECT_TRUE( fields.empty() ); EXPECT_EQ( transport.rawCalls, 0u ); EXPECT_EQ( user->initResult, S_OK );
    }
}
TEST( NexusPresence, DenialCancelledAndInvalidInputsHaveNoPresenceSideEffects )
{
    Apartment apartment; SyntheticTransport transport; transport.currentEndpoints = PresenceEndpoints(); transport.xstsStatus = 403;
    auto user = CreateUser( transport ); ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    user->initDone = 1; user->initResult = S_OK;
    std::vector<std::string> fields;
    EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 123, fields ) ) ); EXPECT_TRUE( fields.empty() );
    EXPECT_EQ( transport.rawCalls, 1u );
    user->cancelled = true; EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 123, fields ) ) );
    EXPECT_TRUE( FAILED( nexus::presence::Prepare( nullptr, 123, fields ) ) );
    EXPECT_TRUE( FAILED( nexus::presence::Prepare( user.get(), 0, fields ) ) ); EXPECT_EQ( transport.rawCalls, 1u );
}
TEST( NexusAuthentication, CompleteHandshakeKeepsActualXboxAndDistinctMsaIdentities )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    EXPECT_EQ( user->xuid, 1234567890123456ull );
    EXPECT_STREQ( user->xbox_msa_id, "0123456789abcdef" );
    EXPECT_STREQ( user->store_msa_id, "fedcba9876543210" );
    EXPECT_STREQ( user->gamertag, "Synthetic" );
    EXPECT_EQ( user->age_group, XUserAgeGroup::Adult );
    EXPECT_EQ( transport.backendCalls, 1u );
    EXPECT_EQ( transport.httpCalls, 4u );
    EXPECT_EQ( transport.unexpected, 0u );
    user->initDone = 1;
    user->initResult = S_OK;
    endpoint info{};
    ASSERT_EQ( user->GetEndpointInfo( "https://service.example.invalid/api/test", &info ), S_OK );
    ASSERT_NE( info.policy, nullptr );
    EXPECT_EQ( info.policy->version, 1u );
    EXPECT_EQ( info.policy->maxBodyBytes, 1024u );
}
TEST( NexusAuthentication, MissingOptionalMsaMetadataDoesNotPreventAuthentication )
{
    Apartment apartment;
    SyntheticTransport transport;
    transport.xml =
        "<MSATokenResponse><Token>synthetic-rps</Token><DeviceRps>synthetic-device</DeviceRps></MSATokenResponse>";
    transport.titleToken = false;
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    EXPECT_EQ( user->xuid, 1234567890123456ull );
    EXPECT_STREQ( user->xbox_msa_id, "" );
    EXPECT_STREQ( user->store_msa_id, "" );
    EXPECT_EQ( user->titleToken, nullptr );
    user->initDone = 1;
    user->initResult = S_OK;
    WCHAR *auth = nullptr;
    ASSERT_EQ( user->GetAuthorization( L"https://service.example.invalid/", &auth ), S_OK );
    ASSERT_NE( auth, nullptr );
    free( auth );
    ASSERT_EQ( transport.signedBodies.size(), 1u );
    EXPECT_EQ( transport.signedBodies[0].find( "TitleToken" ), std::string::npos );
    EXPECT_EQ( transport.unexpected, 0u );
}
TEST( NexusAuthentication, DeviceAuthorizationCacheIsBoundToItsAudience )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    user->initDone = 1;
    user->initResult = S_OK;
    for ( auto audience :
          { "https://one.example.invalid/", "https://one.example.invalid/", "https://two.example.invalid/" } )
    {
        char *auth = nullptr;
        ASSERT_EQ( xuser_device_authorization( user.get(), audience, &auth ), S_OK );
        ASSERT_NE( auth, nullptr );
        free( auth );
    }
    ASSERT_EQ( transport.signedBodies.size(), 2u );
    EXPECT_NE( transport.signedBodies[0].find( "https://one.example.invalid/" ), std::string::npos );
    EXPECT_NE( transport.signedBodies[1].find( "https://two.example.invalid/" ), std::string::npos );
}
TEST( NexusAuthentication, RetryingAnIncompleteHandshakeDoesNotAccumulateOldState )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    transport.currentFails = true;
    EXPECT_TRUE( FAILED( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ) ) );
    transport.currentFails = false;
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    EXPECT_EQ( user->endpointsLen, 2u );
    EXPECT_EQ( user->policiesLen, 2u );
    EXPECT_EQ( transport.backendCalls, 2u );
    EXPECT_EQ( transport.unexpected, 0u );
}
TEST( NexusAuthentication, PolicyReallocationDoesNotInvalidatePreviouslyMatchedEndpoints )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    std::string first = SyntheticTransport::Endpoints();
    ASSERT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( first.data() ), first.size() ), S_OK );
    std::string next = R"({"SignaturePolicies":[)";
    for ( unsigned i = 0; i < 4096; ++i )
    {
        if ( i ) next += ',';
        next += R"({"Version":2,"MaxBodyBytes":2048})";
    }
    next += R"(],"EndPoints":[{"Protocol":"https","Host":"second.example.invalid","SignaturePolicyIndex":4095}]})";
    ASSERT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( next.data() ), next.size() ), S_OK );
    user->initDone = 1;
    user->initResult = S_OK;
    endpoint info{};
    ASSERT_EQ( user->GetEndpointInfo( "https://service.example.invalid/api/test", &info ), S_OK );
    ASSERT_NE( info.policy, nullptr );
    EXPECT_EQ( info.policy, &info.policyValue );
    EXPECT_EQ( info.policy->version, 1u );
    EXPECT_EQ( info.policy->maxBodyBytes, 1024u );
}
TEST( NexusAuthentication, MsaResponseMustHaveExpectedRootAndUniqueTickets )
{
    Apartment apartment;
    for ( auto xml : { "<Wrong><Token>synthetic</Token><DeviceRps>synthetic</DeviceRps></Wrong>",
                       "<MSATokenResponse><Token>first</Token><Token>second</Token><DeviceRps>synthetic</DeviceRps></"
                       "MSATokenResponse>" } )
    {
        SyntheticTransport transport;
        transport.xml = xml;
        auto user = CreateUser( transport );
        EXPECT_TRUE( FAILED( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ) ) );
        EXPECT_EQ( transport.backendCalls, 1u );
        EXPECT_EQ( transport.httpCalls, 1u );
        EXPECT_EQ( transport.unexpected, 0u );
    }
}
TEST( NexusAuthentication, SigningUsesTheActualGeneratedKeyAndCanonicalPayload )
{
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    char signature[104];
    ASSERT_EQ(
        user->GetSignature( 1, "post", "https://example.invalid/api?q=1", "synthetic-auth", 4, "body", signature ),
        S_OK );
    BYTE decoded[76];
    DWORD size = sizeof( decoded );
    ASSERT_TRUE(
        CryptStringToBinaryA( signature, sizeof( signature ), CRYPT_STRING_BASE64, decoded, &size, nullptr, nullptr ) );
    ASSERT_EQ( size, 76u );
    EXPECT_EQ( decoded[3], 1u );
    std::vector<BYTE> payload( decoded, decoded + 4 );
    payload.push_back( 0 );
    payload.insert( payload.end(), decoded + 4, decoded + 12 );
    payload.push_back( 0 );
    for ( auto text : { "POST", "/api?q=1", "synthetic-auth", "body" } )
    {
        payload.insert( payload.end(), text, text + strlen( text ) );
        payload.push_back( 0 );
    }
    BYTE digest[32];
    ASSERT_EQ( HashForVerification( payload.data(), static_cast<ULONG>( payload.size() ), digest ), 0 );
    EXPECT_EQ( BCryptVerifySignature( user->key, nullptr, digest, sizeof( digest ), decoded + 12, 64, 0 ), 0 );
    payload.back() = 'x';
    ASSERT_EQ( HashForVerification( payload.data(), static_cast<ULONG>( payload.size() ), digest ), 0 );
    EXPECT_NE( BCryptVerifySignature( user->key, nullptr, digest, sizeof( digest ), decoded + 12, 64, 0 ), 0 );
    EXPECT_EQ( transport.backendCalls + transport.httpCalls + transport.rawCalls, 0u );
}

TEST( NexusAuthentication, MalformedSignaturePoliciesAreRejectedWithoutIndexing )
{
    Apartment apartment;
    SyntheticTransport transport;
    for ( auto index : { "-1", "0.5", "99" } )
    {
        auto user = CreateUser( transport );
        std::string value = SyntheticTransport::Endpoints();
        auto offset = value.find( "SignaturePolicyIndex\":0" );
        ASSERT_NE( offset, std::string::npos );
        value.replace( offset, strlen( "SignaturePolicyIndex\":0" ), std::string( "SignaturePolicyIndex\":" ) + index );
        EXPECT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( value.data() ), value.size() ), E_INVALIDARG );
    }
}
TEST( NexusAuthentication, EmptyEndpointMetadataIsNotAnAllocationFailure )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    const std::string empty = R"({"SignaturePolicies":[],"EndPoints":[]})";
    EXPECT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( empty.data() ), empty.size() ), S_OK );
    EXPECT_EQ( user->endpointsLen, 0u );
    EXPECT_EQ( user->policiesLen, 0u );
}
TEST( NexusAuthentication, MissingOptionalSignaturePolicyDoesNotFailEndpointMetadata )
{
    Apartment apartment;
    SyntheticTransport transport;
    for ( const std::string value : {
              R"({"EndPoints":[{"Protocol":"https","Host":"unsigned.example.invalid"}]})",
              R"({"SignaturePolicies":[],"EndPoints":[{"Protocol":"https","Host":"unsigned.example.invalid"}]})",
              R"({"SignaturePolicies":[{"Version":1,"MaxBodyBytes":1024}],"EndPoints":[{"Protocol":"https","Host":"unsigned.example.invalid"}]})" } )
    {
        auto user = CreateUser( transport );
        EXPECT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( value.data() ), value.size() ), S_OK );
        ASSERT_EQ( user->endpointsLen, 1u );
        EXPECT_EQ( user->endpoints[0].policy, nullptr );
    }
    EXPECT_EQ( transport.backendCalls + transport.httpCalls + transport.rawCalls, 0u );
}
TEST( NexusAuthentication, SignedAndUnsignedEndpointOrderDoesNotChangeSuccess )
{
    Apartment apartment;
    SyntheticTransport transport;
    const std::string signedEndpoint =
        R"({"Protocol":"https","Host":"signed.example.invalid","SignaturePolicyIndex":0})";
    const std::string unsignedEndpoint = R"({"Protocol":"https","Host":"unsigned.example.invalid"})";
    for ( bool unsignedFirst : { false, true } )
    {
        auto user = CreateUser( transport );
        const std::string value = R"({"SignaturePolicies":[{"Version":1,"MaxBodyBytes":1024}],"EndPoints":[)" +
                                  ( unsignedFirst ? unsignedEndpoint : signedEndpoint ) + "," +
                                  ( unsignedFirst ? signedEndpoint : unsignedEndpoint ) + "]}";
        EXPECT_EQ( user->LoadEndpoints( reinterpret_cast<const BYTE *>( value.data() ), value.size() ), S_OK );
        ASSERT_EQ( user->endpointsLen, 2u );
        EXPECT_EQ( user->endpoints[unsignedFirst ? 0 : 1].policy, nullptr );
        const auto *policy = user->endpoints[unsignedFirst ? 1 : 0].policy;
        ASSERT_NE( policy, nullptr );
        EXPECT_EQ( policy->version, 1u );
        EXPECT_EQ( policy->maxBodyBytes, 1024u );
    }
    EXPECT_EQ( transport.backendCalls + transport.httpCalls + transport.rawCalls, 0u );
}
TEST( NexusAuthentication, PresentInvalidSignaturePolicyIsNotTreatedAsMissing )
{
    Apartment apartment;
    SyntheticTransport transport;
    for ( auto index : { "null", "false", "\"0\"", "{}", "[]" } )
    {
        auto user = CreateUser( transport );
        std::string value = SyntheticTransport::Endpoints();
        const auto offset = value.find( "SignaturePolicyIndex\":0" );
        ASSERT_NE( offset, std::string::npos );
        value.replace( offset, strlen( "SignaturePolicyIndex\":0" ), std::string( "SignaturePolicyIndex\":" ) + index );
        EXPECT_TRUE( FAILED( user->LoadEndpoints( reinterpret_cast<const BYTE *>( value.data() ), value.size() ) ) );
    }
    EXPECT_EQ( transport.backendCalls + transport.httpCalls + transport.rawCalls, 0u );
}
TEST( NexusAuthentication, HandshakeAcceptsUnsignedTitleEndpointWithoutLosingIdentity )
{
    Apartment apartment;
    SyntheticTransport transport;
    transport.currentEndpoints = R"({"EndPoints":[{"Protocol":"https","Host":"unsigned.example.invalid"}]})";
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    EXPECT_EQ( user->xuid, 1234567890123456ull );
    EXPECT_STREQ( user->xbox_msa_id, "0123456789abcdef" );
    EXPECT_STREQ( user->store_msa_id, "fedcba9876543210" );
    EXPECT_STREQ( user->gamertag, "Synthetic" );
    ASSERT_EQ( user->endpointsLen, 2u );
    EXPECT_EQ( user->endpoints[1].policy, nullptr );
    EXPECT_EQ( transport.backendCalls, 1u );
    EXPECT_EQ( transport.httpCalls, 4u );
    EXPECT_EQ( transport.unexpected, 0u );
}
TEST( NexusAuthentication, PartialZeroOrOverflowXboxIdsAreNotAuthenticated )
{
    Apartment apartment;
    for ( auto xid : { "0", "12x", "+123", "18446744073709551616", "-1" } )
    {
        SyntheticTransport transport;
        transport.xid = xid;
        auto user = CreateUser( transport );
        EXPECT_TRUE( FAILED( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ) ) );
        EXPECT_EQ( user->xuid, 0u );
    }
}

TEST( NexusAuthentication, PrivilegesComeFromMatchingServerClaimsNotOptimisticConstants )
{
    Apartment apartment;
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    user->initDone = 1;
    user->initResult = S_OK;
    BOOLEAN granted = FALSE;
    XUserPrivilegeDenyReason reason = XUserPrivilegeDenyReason::Unknown;
    EXPECT_EQ( user->CheckPrivilege( XUserPrivilege::Multiplayer, &granted, &reason ), S_OK );
    EXPECT_TRUE( granted );
    EXPECT_EQ( reason, XUserPrivilegeDenyReason::None );
    granted = TRUE;
    EXPECT_EQ( user->CheckPrivilege( XUserPrivilege::CrossPlay, &granted, &reason ), S_OK );
    EXPECT_FALSE( granted );
    EXPECT_EQ( reason, XUserPrivilegeDenyReason::Unknown );
    EXPECT_EQ( transport.rawCalls, 1u );
}
TEST( NexusAuthentication, WrongIdentityOrServerDenialNeverGrantsAPrivilege )
{
    Apartment apartment;
    for ( bool mismatch : { true, false } )
    {
        SyntheticTransport transport;
        if ( mismatch )
            transport.claimXid = "9999999999999999";
        else
            transport.xstsStatus = 403;
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1;
        user->initResult = S_OK;
        BOOLEAN granted = TRUE;
        XUserPrivilegeDenyReason reason = XUserPrivilegeDenyReason::None;
        EXPECT_TRUE( FAILED( user->CheckPrivilege( XUserPrivilege::Multiplayer, &granted, &reason ) ) );
        EXPECT_FALSE( granted );
        EXPECT_EQ( reason, XUserPrivilegeDenyReason::Unknown );
        EXPECT_FALSE( user->privilegesKnown );
    }
}
TEST( NexusAuthentication, StoreUserRequiresActualMatchingMsaMetadata )
{
    Apartment apartment;
    for ( bool matching : { true, false } )
    {
        SyntheticTransport transport;
        if ( matching )
        {
            auto offset = transport.xml.find( "fedcba9876543210" );
            ASSERT_NE( offset, std::string::npos );
            transport.xml.replace( offset, 16, "0123456789abcdef" );
        }
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1;
        user->initResult = S_OK;
        EXPECT_EQ( !!user->IsStoreUser(), matching );
    }
}

TEST( NexusAuthentication, SigningRejectsInvalidPointersAndSizeOverflowBeforeReading )
{
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    char signature[104];
    memset( signature, 0x5a, sizeof( signature ) );
    EXPECT_EQ( user->GetSignature( 1, nullptr, "https://example.invalid/", "", 0, nullptr, signature ), E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET", nullptr, "", 0, nullptr, signature ), E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET", "https://example.invalid/", nullptr, 0, nullptr, signature ),
               E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET", "https://example.invalid/", "", 1, nullptr, signature ), E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET", "https://example.invalid/", "", 0, nullptr, nullptr ), E_POINTER );
    EXPECT_EQ(
        user->GetSignature( 1, "GET", "https://example.invalid/", "", MAXDWORD, "not-a-large-buffer", signature ),
        E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET\r\ninjected", "https://example.invalid/", "", 0, nullptr, signature ),
               E_INVALIDARG );
    EXPECT_EQ( user->GetSignature( 1, "GET", "https:///missing-host", "", 0, nullptr, signature ), E_INVALIDARG );
    for ( auto byte : signature )
        EXPECT_EQ( byte, 0x5a );
}
TEST( NexusAuthentication, SigningIncludesRootQueryButNotAFragment )
{
    SyntheticTransport transport;
    auto user = CreateUser( transport );
    char signature[104];
    ASSERT_EQ( user->GetSignature( 1, "get", "https://example.invalid?query=1#not-sent", "", 0, nullptr, signature ),
               S_OK );
    BYTE decoded[76];
    DWORD size = sizeof( decoded );
    ASSERT_TRUE(
        CryptStringToBinaryA( signature, sizeof( signature ), CRYPT_STRING_BASE64, decoded, &size, nullptr, nullptr ) );
    std::vector<BYTE> payload( decoded, decoded + 4 );
    payload.push_back( 0 );
    payload.insert( payload.end(), decoded + 4, decoded + 12 );
    payload.push_back( 0 );
    for ( auto text : { "GET", "/?query=1", "", "" } )
    {
        payload.insert( payload.end(), text, text + strlen( text ) );
        payload.push_back( 0 );
    }
    BYTE digest[32];
    ASSERT_EQ( HashForVerification( payload.data(), static_cast<ULONG>( payload.size() ), digest ), 0 );
    EXPECT_EQ( BCryptVerifySignature( user->key, nullptr, digest, sizeof( digest ), decoded + 12, 64, 0 ), 0 );
}

TEST( NexusAuthentication, CancelSignInCompletesBeforeBlockedTransportReturns )
{
    Apartment apartment;
    SyntheticTransport transport;
    transport.blockBackend = true;
    XUserImpl users( transport );
    IXThreadingImpl *threading = nullptr;
    ASSERT_EQ(
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) ),
        S_OK );
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ(
        threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::Manual, &queue ),
        S_OK );
    unsigned callbacks = 0;
    XAsyncBlock async{};
    async.queue = queue;
    async.context = &callbacks;
    async.callback = []( XAsyncBlock *block ) WINAPI { ++*static_cast<unsigned *>( block->context ); };
    ASSERT_EQ( users.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, &async ), S_OK );
    EXPECT_EQ( WaitForSingleObject( transport.backendEntered, 5000 ), WAIT_OBJECT_0 );
    threading->XAsyncCancel( &async );
    const auto cancelled = threading->XAsyncGetStatus( &async, FALSE );
    EXPECT_EQ( cancelled, E_ABORT );
    SetEvent( transport.backendContinue );
    EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
    EXPECT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 5000 ) );
    EXPECT_EQ( callbacks, 1u );
    if ( cancelled == E_PENDING )
        EXPECT_EQ( threading->XAsyncGetStatus( &async, TRUE ), S_OK );
    else
        EXPECT_EQ( threading->XAsyncGetStatus( &async, TRUE ), E_ABORT );
    XUserHandle result = nullptr;
    if ( cancelled == E_PENDING && SUCCEEDED( users.XUserAddResult( &async, &result ) ) )
        users.XUserCloseHandle( result );
    threading->XTaskQueueCloseHandle( queue );
    threading->Release();
}

TEST( NexusAuthentication, AsyncResultTransfersRealIdentityAndChecksOperationIdentity )
{
    Apartment apartment;
    SyntheticTransport transport;
    transport.xml = "<MSATokenResponse><Token>synthetic</Token><DeviceRps>synthetic-device</"
                    "DeviceRps><XboxMsaAccountId>1234567890abcdef</"
                    "XboxMsaAccountId><StoreMsaAccountId>1234567890abcdef</StoreMsaAccountId></MSATokenResponse>";
    XUserImpl users( transport );
    IXThreadingImpl *threading = nullptr;
    ASSERT_EQ(
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) ),
        S_OK );
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ(
        threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::Manual, &queue ),
        S_OK );
    unsigned callbacks = 0;
    XAsyncBlock async{};
    async.queue = queue;
    async.context = &callbacks;
    async.callback = []( XAsyncBlock *block ) WINAPI { ++*static_cast<unsigned *>( block->context ); };
    ASSERT_EQ( users.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, &async ), S_OK );
    EXPECT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 5000 ) );
    EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
    EXPECT_EQ( callbacks, 1u );
    EXPECT_EQ( threading->XAsyncGetStatus( &async, TRUE ), S_OK );
    XUserHandle result = nullptr;
    ASSERT_EQ( users.XUserAddResult( &async, &result ), S_OK );
    ASSERT_NE( result, nullptr );
    UINT64 id = 0;
    EXPECT_EQ( users.XUserGetId( result, &id ), S_OK );
    EXPECT_EQ( id, 1234567890123456ull );
    EXPECT_TRUE( users.XUserIsStoreUser( result ) );
    char gamertag[32]{};
    SIZE_T used = 0;
    EXPECT_EQ( users.XUserGetGamertag( result, XUserGamertagComponent::Classic, sizeof( gamertag ), gamertag, &used ),
               S_OK );
    EXPECT_STREQ( gamertag, "Synthetic" );
    HKEY key = nullptr;
    ASSERT_EQ(
        RegOpenKeyExA( HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Store", 0, KEY_READ, &key ),
        ERROR_SUCCESS );
    char msa[32]{};
    DWORD size = sizeof( msa );
    EXPECT_EQ( RegGetValueA( key, nullptr, "PrimaryWebAccountId", RRF_RT_REG_SZ, nullptr, msa, &size ), ERROR_SUCCESS );
    EXPECT_STREQ( msa, "1234567890abcdef" );
    RegCloseKey( key );
    users.XUserCloseHandle( result );
    XAsyncBlock wrong{};
    wrong.queue = queue;
    ASSERT_EQ( threading->XAsyncRun( &wrong, []( XAsyncBlock * ) WINAPI -> HRESULT { return S_OK; } ), S_OK );
    EXPECT_EQ( threading->XAsyncGetStatus( &wrong, TRUE ), S_OK );
    result = reinterpret_cast<XUserHandle>( 1 );
    EXPECT_TRUE( FAILED( users.XUserAddResult( &wrong, &result ) ) );
    EXPECT_EQ( result, nullptr );
    threading->XTaskQueueCloseHandle( queue );
    threading->Release();
}
TEST( NexusAuthentication, CancelBeforeManualWorkDoesNotReadCredentials )
{
    Apartment apartment;
    SyntheticTransport transport;
    XUserImpl users( transport );
    IXThreadingImpl *threading = nullptr;
    ASSERT_EQ(
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) ),
        S_OK );
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ( threading->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ),
               S_OK );
    unsigned callbacks = 0;
    XAsyncBlock async{};
    async.queue = queue;
    async.context = &callbacks;
    async.callback = []( XAsyncBlock *block ) WINAPI { ++*static_cast<unsigned *>( block->context ); };
    ASSERT_EQ( users.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, &async ), S_OK );
    threading->XAsyncCancel( &async );
    EXPECT_EQ( threading->XAsyncGetStatus( &async, FALSE ), E_ABORT );
    EXPECT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 5000 ) );
    threading->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 );
    EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
    EXPECT_EQ( callbacks, 1u );
    EXPECT_EQ( transport.backendCalls, 0u );
    EXPECT_EQ( transport.httpCalls, 0u );
    XUserHandle result = reinterpret_cast<XUserHandle>( 1 );
    EXPECT_EQ( users.XUserAddResult( &async, &result ), E_ABORT );
    EXPECT_EQ( result, nullptr );
    threading->XTaskQueueCloseHandle( queue );
    threading->Release();
}
TEST( NexusAuthentication, CancelledBlockCanBeReusedWhileTransportIsStillBlocked )
{
    Apartment apartment;
    SyntheticTransport transport;
    transport.blockBackend = true;
    XUserImpl users( transport );
    IXThreadingImpl *threading = nullptr;
    ASSERT_EQ(
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) ),
        S_OK );
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ(
        threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool, XTaskQueueDispatchMode::Manual, &queue ),
        S_OK );
    struct Reuse
    {
        IXThreadingImpl *threading;
        XTaskQueueHandle queue;
        unsigned callbacks = 0;
    } state{ threading, queue };
    auto async = new XAsyncBlock{};
    async->queue = queue;
    async->context = &state;
    async->callback = []( XAsyncBlock *block ) WINAPI
    {
        auto state = static_cast<Reuse *>( block->context );
        ++state->callbacks;
        EXPECT_EQ( state->threading->XAsyncGetStatus( block, FALSE ), E_ABORT );
        *block = {};
        block->queue = state->queue;
        block->context = state;
        block->callback = []( XAsyncBlock *reused ) WINAPI
        {
            ++static_cast<Reuse *>( reused->context )->callbacks;
            delete reused;
        };
        EXPECT_EQ( state->threading->XAsyncRun( block, []( XAsyncBlock * ) WINAPI -> HRESULT { return S_OK; } ), S_OK );
    };
    ASSERT_EQ( users.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, async ), S_OK );
    EXPECT_EQ( WaitForSingleObject( transport.backendEntered, 5000 ), WAIT_OBJECT_0 );
    threading->XAsyncCancel( async );
    EXPECT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 5000 ) );
    EXPECT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 5000 ) );
    EXPECT_EQ( state.callbacks, 2u );
    SetEvent( transport.backendContinue );
    EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
    EXPECT_EQ( transport.httpCalls, 1u );
    EXPECT_EQ( transport.rawCalls, 0u );
    EXPECT_FALSE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) );
    threading->XTaskQueueCloseHandle( queue );
    threading->Release();
}

TEST( NexusAuthentication, PublicTokenProvidersRejectMissingArgumentsBeforeReading )
{
    SyntheticTransport transport;
    XUserImpl api( transport );
    auto user = CreateUser( transport );
    XAsyncBlock block{};
    const auto options = XUserGetTokenAndSignatureOptions::None;
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( nullptr, options, "GET", "https://service.example.invalid/api", 0,
                                                   nullptr, 0, nullptr, &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( user.get(), options, nullptr, "https://service.example.invalid/api",
                                                   0, nullptr, 0, nullptr, &block ),
               E_INVALIDARG );
    EXPECT_EQ(
        api.XUserGetTokenAndSignatureAsync( user.get(), options, "GET", nullptr, 0, nullptr, 0, nullptr, &block ),
        E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( user.get(), options, "GET", "https://service.example.invalid/api", 0,
                                                   nullptr, 0, nullptr, nullptr ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( user.get(), options, "GET", "https://service.example.invalid/api", 1,
                                                   nullptr, 0, nullptr, &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( user.get(), options, "GET", "https://service.example.invalid/api", 0,
                                                   nullptr, 1, nullptr, &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureAsync( user.get(), options, "GET", "https://service.example.invalid/api", 0,
                                                   nullptr, SIZE_MAX, "body", &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Async(
                   nullptr, options, L"GET", L"https://service.example.invalid/api", 0, nullptr, 0, nullptr, &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Async( user.get(), options, nullptr,
                                                        L"https://service.example.invalid/api", 0, nullptr, 0, nullptr,
                                                        &block ),
               E_INVALIDARG );
    EXPECT_EQ(
        api.XUserGetTokenAndSignatureUtf16Async( user.get(), options, L"GET", nullptr, 0, nullptr, 0, nullptr, &block ),
        E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Async( user.get(), options, L"GET",
                                                        L"https://service.example.invalid/api", 1, nullptr, 0, nullptr,
                                                        &block ),
               E_INVALIDARG );
    EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Async( user.get(), options, L"GET",
                                                        L"https://service.example.invalid/api", 0, nullptr, SIZE_MAX,
                                                        "body", &block ),
               E_INVALIDARG );
    EXPECT_EQ( transport.backendCalls + transport.httpCalls + transport.rawCalls, 0u );
    EXPECT_EQ( user->ref, 1 );
}

TEST( NexusAuthentication, PublicTokenResultsAreTerminatedRetryableAndEncodingBound )
{
    Apartment apartment;
    for ( bool wide : { false, true } )
        for ( bool signedRequest : { false, true } )
        {
            SyntheticTransport transport;
            XUserImpl api( transport );
            auto user = CreateUser( transport );
            ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
            user->initDone = 1;
            user->initResult = S_OK;
            if ( !signedRequest )
                for ( UINT i = 0; i < user->endpointsLen; ++i )
                    user->endpoints[i].policy = nullptr;
            IXThreadingImpl *threads = nullptr;
            ASSERT_EQ( QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ),
                                     reinterpret_cast<void **>( &threads ) ),
                       S_OK );
            XTaskQueueHandle queue = nullptr;
            ASSERT_EQ(
                threads->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ),
                S_OK );
            XAsyncBlock block{};
            block.queue = queue;
            auto hr = wide
                          ? api.XUserGetTokenAndSignatureUtf16Async( user.get(), XUserGetTokenAndSignatureOptions::None,
                                                                     L"GET", L"https://service.example.invalid/api", 0,
                                                                     nullptr, 0, nullptr, &block )
                          : api.XUserGetTokenAndSignatureAsync( user.get(), XUserGetTokenAndSignatureOptions::None,
                                                                "GET", "https://service.example.invalid/api", 0,
                                                                nullptr, 0, nullptr, &block );
            ASSERT_EQ( hr, S_OK );
            auto start = GetTickCount64();
            ASSERT_TRUE( threads->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            EXPECT_LT( GetTickCount64() - start, 200u );
            ASSERT_EQ( threads->XAsyncGetStatus( &block, TRUE ), S_OK );
            SIZE_T size = 0, used = 99;
            ASSERT_EQ( threads->XAsyncGetResultSize( &block, &size ), S_OK );
            std::vector<BYTE> bytes( size + 16, 0x7f );
            if ( wide )
            {
                XUserGetTokenAndSignatureData *wrong = reinterpret_cast<XUserGetTokenAndSignatureData *>( 1 );
                EXPECT_EQ( api.XUserGetTokenAndSignatureResult( &block, size, bytes.data(), &wrong, &used ),
                           E_INVALIDARG );
                EXPECT_EQ( wrong, nullptr );
                EXPECT_EQ( used, 0u );
                XUserGetTokenAndSignatureUtf16Data *result =
                    reinterpret_cast<XUserGetTokenAndSignatureUtf16Data *>( 1 );
                EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Result( &block, size - 1, bytes.data(), &result, &used ),
                           HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) );
                EXPECT_EQ( result, nullptr );
                EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Result( &block, size, bytes.data(), nullptr, &used ),
                           E_POINTER );
                ASSERT_EQ( api.XUserGetTokenAndSignatureUtf16Result( &block, size, bytes.data(), &result, &used ),
                           S_OK );
                ASSERT_NE( result, nullptr );
                EXPECT_EQ( used, size );
                EXPECT_EQ( result->signatureCount, signedRequest ? 105u : 1u );
                ASSERT_NE( result->signature, nullptr );
                EXPECT_EQ( result->signature[result->signatureCount - 1], 0 );
                EXPECT_EQ( wcslen( result->signature ), signedRequest ? 104u : 0u );
                ASSERT_NE( result->token, nullptr );
                EXPECT_EQ( result->token[result->tokenCount - 1], 0 );
                EXPECT_GE( reinterpret_cast<const BYTE *>( result->signature ), bytes.data() );
                EXPECT_LE( reinterpret_cast<const BYTE *>( result->signature + result->signatureCount ),
                           bytes.data() + size );
            }
            else
            {
                XUserGetTokenAndSignatureUtf16Data *wrong = reinterpret_cast<XUserGetTokenAndSignatureUtf16Data *>( 1 );
                EXPECT_EQ( api.XUserGetTokenAndSignatureUtf16Result( &block, size, bytes.data(), &wrong, &used ),
                           E_INVALIDARG );
                EXPECT_EQ( wrong, nullptr );
                EXPECT_EQ( used, 0u );
                XUserGetTokenAndSignatureData *result = reinterpret_cast<XUserGetTokenAndSignatureData *>( 1 );
                EXPECT_EQ( api.XUserGetTokenAndSignatureResult( &block, size - 1, bytes.data(), &result, &used ),
                           HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) );
                EXPECT_EQ( result, nullptr );
                EXPECT_EQ( api.XUserGetTokenAndSignatureResult( &block, size, bytes.data(), nullptr, &used ),
                           E_POINTER );
                ASSERT_EQ( api.XUserGetTokenAndSignatureResult( &block, size, bytes.data(), &result, &used ), S_OK );
                ASSERT_NE( result, nullptr );
                EXPECT_EQ( used, size );
                EXPECT_EQ( result->signatureSize, signedRequest ? 105u : 1u );
                ASSERT_NE( result->signature, nullptr );
                EXPECT_EQ( result->signature[result->signatureSize - 1], 0 );
                EXPECT_EQ( strlen( result->signature ), signedRequest ? 104u : 0u );
                ASSERT_NE( result->token, nullptr );
                EXPECT_EQ( result->token[result->tokenSize - 1], 0 );
                EXPECT_GE( reinterpret_cast<const BYTE *>( result->signature ), bytes.data() );
                EXPECT_LE( reinterpret_cast<const BYTE *>( result->signature + result->signatureSize ),
                           bytes.data() + size );
            }
            for ( SIZE_T i = size; i < bytes.size(); ++i )
                EXPECT_EQ( bytes[i], 0x7f );
            while ( threads->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) )
            {
            }
            threads->XTaskQueueCloseHandle( queue );
            threads->Release();
            // Publication can precede the retained worker returning. Require
            // its original final reference balance after a bounded drain.
            const auto deadline = GetTickCount64() + 5000;
            while ( InterlockedCompareExchange( &user->ref, 0, 0 ) != 1 && GetTickCount64() < deadline )
                Sleep( 1 );
            EXPECT_EQ( InterlockedCompareExchange( &user->ref, 0, 0 ), 1 );
            EXPECT_EQ( transport.unexpected, 0u );
        }
}

static void WINAPI CountTokenCompletion( XAsyncBlock *async )
{
    InterlockedIncrement( static_cast<LONG *>( async->context ) );
}

TEST( NexusAuthentication, TokenAndPictureWorkersPreserveManualDispatchAndCancelledOwnership )
{
    Apartment apartment;
    for ( unsigned mode = 0; mode < 6; ++mode )
    {
        SyntheticTransport transport;
        XUserImpl api( transport );
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1;
        user->initResult = S_OK;
        transport.blockAuthorization = true;
        transport.refuseAuthorization = true;
        IXThreadingImpl *threads = nullptr;
        ASSERT_EQ(
            QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threads ) ),
            S_OK );
        XTaskQueueHandle queue = nullptr;
        ASSERT_EQ( threads->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ),
                   S_OK );
        LONG completions = 0;
        XAsyncBlock block{};
        block.queue = queue;
        block.context = &completions;
        block.callback = CountTokenCompletion;
        auto result = mode >= 4 ? api.XUserGetGamerPictureAsync( user.get(), XUserGamerPictureSize::Medium, &block )
                      : mode & 1
                          ? api.XUserGetTokenAndSignatureUtf16Async( user.get(), XUserGetTokenAndSignatureOptions::None,
                                                                     L"GET", L"https://service.example.invalid/api", 0,
                                                                     nullptr, 0, nullptr, &block )
                          : api.XUserGetTokenAndSignatureAsync( user.get(), XUserGetTokenAndSignatureOptions::None,
                                                                "GET", "https://service.example.invalid/api", 0,
                                                                nullptr, 0, nullptr, &block );
        ASSERT_EQ( result, S_OK );
        auto start = GetTickCount64();
        EXPECT_TRUE( threads->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
        EXPECT_LT( GetTickCount64() - start, 200u );
        EXPECT_EQ( WaitForSingleObject( transport.authorizationEntered, 2000 ), WAIT_OBJECT_0 );
        EXPECT_NE( transport.authorizationThread, GetCurrentThreadId() );
        EXPECT_EQ( threads->XAsyncGetStatus( &block, FALSE ), E_PENDING );
        const bool cancel = mode == 2 || mode == 3 || mode == 5;
        if ( cancel )
        {
            threads->XAsyncCancel( &block );
            // Match the original forced-terminal cleanup contract. Do not
            // claim that ordinary cancellation aborts a network transport.
            threads->XAsyncComplete( &block, E_ABORT, 0 );
            while ( threads->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 ) )
            {
            }
            EXPECT_EQ( threads->XAsyncGetStatus( &block, FALSE ), E_ABORT );
            EXPECT_EQ( InterlockedCompareExchange( &user->ref, 0, 0 ), 2 );
        }
        SetEvent( transport.authorizationContinue );
        start = GetTickCount64();
        while ( ( InterlockedCompareExchange( &user->ref, 0, 0 ) != 1 ||
                  !InterlockedCompareExchange( &completions, 0, 0 ) ) &&
                GetTickCount64() - start < 5000 )
        {
            threads->XTaskQueueDispatch( queue, XTaskQueuePort::Completion, 0 );
            Sleep( 1 );
        }
        EXPECT_EQ( completions, 1 );
        EXPECT_EQ( InterlockedCompareExchange( &user->ref, 0, 0 ), 1 );
        EXPECT_EQ( threads->XAsyncGetStatus( &block, FALSE ), cancel ? E_ABORT : E_FAIL );
        threads->XTaskQueueCloseHandle( queue );
        threads->Release();
        EXPECT_EQ( transport.unexpected, 0u );
    }
}

TEST( NexusAuthentication, SignInRetryKeepsFiveAttemptBoundAndNumericDiagnostics )
{
    for ( bool diagnostics : { false, true } )
        for ( unsigned failures : { 2u, 10u } )
        {
            SyntheticTransport transport;
            transport.defaultFailures = failures;
            XUserImpl api( transport );
            IXThreadingImpl *threads = nullptr;
            ASSERT_EQ( QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ),
                                     reinterpret_cast<void **>( &threads ) ),
                       S_OK );
            XTaskQueueHandle queue = nullptr;
            ASSERT_EQ(
                threads->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ),
                S_OK );
            char directory[MAX_PATH], log[MAX_PATH];
            ASSERT_TRUE( GetTempPathA( sizeof( directory ), directory ) );
            ASSERT_TRUE( GetTempFileNameA( directory, "nau", 0, log ) );
            ASSERT_TRUE( SetEnvironmentVariableA( "XUSER_AUTH_METADATA_LOG", diagnostics ? log : nullptr ) );
            XAsyncBlock block{};
            block.queue = queue;
            ASSERT_EQ( api.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, &block ), S_OK );
            ASSERT_TRUE( threads->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 0 ) );
            const auto expected = failures == 2 ? S_OK : E_ACCESSDENIED;
            EXPECT_EQ( threads->XAsyncGetStatus( &block, TRUE ), expected );
            XUser *user = nullptr;
            EXPECT_EQ( api.XUserAddResult( &block, &user ), expected );
            if ( user )
            {
                EXPECT_EQ( user->xuid, 1234567890123456ull );
                user->Release();
            }
            EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
            EXPECT_EQ( transport.retryMilliseconds, failures == 2 ? 6000u : 12000u );
            EXPECT_EQ( transport.retryCalls, failures == 2 ? 60u : 120u );
            EXPECT_EQ( transport.backendCalls, failures == 2 ? 1u : 0u );
            EXPECT_EQ( transport.unexpected, 0u );
            auto file = CreateFileA( log, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, nullptr );
            ASSERT_NE( file, INVALID_HANDLE_VALUE );
            char bytes[32769]{};
            DWORD count = 0;
            EXPECT_TRUE( ReadFile( file, bytes, sizeof( bytes ) - 1, &count, nullptr ) );
            CloseHandle( file );
            if ( diagnostics )
            {
                EXPECT_NE( strstr( bytes, "phase=init-worker-begin" ), nullptr );
                EXPECT_NE( strstr( bytes, "phase=init-attempt-end" ), nullptr );
                EXPECT_NE( strstr( bytes, "phase=init-retry" ), nullptr );
                EXPECT_NE( strstr( bytes, "phase=init-complete" ), nullptr );
                EXPECT_EQ( strstr( bytes, "synthetic" ), nullptr );
                EXPECT_EQ( strstr( bytes, "https:" ), nullptr );
                EXPECT_LE( count, 32768u );
            }
            else
                EXPECT_EQ( count, 0u );
            SetEnvironmentVariableA( "XUSER_AUTH_METADATA_LOG", nullptr );
            DeleteFileA( log );
            threads->XTaskQueueCloseHandle( queue );
            threads->Release();
        }
}

namespace
{
// A private LOCALAPPDATA and account key, and the backend's decision for this launch.
class OfflineLaunch
{
public:
    explicit OfflineLaunch( const WCHAR *mode, const WCHAR *account = L"0123456789abcdef" )
    {
        WCHAR base[MAX_PATH], name[MAX_PATH];
        GetTempPathW( MAX_PATH, base );
        GetTempFileNameW( base, L"oid", 0, name );
        DeleteFileW( name );
        CreateDirectoryW( name, nullptr );
        root = name;
        SetEnvironmentVariableW( L"LOCALAPPDATA", root.c_str() );
        Account( account );
        Mode( mode );
    }
    ~OfflineLaunch()
    {
        for ( auto account : { L"0123456789abcdef", L"fedcba9876543210" } )
            nexus::user::OfflineIdentityStore( root + L"\\Xodus Nexus\\offline-identity\\" + account ).Remove();
        RemoveDirectoryW( ( root + L"\\Xodus Nexus\\offline-identity" ).c_str() );
        RemoveDirectoryW( ( root + L"\\Xodus Nexus" ).c_str() );
        RemoveDirectoryW( root.c_str() );
        for ( auto name : { L"LOCALAPPDATA", L"XODUS_ACCOUNT_HASH", L"XODUS_OFFLINE_IDENTITY", L"XODUS_FORCE_OFFLINE" } )
            SetEnvironmentVariableW( name, nullptr );
        nexus::user::offlineIdentityInUse = false;
    }
    void Mode( const WCHAR *mode )
    {
        SetEnvironmentVariableW( L"XODUS_OFFLINE_IDENTITY", mode );
    }
    void Account( const WCHAR *account )
    {
        SetEnvironmentVariableW( L"XODUS_ACCOUNT_HASH", account );
    }
    bool Cached( const WCHAR *account = L"0123456789abcdef" ) const
    {
        auto file = root + L"\\Xodus Nexus\\offline-identity\\" + account + L"\\identity.txt";
        return GetFileAttributesW( file.c_str() ) != INVALID_FILE_ATTRIBUTES;
    }
    std::wstring root;
};
const HRESULT Unreachable = HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT );
}

TEST( NexusOfflineIdentity, KeptOnlyWhenTheBackendReportsAFreshOfflineLease )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"store" );
    {
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        EXPECT_TRUE( launch.Cached() );
    }
    // Offline play turned off, or the designation moved to another device: the
    // next online launch carries no offline lease and the identity goes.
    launch.Mode( nullptr );
    {
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        EXPECT_FALSE( launch.Cached() );
    }
    EXPECT_EQ( transport.unexpected, 0u );
}

TEST( NexusOfflineIdentity, SignsInOnlyOnALaunchRunningOnAValidatedOfflineLicense )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"store" );
    {
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    }
    ASSERT_TRUE( launch.Cached() );
    transport.unreachable = true;

    // Without the backend's verdict the cache is never read.
    for ( auto mode : { static_cast<const WCHAR *>( nullptr ), L"store", L"1" } )
    {
        launch.Mode( mode );
        auto user = CreateUser( transport );
        EXPECT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), Unreachable );
        EXPECT_EQ( user->SignInOffline( Unreachable ), Unreachable );
        EXPECT_EQ( user->xuid, 0u );
        EXPECT_FALSE( user->offline );
    }
    EXPECT_TRUE( launch.Cached() );

    launch.Mode( L"use" );
    auto user = CreateUser( transport );
    // Refusals and other failures are never replaced by the cache.
    EXPECT_EQ( user->SignInOffline( E_ACCESSDENIED ), E_ACCESSDENIED );
    EXPECT_EQ( user->xuid, 0u );
    ASSERT_EQ( user->SignInOffline( Unreachable ), S_OK );
    EXPECT_TRUE( user->offline );
    // A prepared but unpublished user (including a cancelled sign-in) must
    // not change connectivity for the current signed-in user.
    EXPECT_FALSE( nexus::user::offlineIdentityInUse );
    EXPECT_EQ( user->xuid, 1234567890123456ull );
    EXPECT_STREQ( user->gamertag, "Synthetic" );
    EXPECT_EQ( user->age_group, XUserAgeGroup::Adult );
    EXPECT_EQ( user->userToken, nullptr );
    // No tokens exist: token requests report Microsoft as unreachable.
    user->initDone = 1;
    user->initResult = S_OK;
    WCHAR *auth = nullptr;
    EXPECT_EQ( user->GetAuthorization( L"https://service.example.invalid/", &auth ), Unreachable );
    EXPECT_EQ( auth, nullptr );
    EXPECT_TRUE( transport.signedBodies.empty() );
    EXPECT_EQ( transport.unexpected, 0u );
}

TEST( NexusOfflineIdentity, AnotherAccountNeverReceivesTheCachedIdentity )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"store" );
    {
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    }
    transport.unreachable = true;
    launch.Mode( L"use" );
    for ( auto account : { L"fedcba9876543210", L"", L"not-a-key" } )
    {
        launch.Account( account );
        auto user = CreateUser( transport );
        EXPECT_EQ( user->SignInOffline( Unreachable ), Unreachable ) << account;
        EXPECT_EQ( user->xuid, 0u );
    }
}

TEST( NexusOfflineIdentity, ConnectivityFollowsOnlyThePublishedUserAndReturnsOnline )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"store" );
    {
        auto seed = CreateUser( transport );
        ASSERT_EQ( seed->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
    }
    ASSERT_TRUE( launch.Cached() );
    XUserImpl users( transport );
    IXThreadingImpl *threading = nullptr;
    ASSERT_EQ( QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ),
                            reinterpret_cast<void **>( &threading ) ), S_OK );
    XTaskQueueHandle queue = nullptr;
    ASSERT_EQ( threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool,
                                          XTaskQueueDispatchMode::Manual, &queue ), S_OK );
    for ( bool offline : { true, false } )
    {
        launch.Mode( offline ? L"use" : L"store" );
        SetEnvironmentVariableW( L"XODUS_FORCE_OFFLINE", offline ? L"1" : nullptr );
        XAsyncBlock async{};
        async.queue = queue;
        ASSERT_EQ( users.XUserAddAsync( XUserAddOptions::AddDefaultUserSilently, &async ), S_OK );
        EXPECT_EQ( threading->XAsyncGetStatus( &async, TRUE ), S_OK );
        XUserHandle user = nullptr;
        ASSERT_EQ( users.XUserAddResult( &async, &user ), S_OK );
        ASSERT_NE( user, nullptr );
        EXPECT_EQ( user->offline, offline );
        EXPECT_EQ( nexus::user::offlineIdentityInUse.load(), offline );
        users.XUserCloseHandle( user );
        EXPECT_EQ( WaitForUserSignInWorkers( 5000 ), S_OK );
    }
    threading->XTaskQueueCloseHandle( queue );
    threading->Release();
}

TEST( NexusOfflineIdentity, AnOfflineLaunchNeverContactsMicrosoft )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"use" );
    SetEnvironmentVariableW( L"XODUS_FORCE_OFFLINE", L"1" );
    auto user = CreateUser( transport );
    EXPECT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), Unreachable );
    EXPECT_EQ( transport.httpCalls, 0u );
    EXPECT_EQ( transport.backendCalls, 0u );
    // Nothing was ever cached for this account, so the sign-in fails closed.
    EXPECT_EQ( user->SignInOffline( Unreachable ), Unreachable );
}

TEST( NexusOfflineIdentity, AStaleIdentityIsNotUsed )
{
    Apartment apartment;
    SyntheticTransport transport;
    OfflineLaunch launch( L"use" );
    auto store = nexus::user::OfflineIdentityStore::ForAccount();
    ASSERT_TRUE( store );
    nexus::user::OfflineIdentity identity{ 1234567890123456ull, static_cast<unsigned>( XUserAgeGroup::Adult ),
                                           nexus::user::FileTimeNow() - nexus::user::OfflineIdentityMaxAge - 1,
                                           "Synthetic", "Synthetic", "", "Synthetic" };
    ASSERT_TRUE( store->Save( identity, SyntheticTransport::Endpoints(), SyntheticTransport::Endpoints() ) );
    auto user = CreateUser( transport );
    EXPECT_EQ( user->SignInOffline( Unreachable ), Unreachable );
    EXPECT_EQ( user->xuid, 0u );
}

TEST( NexusAuthentication, EndpointPathsAcceptRelativeAndAbsoluteServiceMetadata )
{
    Apartment apartment;
    for ( const auto path : { "login", "/login", "login/platform", "/login/platform" } )
    {
        SyntheticTransport transport;
        transport.currentEndpoints = std::string( R"({"EndPoints":[{"Protocol":"https","Host":"*.service.example.invalid","HostType":"wildcard","Path":")" ) + path +
            R"(","RelyingParty":"rp://synthetic-service/","TokenType":"JWT"}]})";
        auto user = CreateUser( transport );
        ASSERT_EQ( user->InitializeNetwork( XUserAddOptions::AddDefaultUserSilently ), S_OK );
        user->initDone = 1; user->initResult = S_OK;
        endpoint info{};
        ASSERT_EQ( user->GetEndpointInfo( "https://auth.service.example.invalid/login/platform/xbox", &info ), S_OK ) << path;
        EXPECT_STREQ( WindowsGetStringRawBuffer( info.relyingParty, nullptr ), L"rp://synthetic-service/" );
        EXPECT_STREQ( WindowsGetStringRawBuffer( info.tokenType, nullptr ), L"JWT" );
        EXPECT_EQ( info.policy, nullptr );
        EXPECT_TRUE( FAILED( user->GetEndpointInfo( "https://auth.service.example.invalid/other/login/platform", &info ) ) );
        EXPECT_TRUE( FAILED( user->GetEndpointInfo( "http://auth.service.example.invalid/login/platform", &info ) ) );
        EXPECT_TRUE( FAILED( user->GetEndpointInfo( "https://auth.foreign.invalid/login/platform", &info ) ) );
    }
}
