// SPDX-License-Identifier: MIT
// Synthetic regression coverage for the explicit IXGameSaveImpl3 legacy view.
#include <gtest/gtest.h>
#include "../../src/System/XGameSave.h"
#include "../../src/System/User/XUser.h"
#include "../../src/Runtime/Configuration.h"
#include <cstring>
#include <memory>
#include <string>

namespace
{
class OfflineTransport final : public UserTransport
{
public:
    HRESULT Backend( UINT16, const char *, UINT16, char **out, UINT16 *size ) override
    {
        *out = nullptr;
        *size = 0;
        return E_ACCESSDENIED;
    }
    HRESULT Http( const WCHAR *, const WCHAR *, char *, const WCHAR *, const WCHAR **, BYTE **out,
                  SIZE_T *size ) override
    {
        *out = nullptr;
        *size = 0;
        return E_ACCESSDENIED;
    }
    HRESULT HttpRaw( const WCHAR *, const WCHAR *, const WCHAR *, const void *, DWORD, DWORD *status, BYTE **out,
                     SIZE_T *size ) override
    {
        *status = 403;
        *out = nullptr;
        *size = 0;
        return E_ACCESSDENIED;
    }
};

struct LegacyExtensionProbe : IXGameSaveImpl3
{
    virtual HRESULT WINAPI Unknown0( void *, void *, void *, void * ) = 0;
};

constexpr char validScid[] = "12345678-1234-5678-9abc-def012345678";
constexpr char explicitScid[] = "87654321-4321-8765-cba9-876543210fed";

class LegacyIid3Fixture : public testing::Test
{
protected:
    OfflineTransport transport;
    XUser *user = nullptr;
    IXGameSaveImpl3 *legacy = nullptr;
    IXGameSaveImpl *flat = nullptr;
    IXThreadingImpl *threading = nullptr;
    XTaskQueueHandle queue = nullptr;
    XGameSaveProviderHandle provider = nullptr;

    static void SetUpTestSuite()
    {
        static const auto initialized = []
        {
            InitializeLogging();
            return true;
        }();
        (void)initialized;
        static const char *xml = "<Game><TitleId>0x1234</TitleId><SaveGameStorage><SCID>"
                                 "12345678-1234-5678-9abc-def012345678</SCID></SaveGameStorage></Game>";
        INITIALIZE_OPTIONS options{ 1, TRUE, xml };
        ASSERT_EQ( nexus::InitializeGameConfiguration( &options ), S_OK );
    }

    void SetUp() override
    {
        const auto *config = nexus::GetGameConfiguration();
        ASSERT_NE( config, nullptr );
        std::string scid;
        ASSERT_EQ( nexus::GetGameScid( *config, scid ), S_OK );
        EXPECT_EQ( scid, validScid );
        user = new XUser( transport );
        user->ref = 1;
        user->xuid = 42;
        user->initDone = 1;
        user->initResult = S_OK;
        ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl3 ),
                                 reinterpret_cast<void **>( &legacy ) ),
                   S_OK );
        ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl ),
                                 reinterpret_cast<void **>( &flat ) ),
                   S_OK );
        ASSERT_EQ( QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ),
                                 reinterpret_cast<void **>( &threading ) ),
                   S_OK );
        ASSERT_EQ( threading->XTaskQueueCreate( XTaskQueueDispatchMode::Manual, XTaskQueueDispatchMode::Manual, &queue ),
                   S_OK );
    }

    void TearDown() override
    {
        if ( provider ) legacy->XGameSaveCloseProvider( provider );
        if ( queue ) threading->XTaskQueueCloseHandle( queue );
        if ( threading ) threading->Release();
        if ( flat ) flat->Release();
        if ( legacy ) legacy->Release();
        if ( user ) user->Release();
    }
};
}

TEST( NexusScidReader, ReadsOnlyTrimmedWellFormedCurrentManifestScid )
{
    for ( const char *value : { "12345678-1234-5678-9abc-def012345678",
                                " 12345678-1234-5678-9ABC-DEF012345678\r\n" } )
    {
        nexus::GameConfiguration config;
        ASSERT_EQ( nexus::ParseXml( std::string( "<Game><SaveGameStorage><SCID>" ) + value +
                                        "</SCID></SaveGameStorage></Game>",
                                    config.game ),
                   S_OK );
        std::string scid;
        ASSERT_EQ( nexus::GetGameScid( config, scid ), S_OK );
        EXPECT_EQ( scid.size(), 36u );
    }
    for ( const char *value : { "", " ", "12345678123456789abcdef012345678",
                                "12345678-1234-5678-9abc-def01234567",
                                "12345678-1234-5678-9abc-def01234567g",
                                "{12345678-1234-5678-9abc-def012345678}" } )
    {
        nexus::GameConfiguration config;
        ASSERT_EQ( nexus::ParseXml( std::string( "<Game><SaveGameStorage><SCID>" ) + value +
                                        "</SCID></SaveGameStorage></Game>",
                                    config.game ),
                   S_OK );
        std::string scid;
        EXPECT_EQ( nexus::GetGameScid( config, scid ), E_INVALIDARG ) << value;
    }
    nexus::GameConfiguration missing;
    ASSERT_EQ( nexus::ParseXml( "<Game><SaveGameStorage/></Game>", missing.game ), S_OK );
    std::string scid;
    EXPECT_EQ( nexus::GetGameScid( missing, scid ), E_INVALIDARG );
}

TEST_F( LegacyIid3Fixture, Iid3NullConfigurationUsesManifestScidAndExplicitFlatNullStillRejects )
{
    XAsyncBlock flatAsync{};
    flatAsync.queue = queue;
    EXPECT_EQ( flat->XGameSaveInitializeProviderAsync( user, nullptr, FALSE, &flatAsync ), E_INVALIDARG );
    XAsyncBlock async{};
    async.queue = queue;
    ASSERT_EQ( legacy->XGameSaveInitializeProviderAsync( user, nullptr, FALSE, &async ), S_OK );
    ASSERT_TRUE( threading->XTaskQueueDispatch( queue, XTaskQueuePort::Work, 5000 ) );
    ASSERT_EQ( threading->XAsyncGetStatus( &async, TRUE ), S_OK );
    ASSERT_EQ( legacy->XGameSaveInitializeProviderResult( &async, &provider ), S_OK );
    ASSERT_NE( provider, nullptr );
    XGameSaveProviderHandle fromOwner = nullptr;
    EXPECT_EQ( legacy->XGameSaveInitializeProvider( user, explicitScid, FALSE, &fromOwner ), S_OK );
    ASSERT_NE( fromOwner, nullptr );
    char local[2048]{};
    ASSERT_GT( GetEnvironmentVariableA( "LOCALAPPDATA", local, sizeof( local ) ), 0u );
    const std::string explicitRoot = std::string( local ) + "\\XodusGameSave\\42\\" + explicitScid;
    const DWORD explicitAttributes = GetFileAttributesA( explicitRoot.c_str() );
    EXPECT_NE( explicitAttributes, INVALID_FILE_ATTRIBUTES );
    EXPECT_TRUE( ( explicitAttributes & FILE_ATTRIBUTE_DIRECTORY ) != 0 );
    legacy->XGameSaveCloseProvider( fromOwner );
}

TEST_F( LegacyIid3Fixture, DistinctOwnersHaveDistinctStableViewsAndCanonicalIdentity )
{
    std::unique_ptr<XGameSaveImpl> second( new XGameSaveImpl );
    IXGameSaveImpl3 *other = nullptr, *otherAgain = nullptr;
    ASSERT_EQ( second->QueryInterface( __uuidof( IXGameSaveImpl3 ), reinterpret_cast<void **>( &other ) ), S_OK );
    ASSERT_EQ( second->QueryInterface( __uuidof( IXGameSaveImpl3 ), reinterpret_cast<void **>( &otherAgain ) ), S_OK );
    EXPECT_EQ( other, otherAgain );
    EXPECT_NE( legacy, other );

    IUnknown *firstUnknown = nullptr, *secondUnknown = nullptr;
    ASSERT_EQ( legacy->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &firstUnknown ) ), S_OK );
    ASSERT_EQ( other->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &secondUnknown ) ), S_OK );
    EXPECT_NE( firstUnknown, secondUnknown );

    IXGameSaveImpl4 *firstOwner = nullptr, *secondOwner = nullptr;
    ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl4 ),
                             reinterpret_cast<void **>( &firstOwner ) ),
               S_OK );
    ASSERT_EQ( second->QueryInterface( __uuidof( IXGameSaveImpl4 ), reinterpret_cast<void **>( &secondOwner ) ), S_OK );
    EXPECT_NE( firstOwner, secondOwner );
    EXPECT_EQ( firstUnknown, static_cast<IUnknown *>( firstOwner ) );
    EXPECT_EQ( secondUnknown, static_cast<IUnknown *>( secondOwner ) );

    const ULONG added = other->AddRef();
    EXPECT_GE( added, 1u );
    EXPECT_EQ( other->Release(), added - 1 );
    firstUnknown->Release();
    secondUnknown->Release();
    firstOwner->Release();
    secondOwner->Release();
    other->Release();
    other->Release();
}

TEST_F( LegacyIid3Fixture, LegacyViewKeepsDefensiveExtensionSlotHonest )
{
    auto *probe = reinterpret_cast<LegacyExtensionProbe *>( legacy );
    EXPECT_EQ( probe->Unknown0( nullptr, nullptr, nullptr, nullptr ), E_NOTIMPL );
}

TEST_F( LegacyIid3Fixture, RepeatedIid3ReturnsSameViewWhileOtherInterfacesStayOnOwner )
{
    IXGameSaveImpl3 *again = nullptr;
    ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl3 ),
                             reinterpret_cast<void **>( &again ) ),
               S_OK );
    EXPECT_EQ( legacy, again );
    IUnknown *unknown = nullptr;
    ASSERT_EQ( legacy->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &unknown ) ), S_OK );
    IXGameSaveImpl4 *four = nullptr;
    ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl4 ),
                             reinterpret_cast<void **>( &four ) ),
               S_OK );
    EXPECT_EQ( unknown, static_cast<IUnknown *>( four ) );
    unknown->Release();
    four->Release();
    const ULONG added = legacy->AddRef();
    EXPECT_GE( added, 1u );
    EXPECT_EQ( legacy->Release(), added - 1 );
}
