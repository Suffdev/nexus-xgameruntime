// SPDX-License-Identifier: MIT
// Invalid current-manifest SCID must fail before the IID3 compatibility view
// reaches the shared real provider path. No valid fallback is invented.
#include <gtest/gtest.h>
#include "../../src/System/XGameSave.h"
#include "../../src/Runtime/Configuration.h"
#include <cstdint>
#include <string>

TEST( NexusLegacyIid3InvalidConfig, InvalidManifestScidRejectsNullLegacyInitialization )
{
    static const auto initialized = []
    {
        InitializeLogging();
        static const char *xml = "<Game><TitleId>0x1234</TitleId><SaveGameStorage><SCID>not-a-guid</SCID>"
                                 "</SaveGameStorage></Game>";
        INITIALIZE_OPTIONS options{ 1, TRUE, xml };
        return nexus::InitializeGameConfiguration( &options );
    }();
    ASSERT_EQ( initialized, S_OK );
    const auto *config = nexus::GetGameConfiguration();
    ASSERT_NE( config, nullptr );
    std::string scid = "sentinel";
    EXPECT_EQ( nexus::GetGameScid( *config, scid ), E_INVALIDARG );
    EXPECT_TRUE( scid.empty() );
    IXGameSaveImpl3 *legacy = nullptr;
    ASSERT_EQ( QueryApiImpl( CLSID_XGameSaveImpl, __uuidof( IXGameSaveImpl3 ),
                             reinterpret_cast<void **>( &legacy ) ),
               S_OK );
    XGameSaveProviderHandle provider = reinterpret_cast<XGameSaveProviderHandle>( static_cast<uintptr_t>( 1 ) );
    EXPECT_EQ( legacy->XGameSaveInitializeProvider( nullptr, nullptr, FALSE, &provider ), E_INVALIDARG );
    EXPECT_EQ( provider, nullptr );
    legacy->Release();
}
