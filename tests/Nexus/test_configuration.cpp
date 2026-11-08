// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "../../src/private.h"
#include "../../src/Runtime/Configuration.h"
#include "../../src/Runtime/TitleIdentityDiagnostics.h"
#include <atomic>
#include <fstream>
#include <iterator>
#include <thread>
#include <vector>

TEST( NexusXml, CommentsCdataEntitiesAndUtf8 )
{
    nexus::XmlNode root;
    ASSERT_EQ( nexus::ParseXml( "<?xml version=\"1.0\"?><Game><!-- <Identity Name='Wrong'/> --><Value "
                                "attr='A&amp;B'>A&amp;B<![CDATA[<real>]]>č</Value></Game>",
                                root ),
               S_OK );
    EXPECT_EQ( root.name, "Game" );
    ASSERT_EQ( root.children.size(), 1u );
    EXPECT_EQ( root.children[0].text, "A&B<real>č" );
    EXPECT_EQ( root.children[0].attribute( "attr" ), "A&B" );
}
TEST( NexusXml, RejectsMalformedWithoutPartialPublication )
{
    for ( auto xml :
          { "", "<Game>", "<Game/><Game/>", "<Game><A></B></Game>", "<Game a='1' a='2'/>", "<Game>&missing;</Game>" } )
    {
        nexus::XmlNode root;
        root.name = "untouched";
        EXPECT_TRUE( FAILED( nexus::ParseXml( xml, root ) ) ) << xml;
        EXPECT_EQ( root.name, "untouched" );
    }
}
TEST( NexusXml, ProhibitsDtdAndExternalEntities )
{
    for ( auto xml : { "<!DOCTYPE Game [<!ENTITY x 'substitution'>]><Game>&x;</Game>",
                       "<!DOCTYPE Game SYSTEM 'http://127.0.0.1:9/no-network'><Game/>",
                       "<!DOCTYPE Game [<!ENTITY x SYSTEM 'file:///C:/no-private-files'>]><Game>&x;</Game>" } )
    {
        nexus::XmlNode root;
        EXPECT_TRUE( FAILED( nexus::ParseXml( xml, root ) ) );
    }
}
TEST( NexusXml, EnforcesDocumentAndTreeBounds )
{
    nexus::XmlNode root;
    EXPECT_TRUE( FAILED( nexus::ParseXml( std::string( 4 * 1024 * 1024 + 1, 'x' ), root ) ) );
    std::string deep;
    for ( int i = 0; i < 70; ++i )
        deep += "<A>";
    for ( int i = 0; i < 70; ++i )
        deep += "</A>";
    EXPECT_TRUE( FAILED( nexus::ParseXml( deep, root ) ) );
    std::string wide = "<Game>";
    for ( int i = 0; i < 16385; ++i )
        wide += "<A/>";
    wide += "</Game>";
    EXPECT_TRUE( FAILED( nexus::ParseXml( wide, root ) ) );
}
TEST( NexusXml, ConvertsUtf8WithoutLossOrSilentReplacement )
{
    std::wstring wide;
    std::string text;
    ASSERT_EQ( nexus::ToUtf16( "Příliš červený", wide ), S_OK );
    ASSERT_EQ( nexus::ToUtf8( wide, text ), S_OK );
    EXPECT_EQ( text, "Příliš červený" );
    EXPECT_TRUE( FAILED( nexus::ToUtf16( std::string_view( "\xff", 1 ), wide ) ) );
    EXPECT_TRUE( FAILED( nexus::ToUtf8( std::wstring( 1, 0xd800 ), text ) ) );
}
TEST( NexusConfiguration, DerivesRealPackageFamilyWithoutIdentitySubstitution )
{
    std::string result;
    ASSERT_EQ( nexus::GetPackageFamilyName(
                   "Microsoft.WindowsCalculator",
                   "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", result ),
               S_OK );
    EXPECT_EQ( result, "Microsoft.WindowsCalculator_8wekyb3d8bbwe" );
    std::string second;
    ASSERT_EQ( nexus::GetPackageFamilyName( "Microsoft.WindowsCalculator", "CN=DifferentPublisher", second ), S_OK );
    EXPECT_NE( result, second );
    for ( auto name : { "", "..", "../elsewhere", "C:\\elsewhere", "directory/file", "a:b" } )
        EXPECT_TRUE( FAILED( nexus::GetPackageFamilyName( name, "CN=Publisher", result ) ) );
}
TEST( NexusConfiguration, LegacyFullTrustUsesOnlyExplicitSchemaZeroWithoutTitleClientSubstitution )
{
    nexus::GameConfiguration config;
    config.fullTrust = true;
    for ( auto schema : { "", "1", "2", "00", "0suffix", "-1" } )
    {
        config.game.attributes = { { "configVersion", schema } };
        EXPECT_FALSE( nexus::UsesLegacyFullTrust( config ) );
    }
    config.game.attributes = { { "configVersion", "0" } };
    EXPECT_TRUE( nexus::UsesLegacyFullTrust( config ) );
    EXPECT_TRUE( config.msaAppId.empty() );
    config.fullTrust = false;
    EXPECT_FALSE( nexus::UsesLegacyFullTrust( config ) );
    config.fullTrust = true;
    config.msaAppId = "actual-explicit-client";
    EXPECT_FALSE( nexus::UsesLegacyFullTrust( config ) );
    EXPECT_EQ( config.msaAppId, "actual-explicit-client" );
}
TEST( NexusConfiguration, FailedInitializationIsRetryableThenPublishesAtomically )
{
    ASSERT_EQ( nexus::GetGameConfiguration(), nullptr );
    const char *invalid[] = {
        "<invalid>",
        "<Wrong/>",
        "<Game><TitleId>not-hex</TitleId></Game>",
        "<Game><Identity Name='../bad' Publisher='CN=A'/></Game>",
        "<Game><RelatedProducts><RelatedProduct>invalid</RelatedProduct></RelatedProducts></Game>",
        "<!DOCTYPE Game [<!ENTITY x 'x'>]><Game>&x;</Game>" };
    for ( auto xml : invalid )
    {
        INITIALIZE_OPTIONS options{ 1, TRUE, xml };
        EXPECT_EQ( nexus::InitializeGameConfiguration( &options ), E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT );
        EXPECT_EQ( nexus::GetGameConfiguration(), nullptr );
    }
    INITIALIZE_OPTIONS missing{ 1, TRUE, nullptr };
    EXPECT_EQ( nexus::InitializeGameConfiguration( &missing ), E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT );
    ASSERT_TRUE( SetEnvironmentVariableA( "NEXUS_RELATED_PRODUCT_IDS", "9AAAAAAAAAAA,9BBBBBBBBBBB,9AAAAAAAAAAA" ) );
    const char *xml =
        "<Game><Identity Name='Nexus.Test' Publisher='CN=Publisher'/><TitleId> 0x1234\n</TitleId>"
        "<MSAAppId>real-app-input</MSAAppId><StoreId>9CCCCCCCCCCC</StoreId><MSAFullTrust>true</MSAFullTrust>"
        "<RelatedProducts><RelatedProduct>9AAAAAAAAAAA</RelatedProduct></RelatedProducts></Game>";
    INITIALIZE_OPTIONS options{ 1, TRUE, xml };
    std::atomic<int> failed{ 0 };
    std::vector<std::thread> threads;
    for ( int i = 0; i < 12; ++i )
        threads.emplace_back(
            [&]
            {
                if ( nexus::InitializeGameConfiguration( &options ) != S_OK ) ++failed;
                const auto *current = nexus::GetGameConfiguration();
                if ( !current || current->titleId != 0x1234 || current->msaAppId != "real-app-input" ||
                     current->relatedProducts.size() != 2 )
                    ++failed;
            } );
    for ( auto &thread : threads )
        thread.join();
    ASSERT_EQ( failed.load(), 0 );
    const auto *current = nexus::GetGameConfiguration();
    ASSERT_NE( current, nullptr );
    EXPECT_EQ( current->storeId, "9CCCCCCCCCCC" );
    EXPECT_TRUE( current->fullTrust );
    EXPECT_TRUE( current->packageFamilyName.starts_with( "Nexus.Test_" ) );
    EXPECT_EQ( current->relatedProducts[1], "9BBBBBBBBBBB" );
    EXPECT_EQ( nexus::InitializeGameConfiguration( &missing ), S_OK );
    EXPECT_EQ( nexus::GetGameConfiguration(), current );
    SetEnvironmentVariableA( "NEXUS_RELATED_PRODUCT_IDS", nullptr );
}

TEST( NexusConfiguration, InheritedSaveConfigurationRoundTripPreservesActualManifestValues )
{
    nexus::XmlNode original, reloaded;
    std::string bytes;
    ASSERT_EQ( nexus::ParseXml( "<Game><Identity Name='Nexus.Test' Publisher='CN=Test &amp; "
                                "Sons'/><MSAAppId>test-app</MSAAppId><TitleId>0x1234</TitleId><MSAFullTrust>true</"
                                "MSAFullTrust><Description>Text &lt; &amp; &quot;quoted&quot;</Description></Game>",
                                original ),
               S_OK );
    ASSERT_EQ( nexus::SerializeXml( original, bytes ), S_OK );
    ASSERT_EQ( nexus::ParseXml( bytes, reloaded ), S_OK );
    EXPECT_EQ( reloaded.name, original.name );
    ASSERT_EQ( reloaded.children.size(), original.children.size() );
    for ( size_t i = 0; i < original.children.size(); ++i )
    {
        EXPECT_EQ( reloaded.children[i].name, original.children[i].name );
        EXPECT_EQ( reloaded.children[i].text, original.children[i].text );
        EXPECT_EQ( reloaded.children[i].attributes, original.children[i].attributes );
    }
}
TEST( NexusConfiguration, InheritedConfigurationRejectsInvalidOrDuplicateXmlNames )
{
    nexus::XmlNode root;
    root.name = "<!DOCTYPE malicious>";
    std::string bytes;
    EXPECT_EQ( nexus::SerializeXml( root, bytes ), E_INVALIDARG );
    EXPECT_TRUE( bytes.empty() );
    root.name = "Game";
    root.attributes = { { "Name", "one" }, { "Name", "two" } };
    EXPECT_EQ( nexus::SerializeXml( root, bytes ), E_INVALIDARG );
    EXPECT_TRUE( bytes.empty() );
}

TEST( NexusConfiguration, TitleIdentityDiagnosticsAreBoundedSanitizedAndOptIn )
{
    SetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", nullptr );
    EXPECT_FALSE( nexus::title_identity::Enabled() );
    WCHAR temp[MAX_PATH], path[MAX_PATH];
    ASSERT_GT( GetTempPathW( MAX_PATH, temp ), 0u );
    ASSERT_GT( GetTempFileNameW( temp, L"tid", 0, path ), 0u );
    std::string logPath;
    ASSERT_EQ( nexus::ToUtf8( path, logPath ), S_OK );
    nexus::GameConfiguration config;
    config.configSource = nexus::GameConfigSource::Default;
    config.titleId = 0x1234;
    config.game.attributes = { { "configVersion", "0" } };
    config.directory = L"Z:\\Nexus\\DiagnosticGate";
    nexus::title_identity::WriteConfig( config );
    config.directory.clear();
    {
        std::ifstream file( path, std::ios::binary );
        ASSERT_TRUE( file.good() );
        std::string empty( ( std::istreambuf_iterator<char>( file ) ), std::istreambuf_iterator<char>() );
        EXPECT_TRUE( empty.empty() );
    }
    std::string overlong( MAX_PATH + 1, 'a' );
    ASSERT_TRUE( SetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", overlong.c_str() ) );
    EXPECT_FALSE( nexus::title_identity::Enabled() );
    nexus::title_identity::WriteConfig( config );
    {
        std::ifstream file( path, std::ios::binary );
        ASSERT_TRUE( file.good() );
        std::string empty( ( std::istreambuf_iterator<char>( file ) ), std::istreambuf_iterator<char>() );
        EXPECT_TRUE( empty.empty() );
    }
    ASSERT_TRUE( SetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", logPath.c_str() ) );
    EXPECT_TRUE( nexus::title_identity::Enabled() );
    config.msaAppId = "0000000040159362";
    config.msaAppIdSource = nexus::MsaAppIdSource::Explicit;
    nexus::title_identity::WriteConfig( config );
    config.msaAppId = "not-a-client/path";
    config.msaAppIdSource = nexus::MsaAppIdSource::Explicit;
    config.game.attributes = { { "configVersion", "0\nXUID=1" } };
    nexus::title_identity::WriteConfig( config );
    nexus::title_identity::WriteBinding( &config, E_INVALIDARG, 0, "malformed" );
    nexus::title_identity::WriteBinding( &config, S_OK, 0x9999, "mismatch" );
    for ( int i = 0; i < 500; ++i ) nexus::title_identity::WriteConfig( config );
    std::ifstream file( path, std::ios::binary );
    ASSERT_TRUE( file.good() );
    std::string log( ( std::istreambuf_iterator<char>( file ) ), std::istreambuf_iterator<char>() );
    EXPECT_LE( log.size(), 32768u );
    EXPECT_NE( log.find( "TITLE_IDENTITY_CONFIG source=default version=0 title=00001234 msa=0000000040159362 "
                         "client=explicit legacy_root=none legacy_exe=missing" ),
               std::string::npos );
    EXPECT_NE( log.find( "TITLE_IDENTITY_CONFIG source=default version=invalid title=00001234 msa=invalid "
                         "client=explicit legacy_root=none legacy_exe=missing" ),
               std::string::npos );
    EXPECT_EQ( log.find( "not-a-client" ), std::string::npos );
    EXPECT_EQ( log.find( "XUID=1" ), std::string::npos );
    EXPECT_NE( log.find( "TITLE_IDENTITY_BINDING source=default client=explicit claim_hr=80070057 claimed=none "
                         "binding=malformed" ),
               std::string::npos );
    EXPECT_NE( log.find( "TITLE_IDENTITY_BINDING source=default client=explicit claim_hr=00000000 claimed=39321 "
                         "binding=mismatch" ),
               std::string::npos );
    SetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", nullptr );
    DeleteFileW( path );
}
