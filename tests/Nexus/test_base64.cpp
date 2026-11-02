// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "../../src/private.h"
#include "../../src/HttpClient.h"
#include <string>
#include <vector>

namespace
{
template <typename Char>
void CheckEncoding( HRESULT ( *encode )( UINT32, const BYTE *, UINT32, Char *, BOOLEAN ), const char *binaryExpected )
{
    const Char sentinel = static_cast<Char>( '!' );
    const BYTE binary[] = { 0xfb, 0xff, 0xff };
    Char binaryOut[5] = { sentinel, sentinel, sentinel, sentinel, sentinel };
    ASSERT_EQ( encode( 3, binary, 4, binaryOut, TRUE ), S_OK );
    for ( unsigned i = 0; i < 4; i++ ) EXPECT_EQ( binaryOut[i], binaryExpected[i] );
    EXPECT_EQ( binaryOut[4], sentinel );

    for ( UINT32 length = 0; length <= 64; length++ )
    {
        const std::vector<BYTE> input( length, 'A' );
        std::string text;
        for ( UINT32 i = 0; i < length / 3; i++ ) text += "QUFB";
        if ( length % 3 == 1 ) text += "QQ";
        if ( length % 3 == 2 ) text += "QUE";
        for ( BOOLEAN pad : { FALSE, TRUE } )
        {
            auto expected = text;
            if ( pad ) while ( expected.size() % 4 ) expected += '=';
            const UINT32 needed = static_cast<UINT32>( expected.size() );
            for ( UINT32 capacity = needed ? needed - 1 : 0; capacity <= needed + 1; capacity++ )
            {
                SCOPED_TRACE( testing::Message() << "length=" << length << " pad=" << unsigned( pad )
                                                << " capacity=" << capacity );
                std::vector<Char> output( needed + 3, sentinel );
                HRESULT hr = encode( length, input.data(), capacity, output.data(), pad );
                if ( capacity < needed )
                {
                    ASSERT_EQ( hr, HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) );
                    for ( Char value : output ) EXPECT_EQ( value, sentinel );
                }
                else
                {
                    ASSERT_EQ( hr, S_OK );
                    for ( UINT32 i = 0; i < needed; i++ ) EXPECT_EQ( output[i], expected[i] );
                    for ( UINT32 i = needed; i < output.size(); i++ ) EXPECT_EQ( output[i], sentinel );
                }
            }
        }
    }
    // Reject an unrepresentable output before dereferencing the input. The
    // advertised maximum capacity must not make UINT32 arithmetic wrap.
    for ( UINT32 length : { 0xc0000000u, 0xfffffffeu, 0xffffffffu } )
        for ( BOOLEAN pad : { FALSE, TRUE } )
        {
            Char out = sentinel;
            EXPECT_EQ( encode( length, nullptr, MAXDWORD, &out, pad ),
                       HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) );
            EXPECT_EQ( out, sentinel );
        }
}
}

TEST( Base64, StandardEncodingRespectsCapacity ) { CheckEncoding( encode_base64, "+///" ); }
TEST( Base64, UrlEncodingRespectsCapacity ) { CheckEncoding( encode_base64_url, "-___" ); }
TEST( Base64, WideEncodingRespectsCapacity ) { CheckEncoding( encode_base64_utf16, "+///" ); }
