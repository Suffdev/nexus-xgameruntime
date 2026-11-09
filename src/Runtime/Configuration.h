// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "Xml.h"
#include <xgameruntimeinit.h>

namespace nexus
{
enum class GameConfigSource
{
    Default,
    Inline,
    File,
};

enum class MsaAppIdSource
{
    None,
    Explicit,
    Legacy,
};

struct GameConfiguration
{
    XmlNode game;
    std::string msaAppId, storeId, packageFamilyName;
    UINT32 titleId = 0;
    bool fullTrust = false;
    std::wstring directory;
    std::vector<std::string> relatedProducts;
    GameConfigSource configSource = GameConfigSource::Default;
    MsaAppIdSource msaAppIdSource = MsaAppIdSource::None;
};
inline bool UsesLegacyFullTrust( const GameConfiguration &config ) noexcept
{
    return config.fullTrust && config.msaAppId.empty() && config.game.attribute( "configVersion" ) == "0";
}
HRESULT InitializeGameConfiguration( const INITIALIZE_OPTIONS *options ) noexcept;
const GameConfiguration *GetGameConfiguration() noexcept;
// Narrow current-package SCID reader for the explicit legacy IID3 compatibility
// view. It uses the already parsed immutable manifest; no second file search.
HRESULT GetGameScid( const GameConfiguration &config, std::string &scid ) noexcept;
HRESULT GetGameScid( std::string &scid ) noexcept;
HRESULT GetPackageFamilyName( std::string_view name, std::string_view publisher, std::string &result ) noexcept;
}
