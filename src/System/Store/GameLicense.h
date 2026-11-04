// SPDX-License-Identifier: LGPL-2.1-or-later
// Current-game licenses are selected only from verified, unexpired receipts.
// Installation, catalog discovery and sign-in metadata are not license proof.
static HRESULT game_license_from_snapshot( const entitled_snapshot *snapshot, const char *parent,
                                           XStoreGameLicense *out )
{
    if ( !out ) return E_POINTER;
    *out = {};
    const auto now = static_cast<UINT64>( time( nullptr ) );
    if ( !snapshot || !entitled_id( parent ) || snapshot->proof_until <= now ||
         snapshot->count > ENTITLED_MAX_PRODUCTS )
        return E_ACCESSDENIED;
    if ( snapshot->count && !snapshot->products ) return E_ACCESSDENIED;
    const XStoreSku *selected = nullptr;
    UINT64 until = 0;
    bool found = false;
    for ( UINT32 i = 0; i < snapshot->count; ++i )
    {
        const auto &product = snapshot->products[i];
        if ( !product.storeId || strcmp( product.storeId, parent ) ) continue;
        if ( found ) return E_ACCESSDENIED;
        found = true;
        if ( product.productKind != XStoreProductKind::Game || !product.isInUserCollection || !product.skus ||
             product.skusCount > ENTITLED_MAX_SKUS )
            return E_ACCESSDENIED;
        for ( UINT32 j = 0; j < product.skusCount; ++j )
        {
            const auto &sku = product.skus[j];
            if ( !sku.isInUserCollection || sku.isTrial || !entitled_sku_id( sku.skuId ) ||
                 sku.collectionData.endDate <= 0 || static_cast<UINT64>( sku.collectionData.endDate ) <= now )
                continue;
            const auto expiry = std::min( snapshot->proof_until, static_cast<UINT64>( sku.collectionData.endDate ) );
            if ( !selected || expiry > until )
            {
                selected = &sku;
                until = expiry;
            }
        }
    }
    if ( !selected || until > static_cast<UINT64>( INT64_MAX ) ) return E_ACCESSDENIED;
    snprintf( out->skuStoreId, sizeof( out->skuStoreId ), "%s/%s", parent, selected->skuId );
    out->isActive = TRUE;
    out->expirationDate = static_cast<INT64>( until );
    return S_OK;
}
