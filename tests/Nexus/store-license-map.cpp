// SPDX-License-Identifier: LGPL-2.1-or-later
// Account-free projection tests. Synthetic records never reach the transport.
// clang-format off
#define INITGUID
#include "../../src/private.h"
#include <xstore.h>
#include <cstdio>
#include <ctime>
#include "../../src/System/Store/StoreContext.h"
// clang-format on
namespace nexus_store_context
{
static HRESULT query_game_license(XStoreGameLicense *out, const std::atomic<bool> &, HANDLE)
{
    *out = {};
    return E_ACCESSDENIED;
}
static HRESULT query_addon_licenses(AddonLicenseSnapshot *out)
{
    *out = {};
    return E_ACCESSDENIED;
}
} // namespace nexus_store_context
using namespace nexus_store_context;
static unsigned checks, failures;
#define CHECK(e)                                                                                                  \
    do                                                                                                            \
    {                                                                                                             \
        ++checks;                                                                                                 \
        if (!(e))                                                                                                 \
        {                                                                                                         \
            ++failures;                                                                                           \
            printf("FAIL line=%d\n", __LINE__);                                                                   \
        }                                                                                                         \
    } while (0)
static AddonLicenseSnapshot fixture()
{
    AddonLicenseSnapshot value;
    value.proof_until = std::time(nullptr) + 120;
    value.licenses = {{"B00000000001/0001", "first", std::time(nullptr) + 60},
                      {"B00000000002/0002", "second", std::time(nullptr) + 90}};
    return value;
}
static bool text(HSTRING s, const WCHAR *expected)
{
    UINT32 n;
    const WCHAR *p = WindowsGetStringRawBuffer(s, &n);
    return n == wcslen(expected) && !wmemcmp(p, expected, n);
}
static IJsonObject *parse_json(HSTRING input)
{
    HSTRING name = nullptr;
    IJsonValueStatics *factory = nullptr;
    IJsonValue *value = nullptr;
    IJsonObject *object = nullptr;
    HRESULT hr = WindowsCreateString(RuntimeClass_Windows_Data_Json_JsonValue,
                                     wcslen(RuntimeClass_Windows_Data_Json_JsonValue), &name);
    if (SUCCEEDED(hr))
        hr = RoGetActivationFactory(name, __uuidof(IJsonValueStatics), (void **)&factory);
    if (SUCCEEDED(hr))
        hr = factory->Parse(input, &value);
    if (SUCCEEDED(hr))
        hr = value->GetObject(&object);
    CHECK(SUCCEEDED(hr) && object);
    if (value)
        value->Release();
    if (factory)
        factory->Release();
    WindowsDeleteString(name);
    return object;
}
static bool json_text(IJsonObject *object, const WCHAR *field, const std::wstring &expected)
{
    HSTRING key = nullptr, value = nullptr;
    HRESULT hr = WindowsCreateString(field, wcslen(field), &key);
    if (SUCCEEDED(hr))
        hr = object->GetNamedString(key, &value);
    UINT32 length = 0;
    const WCHAR *raw = WindowsGetStringRawBuffer(value, &length);
    bool match = SUCCEEDED(hr) && length == expected.size() && !wmemcmp(raw, expected.data(), length);
    WindowsDeleteString(key);
    WindowsDeleteString(value);
    return match;
}
static void json_checks()
{
    auto shared = std::make_shared<AddonLicenseSnapshot>(fixture());
    // Native WinRT parser validates independent JSON syntax and string round-trip.
    shared->licenses[0].offer =
        std::string("quote\" slash\\ line\n tab\t control\1 nul") + std::string(1, '\0') + "\xc5\xbe";
    const std::string &offer = shared->licenses[0].offer;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, offer.data(), offer.size(), nullptr, 0);
    std::wstring expected(count, L' ');
    CHECK(count > 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, offer.data(), offer.size(),
                                           expected.data(), count) == count);
    IAddonLicense *license = new AddonLicense(shared, 0);
    CHECK(license->Json(nullptr) == E_POINTER);
    HSTRING json = nullptr;
    CHECK(license->Json(&json) == S_OK && json);
    IJsonObject *object = parse_json(json);
    if (object)
    {
        CHECK(json_text(object, L"productId", L"B00000000001"));
        CHECK(json_text(object, L"skuId", L"0001"));
        CHECK(json_text(object, L"productType", L"Durable"));
        CHECK(json_text(object, L"skuType", L"Full"));
        CHECK(json_text(object, L"inAppOfferToken", expected));
        HSTRING key = nullptr;
        boolean active = false;
        WindowsCreateString(L"isActive", 8, &key);
        CHECK(object->GetNamedBoolean(key, &active) == S_OK && active);
        WindowsDeleteString(key);
        INT64 expiration = 0;
        CHECK(license->Expiration(&expiration) == S_OK);
        ULARGE_INTEGER ticks;
        ticks.QuadPart = expiration;
        FILETIME ft = {ticks.LowPart, ticks.HighPart};
        SYSTEMTIME date = {};
        CHECK(FileTimeToSystemTime(&ft, &date));
        WCHAR formatted[32];
        swprintf(formatted, 32, L"%04u-%02u-%02u %02u:%02u:%02u", (unsigned)date.wYear, (unsigned)date.wMonth,
                 (unsigned)date.wDay, (unsigned)date.wHour, (unsigned)date.wMinute, (unsigned)date.wSecond);
        CHECK(json_text(object, L"expiration", formatted));
        object->Release();
    }
    WindowsDeleteString(json);
    shared->licenses[0].trial = true;
    CHECK(license->Json(&json) == S_OK && json);
    object = parse_json(json);
    if (object)
    {
        CHECK(json_text(object, L"skuType", L"Trial"));
        object->Release();
    }
    WindowsDeleteString(json);
    shared->licenses[0].offer = std::string(4096, '\1');
    CHECK(license->Json(&json) == S_OK && WindowsGetStringLen(json) > 24000);
    object = parse_json(json);
    if (object)
    {
        CHECK(json_text(object, L"inAppOfferToken", std::wstring(4096, L'\1')));
        object->Release();
    }
    WindowsDeleteString(json);
    shared->licenses[0].offer = "\xc0\xaf"; // Invalid overlong UTF-8 must not silently change.
    json = (HSTRING)1;
    CHECK(license->Json(&json) == HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) && !json);
    shared->licenses[0].offer = "first";
    auto expiry = shared->licenses[0].expiration;
    shared->licenses[0].expiration = 253402300800LL;
    CHECK(license->Json(&json) == E_INVALIDARG && !json);
    shared->licenses[0].expiration = std::time(nullptr) - 1;
    CHECK(license->Json(&json) == E_ACCESSDENIED && !json);
    shared->licenses[0].expiration = expiry;
    shared->proof_until = std::time(nullptr) - 1;
    CHECK(license->Json(&json) == E_ACCESSDENIED && !json);
    license->Release();
}
int main()
{
    CHECK(SUCCEEDED(RoInitialize(RO_INIT_MULTITHREADED)));
    json_checks();
    CHECK(make_addon_license_map(fixture(), nullptr) == E_POINTER);
    IInspectable *raw = nullptr;
    CHECK(make_addon_license_map(fixture(), &raw) == S_OK && raw);
    if (!raw)
        return 1;
    ILicenseMap *map = nullptr;
    ILicenseIterable *iterable = nullptr;
    CHECK(raw->QueryInterface(IID_LicenseMap, (void **)&map) == S_OK && map);
    CHECK(raw->QueryInterface(IID_LicenseIterable, (void **)&iterable) == S_OK && iterable);
    IUnknown *a = nullptr, *b = nullptr;
    CHECK(map->QueryInterface(IID_IUnknown, (void **)&a) == S_OK);
    CHECK(iterable->QueryInterface(IID_IUnknown, (void **)&b) == S_OK && a == b);
    a->Release();
    b->Release();
    raw->Release();
    UINT32 n = 999;
    CHECK(map->Size(&n) == S_OK && n == 2);
    CHECK(map->Size(nullptr) == E_POINTER);
    HSTRING key = nullptr;
    CHECK(WindowsCreateString(L"B00000000001/0001", 17, &key) == S_OK);
    boolean present = false;
    CHECK(map->HasKey(key, &present) == S_OK && present);
    IAddonLicense *license = nullptr;
    CHECK(map->Lookup(key, &license) == S_OK && license);
    CHECK(map->Lookup(key, nullptr) == E_POINTER);
    CHECK(map->HasKey(key, nullptr) == E_POINTER);
    WindowsDeleteString(key);
    key = nullptr;
    CHECK(license->Sku(&key) == S_OK && text(key, L"B00000000001/0001"));
    WindowsDeleteString(key);
    CHECK(license->Offer(&key) == S_OK && text(key, L"first"));
    WindowsDeleteString(key);
    CHECK(license->Active(&present) == S_OK && present);
    INT64 expiration = 0;
    CHECK(license->Expiration(&expiration) == S_OK && expiration > 116444736000000000LL);
    CHECK(license->Sku(nullptr) == E_POINTER);
    CHECK(license->Offer(nullptr) == E_POINTER);
    CHECK(license->Expiration(nullptr) == E_POINTER);
    CHECK(license->Active(nullptr) == E_POINTER);
    key = (HSTRING)1;
    CHECK(license->Json(&key) == S_OK && key);
    WindowsDeleteString(key);
    license->Release();
    CHECK(map->HasKey(nullptr, &present) == S_OK && !present);
    license = (IAddonLicense *)1;
    CHECK(map->Lookup(nullptr, &license) == LICENSE_E_BOUNDS && !license);
    ILicenseIterator *it = nullptr;
    CHECK(iterable->First(&it) == S_OK && it);
    CHECK(iterable->First(nullptr) == E_POINTER);
    ILicensePair *pair = nullptr;
    CHECK(it->Current(&pair) == S_OK && pair);
    CHECK(pair->Key(&key) == S_OK && text(key, L"B00000000001/0001"));
    WindowsDeleteString(key);
    CHECK(pair->Value(&license) == S_OK && license);
    license->Release();
    CHECK(pair->Key(nullptr) == E_POINTER);
    CHECK(pair->Value(nullptr) == E_POINTER);
    pair->Release();
    CHECK(it->HasCurrent(&present) == S_OK && present);
    CHECK(it->MoveNext(&present) == S_OK && present);
    CHECK(it->Current(&pair) == S_OK && pair);
    CHECK(pair->Key(&key) == S_OK && text(key, L"B00000000002/0002"));
    WindowsDeleteString(key);
    pair->Release();
    CHECK(it->MoveNext(&present) == S_OK && !present);
    pair = (ILicensePair *)1;
    CHECK(it->Current(&pair) == LICENSE_E_BOUNDS && !pair);
    CHECK(it->MoveNext(&present) == S_OK && !present);
    CHECK(it->GetMany(0, nullptr, &n) == S_OK && n == 0);
    CHECK(it->GetMany(1, nullptr, &n) == E_POINTER);
    CHECK(it->GetMany(0, nullptr, nullptr) == E_POINTER);
    CHECK(it->Current(nullptr) == E_POINTER);
    CHECK(it->HasCurrent(nullptr) == E_POINTER);
    CHECK(it->MoveNext(nullptr) == E_POINTER);
    it->Release();
    CHECK(iterable->First(&it) == S_OK);
    ILicensePair *many[3] = {};
    CHECK(it->GetMany(3, many, &n) == S_OK && n == 2 && many[0] && many[1]);
    for (UINT32 i = 0; i < n; ++i)
        many[i]->Release();
    CHECK(it->HasCurrent(&present) == S_OK && !present);
    it->Release();
    ILicenseMap *left = nullptr, *right = nullptr;
    CHECK(map->Split(&left, &right) == S_OK && left && right);
    CHECK(map->Split(&left, &left) == E_INVALIDARG);
    CHECK(left->Size(&n) == S_OK && n == 1);
    CHECK(right->Size(&n) == S_OK && n == 1);
    CHECK(left->Split(nullptr, &right) == E_POINTER);
    left->Release();
    right->Release();
    iterable->Release();
    map->Release();
    AddonLicenseSnapshot empty;
    empty.proof_until = std::time(nullptr) + 60;
    CHECK(make_addon_license_map(empty, &raw) == S_OK && raw);
    CHECK(raw->QueryInterface(IID_LicenseMap, (void **)&map) == S_OK);
    raw->Release();
    CHECK(map->Size(&n) == S_OK && n == 0);
    left = right = (ILicenseMap *)1;
    CHECK(map->Split(&left, &right) == S_OK && !left && !right);
    map->Release();
    auto bad = fixture();
    bad.proof_until = 0;
    raw = (IInspectable *)1;
    CHECK(make_addon_license_map(bad, &raw) == E_ACCESSDENIED && !raw);
    bad = fixture();
    bad.licenses[0].expiration = std::time(nullptr) - 1;
    CHECK(make_addon_license_map(bad, &raw) == E_UNEXPECTED && !raw);
    bad = fixture();
    bad.licenses[1].sku = bad.licenses[0].sku;
    CHECK(make_addon_license_map(bad, &raw) == E_UNEXPECTED && !raw);
    bad = fixture();
    bad.licenses[0].sku = "invalid";
    CHECK(make_addon_license_map(bad, &raw) == E_UNEXPECTED && !raw);
    AppLicense inactive({});
    raw = (IInspectable *)1;
    CHECK(inactive.get_AddOnLicenses(&raw) == E_ACCESSDENIED && !raw);
    XStoreGameLicense active = {};
    active.isActive = true;
    active.expirationDate = std::time(nullptr) + 60;
    AppLicense unavailable(active);
    raw = (IInspectable *)1;
    CHECK(unavailable.get_AddOnLicenses(&raw) == E_ACCESSDENIED && !raw);
    // Shared immutable lifetime survives map release. Expired proof refuses
    // enumeration.
    auto shared = std::make_shared<AddonLicenseSnapshot>(fixture());
    map = new LicenseMap(shared, 0, 2);
    CHECK(map->QueryInterface(IID_LicenseIterable, (void **)&iterable) == S_OK);
    CHECK(iterable->First(&it) == S_OK);
    map->Release();
    iterable->Release();
    CHECK(it->Current(&pair) == S_OK && pair);
    pair->Release();
    shared->proof_until = std::time(nullptr) - 1;
    CHECK(it->HasCurrent(&present) == E_ACCESSDENIED && !present);
    it->Release();
    RoUninitialize();
    printf("CHECKS %u FAILURES %u\n", checks, failures);
    return failures ? 1 : 0;
}
