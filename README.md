# Nexus XGameRuntime

An independent, unofficial fork of [Xodus XGameRuntime](https://github.com/xodus-gaming/xgameruntime), based on its C++ implementation. It is not an official Xodus or Microsoft project.

Nexus integrations include account authentication, cloud saves, package metadata and access, and Store/DLC licensing. API coverage and game compatibility vary. Build and use this component through [Nexus Runtime](https://github.com/domsvoboda/nexus-runtime), which provides the matching Wine and Proton components.

## Store and licensing scope

Associated-product queries use the public retail catalog with fixed 25-item service windows and local result pages limited to 100 items. They support the currently configured title only; foreign association roots, authenticated or private-audience catalogs and purchase UI are not supported. Collection flags come from verified current-title Store receipts, never from the public listing. 32-bit parity is not verified.

## Building

Linux cross-compilation requires CMake 3.20 or later, Make, MinGW-w64 with C++23 support, and Wine's WIDL. Tests also require Node.js 22, Wine with both Windows architectures enabled, the pinned GoogleTest submodule, and the Wine source tree selected by `cmake/xml2.lock.json`. Its bundled libxml2 is compiled from source, with every input checked against that lock.

```sh
git submodule update --init --recursive
# Use a separate Wine source checkout at the commit in cmake/xml2.lock.json.
cmake -S . -B build/x64 -DCMAKE_TOOLCHAIN_FILE=win64-target.cmake -DENABLE_TESTS=ON -DNEXUS_MIGRATION_PROBES=ON -DNEXUS_WINE_SOURCE=/path/to/wine
cmake --build build/x64 --parallel
node scripts/test-component.mjs build/x64
```

Use `win32-target.cmake` and a separate build directory for 32-bit Windows. The test runner creates an isolated, unauthenticated Wine prefix and checks the exact component binaries. Component tests do not establish full Proton or game compatibility.

## Licensing

Upstream copyright and license notices remain in their files. See [LICENSE](LICENSE) and the [Nexus test license](tests/Nexus/LICENSE).
