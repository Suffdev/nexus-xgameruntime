foreach(probe IN ITEMS auth-rejection-metadata token-endpoint store-public-fetch)
    add_executable(nexus_${probe} Nexus/${probe}.cpp)
    add_dependencies(nexus_${probe} xgameruntime-idl)
    target_include_directories(nexus_${probe} PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
    target_link_libraries(nexus_${probe} PRIVATE xgameruntime-common runtimeobject ole32)
    target_compile_features(nexus_${probe} PRIVATE cxx_std_23)
    target_link_options(nexus_${probe} PRIVATE -static -static-libgcc -static-libstdc++)
    set_target_properties(nexus_${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endforeach()
target_link_libraries(nexus_store-public-fetch PRIVATE winhttp)

configure_file(Nexus/MicrosoftGame.config "${CMAKE_BINARY_DIR}/bin/MicrosoftGame.config" COPYONLY)

add_executable(nexus_store-context Nexus/store-context.cpp)
add_dependencies(nexus_store-context xgameruntime-idl)
target_include_directories(nexus_store-context PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(nexus_store-context PRIVATE xgameruntime-common runtimeobject ole32)
target_compile_features(nexus_store-context PRIVATE cxx_std_23)
target_link_options(nexus_store-context PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_store-context PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_executable(nexus_store-license-map Nexus/store-license-map.cpp)
add_dependencies(nexus_store-license-map xgameruntime-idl)
target_include_directories(nexus_store-license-map PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(nexus_store-license-map PRIVATE xgameruntime-common runtimeobject ole32)
target_compile_features(nexus_store-license-map PRIVATE cxx_std_23)
target_link_options(nexus_store-license-map PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_store-license-map PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_executable(nexus_store-context-raw Nexus/store-context-raw.cpp)
target_link_libraries(nexus_store-context-raw PRIVATE runtimeobject ole32)
target_compile_features(nexus_store-context-raw PRIVATE cxx_std_23)
target_link_options(nexus_store-context-raw PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_store-context-raw PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(test_xgameruntime
        Nexus/test_system.cpp
        Nexus/test_com_ownership.cpp
        Nexus/test_optional_providers.cpp
        Nexus/test_connectivity.cpp
        Nexus/test_offline_identity.cpp
        Nexus/test_shutdown.cpp
        Nexus/test_package_layout.cpp
        Nexus/test_async_results.cpp
        Nexus/test_thread_local.cpp
        Nexus/test_async_wait.cpp
        System/test_xthreading.cpp
        test_fixtures.cpp)

target_link_libraries(test_xgameruntime
        PRIVATE
        libxgameruntime
        GTest::gtest_main ws2_32 iphlpapi )

target_link_options(test_xgameruntime PRIVATE
        -static
        -static-libgcc
        -static-libstdc++ )

target_compile_features(test_xgameruntime
        PUBLIC
        cxx_std_23 )

include( GoogleTest )

target_include_directories(test_xgameruntime
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/external/googletest/googletest/include )

add_executable(test_nexus_timer Nexus/test_timer.cpp)
target_link_libraries(test_nexus_timer PRIVATE xgameruntime-impl GTest::gtest_main)
target_compile_features(test_nexus_timer PRIVATE cxx_std_23)
target_link_options(test_nexus_timer PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(test_nexus_timer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(test_nexus_save Nexus/test_save.cpp)
target_link_libraries(test_nexus_save PRIVATE xgameruntime-impl GTest::gtest_main)
target_compile_features(test_nexus_save PRIVATE cxx_std_23)
target_link_options(test_nexus_save PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(test_nexus_save PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(test_nexus_user Nexus/test_user.cpp)
target_link_libraries(test_nexus_user PRIVATE xgameruntime-impl GTest::gtest_main)
target_compile_features(test_nexus_user PRIVATE cxx_std_23)
target_link_options(test_nexus_user PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(test_nexus_user PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(test_nexus_configuration Nexus/test_configuration.cpp)
target_link_libraries(test_nexus_configuration PRIVATE xgameruntime-impl GTest::gtest_main)
target_compile_features(test_nexus_configuration PRIVATE cxx_std_23)
target_link_options(test_nexus_configuration PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(test_nexus_configuration PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_legacy-service-client Nexus/legacy-service-client.cpp)
target_link_libraries(nexus_legacy-service-client PRIVATE xgameruntime-impl nexus-xml2)
target_compile_features(nexus_legacy-service-client PRIVATE cxx_std_23)
target_link_options(nexus_legacy-service-client PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_legacy-service-client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# For discovery purposes.
set_target_properties(test_xgameruntime PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin" )

if( CMAKE_CROSSCOMPILING )
    message( STATUS "We are cross compiling tests" )
    find_program( WINE_EXECUTABLE wine )
    message( STATUS "Using wine: ${WINE_EXECUTABLE}" )
    if( NOT WINE_EXECUTABLE )
        message( FATAL_ERROR "Wine is required to run Windows tests on non-Windows hosts" )
    endif()
    set_property(
            TARGET test_xgameruntime
            PROPERTY CROSSCOMPILING_EMULATOR
            "${WINE_EXECUTABLE}" )
endif()

# We should not be pre-running tests during build.
gtest_discover_tests(
        test_xgameruntime
        DISCOVERY_MODE PRE_TEST
        DISCOVERY_TIMEOUT 30 )

add_executable(nexus_system_device_id Nexus/system-device-id-probe.c)
set_target_properties(nexus_system_device_id PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
if(CMAKE_CROSSCOMPILING)
    set_property(TARGET nexus_system_device_id PROPERTY CROSSCOMPILING_EMULATOR "${WINE_EXECUTABLE}")
endif()
add_test(NAME NexusSystem.RawDeviceIdContract COMMAND nexus_system_device_id)

option(NEXUS_MIGRATION_PROBES "Build the original Nexus ABI migration regressions" ON)
if(NEXUS_MIGRATION_PROBES)
    foreach(probe runtime-init async-schedule async-completion-lifetime taskqueue-teardown taskqueue-contract taskqueue-close)
        add_executable(nexus_${probe} Nexus/${probe}-probe.c)
        add_dependencies(nexus_${probe} xgameruntime-idl)
        target_compile_definitions(nexus_${probe} PRIVATE __WINESRC__)
        target_include_directories(nexus_${probe} PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
        set_target_properties(nexus_${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
        if(CMAKE_CROSSCOMPILING)
            set_property(TARGET nexus_${probe} PROPERTY CROSSCOMPILING_EMULATOR "${WINE_EXECUTABLE}")
        endif()
        add_test(NAME NexusMigration.${probe} COMMAND nexus_${probe})
        set_tests_properties(NexusMigration.${probe} PROPERTIES TIMEOUT 45)
    endforeach()
endif()

foreach(probe sync transfer commit)
    add_executable(nexus_gamesave-${probe} Nexus/gamesave-${probe}.cpp)
    target_link_libraries(nexus_gamesave-${probe} PRIVATE xgameruntime-impl)
    target_compile_features(nexus_gamesave-${probe} PRIVATE cxx_std_23)
    target_link_options(nexus_gamesave-${probe} PRIVATE -static -static-libgcc -static-libstdc++)
    set_target_properties(nexus_gamesave-${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endforeach()

add_executable(nexus_gamesave-file-paths Nexus/gamesave-file-paths.cpp)

add_executable(nexus_game-invitations Nexus/game-invitations.cpp)
target_link_libraries(nexus_game-invitations PRIVATE xgameruntime-impl)
target_compile_features(nexus_game-invitations PRIVATE cxx_std_23)
target_link_options(nexus_game-invitations PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_game-invitations PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(nexus_gamesave-file-paths PRIVATE xgameruntime-impl)
target_compile_features(nexus_gamesave-file-paths PRIVATE cxx_std_23)
target_link_options(nexus_gamesave-file-paths PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_gamesave-file-paths PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_gamesave-files Nexus/gamesave-files.cpp)
target_link_libraries(nexus_gamesave-files PRIVATE xgameruntime-impl)
target_compile_features(nexus_gamesave-files PRIVATE cxx_std_23)
target_link_options(nexus_gamesave-files PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_gamesave-files PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(NEXUS_MIGRATION_PROBES)
    foreach(probe package-identity package-legacy package-chunks package-monitors package-progress-bytes package-selection)
        set(package_probe_source "Nexus/${probe}-probe.c")
        if(probe STREQUAL "package-legacy" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
            set(package_probe_source "Nexus/package-legacy-32-probe.c")
        endif()
        add_executable(nexus_${probe} ${package_probe_source})
        add_dependencies(nexus_${probe} xgameruntime-idl)
        target_compile_definitions(nexus_${probe} PRIVATE __WINESRC__)
        target_include_directories(nexus_${probe} PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
        set_target_properties(nexus_${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    endforeach()
endif()

foreach(probe store-entitlements package-content)
    add_executable(nexus_${probe} Nexus/${probe}.cpp)
    add_dependencies(nexus_${probe} xgameruntime-idl)
    target_include_directories(nexus_${probe} PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
    target_link_libraries(nexus_${probe} PRIVATE nexus-xml2 xgameruntime-common shell32 bcrypt crypt32 advapi32 runtimeobject ole32 winhttp wininet ws2_32)
    target_compile_features(nexus_${probe} PRIVATE cxx_std_23)
    target_link_options(nexus_${probe} PRIVATE -static -static-libgcc -static-libstdc++)
    set_target_properties(nexus_${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endforeach()
target_link_libraries(nexus_package-content PRIVATE xgameruntime-impl)

add_executable(nexus_package-installed Nexus/package-installed.cpp)
add_dependencies(nexus_package-installed xgameruntime-idl)
target_compile_definitions(nexus_package-installed PRIVATE __WINESRC__)
target_include_directories(nexus_package-installed PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_compile_features(nexus_package-installed PRIVATE cxx_std_17)
target_link_options(nexus_package-installed PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_package-installed PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")


if(NEXUS_MIGRATION_PROBES)
    foreach(probe game-relaunch game-relaunch-search async-provider-contract)
        add_executable(nexus_${probe} Nexus/${probe}-probe.c)
        add_dependencies(nexus_${probe} xgameruntime-idl)
        target_compile_definitions(nexus_${probe} PRIVATE __WINESRC__)
        target_include_directories(nexus_${probe} PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
        set_target_properties(nexus_${probe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    endforeach()
    target_link_options(nexus_game-relaunch PRIVATE -municode)
    target_link_options(nexus_game-relaunch-search PRIVATE -municode)
endif()

add_executable(nexus_user-device-association Nexus/user-device-association.cpp)
add_dependencies(nexus_user-device-association xgameruntime-idl)
target_include_directories(nexus_user-device-association PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_compile_features(nexus_user-device-association PRIVATE cxx_std_23)
target_link_options(nexus_user-device-association PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_user-device-association PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_windows-account-metadata Nexus/windows-account-metadata.cpp)
target_link_libraries(nexus_windows-account-metadata PRIVATE xgameruntime-impl nexus-xml2)
target_compile_features(nexus_windows-account-metadata PRIVATE cxx_std_23)
target_link_options(nexus_windows-account-metadata PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_windows-account-metadata PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_user-audio Nexus/user-audio.cpp)
add_dependencies(nexus_user-audio xgameruntime-idl)
target_include_directories(nexus_user-audio PRIVATE "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(nexus_user-audio PRIVATE xgameruntime-common ole32 uuid)
target_compile_features(nexus_user-audio PRIVATE cxx_std_23)
target_link_options(nexus_user-audio PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_user-audio PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_user-privilege Nexus/user-privilege.cpp)
target_link_libraries(nexus_user-privilege PRIVATE xgameruntime-impl nexus-xml2)
target_compile_features(nexus_user-privilege PRIVATE cxx_std_23)
target_link_options(nexus_user-privilege PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_user-privilege PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(test_nexus_async_identity Nexus/test_async_identity.cpp)
target_link_libraries(test_nexus_async_identity PRIVATE xgameruntime-impl GTest::gtest_main)
target_compile_features(test_nexus_async_identity PRIVATE cxx_std_23)
target_link_options(test_nexus_async_identity PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(test_nexus_async_identity PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_auth-metadata Nexus/auth-metadata.cpp)
target_link_libraries(nexus_auth-metadata PRIVATE xgameruntime-impl nexus-xml2)
target_compile_features(nexus_auth-metadata PRIVATE cxx_std_23)
target_link_options(nexus_auth-metadata PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_auth-metadata PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(nexus_connectivity-events Nexus/connectivity-events.cpp)
target_link_libraries(nexus_connectivity-events PRIVATE xgameruntime-impl)
target_compile_features(nexus_connectivity-events PRIVATE cxx_std_23)
target_link_options(nexus_connectivity-events PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_connectivity-events PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(NEXUS_MIGRATION_PROBES)
add_executable(nexus_gamesave-conflict-ui Nexus/gamesave-conflict-ui.cpp)
target_link_libraries(nexus_gamesave-conflict-ui PRIVATE user32 gdi32)
target_compile_features(nexus_gamesave-conflict-ui PRIVATE cxx_std_23)
target_link_options(nexus_gamesave-conflict-ui PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_gamesave-conflict-ui PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

# This target compiles the actual queue with fixture-only API interposition.
# Production library objects never include the shim.
add_executable(nexus_taskqueue-composite-waiters
    Nexus/taskqueue-composite-waiters.cpp
    "${PROJECT_SOURCE_DIR}/src/System/Threading/XTaskQueue.cpp")
add_dependencies(nexus_taskqueue-composite-waiters xgameruntime-idl)
target_include_directories(nexus_taskqueue-composite-waiters PRIVATE
    "${PROJECT_SOURCE_DIR}" "${IDL_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(nexus_taskqueue-composite-waiters PRIVATE LIBXML_STATIC)
target_compile_options(nexus_taskqueue-composite-waiters PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/Nexus/taskqueue-composite-waiters-shim.h")
target_compile_features(nexus_taskqueue-composite-waiters PRIVATE cxx_std_23)
target_link_libraries(nexus_taskqueue-composite-waiters PRIVATE
    xgameruntime-impl nexus-xml2 xgameruntime-common shell32 bcrypt crypt32 advapi32
    runtimeobject ole32 winhttp wininet ws2_32 iphlpapi)
target_link_options(nexus_taskqueue-composite-waiters PRIVATE -static -static-libgcc -static-libstdc++)
set_target_properties(nexus_taskqueue-composite-waiters PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
