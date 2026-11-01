cmake_minimum_required(VERSION 3.20)
project(XIII_0S1nt VERSION 2.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC optimization and warnings
if(MSVC)
    add_compile_options(/W4 /EHsc /utf-8 /permissive- /O2 /Oi /Gy)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(SOURCES
    src/main.cpp
    src/application.cpp
    src/console.cpp
    src/utils.cpp
    src/http_client.cpp
    src/config_manager.cpp
    src/license.cpp
    src/report_generator.cpp
    src/api_registry.cpp
    src/menu.cpp
    src/modules/username.cpp
    src/modules/email.cpp
    src/modules/phone.cpp
    src/modules/ip.cpp
    src/modules/domain.cpp
    src/modules/website.cpp
    src/modules/discord.cpp
    src/modules/github.cpp
    src/modules/social.cpp
    src/modules/breach.cpp
    src/modules/dns.cpp
    src/modules/whois.cpp
    src/modules/network.cpp
    src/modules/url_rep.cpp
    src/modules/hash.cpp
    src/modules/threat.cpp
    src/modules/profile.cpp
    src/modules/searchengine.cpp
    src/modules/comprehensive.cpp
    src/modules/report_manager.cpp
    src/modules/api_status.cpp
    src/modules/settings.cpp
)

add_executable(XIII_0S1nt ${SOURCES})

target_link_libraries(XIII_0S1nt PRIVATE
    winhttp
    crypt32
    bcrypt
    advapi32
    shell32
    user32
    ole32
)

set_target_properties(XIII_0S1nt PROPERTIES
    OUTPUT_NAME "XIII_0S1nt"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
