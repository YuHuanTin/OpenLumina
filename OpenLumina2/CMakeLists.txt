cmake_minimum_required(VERSION ${CMAKE_VERSION})

set(VCPKG_TARGET_TRIPLET "x64-windows-static")

project(OpenLumina2 CXX)

set(IDA_SDK_PATH "./idasdk90")
set(CMAKE_CXX_STANDARD 26)

add_compile_options(/clang:-Wall -Wextra -Wpedantic -Wconversion)

include_directories(${IDA_SDK_PATH}/include)
link_directories(${IDA_SDK_PATH}/lib/x64_win_vc_32)

find_package(minhook CONFIG REQUIRED)


add_library(${PROJECT_NAME} SHARED main.cpp)

target_precompile_headers(${PROJECT_NAME} PUBLIC pch.h)
target_link_libraries(${PROJECT_NAME} PUBLIC ida.lib)
target_link_libraries(${PROJECT_NAME} PUBLIC Crypt32.lib)
target_link_libraries(${PROJECT_NAME} PRIVATE minhook::minhook)
