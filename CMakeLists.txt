cmake_minimum_required(VERSION 3.20)
project(pierce LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PIERCE_SANITIZE "Build with ASan/UBSan" OFF)
if(PIERCE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# GoogleTest comes from vcpkg, or from the distro package (apt install libgtest-dev).
find_package(GTest CONFIG REQUIRED)

add_library(stun STATIC stun/message.cpp)
target_include_directories(stun PUBLIC ${CMAKE_SOURCE_DIR})

enable_testing()
add_executable(stun_tests tests/stun_message_test.cpp)
target_link_libraries(stun_tests PRIVATE stun GTest::gtest_main)
add_test(NAME stun_tests COMMAND stun_tests)
