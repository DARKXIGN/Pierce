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

add_library(stun STATIC stun/message.cpp stun/udp.cpp stun/server.cpp stun/client.cpp
            stun/detector.cpp)
target_include_directories(stun PUBLIC ${CMAKE_SOURCE_DIR})
add_executable(stun_server stun/server_main.cpp)
target_link_libraries(stun_server PRIVATE stun)
add_executable(nat_detect stun/nat_detect_main.cpp)
target_link_libraries(nat_detect PRIVATE stun)

# Userspace NAT for the lab's symmetric-sequential type (Linux only: AF_PACKET + raw sockets).
add_library(usernat_core STATIC lab/usernat/nat_table.cpp lab/usernat/packet.cpp)
target_include_directories(usernat_core PUBLIC ${CMAKE_SOURCE_DIR})
add_executable(usernat lab/usernat/main.cpp)
target_link_libraries(usernat PRIVATE usernat_core)

# Stage 2: probes, hole punching, coordination server, agent.
find_package(OpenSSL REQUIRED)
add_library(agent_core STATIC agent/probe.cpp agent/candidates.cpp agent/punch.cpp)
target_include_directories(agent_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(agent_core PUBLIC stun OpenSSL::Crypto)

enable_testing()
add_executable(stun_tests tests/stun_message_test.cpp tests/stun_detector_test.cpp)
target_link_libraries(stun_tests PRIVATE stun GTest::gtest_main)
add_test(NAME stun_tests COMMAND stun_tests)

add_executable(usernat_tests tests/usernat_test.cpp)
target_link_libraries(usernat_tests PRIVATE usernat_core GTest::gtest_main)
add_test(NAME usernat_tests COMMAND usernat_tests)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_test(NAME report_tests COMMAND Python3::Interpreter ${CMAKE_SOURCE_DIR}/lab/test_report.py)
endif()

add_executable(agent_tests tests/probe_test.cpp tests/punch_test.cpp)
target_link_libraries(agent_tests PRIVATE agent_core GTest::gtest_main)
add_test(NAME agent_tests COMMAND agent_tests)
