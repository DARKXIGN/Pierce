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
add_library(agent_core STATIC agent/probe.cpp agent/candidates.cpp agent/punch.cpp
            agent/predict.cpp agent/relay_client.cpp)
target_include_directories(agent_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(agent_core PUBLIC stun relay_core OpenSSL::Crypto)

# Stage 3: relay.
add_library(relay_core STATIC relay/protocol.cpp relay/table.cpp)
target_include_directories(relay_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(relay_core PUBLIC stun OpenSSL::Crypto)
add_executable(pierce-relay relay/main.cpp)
target_link_libraries(pierce-relay PRIVATE relay_core)

# gRPC code generated from proto/coord.proto into the build directory.
find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(SQLite3 REQUIRED)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)
set(PROTO_OUT ${CMAKE_BINARY_DIR}/gen)
file(MAKE_DIRECTORY ${PROTO_OUT})
set(PROTO_SRCS ${PROTO_OUT}/coord.pb.cc ${PROTO_OUT}/coord.grpc.pb.cc)
add_custom_command(
  OUTPUT ${PROTO_SRCS} ${PROTO_OUT}/coord.pb.h ${PROTO_OUT}/coord.grpc.pb.h
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I ${CMAKE_SOURCE_DIR}/proto --cpp_out=${PROTO_OUT}
          --grpc_out=${PROTO_OUT} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
          ${CMAKE_SOURCE_DIR}/proto/coord.proto
  DEPENDS ${CMAKE_SOURCE_DIR}/proto/coord.proto)
add_library(coord_proto STATIC ${PROTO_SRCS})
target_include_directories(coord_proto PUBLIC ${PROTO_OUT})
target_link_libraries(coord_proto PUBLIC gRPC::grpc++ protobuf::libprotobuf)
# Generated code is not ours to fix; keep its warnings out of the build log.
set_source_files_properties(${PROTO_SRCS} PROPERTIES COMPILE_OPTIONS "-w")

add_library(coord_core STATIC coord/db.cpp coord/service.cpp)
target_include_directories(coord_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(coord_core PUBLIC coord_proto relay_core SQLite::SQLite3 OpenSSL::Crypto)
add_executable(pierce-coord coord/main.cpp)
target_link_libraries(pierce-coord PRIVATE coord_core)
add_executable(pierce-agent agent/main.cpp)
target_link_libraries(pierce-agent PRIVATE agent_core coord_proto)

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

add_executable(agent_tests tests/probe_test.cpp tests/punch_test.cpp
               tests/predict_test.cpp)
target_link_libraries(agent_tests PRIVATE agent_core GTest::gtest_main)
add_test(NAME agent_tests COMMAND agent_tests)

add_executable(coord_tests tests/coord_test.cpp)
target_link_libraries(coord_tests PRIVATE coord_core GTest::gtest_main)
add_test(NAME coord_tests COMMAND coord_tests)

add_executable(relay_tests tests/relay_test.cpp)
target_link_libraries(relay_tests PRIVATE relay_core GTest::gtest_main)
add_test(NAME relay_tests COMMAND relay_tests)
