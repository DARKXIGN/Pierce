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
            agent/predict.cpp agent/relay_client.cpp agent/tls_relay.cpp agent/pcp.cpp
            agent/portmap.cpp)
target_include_directories(agent_core PUBLIC ${CMAKE_SOURCE_DIR})
# Port mapping clients: PCP is ours and always built; NAT-PMP (libnatpmp) and UPnP (miniupnpc)
# are used when their libraries are installed (apt install libnatpmp-dev libminiupnpc-dev).
find_path(NATPMP_INCLUDE natpmp.h)
find_library(NATPMP_LIB natpmp)
if(NATPMP_INCLUDE AND NATPMP_LIB)
  target_compile_definitions(agent_core PRIVATE PIERCE_HAVE_NATPMP=1)
  target_include_directories(agent_core PRIVATE ${NATPMP_INCLUDE})
  target_link_libraries(agent_core PUBLIC ${NATPMP_LIB})
else()
  message(WARNING "libnatpmp not found: NAT-PMP port mapping disabled")
endif()
find_path(MINIUPNPC_INCLUDE miniupnpc/miniupnpc.h)
find_library(MINIUPNPC_LIB miniupnpc)
if(MINIUPNPC_INCLUDE AND MINIUPNPC_LIB)
  target_compile_definitions(agent_core PRIVATE PIERCE_HAVE_MINIUPNPC=1)
  target_include_directories(agent_core PRIVATE ${MINIUPNPC_INCLUDE})
  target_link_libraries(agent_core PUBLIC ${MINIUPNPC_LIB})
else()
  message(WARNING "miniupnpc not found: UPnP port mapping disabled")
endif()
target_link_libraries(agent_core PUBLIC stun relay_core OpenSSL::Crypto)

# Stage 3: relay.
add_library(relay_core STATIC relay/protocol.cpp relay/table.cpp relay/framing.cpp
            relay/tls_server.cpp)
target_include_directories(relay_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(relay_core PUBLIC stun OpenSSL::SSL OpenSSL::Crypto)
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

# Stage 4: WireGuard data plane through BoringTun (Rust, built with cargo as a static library).
# Optional, so stages 1-3 still build on a machine without a Rust toolchain.
find_program(CARGO cargo HINTS $ENV{HOME}/.cargo/bin)
option(PIERCE_WIREGUARD "Build the WireGuard data plane (needs cargo for BoringTun)" ON)
if(PIERCE_WIREGUARD AND CARGO)
  set(BT_DIR ${CMAKE_SOURCE_DIR}/third_party/boringtun)
  set(BT_TARGET_DIR ${CMAKE_BINARY_DIR}/cargo)
  set(BT_LIB ${BT_TARGET_DIR}/release/libpierce_boringtun.a)
  add_custom_command(
    OUTPUT ${BT_LIB}
    # env --unset: cargo would complain about make's jobserver flags it cannot use.
    COMMAND ${CMAKE_COMMAND} -E env --unset=MAKEFLAGS --unset=MFLAGS
            ${CARGO} build --release --locked --manifest-path ${BT_DIR}/Cargo.toml
            --target-dir ${BT_TARGET_DIR}
    DEPENDS ${BT_DIR}/Cargo.toml ${BT_DIR}/Cargo.lock ${BT_DIR}/lib.rs
    COMMENT "Building BoringTun with cargo")
  add_custom_target(boringtun_build DEPENDS ${BT_LIB})
  find_package(Threads REQUIRED)
  add_library(boringtun STATIC IMPORTED)
  set_target_properties(boringtun PROPERTIES IMPORTED_LOCATION ${BT_LIB})
  # A Rust static library needs these system libraries at link time.
  target_link_libraries(boringtun INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)
  add_dependencies(boringtun boringtun_build)

  add_library(wg_core STATIC wg/tunnel.cpp wg/tun.cpp wg/dataplane.cpp)
  target_include_directories(wg_core PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(wg_core PUBLIC boringtun agent_core OpenSSL::Crypto)
  add_executable(pierce-wgkey wg/keytool.cpp)
  target_link_libraries(pierce-wgkey PRIVATE wg_core)
  target_link_libraries(pierce-agent PRIVATE wg_core)
  target_compile_definitions(pierce-agent PRIVATE PIERCE_HAVE_WIREGUARD=1)
  set(PIERCE_HAVE_WIREGUARD ON)
else()
  message(WARNING "cargo not found (or PIERCE_WIREGUARD=OFF): building without the WireGuard "
                  "data plane. Install Rust with rustup to enable it.")
endif()

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
               tests/predict_test.cpp tests/pcp_test.cpp)
target_link_libraries(agent_tests PRIVATE agent_core GTest::gtest_main)
add_test(NAME agent_tests COMMAND agent_tests)

add_executable(coord_tests tests/coord_test.cpp)
target_link_libraries(coord_tests PRIVATE coord_core GTest::gtest_main)
add_test(NAME coord_tests COMMAND coord_tests)

add_executable(relay_tests tests/relay_test.cpp)
target_link_libraries(relay_tests PRIVATE relay_core GTest::gtest_main)
add_test(NAME relay_tests COMMAND relay_tests)

if(PIERCE_HAVE_WIREGUARD)
  add_executable(wg_tests tests/wg_test.cpp)
  target_link_libraries(wg_tests PRIVATE wg_core GTest::gtest_main)
  add_test(NAME wg_tests COMMAND wg_tests)
endif()
