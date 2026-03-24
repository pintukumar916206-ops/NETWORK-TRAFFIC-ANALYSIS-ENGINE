cmake_minimum_required(VERSION 3.16)
project(NETWORK_TRAFFIC_ANALYSIS_ENGINE LANGUAGES CXX)

# Use C++14 because GCC 6.3.0 has better support for it than C++17
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600)
    # Check if we are using MinGW or MSVC
    if(MSVC)
        add_compile_options(/W4 /std:c++14)
    else()
        add_compile_options(-Wall -Wextra -std=c++14)
    endif()
endif()

# Optimization for production
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Enable high-performance flags
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -flto")
endif()

# Core Infrastructure
include_directories(${CMAKE_SOURCE_DIR}/include)

# Threading is the only external dependency
find_package(Threads REQUIRED)

# Source files
set(SOURCES
    src/types.cpp
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/flow_tracker.cpp
    src/rule_engine.cpp
    src/packet_pool.cpp
    src/dpi_pipeline.cpp
)

# Main Executable
add_executable(traffic_engine src/main.cpp ${SOURCES})
target_link_libraries(traffic_engine PRIVATE Threads::Threads)

# Internal Test Suite
add_executable(test_runner tests/test_runner.cpp ${SOURCES})
target_link_libraries(test_runner PRIVATE Threads::Threads)

# Testing
enable_testing()
add_test(NAME InternalTests COMMAND test_runner)
