# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.10)

# Project's name
project(my_tcp)


include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB SOURCES "src/*.c")

add_executable(my_tcp ${SOURCES})

# Link the libraries
target_link_libraries(my_tcp pcap)