cmake_minimum_required(VERSION 3.27)
project(send_arp_test)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)

add_executable(send_arp_test
        src/arphdr.cpp
        src/arphdr.h
        src/ethhdr.cpp
        src/ethhdr.h
        src/ip.cpp
        src/ip.h
        src/mac.cpp
        src/mac.h
        src/main.cpp)
