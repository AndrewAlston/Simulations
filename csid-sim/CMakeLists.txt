cmake_minimum_required(VERSION 3.19)
project(csid_sim C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2 -msse2 -msse4.1 -lm -fno-inline-functions -O1 -fdump-rtl-expand -Wno-attributes -Wno-deprecated-declarations -Wno-undef")

add_executable(csid_sim main.c helpers.c helpers.h)