cmake_minimum_required(VERSION 3.25)
project(wol C)

set(CMAKE_C_STANDARD 11)

set(SOURCES main.c)

if(WIN32)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/resources.rc)
endif()

add_executable(wol-old old.c)
add_executable(wol ${SOURCES})

if(WIN32)
    target_link_libraries(wol PRIVATE ws2_32)
endif()