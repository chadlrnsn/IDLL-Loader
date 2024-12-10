cmake_minimum_required(VERSION 3.15)
project(IDL)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_FILES 
IDL/src/framework/stdafx.cpp

IDL/src/ConsoleHandler.cpp
IDL/src/main.cpp
)

add_library(IDL ${SOURCE_FILES})

target_include_directories(IDL PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/IDL/includes
    ${CMAKE_CURRENT_SOURCE_DIR}/IDL/src
    ${CMAKE_CURRENT_SOURCE_DIR}/IDL/src/framework
)