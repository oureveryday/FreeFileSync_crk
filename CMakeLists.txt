cmake_minimum_required(VERSION 3.30)
project (crack)

set(CMAKE_CXX_STANDARD 23)
add_definitions(-DUNICODE -D_UNICODE)

enable_language(ASM_MASM)

set(ASM_SOURCES version.asm)

add_library(version SHARED crack.cpp exports.cpp ${ASM_SOURCES})
target_link_libraries(version minhook)
target_include_directories(version PRIVATE minhook/src)

set_target_properties(version PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/exports.def\"")

add_subdirectory(minhook)