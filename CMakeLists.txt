cmake_minimum_required(VERSION 3.10)

project(h7shim LANGUAGES C)
find_package(SDL2 REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(h7shim h7shim.c winapi2sdl.c wol64.c)
target_link_libraries(h7shim PRIVATE Threads::Threads SDL2::SDL2)

target_link_options(h7shim PRIVATE -no-pie -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/reserve.ld)
target_compile_options(h7shim PRIVATE -fomit-frame-pointer)
