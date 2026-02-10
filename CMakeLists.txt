cmake_minimum_required(VERSION 3.10)

project(HEAVEN7L LANGUAGES C)
find_package(SDL2 REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(HEAVEN7L heaven7l.c winapi2sdl.c wol64.c)
target_link_libraries(HEAVEN7L PRIVATE Threads::Threads SDL2::SDL2)

target_link_options(HEAVEN7L PRIVATE -no-pie -Wl,-Ttext-segment=0x500000 -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/reserve.ld)
target_compile_options(HEAVEN7L PRIVATE -fomit-frame-pointer)
