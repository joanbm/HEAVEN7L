cmake_minimum_required(VERSION 3.10)

project(HEAVEN7L LANGUAGES C)
find_package(SDL2 REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(HEAVEN7W_EXE "${CMAKE_CURRENT_SOURCE_DIR}/HEAVEN7W.EXE")
add_custom_command(
    OUTPUT "${HEAVEN7W_EXE}"
    COMMAND /bin/sh "${CMAKE_CURRENT_SOURCE_DIR}/download_HEAVEN7W.sh"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/download_HEAVEN7W.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_custom_target(download_HEAVEN7W DEPENDS "${HEAVEN7W_EXE}")

add_executable(HEAVEN7L heaven7l.c winapi2sdl.c wol64.c)
target_link_libraries(HEAVEN7L PRIVATE Threads::Threads SDL2::SDL2)
add_dependencies(HEAVEN7L download_HEAVEN7W)

target_link_options(HEAVEN7L PRIVATE -no-pie -Wl,-Ttext-segment=0x500000 -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/reserve.ld)
target_compile_options(HEAVEN7L PRIVATE -fomit-frame-pointer)
