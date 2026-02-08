#ifndef WINAPI2SDL_H
#define WINAPI2SDL_H

#include <stdbool.h>

__attribute__((naked)) void KERNEL32_ExitProcess_32to64();
__attribute__((naked)) void KERNEL32_LoadLibraryA_32to64();
__attribute__((naked)) void KERNEL32_GetProcAddress_32to64();

bool WinAPI2SDL_Init(int argc, char *argv[]);
void WinAPI2SDL_Quit();

#endif
