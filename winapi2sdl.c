#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <SDL.h>
#include "winapi2sdl.h"
#include "wol64.h"

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_ ## x
#endif

// This attribute needs to be applied to all calls from HEAVEN7 application code back to our code
// It sets force_align_arg_pointer because if some libraries (SDL mostly) uses SSE code,
// we need to make sure the stack is properly re-aligned after HEAVEN7 de-aligned it,
// or the SSE instructions will cause a crash due to an unaligned load/store
// Also coming from the WoL64 mode, our stack may not be aligned.
#define API_CALLBACK __attribute__((force_align_arg_pointer))

#define SETTING_RESOLUTION 3 // 0 = 320x240, 1 = 512x384, 2 = 640x480, 3 = 800x600
// But actually the values are: 0 = 320x176, 1 = 512x280, 2 = 640x352, 3 = 800x440
#define SETTING_TRACER 0 // 0 = 1x1, 1 = 2x2, 2 = 4x4
#define SETTING_SOUND 0 // 0 = 44 Khz, 1 = 22 Khz, 2 = Disabled
#define SETTING_WINDOWED 0 // 0 or 1
#define SETTING_NOTEXT 0 // 0 or 1
#define SETTING_LOOP 0 // 0 or 1

static const bool resolution_hack = false;
#define SPEEDUP_FACTOR 1

#ifdef DEBUG
#define LOG_EMULATED() printf("[!] %s EMULATED!\n", __func__)
#else
#define LOG_EMULATED() do { } while(0)
#endif

typedef struct SymbolTable
{
    const char *symbolName;
    void *symbol;
} SymbolTable;

typedef struct LibraryTable
{
    const char *libraryName;
    const SymbolTable *symbolTable;
} LibraryTable;

#define MAKE_SYMBOL_ORDINAL(ord) ((char *)(uint32_t)(ord))

static const LibraryTable *GLOBAL_LIBRARY_TABLE;

// ------
// DSOUND
// ------

#define DSBSTATUS_PLAYING 0x1
#define DSBSTATUS_LOOPING 0x4

typedef struct DSound_SoundBufferImpl_Object
{
    uint32_t vtableptr;

    bool is_primary;
    uint8_t *audio_buffer;
    uint32_t audio_buffer_size;
    bool audio_playing;
    uint32_t audio_playpos;
} DSound_SoundBufferImpl_Object;

API_CALLBACK void *DSOUND_SoundBufferImpl_GetStatus(void *cominterface, uint32_t *status)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(status != NULL);

    *status = DSBSTATUS_PLAYING | DSBSTATUS_LOOPING;
    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_GetStatus, 2);

API_CALLBACK void *DSOUND_SoundBufferImpl_Restore(void *cominterface)
{
    // This is never called in practice since our GetStatus does never return
    // status = 2 (DSBSTATUS_BUFFERLOST) since there isn't a SDL equivalent
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Restore, 1);

API_CALLBACK void *DSOUND_SoundBufferImpl_Lock(
    void *cominterface,
    uint32_t dwOffset, uint32_t dwBytes,
    void **ppvAudioPtr1, uint32_t *pdwAudioBytes1,
    void **UNUSED(ppvAudioPtr2), uint32_t *UNUSED(pdwAudioBytes2),
    uint32_t UNUSED(dwFlags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    SDL_LockAudio();

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    assert(dwOffset <= bufferobj->audio_buffer_size);
    assert(dwBytes <= bufferobj->audio_buffer_size);
    assert(dwOffset + dwBytes <= bufferobj->audio_buffer_size);
    if (bufferobj->audio_playing) {
        assert(dwOffset > bufferobj->audio_playpos ||
               (dwOffset + dwBytes <= bufferobj->audio_playpos));
    }

    *(uint32_t *)ppvAudioPtr1 = as32bitptr(&bufferobj->audio_buffer[dwOffset]);
    *pdwAudioBytes1 = dwBytes;

    return NULL;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Lock, 8);

API_CALLBACK void *DSOUND_SoundBufferImpl_Unlock(
    void *cominterface, void *UNUSED(pvAudioPtr1), uint32_t UNUSED(dwAudioBytes1),
    void *UNUSED(pvAudioPtr2), uint32_t UNUSED(dwAudioBytes2))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    SDL_UnlockAudio();

    return NULL;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Unlock, 5);

API_CALLBACK void *DSOUND_SoundBufferImpl_SetFormat(void *cominterface, void *format)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(format != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_SetFormat, 2);

API_CALLBACK void *DSOUND_SoundBufferImpl_Play(
         void *cominterface,
         uint32_t UNUSED(dwReserved1),
         uint32_t UNUSED(dwPriority),
         uint32_t UNUSED(dwFlags))
{
    LOG_EMULATED();
    assert(cominterface != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    bufferobj->audio_playing = true;
    bufferobj->audio_playpos = 0;
    SDL_PauseAudio(0);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Play, 4);

API_CALLBACK void *DSOUND_SoundBufferImpl_GetCurrentPosition(
    void *cominterface, uint32_t *pdwCurrentPlayCursor, uint32_t *pdwCurrentWriteCursor)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(pdwCurrentPlayCursor != NULL);
    assert(pdwCurrentWriteCursor != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    *pdwCurrentPlayCursor = bufferobj->audio_playpos;
    *pdwCurrentWriteCursor = *pdwCurrentPlayCursor; // Don't matter

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_GetCurrentPosition, 3);

API_CALLBACK void *DSOUND_SoundBufferImpl_Stop(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    bufferobj->audio_playing = false;
    bufferobj->audio_playpos = 0;
    SDL_PauseAudio(0);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Stop, 1);

API_CALLBACK void *DSOUND_SoundBufferImpl_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    if (!bufferobj->is_primary) {
        SDL_CloseAudio();
    }
    free32(bufferobj->audio_buffer);
    free32(bufferobj);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SoundBufferImpl_Release, 1);

static uint32_t DSound_SoundBufferImpl_VTABLE[256];
__attribute__((constructor)) static void init_DSound_SoundBufferImpl_VTABLE(void) {
    uint32_t *vt = DSound_SoundBufferImpl_VTABLE;
    vt[0x24/4] = as32bitptr(DSOUND_SoundBufferImpl_GetStatus_32to64);
    vt[0x50/4] = as32bitptr(DSOUND_SoundBufferImpl_Restore_32to64);
    vt[0x2C/4] = as32bitptr(DSOUND_SoundBufferImpl_Lock_32to64);
    vt[0x4C/4] = as32bitptr(DSOUND_SoundBufferImpl_Unlock_32to64);
    vt[0x38/4] = as32bitptr(DSOUND_SoundBufferImpl_SetFormat_32to64);
    vt[0x30/4] = as32bitptr(DSOUND_SoundBufferImpl_Play_32to64);
    vt[0x10/4] = as32bitptr(DSOUND_SoundBufferImpl_GetCurrentPosition_32to64);
    vt[0x48/4] = as32bitptr(DSOUND_SoundBufferImpl_Stop_32to64);
    vt[0x8/4] = as32bitptr(DSOUND_SoundBufferImpl_Release_32to64);
}

static void AudioCallback(void *userdata, Uint8 *stream, int len)
{
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)userdata;

    uint32_t stream_pos = 0, stream_len = (uint32_t)len;
    assert(stream_len < bufferobj->audio_buffer_size);

    if (bufferobj->audio_playing) {
        for (size_t i = 0; i < 2; i++) { // Drain twice to handle circular buffer wraparound
            uint32_t buffer_avail = bufferobj->audio_buffer_size - bufferobj->audio_playpos;
            uint32_t take = stream_len < buffer_avail ? stream_len : buffer_avail;

            memcpy(stream + stream_pos, bufferobj->audio_buffer + bufferobj->audio_playpos, take);
            bufferobj->audio_playpos += take;
            if (bufferobj->audio_playpos == bufferobj->audio_buffer_size)
                bufferobj->audio_playpos = 0;
            stream_pos += take;
            stream_len -= take;
        }
    }

    memset(stream + stream_pos, 0, stream_len);
}

API_CALLBACK void *DSOUND_CreateSoundBuffer(
    void *cominterface, void *buffer_desc, void **ppdsb, void *unk)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(buffer_desc != NULL);
    assert(ppdsb != NULL);
    assert(unk == NULL);

    bool is_primary_buffer = *(uint32_t *)((uint8_t *)buffer_desc + 4) & 1;
    uint32_t buffer_size = *(uint32_t *)((uint8_t *)buffer_desc + 8);
    void *waveformatex = (void *)(uintptr_t)*(uint32_t *)((uint8_t *)buffer_desc + 16);
    uint32_t raw_freq = waveformatex != NULL ? *(uint32_t *)((uint8_t *)waveformatex + 4) : 0;
    assert(raw_freq < INT_MAX);
    int freq = (int)raw_freq;

    DSound_SoundBufferImpl_Object *bufferobj = malloc32(sizeof(DSound_SoundBufferImpl_Object));
    bufferobj->vtableptr = as32bitptr(DSound_SoundBufferImpl_VTABLE);
    bufferobj->is_primary = is_primary_buffer;
    bufferobj->audio_buffer = !is_primary_buffer ? malloc32(buffer_size) : NULL;
    bufferobj->audio_buffer_size = !is_primary_buffer ? buffer_size : 0;
    bufferobj->audio_playing = false;
    bufferobj->audio_playpos = 0;

    if (!bufferobj->is_primary) {
        SDL_AudioSpec wav_spec;
        SDL_memset(&wav_spec, 0, sizeof(wav_spec));
        wav_spec.freq = freq * SPEEDUP_FACTOR;
        wav_spec.format = AUDIO_S16;
        wav_spec.channels = 2;
        // Make the audio buffer small, because H7 uses the consumed audio samples
        // for video timing, so a big audio buffer results in a choppy frame rate
        wav_spec.samples = 512;
        wav_spec.callback = AudioCallback;
        wav_spec.userdata = bufferobj;

        if (SDL_OpenAudio(&wav_spec, NULL) < 0) {
            fprintf(stderr, "Couldn't open SDL audio: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }
    }

    *(uint32_t *)ppdsb = as32bitptr(bufferobj);
    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_CreateSoundBuffer, 4);

API_CALLBACK void *DSOUND_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t UNUSED(flags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_SetCooperativeLevel, 3);

API_CALLBACK void *DSOUND_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_Release, 1);

static uint32_t DSOUND_VTABLE[256];
__attribute__((constructor)) static void init_DSound_VTABLE(void) {
    uint32_t *vt = DSOUND_VTABLE;
    vt[0x0C/4] = as32bitptr(DSOUND_CreateSoundBuffer_32to64);
    vt[0x18/4] = as32bitptr(DSOUND_SetCooperativeLevel_32to64);
    vt[0x8/4] = as32bitptr(DSOUND_Release_32to64);
}

typedef struct DSOUND_Object
{
    uint32_t vtableptr;
} DSOUND_Object;

API_CALLBACK void *DSOUND_DirectSoundCreate(
   void *guid, void **lpds, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpds != NULL);
    assert(unkouter == NULL);

    static DSOUND_Object DSOUND_NULLOBJECT;
    DSOUND_NULLOBJECT.vtableptr = as32bitptr(DSOUND_VTABLE);
    *(uint32_t *)lpds = as32bitptr(&DSOUND_NULLOBJECT);
    return 0;
}
MK_TRAMPOLINE_32TO64(DSOUND_DirectSoundCreate, 3);

static const SymbolTable DSOUND_SYMBOLS[] = {
    { MAKE_SYMBOL_ORDINAL(0x0001), DSOUND_DirectSoundCreate_32to64 },
    { NULL, NULL }
};

// --------
// KERNEL32
// --------

// **MEMORY**

API_CALLBACK void *KERNEL32_GlobalAlloc(uint32_t flags, uint32_t memsize)
{
    LOG_EMULATED();

    assert(flags == 0);

    return malloc32(memsize);
}
MK_TRAMPOLINE_32TO64(KERNEL32_GlobalAlloc, 2);

API_CALLBACK void *KERNEL32_GlobalFree(void *ptr)
{
    LOG_EMULATED();
    free32(ptr);
    return NULL;
}
MK_TRAMPOLINE_32TO64(KERNEL32_GlobalFree, 1);

// **THREADING**

typedef struct HANDLE_THREAD {
    pthread_t pthread;
} HANDLE_THREAD;

API_CALLBACK void *KERNEL32_CreateThread(
      void *UNUSED(lpThreadAttributes), uint32_t UNUSED(dwStackSize), void *lpStartAddress,
      void *lpParameter, uint32_t UNUSED(dwCreationFlags), uint32_t *UNUSED(lpThreadId)
)
{
    LOG_EMULATED();

    HANDLE_THREAD *handle_thread = malloc32(sizeof(HANDLE_THREAD));
    if (!Launch32(&handle_thread->pthread, lpStartAddress, lpParameter)) {
        fprintf(stderr, "Failed to lauch Win32 thread.\n");
        exit(EXIT_FAILURE);
    }
    return handle_thread;
}
MK_TRAMPOLINE_32TO64(KERNEL32_CreateThread, 6);

API_CALLBACK uint32_t KERNEL32_SetThreadPriority(void *UNUSED(thread), int UNUSED(priority))
{
    LOG_EMULATED();

    return 1;
}
MK_TRAMPOLINE_32TO64(KERNEL32_SetThreadPriority, 2);

API_CALLBACK uint32_t KERNEL32_TerminateThread(void *thread, uint32_t UNUSED(exitCode))
{
    LOG_EMULATED();

    HANDLE_THREAD *hthread = (HANDLE_THREAD *)thread;
    pthread_cancel(hthread->pthread);
    pthread_join(hthread->pthread, NULL);
    return 1;
}
MK_TRAMPOLINE_32TO64(KERNEL32_TerminateThread, 2);

API_CALLBACK uint32_t KERNEL32_CloseHandle(void *object)
{
    LOG_EMULATED();

    HANDLE_THREAD *hthread = (HANDLE_THREAD *)object;
    free32(hthread);

    return 1;
}
MK_TRAMPOLINE_32TO64(KERNEL32_CloseHandle, 1);

// **CRITICAL SECTION**

API_CALLBACK void KERNEL32_InitializeCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = malloc32(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    *(uint32_t *)pcs = as32bitptr(mutex);
}
MK_TRAMPOLINE_32TO64(KERNEL32_InitializeCriticalSection, 1);

API_CALLBACK void KERNEL32_EnterCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = (pthread_mutex_t *)(uintptr_t)(*(uint32_t *)pcs);
    pthread_mutex_lock(mutex);
}
MK_TRAMPOLINE_32TO64(KERNEL32_EnterCriticalSection, 1);

API_CALLBACK void KERNEL32_LeaveCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = (pthread_mutex_t *)(uintptr_t)(*(uint32_t *)pcs);
    pthread_mutex_unlock(mutex);
}
MK_TRAMPOLINE_32TO64(KERNEL32_LeaveCriticalSection, 1);

API_CALLBACK void KERNEL32_DeleteCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = (pthread_mutex_t *)(uintptr_t)(*(uint32_t *)pcs);
    pthread_mutex_destroy(mutex);
    free32(mutex);
}
MK_TRAMPOLINE_32TO64(KERNEL32_DeleteCriticalSection, 1);

// **MISC**

static char *COMMANDLINE;

API_CALLBACK char *KERNEL32_GetCommandLineA(void)
{
    LOG_EMULATED();
    // Arguments:
    // (Default: 44Khz sound)
    // n -> No sound
    // s -> 22Khz sound

    // (Default: 1x1 tracer)
    // a -> 4x4 tracer
    // b -> 2x2 tracer

    // (Default: Fullscreen, lowest resolution)
    // w -> Windowed
    // 0123 -> Resolution (higher = better)
    // d -> Double resolution

    // l -> Looping
    // t -> No text
    return COMMANDLINE;
}
MK_TRAMPOLINE_32TO64(KERNEL32_GetCommandLineA, 0);

API_CALLBACK void *KERNEL32_GetModuleHandleA(const char *moduleName)
{
    LOG_EMULATED();

    assert(moduleName == NULL);
    return NULL; // Theoretically we should actually return IMAGEBASE here,
                 // but it doesn't matter since the code never uses this value
}
MK_TRAMPOLINE_32TO64(KERNEL32_GetModuleHandleA, 1);

API_CALLBACK void KERNEL32_ExitProcess(uint32_t exitcode)
{
    LOG_EMULATED();
    exit((int)exitcode);
}
MK_TRAMPOLINE_32TO64(KERNEL32_ExitProcess, 1);

API_CALLBACK void KERNEL32_Sleep(uint32_t timems)
{
    LOG_EMULATED();

    struct timespec ts;
    ts.tv_sec = (time_t)(timems / 1000);
    ts.tv_nsec = (long)((timems % 1000) * 1000000);
    nanosleep(&ts, NULL);
}
MK_TRAMPOLINE_32TO64(KERNEL32_Sleep, 1);

API_CALLBACK void *KERNEL32_LoadLibraryA(const char *libraryName)
{
    LOG_EMULATED();

    assert(libraryName != NULL);

    const LibraryTable *found = NULL;
    for (const LibraryTable *l = GLOBAL_LIBRARY_TABLE; l->libraryName != NULL; l++) {
        if (strcasecmp(l->libraryName, libraryName) == 0) {
            found = l;
            break;
        }
    }

    if (found == NULL) {
        fprintf(stderr, "WARNING: Library '%s' not found.\n", libraryName);
    }

    return (void *)found;
}
MK_TRAMPOLINE_32TO64(KERNEL32_LoadLibraryA, 1)

static bool symbol_is_ordinal(const char *p)
{
    return (uintptr_t)p <= 0xFFFF;
}

static bool symbol_compare(const char *s1, const char *s2)
{
        return
            (symbol_is_ordinal(s1) && symbol_is_ordinal(s2) && s1 == s2) ||
            (!symbol_is_ordinal(s1) && !symbol_is_ordinal(s2) && strcmp(s1, s2) == 0);
}

API_CALLBACK void *KERNEL32_GetProcAddress(void *module, const char *procName)
{
    LOG_EMULATED();

    assert(module != NULL);
    assert(procName != NULL);

    const LibraryTable *lib = (const LibraryTable *)module;
    const SymbolTable *found = NULL;

    for (const SymbolTable *s = lib->symbolTable; s->symbolName != NULL; s++) {
        if (symbol_compare(s->symbolName, procName)) {
            found = s;
            break;
        }
    }

    if (found == NULL) {
        fprintf(stderr, "WARNING: Symbol '");
        fprintf(stderr, symbol_is_ordinal(procName) ? "ORD:%p" : "%s", procName);
        fprintf(stderr, "' not found on library %s.\n", lib->libraryName);
    }

    return found != NULL ? found->symbol : NULL;
}
MK_TRAMPOLINE_32TO64(KERNEL32_GetProcAddress, 2)

static const SymbolTable KERNEL32_SYMBOLS[] = {
    { "GetCommandLineA", KERNEL32_GetCommandLineA_32to64 },
    { "GlobalFree", KERNEL32_GlobalFree_32to64 },
    { "CreateThread", KERNEL32_CreateThread_32to64 },
    { "GetModuleHandleA", KERNEL32_GetModuleHandleA_32to64 },
    { "LeaveCriticalSection", KERNEL32_LeaveCriticalSection_32to64 },
    { "ExitProcess", KERNEL32_ExitProcess_32to64 },
    { "InitializeCriticalSection", KERNEL32_InitializeCriticalSection_32to64 },
    { "SetThreadPriority", KERNEL32_SetThreadPriority_32to64 },
    { "EnterCriticalSection", KERNEL32_EnterCriticalSection_32to64 },
    { "CloseHandle", KERNEL32_CloseHandle_32to64 },
    { "DeleteCriticalSection", KERNEL32_DeleteCriticalSection_32to64 },
    { "GlobalAlloc", KERNEL32_GlobalAlloc_32to64 },
    { "Sleep", KERNEL32_Sleep_32to64 },
    { "TerminateThread", KERNEL32_TerminateThread_32to64 },
    { "LoadLibraryA", KERNEL32_LoadLibraryA_32to64 },
    { "GetProcAddress", KERNEL32_GetProcAddress_32to64 },
    { NULL, NULL }
};

// ------
// USER32
// ------

typedef intptr_t (*DialogProc)(void *hdlg, uint32_t msg, uintptr_t wParam, intptr_t lParam);
typedef struct MSG
{
    void *hwnd;
    uint32_t message;
    uintptr_t wParam;
    intptr_t lParam;
} MSG;
#define PM_REMOVE 1
#define WM_CREATE 0x1
#define WM_DESTROY 0x2
#define WM_PAINT 0xf
#define WM_QUIT 0x12
#define WM_KEYDOWN 0x100
#define WM_SYSKEYDOWN 0x104
#define WM_COMMAND 0x111
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SM_CYSCAPTION 4
#define SPI_GETBORDER 5
#define MB_ICONERROR 0x10

// **WINDOW**

typedef struct HWND {
    SDL_Window *sdl_window;
} HWND;

typedef intptr_t (*WindowProc)(void *hwnd, uint32_t msg, uintptr_t wParam, intptr_t lParam);

typedef struct USER32_WindowClassObject
{
    WindowProc windowProc;
    const char *name;
    struct USER32_WindowClassObject *next;
} USER32_WindowClassObject;

static USER32_WindowClassObject *WINDOWCLASS_HEAD = NULL;
static const char *WINDOWDATA_WINDOWPROC = "WindowProc";
static const char *WINDOWDATA_HWND = "HWND";

static void free_windowclass_list(void)
{
    while (WINDOWCLASS_HEAD != NULL) {
        USER32_WindowClassObject *next = WINDOWCLASS_HEAD->next;
        free32(WINDOWCLASS_HEAD);
        WINDOWCLASS_HEAD = next;
    }
}

API_CALLBACK void *USER32_RegisterClassA(const void *wndClass)
{
    LOG_EMULATED();

    assert(wndClass != NULL);

    WindowProc windowProc = (WindowProc)(uintptr_t)*(uint32_t *)((char*)wndClass + 4);
    const char *className = (const char *)(uintptr_t)*(uint32_t *)((char*)wndClass + 36);

    USER32_WindowClassObject *classobj = malloc32(sizeof(USER32_WindowClassObject));
    classobj->windowProc = windowProc;
    classobj->name = className;
    classobj->next = WINDOWCLASS_HEAD;
    WINDOWCLASS_HEAD = classobj;

    return (void *)classobj; // Doesn't really matter
}
MK_TRAMPOLINE_32TO64(USER32_RegisterClassA, 1)

API_CALLBACK void *USER32_CreateWindowExA(
    uint32_t UNUSED(exStyle), const char *className, const char *UNUSED(windowName), uint32_t UNUSED(style),
    int UNUSED(x), int UNUSED(y), int UNUSED(width), int UNUSED(height),
    void *UNUSED(hwndParent), void *UNUSED(menu), void *UNUSED(instance), void *UNUSED(pparam))
{
    LOG_EMULATED();

    // Find class
    USER32_WindowClassObject *class = WINDOWCLASS_HEAD;
    while (class != NULL && strcmp(className, class->name) != 0)
        class = class->next;
    assert(class != NULL);

    // Create window and associate windowproc for later calling
    SDL_Window *sdl_window = SDL_CreateWindow("HEAVEN7",
                                              SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                                              123, 123, 0); // Actual size will be set later
    if (sdl_window == NULL) {
        fprintf(stderr, "Couldn't open SDL window: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }
    SDL_SetWindowData(sdl_window, WINDOWDATA_WINDOWPROC, class->windowProc);

    // Create HWND, and associate it so we can recover later it from SDL events
    HWND *hwnd = malloc32(sizeof(HWND));
    hwnd->sdl_window = sdl_window;
    SDL_SetWindowData(sdl_window, WINDOWDATA_HWND, hwnd);

    // Generate window creation event
    Call32(class->windowProc, 4, (void *)hwnd, WM_CREATE, 0, 0);
    return hwnd;
}
MK_TRAMPOLINE_32TO64(USER32_CreateWindowExA, 12)

API_CALLBACK uint32_t USER32_ShowWindow(void *hwnd, uint32_t cmdshow)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(cmdshow == 1);

    return 0;
}
MK_TRAMPOLINE_32TO64(USER32_ShowWindow, 2)

API_CALLBACK intptr_t USER32_DefWindowProcA(void *UNUSED(hwnd), uint32_t UNUSED(msg),
    uintptr_t UNUSED(wParam), intptr_t UNUSED(lParam))
{
    LOG_EMULATED();
    return 0;
}
MK_TRAMPOLINE_32TO64(USER32_DefWindowProcA, 4)

API_CALLBACK uint32_t USER32_PeekMessageA(
      void *msg, void *UNUSED(hWnd),
      uint32_t UNUSED(msgFilterMin), uint32_t UNUSED(msgFilterMax),
      uint32_t UNUSED(removeMsg))
{
    LOG_EMULATED();

    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        if (event.type == SDL_WINDOWEVENT) {
            // We really only need to send WM_DESTROY window messages here...
            // But we also send any other messge as WM_PAINT so we can keep
            // wndProc busy and receive calls to DefWindowProcA later
            uint32_t message = event.window.event == SDL_WINDOWEVENT_CLOSE
                ? WM_DESTROY : WM_PAINT;

            SDL_Window *window = SDL_GetWindowFromID(event.window.windowID);
            HWND *hwnd = (HWND *)SDL_GetWindowData(window, WINDOWDATA_HWND);
            assert(hwnd != NULL);
            *(uint32_t *)((char*)msg + 0)  = as32bitptr(hwnd);
            *(uint32_t *)((char*)msg + 4)  = message;
            *(uint32_t *)((char*)msg + 8)  = 0;
            *(int32_t *)((char*)msg + 12) = 0;
            return 1;
        } else if (event.type == SDL_QUIT) {
            *(uint32_t *)((char*)msg + 0)  = as32bitptr(NULL);
            *(uint32_t *)((char*)msg + 4)  = WM_QUIT;
            *(uint32_t *)((char*)msg + 8)  = 0;
            *(int32_t *)((char*)msg + 12) = 0;
            return 1;
        }
    }

    return 0;
}
MK_TRAMPOLINE_32TO64(USER32_PeekMessageA, 5)

API_CALLBACK void USER32_DispatchMessageA(const void *msg)
{
    LOG_EMULATED();

    HWND *hwnd = (HWND *)(uintptr_t)*(uint32_t *)((char*)msg + 0);
    uint32_t message  = *(uint32_t *)((char*)msg + 4);
    uint32_t wParam = *(uint32_t *)((char*)msg + 8);
    int32_t lParam = *(uint32_t *)((char*)msg + 12);

    WindowProc windowProc = (WindowProc)SDL_GetWindowData(hwnd->sdl_window, WINDOWDATA_WINDOWPROC);
    Call32(windowProc, 4, hwnd, message, wParam, lParam);
}
MK_TRAMPOLINE_32TO64(USER32_DispatchMessageA, 1)

API_CALLBACK uint32_t USER32_DestroyWindow(void *hwnd)
{
    LOG_EMULATED();

    assert(hwnd != NULL);

    SDL_DestroyWindow(((HWND *)hwnd)->sdl_window);
    free32(hwnd);
    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_DestroyWindow, 1)

API_CALLBACK uint32_t USER32_ClientToScreen(void *hwnd, void *point)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(point != NULL);

    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_ClientToScreen, 2)

API_CALLBACK uint32_t USER32_GetClientRect(void *hwnd, void *rect)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(rect != NULL);

    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_GetClientRect, 2)

// **DIALOG**
API_CALLBACK uint32_t USER32_DialogBoxIndirectParamA(
    void *UNUSED(instance), void *UNUSED(dialogTemplate),
    void *UNUSED(hwndParent), DialogProc dialogFunc, void *UNUSED(initParam))
{
    LOG_EMULATED();

    Call32(dialogFunc, 4, NULL, WM_COMMAND, 1 /* Accept button */, 12345);

    if (resolution_hack) {
        ushort *resolutionTable = (ushort *)0x410027;
        SDL_DisplayMode current;
        SDL_GetCurrentDisplayMode(0, &current);
        resolutionTable[SETTING_RESOLUTION*2+0] = current.w;
        resolutionTable[SETTING_RESOLUTION*2+1] = current.h;
    }
    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_DialogBoxIndirectParamA, 5)

API_CALLBACK intptr_t USER32_SendDlgItemMessageA(void *UNUSED(hdlg),
    int controlid, uint32_t UNUSED(msg), uintptr_t UNUSED(wParam), intptr_t UNUSED(lParam))
{
    LOG_EMULATED();

    if (controlid == 0x3EB) // Resolution combobox
        return SETTING_RESOLUTION;
    if (controlid == 0x3EC) // Tracer combobox
        return SETTING_TRACER;
    if (controlid == 0x3F1) // Sound combobox
        return SETTING_SOUND;
    if (controlid == 0x3EE) // Windowed checkbox
        return SETTING_WINDOWED;
    if (controlid == 0x3ED) // No text checkbox
        return SETTING_NOTEXT;
    if (controlid == 0x3EF) // Looping checkbox
        return SETTING_LOOP;

    assert(0);
}
MK_TRAMPOLINE_32TO64(USER32_SendDlgItemMessageA, 5)

API_CALLBACK uint32_t USER32_EndDialog(void *UNUSED(hdlg), intptr_t UNUSED(result))
{
    LOG_EMULATED();

    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_EndDialog, 2)

// **MISC**

API_CALLBACK int USER32_MessageBoxA(void *hwnd, const char *text, const char *caption, uint32_t UNUSED(type))
{
    LOG_EMULATED();
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, caption, text, ((HWND *)hwnd)->sdl_window);
    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_MessageBoxA, 4)

API_CALLBACK uint32_t USER32_OffsetRect(void *rect, int UNUSED(dx), int UNUSED(dy))
{
    LOG_EMULATED();

    assert(rect != NULL);
    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_OffsetRect, 3)

API_CALLBACK int USER32_GetSystemMetrics(int index)
{
    LOG_EMULATED();

    if (index == SM_CXSCREEN)
        return 1920;
    else if (index == SM_CYSCREEN)
        return 1080;
    else if (index == SM_CYSCAPTION)
        return 19;
    else
        assert(0);
}
MK_TRAMPOLINE_32TO64(USER32_GetSystemMetrics, 1)

API_CALLBACK uint32_t USER32_SystemParametersInfoA(
    uint32_t action, uint32_t wParam, void *pparam, uint32_t winini)
{
    LOG_EMULATED();

    assert(action == SPI_GETBORDER);
    assert(wParam == 0);
    assert(pparam != NULL);
    assert(winini == 0);

    *(uint32_t *)pparam = 1;
    return 1;
}
MK_TRAMPOLINE_32TO64(USER32_SystemParametersInfoA, 4)

API_CALLBACK void *USER32_SetCursor(void *cursor)
{
    LOG_EMULATED();
    SDL_ShowCursor(cursor != NULL ? SDL_ENABLE : SDL_DISABLE);
    return NULL;
}
MK_TRAMPOLINE_32TO64(USER32_SetCursor, 1)

static const SymbolTable USER32_SYMBOLS[] = {
    { "CreateWindowExA", USER32_CreateWindowExA_32to64 },
    { "EndDialog", USER32_EndDialog_32to64 },
    { "OffsetRect", USER32_OffsetRect_32to64 },
    { "ClientToScreen", USER32_ClientToScreen_32to64 },
    { "GetSystemMetrics", USER32_GetSystemMetrics_32to64 },
    { "SetCursor", USER32_SetCursor_32to64 },
    { "DestroyWindow", USER32_DestroyWindow_32to64 },
    { "ShowWindow", USER32_ShowWindow_32to64 },
    { "SystemParametersInfoA", USER32_SystemParametersInfoA_32to64 },
    { "GetClientRect", USER32_GetClientRect_32to64 },
    { "RegisterClassA", USER32_RegisterClassA_32to64 },
    { "MessageBoxA", USER32_MessageBoxA_32to64 },
    { "DispatchMessageA", USER32_DispatchMessageA_32to64 },
    { "DefWindowProcA", USER32_DefWindowProcA_32to64 },
    { "PeekMessageA", USER32_PeekMessageA_32to64 },
    { "DialogBoxIndirectParamA", USER32_DialogBoxIndirectParamA_32to64 },
    { "SendDlgItemMessageA", USER32_SendDlgItemMessageA_32to64 },
    { NULL, NULL }
};

// -----
// WINMM
// -----

API_CALLBACK uint32_t WINMM_timeGetTime(void)
{
    LOG_EMULATED();

    return SDL_GetTicks() * SPEEDUP_FACTOR;
}
MK_TRAMPOLINE_32TO64(WINMM_timeGetTime, 0)

static const SymbolTable WINMM_SYMBOLS[] = {
    { "timeGetTime", WINMM_timeGetTime_32to64 },
    { NULL, NULL }
};

// -----
// DDRAW
// -----

#define DDSCL_FULLSCREEN 0x1
#define DDSCL_EXCLUSIVE 0x10
#define DDSCAPS_PRIMARYSURFACE 0x200

typedef struct DDRAW_Surface_Object
{
    uint32_t vtableptr;

    bool is_primary;
    SDL_Renderer *renderer;
    SDL_Texture *texture;

    void *sdl_pixbuf;
    int sdl_pixbuf_size;

    void *lo32_for_sdl_pixbuf;
} DDRAW_Surface_Object;

API_CALLBACK uint32_t DDRAW_Surface_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    DDRAW_Surface_Object *surfaceobj = cominterface;
    if (!surfaceobj->is_primary) {
        SDL_DestroyTexture(surfaceobj->texture);
        SDL_DestroyRenderer(surfaceobj->renderer);
    }
    free32(surfaceobj);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_Release, 1)

API_CALLBACK void *DDRAW_Surface_Blt(
    void *cominterface, void *UNUSED(rect1), void *UNUSED(surface),
    void *UNUSED(rect2), uint32_t UNUSED(flags), void *UNUSED(bltfx))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_Blt, 6)

API_CALLBACK void *DDRAW_Surface_GetSurfaceDesc(void *cominterface, void *surface_desc)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(surface_desc != NULL);

    // Those are the values on my computer, I think it's safe to assume
    // nowaways we can always get RGBA8 anyway...
    // ddrawsurfacedesc->pixelformat->dwRGBBitCount
    *((uint32_t *)surface_desc+0x54/4) = 32;
    // ddrawsurfacedesc->pixelformat->dwRBitMask
    *((uint32_t *)surface_desc+0x58/4) = 0x00FF0000;
    // ddrawsurfacedesc->pixelformat->dwGBitMask
    *((uint32_t *)surface_desc+0x5C/4) = 0x0000FF00;

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_GetSurfaceDesc, 2)

API_CALLBACK void *DDRAW_Surface_IsLost(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_IsLost, 1)

API_CALLBACK void *DDRAW_Surface_Restore(void *cominterface)
{
    // This is never called in practice since our IsLost does never return
    // true since there isn't a SDL equivalent
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_Restore, 1)

API_CALLBACK void *DDRAW_Surface_Lock(void *cominterface, void *rect, void *surface_desc, uint32_t flags, void *event)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect == NULL);
    assert(surface_desc != NULL);
    assert(flags == 1);
    assert(event == NULL);

    DDRAW_Surface_Object *surfaceobj = (DDRAW_Surface_Object *)cominterface;
    assert(!surfaceobj->is_primary);
    assert(surfaceobj->sdl_pixbuf == NULL);
    assert(surfaceobj->lo32_for_sdl_pixbuf == NULL);

    int height;
    if (SDL_QueryTexture(surfaceobj->texture, NULL, NULL, NULL, &height) < 0) {
        fprintf(stderr, "Couldn't query SDL texture: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    int pitch;
    if (SDL_LockTexture(surfaceobj->texture, NULL, &surfaceobj->sdl_pixbuf, &pitch) < 0) {
        fprintf(stderr, "Couldn't lock SDL texture: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    surfaceobj->sdl_pixbuf_size = height * pitch;
    surfaceobj->lo32_for_sdl_pixbuf = malloc32(surfaceobj->sdl_pixbuf_size);

    // pitch
    *((uint32_t *)surface_desc+0x10/4) = (uint32_t)pitch;
    // Surface data pointer
    *(uint32_t *)((char*)surface_desc + 0x24) = as32bitptr(surfaceobj->lo32_for_sdl_pixbuf);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_Lock, 5)

API_CALLBACK void *DDRAW_Surface_SetClipper(void *cominterface, void *clipper)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(clipper != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_SetClipper, 2)

API_CALLBACK void *DDRAW_Surface_Unlock(void *cominterface, void *rect)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect != NULL);

    DDRAW_Surface_Object *surfaceobj = (DDRAW_Surface_Object *)cominterface;
    assert(!surfaceobj->is_primary);
    assert(surfaceobj->sdl_pixbuf != NULL);
    assert(surfaceobj->sdl_pixbuf_size != 0);
    assert(surfaceobj->lo32_for_sdl_pixbuf != NULL);

    memcpy(surfaceobj->sdl_pixbuf, surfaceobj->lo32_for_sdl_pixbuf, surfaceobj->sdl_pixbuf_size);

    SDL_UnlockTexture(surfaceobj->texture);
    free32(surfaceobj->lo32_for_sdl_pixbuf);
    surfaceobj->sdl_pixbuf = NULL;
    surfaceobj->sdl_pixbuf_size = 0;
    surfaceobj->lo32_for_sdl_pixbuf = NULL;

    SDL_RenderClear(surfaceobj->renderer);
    SDL_RenderCopy(surfaceobj->renderer, surfaceobj->texture, NULL, NULL);
    SDL_RenderPresent(surfaceobj->renderer);

    return  0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Surface_Unlock, 2)

static uint32_t DDRAW_Surface_VTABLE[256];
__attribute__((constructor)) static void init_DDRAW_Surface_VTABLE(void) {
    uint32_t *vt = DDRAW_Surface_VTABLE;
    vt[0x08/4] = as32bitptr(DDRAW_Surface_Release_32to64);
    vt[0x14/4] = as32bitptr(DDRAW_Surface_Blt_32to64);
    vt[0x58/4] = as32bitptr(DDRAW_Surface_GetSurfaceDesc_32to64);
    vt[0x60/4] = as32bitptr(DDRAW_Surface_IsLost_32to64);
    vt[0x64/4] = as32bitptr(DDRAW_Surface_Lock_32to64);
    vt[0x6C/4] = as32bitptr(DDRAW_Surface_Restore_32to64);
    vt[0x70/4] = as32bitptr(DDRAW_Surface_SetClipper_32to64);
    vt[0x80/4] = as32bitptr(DDRAW_Surface_Unlock_32to64);
}

API_CALLBACK uint32_t DDRAW_Clipper_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Clipper_Release, 1)

API_CALLBACK void *DDRAW_Clipper_SetHWnd(void *cominterface, uint32_t flags, void *hwnd)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(hwnd != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Clipper_SetHWnd, 3)

static uint32_t DDRAW_Clipper_VTABLE[256];
__attribute__((constructor)) static void init_DDRAW_Clipper_VTABLE(void) {
    uint32_t *vt = DDRAW_Clipper_VTABLE;
    vt[0x08/4] = as32bitptr(DDRAW_Clipper_Release_32to64);
    vt[0x20/4] = as32bitptr(DDRAW_Clipper_SetHWnd_32to64);
}

typedef struct DDRAW_Clipper_Object
{
    uint32_t vtableptr;
} DDRAW_Clipper_Object;

typedef struct DDRAW_Object
{
    uint32_t vtableptr;
    SDL_Window *sdl_window;
} DDRAW_Object;

API_CALLBACK uint32_t DDRAW_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    free32((DDRAW_Object *)cominterface);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_Release, 1)

API_CALLBACK void *DDRAW_CreateClipper(void *cominterface, uint32_t flags, void **clipper, void *outer)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(clipper != NULL);
    assert(outer == 0);

    static DDRAW_Clipper_Object DDRAW_Clipper_NULLOBJECT = {};
    DDRAW_Clipper_NULLOBJECT.vtableptr = as32bitptr(DDRAW_Clipper_VTABLE);
    *(uint32_t *)clipper = as32bitptr(&DDRAW_Clipper_NULLOBJECT);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_CreateClipper, 4)

API_CALLBACK void *DDRAW_CreateSurface(
    void *cominterface, void *surface_desc, void **surface, void *outer)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(surface_desc != NULL);
    assert(surface != NULL);
    assert(outer == NULL);

    DDRAW_Object *ddraw = (DDRAW_Object *)cominterface;
    assert(ddraw->sdl_window != NULL);

    bool is_primary_surface = *(uint32_t *)((uint8_t *)surface_desc + 104) & DDSCAPS_PRIMARYSURFACE;
    uint32_t raw_height = *(uint32_t *)((uint8_t *)surface_desc + 8);
    uint32_t raw_width = *(uint32_t *)((uint8_t *)surface_desc + 12);
    assert(raw_height < INT_MAX && raw_width < INT_MAX);
    int height = (int)raw_height, width = (int)raw_width;

    DDRAW_Surface_Object *surfaceobj = malloc32(sizeof(DDRAW_Surface_Object));
    surfaceobj->vtableptr = as32bitptr(DDRAW_Surface_VTABLE);
    surfaceobj->is_primary = is_primary_surface;
    surfaceobj->renderer = NULL;
    surfaceobj->texture = NULL;
    surfaceobj->sdl_pixbuf = NULL;
    surfaceobj->sdl_pixbuf_size = 0;
    surfaceobj->lo32_for_sdl_pixbuf = NULL;

    if (!is_primary_surface) {
        SDL_SetWindowSize(ddraw->sdl_window, width, height);

        surfaceobj->renderer = SDL_CreateRenderer(ddraw->sdl_window, -1, 0);
        if (surfaceobj->renderer == NULL) {
            fprintf(stderr, "Couldn't open SDL renderer: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }

        surfaceobj->texture = SDL_CreateTexture(surfaceobj->renderer, SDL_PIXELFORMAT_ARGB8888,
                                                SDL_TEXTUREACCESS_STREAMING, width, height);
        if (surfaceobj->texture == NULL) {
            fprintf(stderr, "Couldn't open SDL texture: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }
    }

    *((uint32_t *)surface) = as32bitptr(surfaceobj);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_CreateSurface, 4)

API_CALLBACK void *DDRAW_RestoreDisplayMode(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_RestoreDisplayMode, 1)

API_CALLBACK void *DDRAW_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t flags)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd != NULL);

    DDRAW_Object *ddraw = (DDRAW_Object *)cominterface;
    assert(ddraw->sdl_window == NULL);
    ddraw->sdl_window = ((HWND *)hwnd)->sdl_window;

    if (flags & (DDSCL_FULLSCREEN | DDSCL_EXCLUSIVE)) {
        SDL_SetWindowFullscreen(ddraw->sdl_window, SDL_WINDOW_FULLSCREEN_DESKTOP);
    }

    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_SetCooperativeLevel, 3)

API_CALLBACK void *DDRAW_SetDisplayMode(void *cominterface,
    uint32_t UNUSED(width), uint32_t UNUSED(height), uint32_t bpp)
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    assert(bpp == 32);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_SetDisplayMode, 4)

static uint32_t DDRAW_VTABLE[256];
__attribute__((constructor)) static void init_DDRAW_VTABLE(void) {
    uint32_t *vt = DDRAW_VTABLE;
    vt[0x08/4] = as32bitptr(DDRAW_Release_32to64);
    vt[0x10/4] = as32bitptr(DDRAW_CreateClipper_32to64);
    vt[0x18/4] = as32bitptr(DDRAW_CreateSurface_32to64);
    vt[0x4C/4] = as32bitptr(DDRAW_RestoreDisplayMode_32to64);
    vt[0x50/4] = as32bitptr(DDRAW_SetCooperativeLevel_32to64);
    vt[0x54/4] = as32bitptr(DDRAW_SetDisplayMode_32to64);
}

API_CALLBACK void *DDRAW_DirectDrawCreate(
    void *guid, void **lpdd, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpdd != NULL);
    assert(unkouter == NULL);

    DDRAW_Object *ddraw = malloc32(sizeof(DDRAW_Object));
    ddraw->vtableptr = as32bitptr(DDRAW_VTABLE);
    ddraw->sdl_window = NULL;
    *((uint32_t *)lpdd) = as32bitptr(ddraw);
    return 0;
}
MK_TRAMPOLINE_32TO64(DDRAW_DirectDrawCreate, 3)

static const SymbolTable DDRAW_SYMBOLS[] = {
    { "DirectDrawCreate", DDRAW_DirectDrawCreate_32to64 },
    { NULL, NULL }
};

// -----
// SETUP
// -----

static const LibraryTable GLOBAL_LIBRARY_TABLE_TMP[] = {
    { "ddraw.dll", DDRAW_SYMBOLS },
    { "dsound.dll", DSOUND_SYMBOLS },
    { "kernel32.dll", KERNEL32_SYMBOLS },
    { "user32.dll", USER32_SYMBOLS },
    { "winmm.dll", WINMM_SYMBOLS },
    { NULL, NULL }
};

static const LibraryTable *GLOBAL_LIBRARY_TABLE = GLOBAL_LIBRARY_TABLE_TMP;

static int is_simple_command(const char *s) {
    for (size_t i = 0; i < strlen(s); i++)
        // List of characters from python's shlex.quote
        if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-", s[i]))
            return false;
    return true;
}

// Converts a argc / argv pair to a single command line string,
// quoting arguments and escaping characters if necessary
// e.g. argv = ['./HEAVEN7L', 'w', 'the game', 'the ga"\me']
// -> './HEAVEN7L w "the game" "the ga\"\\me"'
// NOTE: This function is not bulletproof (e.g. UTF-8 support, )
static char *ArgvToCommandLine(int argc, char *argv[]) {
    size_t maxlen = 1;
    for (int argi = 0; argi < argc; argi++)
        maxlen += strlen(argv[argi]) * 2 + 3;

    char *command_line = malloc32(maxlen);
    if (command_line == NULL)
        return NULL;

    char *cmdp = command_line;
    for (int argi = 0; argi < argc; argi++) {
        if (is_simple_command(argv[argi])) {
            strcpy(cmdp, argv[argi]);
            cmdp += strlen(argv[argi]);
        } else {
            *cmdp++ = '"';
            for (size_t i = 0; i < strlen(argv[argi]); i++) {
                if (argv[argi][i] == '"' || argv[argi][i] == '\\')
                    *cmdp++ = '\\';
                *cmdp++ = argv[argi][i];
            }
            *cmdp++ = '"';
        }

        if (argi != argc - 1)
            *cmdp++ = ' ';
    }
    *cmdp = '\0';
    return command_line;
}

static void free_command_line(void) {
    free32(COMMANDLINE);
}

bool WinAPI2SDL_Init(int argc, char *argv[]) {
    COMMANDLINE = ArgvToCommandLine(argc, argv);
    if (COMMANDLINE == NULL) {
        fprintf(stderr, "ERROR: Failed to set up command line.\n");
        return false;
    }

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
        fprintf(stderr, "WARNING: Failed to initialize SDL.\n");
        free32(COMMANDLINE);
        return false;
    }

    return true;
}

void WinAPI2SDL_Quit() {
    free_windowclass_list();
    free_command_line();
    SDL_Quit();
}
