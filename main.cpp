#include <jni.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <android/log.h>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

#define LOG_TAG "IL2CPP_PATCH"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ─── Offsets ──────────────────────────────────────────────────────────────────
#ifdef __aarch64__
// ARM64 (arm64-v8a)
static constexpr uintptr_t OFF_RESET_GUEST_1 = 0x635DB70;
static constexpr uintptr_t OFF_RESET_GUEST_2 = 0x635DC24;
#else
// ARM32 (armeabi-v7a)
static constexpr uintptr_t OFF_RESET_GUEST_1 = 0x5340504;
static constexpr uintptr_t OFF_RESET_GUEST_2 = 0x53405EC;
#endif

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Returns the load base address of a mapped library.
static uintptr_t getLibBase(const char *libName) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libName) && strstr(line, "r-xp")) {
            base = (uintptr_t)strtoul(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

// Writes `size` bytes at `addr`, temporarily making the page writable.
static bool patchBytes(uintptr_t addr, const uint8_t *patch, size_t size) {
    long pageSize   = sysconf(_SC_PAGESIZE);
    uintptr_t page  = addr & ~(uintptr_t)(pageSize - 1);
    size_t    range = pageSize * 2;

    if (mprotect((void *)page, range, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect RWX failed at 0x%lx", (unsigned long)addr);
        return false;
    }
    memcpy((void *)addr, patch, size);
    // Flush instruction cache so the CPU sees the new bytes.
    __builtin___clear_cache((char *)addr, (char *)(addr + size));
    mprotect((void *)page, range, PROT_READ | PROT_EXEC);
    LOGI("Patched 0x%lx (%zu bytes)", (unsigned long)addr, size);
    return true;
}

// ─── Patch: reset_guest → always return true ──────────────────────────────────

static void patchResetGuest(uintptr_t base) {
#ifdef __aarch64__
    // ARM64: MOV W0, #1  (20 00 80 52)
    //        RET          (C0 03 5F D6)
    const uint8_t retTrue[] = { 0x20, 0x00, 0x80, 0x52,
                                 0xC0, 0x03, 0x5F, 0xD6 };
#else
    // ARM32: MOV R0, #1  (01 00 A0 E3)
    //        BX  LR      (1E FF 2F E1)
    const uint8_t retTrue[] = { 0x01, 0x00, 0xA0, 0xE3,
                                 0x1E, 0xFF, 0x2F, 0xE1 };
#endif

    patchBytes(base + OFF_RESET_GUEST_1, retTrue, sizeof(retTrue));
    patchBytes(base + OFF_RESET_GUEST_2, retTrue, sizeof(retTrue));
}

// ─── JNI entry point ──────────────────────────────────────────────────────────

extern "C"
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    uintptr_t base = getLibBase("libil2cpp.so");
    if (!base) {
        LOGE("libil2cpp.so base not found");
        return JNI_VERSION_1_6;
    }
    LOGI("libil2cpp.so base: 0x%lx", (unsigned long)base);

#ifdef __aarch64__
    LOGI("Architecture: ARM64 (arm64-v8a)");
#else
    LOGI("Architecture: ARM32 (armeabi-v7a)");
#endif

    patchResetGuest(base);

    return JNI_VERSION_1_6;
}
