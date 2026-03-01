#pragma once
/*
 * rust_sdk.h  -  Rust game memory reader for external ESP
 *
 * Uses DriverComm (kernel driver) to read game memory.
 * All entity iteration goes through BaseNetworkable entity list.
 */

#include <TlHelp32.h>
#include <Windows.h>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "driver_comm.h"
#include "il2cpp_resolver.h"
#include "rust_offsets.h"

/* ── Math types ──────────────────────────────────────────────────── */

struct Vec3 {
  float x, y, z;
  Vec3() : x(0), y(0), z(0) {}
  Vec3(float x, float y, float z) : x(x), y(y), z(z) {}

  Vec3 operator-(const Vec3 &o) const { return {x - o.x, y - o.y, z - o.z}; }
  Vec3 operator+(const Vec3 &o) const { return {x + o.x, y + o.y, z + o.z}; }
  Vec3 operator*(const Vec3 &o) const { return {x * o.x, y * o.y, z * o.z}; }
  Vec3 operator*(float s) const { return {x * s, y * s, z * s}; }
  Vec3 operator/(float s) const { float inv = 1.0f / s; return {x * inv, y * inv, z * inv}; }
  Vec3& operator+=(const Vec3 &o) { x += o.x; y += o.y; z += o.z; return *this; }
  Vec3& operator*=(float s) { x *= s; y *= s; z *= s; return *this; }
  float& operator[](int i) { return (&x)[i]; }
  float operator[](int i) const { return (&x)[i]; }
  float Length() const { return sqrtf(x * x + y * y + z * z); }
  float length_squared() const { return x * x + y * y + z * z; }
  float dot(const Vec3 &o) const { return x * o.x + y * o.y + z * o.z; }
  Vec3 cross(const Vec3 &o) const {
    return {y * o.z - z * o.y, z * o.x - x * o.z, x * o.y - y * o.x};
  }
  Vec3 normalize() const {
    float len = Length();
    if (len < 1e-6f) return {0, 0, 0};
    return {x / len, y / len, z / len};
  }
  bool is_empty() const { return x == 0.f && y == 0.f && z == 0.f; }
};

struct Vec4 {
  float x, y, z, w;
  Vec4() : x(0), y(0), z(0), w(1) {}
  Vec4(float x, float y, float z, float w) : x(x), y(y), z(z), w(w) {}

  Vec3 operator*(const Vec3 &rhs) const {
    float x2 = x * 2.0f;
    float y2 = y * 2.0f;
    float z2 = z * 2.0f;
    float xx = x * x2;
    float yy = y * y2;
    float zz = z * z2;
    float xy = x * y2;
    float xz = x * z2;
    float yz = y * z2;
    float wx = w * x2;
    float wy = w * y2;
    float wz = w * z2;

    Vec3 res;
    res.x = (1.0f - (yy + zz)) * rhs.x + (xy - wz) * rhs.y + (xz + wy) * rhs.z;
    res.y = (xy + wz) * rhs.x + (1.0f - (xx + zz)) * rhs.y + (yz - wx) * rhs.z;
    res.z = (xz - wy) * rhs.x + (yz + wx) * rhs.y + (1.0f - (xx + yy)) * rhs.z;
    return res;
  }

  Vec4 operator*(const Vec4 &q) const {
    return Vec4(w * q.x + x * q.w + y * q.z - z * q.y,
                w * q.y - x * q.z + y * q.w + z * q.x,
                w * q.z + x * q.y - y * q.x + z * q.w,
                w * q.w - x * q.x - y * q.y - z * q.z);
  }
  Vec3 rotate(const Vec3 &v) const { return (*this) * v; }
  Vec3 rotate_inv(const Vec3 &v) const { return conjugate() * v; }
  Vec4 conjugate() const { return Vec4(-x, -y, -z, w); }
};

struct Vec2 {
  float x, y;
};

struct ViewMatrix {
  float m[4][4];
};

/* ── Rust bone indices (character rig) ───────────────────────────── */
/*
 * Rust player model bone order (indices 6-11 are genital/censor bones):
 *   0=pelvis, 1=l_hip, 2=l_knee, 3=l_foot, 4=l_toe, 5=l_ankle_scale,
 *   6-11=genital/censor, 12=r_hip, 13=r_knee, 14=r_foot, 15=r_toe,
 *   16=r_ankle_scale, 17=spine1, 18=spine1a, 19=spine2, 20=spine3,
 *   21=spine4, 22=neck, 23=head, 24=jaw, 25=l_eye, 26=r_eye,
 *   27=l_clavicle, 28=l_upperarm, 29=l_forearm, 30=l_hand, 31-46=fingers,
 *   47=r_clavicle, 48=r_upperarm, 49=r_forearm, 50=r_hand
 */

enum RustBone {
  BONE_PELVIS = 1,
  BONE_L_HIP = 2,
  BONE_L_KNEE = 3,
  BONE_L_FOOT = 4,
  BONE_R_HIP = 13,
  BONE_R_KNEE = 14,
  BONE_R_FOOT = 15,
  BONE_SPINE1 = 18,
  BONE_SPINE2 = 20,
  BONE_SPINE3 = 21,
  BONE_SPINE4 = 22,
  BONE_L_CLAVICLE = 23,
  BONE_L_UPPER = 24,
  BONE_L_FOREARM = 25,
  BONE_L_HAND = 26,
  BONE_NECK = 46,
  BONE_HEAD = 47,
  BONE_R_CLAVICLE = 55,
  BONE_R_UPPER = 55,
  BONE_R_FOREARM = 56,
  BONE_R_HAND = 57,
  BONE_MAX = 80,
};

/* Skeleton connections for drawing (uses verified BoneList indices) */
struct BonePair {
  int from, to;
};
static const BonePair g_skeletonPairs[] = {
    // Spine + head
    {BONE_HEAD, BONE_SPINE4},
    {BONE_SPINE4, BONE_SPINE3},
    {BONE_SPINE3, BONE_SPINE2},
    {BONE_SPINE2, BONE_SPINE1},
    {BONE_SPINE1, BONE_PELVIS},
    // Left arm
    {BONE_SPINE4, BONE_L_UPPER},
    {BONE_L_UPPER, BONE_L_FOREARM},
    {BONE_L_FOREARM, BONE_L_HAND},
    // Right arm
    {BONE_SPINE4, BONE_R_UPPER},
    {BONE_R_UPPER, BONE_R_FOREARM},
    {BONE_R_FOREARM, BONE_R_HAND},
    // Left leg
    {BONE_PELVIS, BONE_L_HIP},
    {BONE_L_HIP, BONE_L_KNEE},
    {BONE_L_KNEE, BONE_L_FOOT},
    // Right leg
    {BONE_PELVIS, BONE_R_HIP},
    {BONE_R_HIP, BONE_R_KNEE},
    {BONE_R_KNEE, BONE_R_FOOT},
};
static const int g_skeletonPairCount =
    sizeof(g_skeletonPairs) / sizeof(g_skeletonPairs[0]);

/* ── Player info (output of ReadPlayer) ──────────────────────────── */

struct PlayerData {
  uintptr_t address;
  Vec3 position;
  Vec3 headPos; /* position + eye offset */
  std::wstring name;
  uint64_t teamID;
  uint32_t flags;
  uint32_t lifestate;
  bool isVisible;
  bool isSleeping;
  bool isWounded;
  float distance; /* filled by caller */
  float health;
  float maxHealth;
  std::vector<Vec3> bones; /* world-space bone positions (indexed by bone ID) */
  std::vector<std::string>
      hotbarItems; /* short names of belt items (up to 6 slots) */
  std::vector<std::string>
      wearItems; /* short names of wear items (clothing, up to 7 slots) */
};

/* ── Decryption helpers ──────────────────────────────────────────── */
/*
 * Rust (EAC-protected Unity/IL2CPP) encrypts some pointers.
 * The decryption routines are game-version-specific.
 * These implement the algorithms from the Feb 10 2026 patch.
 *
 * Since il2cpp_get_handle resolves GC handles, and we can't call
 * game code externally, we try the DIRECT pointer chain first.
 * If that fails (null/invalid), we fall back to manual decryption.
 */

namespace RustDecrypt {

/* ── Enhanced decrypt functions with multiple methods ──────────────────────── */

/* Method 1: Current UPDATE decrypt functions */
static uintptr_t DecryptClientEntities_Method1(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    v += 0xF1B06211u;
    uint32_t temp = v;
    v = (v << 14) | (temp >> 18);
    v ^= 0x24383967u;
    v -= 0x5801F290u;
    parts[i] = v;
  }
  return encrypted_qword;
}

/* Method 2: Alternative decrypt (common pattern) */
static uintptr_t DecryptClientEntities_Method2(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    v ^= 0x12345678u;
    uint32_t temp = v;
    v = (v << 8) | (temp >> 24);
    v += 0xABCDEF00u;
    parts[i] = v;
  }
  return encrypted_qword;
}

/* Method 3: Simple XOR (fallback) */
static uintptr_t DecryptClientEntities_Method3(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    parts[i] ^= 0x87654321u;
  }
  return encrypted_qword;
}

/* Method 4: No encryption (direct) */
static uintptr_t DecryptClientEntities_Method4(uintptr_t encrypted_qword) {
  return encrypted_qword;
}

/* Enhanced DecryptClientEntities with multiple methods */
static uintptr_t DecryptClientEntities(uintptr_t encrypted_qword, bool resetCache = false) {
  static int lastWorkingMethod = 0;
  static int failCount = 0;
  
  // Reset cache if requested
  if (resetCache) {
    lastWorkingMethod = 0;
    failCount = 0;
    printf("[DECRYPT] client_entities: Cache reset\n");
  }
  
  // Try the last working method first
  if (lastWorkingMethod > 0) {
    uintptr_t result = 0;
    switch (lastWorkingMethod) {
      case 1: result = DecryptClientEntities_Method1(encrypted_qword); break;
      case 2: result = DecryptClientEntities_Method2(encrypted_qword); break;
      case 3: result = DecryptClientEntities_Method3(encrypted_qword); break;
      case 4: result = DecryptClientEntities_Method4(encrypted_qword); break;
    }
    
    // Validate the result
    uint32_t handle = (uint32_t)(result & 0xFFFFFFFF);
    if (handle != 0 && handle < 0x10000000) {
      failCount = 0;
      return result;
    }
  }
  
  // Try all methods
  for (int method = 1; method <= 4; method++) {
    uintptr_t result = 0;
    switch (method) {
      case 1: result = DecryptClientEntities_Method1(encrypted_qword); break;
      case 2: result = DecryptClientEntities_Method2(encrypted_qword); break;
      case 3: result = DecryptClientEntities_Method3(encrypted_qword); break;
      case 4: result = DecryptClientEntities_Method4(encrypted_qword); break;
    }
    
    // Validate the result
    uint32_t handle = (uint32_t)(result & 0xFFFFFFFF);
    if (handle != 0 && handle < 0x10000000) {
      if (lastWorkingMethod != method) {
        printf("[DECRYPT] client_entities: Method %d now working (handle=0x%X)\n", method, handle);
        lastWorkingMethod = method;
      }
      failCount = 0;
      return result;
    }
  }
  
  failCount++;
  if (failCount % 100 == 1) {
    printf("[DECRYPT] client_entities: All methods failed (attempt %d)\n", failCount);
  }
  
  return 0;
}

// Reset function for client_entities decryption
inline void ResetClientEntitiesMethod() {
  // Call with resetCache flag
  DecryptClientEntities(0, true);
}

/* Decrypt entity_list pointer (NEW)
 * SHR 0x13, SHL 0x0D, OR, SUB 0x48F9C02E, XOR 0x6CCF6779 */
static uintptr_t DecryptEntityList(uintptr_t encrypted_qword, bool resetCache = false) {
  static int lastWorkingMethod = 0;
  static int failCount = 0;
  
  // Reset cache if requested
  if (resetCache) {
    lastWorkingMethod = 0;
    failCount = 0;
    printf("[DECRYPT] entity_list: Cache reset\n");
    return 0;
  }
  
  // For now, only one method for entity_list
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    uint32_t temp = v;
    v = (temp >> 19) | (v << 13);
    v -= 0x48F9C02Eu;
    v ^= 0x6CCF6779u;
    parts[i] = v;
  }
  return encrypted_qword;
}

// Reset function for entity_list decryption
inline void ResetEntityListMethod() {
  // Call with resetCache flag
  DecryptEntityList(0, true);
}

// Reset decryption method cache to force re-detection
inline void ResetDecryptionCache() {
  // Reset all static decryption method caches
  ResetClientEntitiesMethod();
  ResetEntityListMethod();
  
  printf("[DECRYPT] Reset all decryption method caches\n");
}

/* Decrypt player_eyes pointer (NEW)
 * SHR 0x1C, SHL 0x04, OR, ADD 0x6851055B, XOR 0x442249A6 */
static uintptr_t DecryptPlayerEyes(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    uint32_t temp = v;
    v = (temp >> 28) | (v << 4);
    v += 0x6851055Bu;
    v ^= 0x442249A6u;
    parts[i] = v;
  }
  return encrypted_qword;
}

/* Decrypt player_inventory pointer (NEW)
 * ADD 0x59558B36, XOR 0x2D277853, ADD 0x19F01F38, SHL 1, SHR 0x1F, OR */
static uintptr_t DecryptPlayerInventory(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    v += 0x59558B36u;
    v ^= 0x2D277853u;
    v += 0x19F01F38u;
    uint32_t temp = v;
    v = v + v; // SHL 1
    v |= (temp >> 31);
    parts[i] = v;
  }
  return encrypted_qword;
}

/* Decrypt cl_active_item (NEW)
 * ADD 0x290AB327, SHL 0x16, SHR 0x0A, OR, SUB 0x761F3138
 * Returns item UID directly (NOT a GC handle) */
static uintptr_t DecryptClActiveItem(uintptr_t encrypted_qword) {
  uint32_t *parts = (uint32_t *)&encrypted_qword;
  for (int i = 0; i < 2; i++) {
    uint32_t v = parts[i];
    v += 0x290AB327u;
    uint32_t temp = v;
    v = (v << 22) | (temp >> 10);
    v -= 0x761F3138u;
    parts[i] = v;
  }
  return encrypted_qword;
}

} // namespace RustDecrypt

/* ── Free pointer-validation helper (used by aimbot_wrapper.h too) ─ */

inline bool IsValidPtr(uintptr_t p) {
  return p > 0x10000ULL && p < 0x7FFFFFFFFFFF;
}

/* ── Forward declarations for globals used inside RustSDK ─────────── */
extern float g_recoilControl;

/* ── Main SDK class ──────────────────────────────────────────────── */

class RustSDK {
private:
  DriverComm *drv;
  DWORD pid = 0;
  uintptr_t gameAssembly = 0;
  bool attached = false;
  Il2CppResolver resolver;

  /* Cached object addresses to avoid repeated chain walks */
  uintptr_t entityBuffer = 0;
  int entityCount = 0;
  uintptr_t cachedLocalPlayer = 0;
  ULONGLONG lastLocalRefresh = 0;

public:
  /* Debug state for entity refresh chain — read by debug overlay */
  struct EntityChainDebug {
    int lastFailStep = 0; // 0=not run, 1-7=which step failed, 99=success
    uintptr_t typeInfo = 0;
    uintptr_t staticFields = 0;
    uintptr_t wrapper1 = 0;
    uintptr_t clientEntities = 0;
    uintptr_t wrapper2 = 0;
    uintptr_t entityList = 0;
    uintptr_t bufferList = 0;
    uintptr_t entityArray = 0;
    int rawCount = 0;
  } entDbg;

private:
  /* GC Handle table for resolving encrypted/managed pointers */
  uintptr_t gcHandleTable = 0;

  /* Address of the bitmap global (for scanning nearby for objects array) */
  uintptr_t bitmapGlobalAddr = 0;

  /* ── Bone hierarchy cache (cached transform data for fast bone reads) ── */

  struct TransformAccess {
    uintptr_t hierarchyAddr;
    int index;
  };

  struct trsX {
    Vec3 t;
    char pad0[4];
    Vec4 q;
    Vec3 s;
    char pad1[4];
  };

  struct HierarchyCache {
    uintptr_t hierarchyAddr = 0;
    uintptr_t localT = 0;
    uintptr_t parentI = 0;
    std::vector<trsX> transforms;
    std::vector<int> parents;
    bool valid = false;
    uint64_t lastAccess = 0;
    uint64_t lastUpdate = 0;
  };

  static constexpr int BONE_CACHE_SLOTS = 64;
  static constexpr int MAX_HIERARCHY_TRANSFORMS = 150;
  HierarchyCache boneCache[BONE_CACHE_SLOTS];

  template <typename T> bool ReadArray(uintptr_t addr, T *out, int count) {
    return ReadRaw(addr, out, (size_t)count * sizeof(T));
  }

  HierarchyCache *FindOrAllocateCache(uintptr_t hierarchyAddr) {
    static uint64_t accessCounter = 0;
    accessCounter++;
    for (auto &c : boneCache) {
      if (c.valid && c.hierarchyAddr == hierarchyAddr) {
        c.lastAccess = accessCounter;
        return &c;
      }
    }
    for (auto &c : boneCache) {
      if (!c.valid) {
        c.lastAccess = accessCounter;
        return &c;
      }
    }
    HierarchyCache *oldest = &boneCache[0];
    for (auto &c : boneCache) {
      if (c.lastAccess < oldest->lastAccess)
        oldest = &c;
    }
    oldest->valid = false;
    oldest->lastAccess = accessCounter;
    return oldest;
  }

  bool ValidateHierarchyCache(HierarchyCache *cache, uintptr_t hierarchyAddr) {
    if (!cache->valid || cache->hierarchyAddr != hierarchyAddr)
      return false;
    uintptr_t curLocalT = Read<uintptr_t>(hierarchyAddr + 0x18);
    uintptr_t curParentI = Read<uintptr_t>(hierarchyAddr + 0x20);
    if (!curLocalT || !curParentI)
      return false;
    return (cache->localT == curLocalT && cache->parentI == curParentI);
  }

  bool CacheHierarchy(uintptr_t hierarchyAddr) {
    if (!hierarchyAddr || !IsValidPtr(hierarchyAddr))
      return false;
    HierarchyCache *cache = FindOrAllocateCache(hierarchyAddr);
    uint64_t now = GetTickCount64();

    if (ValidateHierarchyCache(cache, hierarchyAddr)) {
      if ((now - cache->lastUpdate) < 5)
        return true;
      if (!ReadArray<trsX>(cache->localT, cache->transforms.data(),
                           MAX_HIERARCHY_TRANSFORMS)) {
        cache->valid = false;
        return false;
      }
      if (!ReadArray<int>(cache->parentI, cache->parents.data(),
                          MAX_HIERARCHY_TRANSFORMS)) {
        cache->valid = false;
        return false;
      }
      cache->lastUpdate = now;
      return true;
    }

    uintptr_t localT = Read<uintptr_t>(hierarchyAddr + 0x18);
    uintptr_t parentI = Read<uintptr_t>(hierarchyAddr + 0x20);
    if (!localT || !parentI) {
      cache->valid = false;
      return false;
    }

    cache->hierarchyAddr = hierarchyAddr;
    cache->localT = localT;
    cache->parentI = parentI;
    cache->transforms.resize(MAX_HIERARCHY_TRANSFORMS);
    cache->parents.resize(MAX_HIERARCHY_TRANSFORMS);

    if (!ReadArray<trsX>(localT, cache->transforms.data(),
                         MAX_HIERARCHY_TRANSFORMS)) {
      cache->valid = false;
      return false;
    }
    if (!ReadArray<int>(parentI, cache->parents.data(),
                        MAX_HIERARCHY_TRANSFORMS)) {
      cache->valid = false;
      return false;
    }
    cache->valid = true;
    cache->lastUpdate = now;
    return true;
  }

  const HierarchyCache *GetHierarchyCache(uintptr_t hierarchyAddr) {
    for (const auto &c : boneCache) {
      if (c.valid && c.hierarchyAddr == hierarchyAddr)
        return &c;
    }
    return nullptr;
  }

  Vec3 CalcWorldPos(int index, uintptr_t hierarchyAddr) {
    const HierarchyCache *cache = GetHierarchyCache(hierarchyAddr);
    if (cache && index >= 0 && index < (int)cache->transforms.size()) {
      Vec3 worldPos = cache->transforms[index].t;
      int pIdx = cache->parents[index];
      int safety = 0;
      while (pIdx >= 0 && pIdx < (int)cache->transforms.size() &&
             safety < 120) {
        const auto &p = cache->transforms[pIdx];
        worldPos = p.q * worldPos;
        worldPos = worldPos * p.s;
        worldPos = worldPos + p.t;
        pIdx = cache->parents[pIdx];
        safety++;
      }
      return worldPos;
    }
    /* Fallback: read hierarchy per-bone (slow) */
    if (!IsValidPtr(hierarchyAddr))
      return {};
    uintptr_t localT = Read<uintptr_t>(hierarchyAddr + 0x18);
    uintptr_t parentI = Read<uintptr_t>(hierarchyAddr + 0x20);
    if (!localT || !parentI || !IsValidPtr(localT) || !IsValidPtr(parentI))
      return {};
    trsX cur = Read<trsX>(localT + (uintptr_t)index * sizeof(trsX));
    Vec3 worldPos = cur.t;
    int pIdx = Read<int>(parentI + (uintptr_t)index * sizeof(int));
    int safety = 0;
    while (pIdx >= 0 && safety < 120) {
      trsX p = Read<trsX>(localT + (uintptr_t)pIdx * sizeof(trsX));
      worldPos = p.q * worldPos;
      worldPos = worldPos * p.s;
      worldPos = worldPos + p.t;
      pIdx = Read<int>(parentI + (uintptr_t)pIdx * sizeof(int));
      safety++;
    }
    return worldPos;
  }

  /* Debug: throttle spam — only print full chain every N frames */
  int dbgFrame = 0;
  bool dbgVerbose() { return (dbgFrame <= 5 || dbgFrame % 300 == 0); }

  /* IsValidPtr is now a free function defined above the class */

  /* Check if a value looks like an 8-byte aligned managed object */
  static bool IsAlignedPtr(uintptr_t p) {
    return ::IsValidPtr(p) && (p & 7) == 0;
  }

  /* Check if a value looks like a GC handle.
   * IL2CPP GC handles: lower 32 bits only, type = handle & 7 (1-4), index =
   * handle >> 3 */
  static bool IsGCHandle(uintptr_t val) {
    if (val == 0)
      return false;
    uint32_t handle = (uint32_t)(val & 0xFFFFFFFF);
    uint32_t type = handle & 7;
    uint32_t index = handle >> 3;
    /* Valid types: 1=Weak, 2=Normal/Pinned, 3=Pinned, 4=WeakTrack */
    return (type >= 1 && type <= 4 && index < 0x100000);
  }

  /* ---------- low-level helpers ---------- */

  template <typename T> T Read(uintptr_t addr) {
    return drv->Read<T>(pid, addr);
  }

  bool ReadRaw(uintptr_t addr, void *buf, size_t sz) {
    return drv->ReadMemory(pid, addr, buf, sz);
  }

  /* Read a C# System.String (UTF-16) -> wstring */
  std::wstring ReadString(uintptr_t strPtr, int maxChars = 64) {
    if (!strPtr)
      return L"";
    int len = Read<int>(strPtr + 0x10);
    if (len <= 0 || len > maxChars)
      len = maxChars;
    std::wstring result(len, L'\0');
    ReadRaw(strPtr + 0x14, (void *)result.data(), len * sizeof(wchar_t));
    return result;
  }

  /* Follow a simple pointer chain (no decryption) */
  uintptr_t ReadChain(uintptr_t base, const std::vector<uint32_t> &offsets) {
    uintptr_t addr = base;
    for (auto off : offsets) {
      addr = Read<uintptr_t>(addr + off);
      if (!addr)
        return 0;
    }
    return addr;
  }

  /* ── GC Handle Table Discovery ──────────────────────────── */

  /*
   * Given function code bytes, find ALL RIP-relative references and
   * try each as the GC handle objects array.
   * Entries must be 8-byte aligned valid pointers or NULL.
   */
  bool TryExtractTableFromCode(uintptr_t funcAddr, const uint8_t *code,
                               int codeLen) {
    for (int i = 0; i < codeLen - 7; i++) {
      uint8_t rex = code[i];
      if (rex != 0x48 && rex != 0x4C)
        continue;
      uint8_t op = code[i + 1];
      if (op != 0x8B && op != 0x8D)
        continue;
      uint8_t modrm = code[i + 2];
      if ((modrm & 0xC7) != 0x05)
        continue;

      int32_t disp = *(int32_t *)(code + i + 3);
      uintptr_t refAddr = funcAddr + i + 7 + disp;

      printf("[GC]   RIP-rel @ +%d -> global 0x%llX\n", i, (uint64_t)refAddr);

      uintptr_t val = Read<uintptr_t>(refAddr);
      printf("[GC]     val = 0x%llX\n", (uint64_t)val);

      /* Check if val points to bitmap (all FFs = allocation bitmask) */
      if (IsValidPtr(val)) {
        uintptr_t t0 = Read<uintptr_t>(val);
        uintptr_t t1 = Read<uintptr_t>(val + 8);
        printf("[GC]     [0]=0x%llX  [1]=0x%llX\n", (uint64_t)t0, (uint64_t)t1);

        /* Check for bitmap pattern (high bits set = allocation mask) */
        bool isBitmap = (t0 > 0x7FFFFFFFFFFF || t1 > 0x7FFFFFFFFFFF);
        if (isBitmap) {
          printf("[GC]     Looks like bitmap, saving addr\n");
          bitmapGlobalAddr = refAddr;
          continue; /* keep searching */
        }

        /* Entries must be 8-byte aligned ptrs or NULL */
        bool t0ok = (t0 == 0 || IsAlignedPtr(t0));
        bool t1ok = (t1 == 0 || IsAlignedPtr(t1));
        if (t0ok && t1ok && (t0 != 0 || t1 != 0)) {
          gcHandleTable = val;
          printf("[GC] ==> Handle table: 0x%llX\n", (uint64_t)gcHandleTable);
          return true;
        }
        printf("[GC]     Rejected (not aligned object ptrs)\n");
      }

      /* Struct dereference */
      if (val && !IsValidPtr(val))
        continue;
      if (IsValidPtr(val)) {
        /* Try +0x00 and +0x08 as struct fields pointing to objects array */
        for (int off = 0; off <= 0x18; off += 8) {
          uintptr_t inner = Read<uintptr_t>(val + off);
          if (!IsValidPtr(inner))
            continue;
          uintptr_t e0 = Read<uintptr_t>(inner);
          uintptr_t e1 = Read<uintptr_t>(inner + 8);
          bool ok0 = (e0 == 0 || IsAlignedPtr(e0));
          bool ok1 = (e1 == 0 || IsAlignedPtr(e1));
          if (ok0 && ok1 && (e0 != 0 || e1 != 0)) {
            gcHandleTable = inner;
            printf("[GC] ==> Handle table (deref+%d): 0x%llX\n", off,
                   (uint64_t)gcHandleTable);
            return true;
          }
        }
      }
    }
    return false;
  }

  /* ── Method A: Load from DISK + follow JMP thunks ── */

  bool FindGCTableFromDisk() {
    printf("[GC] Method A: Loading GameAssembly.dll from disk...\n");

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
      printf("[GC]   OpenProcess failed (err=%lu)\n", GetLastError());
      return false;
    }
    wchar_t exePath[MAX_PATH] = {};
    DWORD pathLen = MAX_PATH;
    BOOL pathOk = QueryFullProcessImageNameW(hProc, 0, exePath, &pathLen);
    CloseHandle(hProc);
    if (!pathOk)
      return false;

    wchar_t *lastSlash = wcsrchr(exePath, L'\\');
    if (!lastSlash)
      return false;
    wcscpy_s(lastSlash + 1, MAX_PATH - (int)(lastSlash + 1 - exePath),
             L"GameAssembly.dll");

    wprintf(L"[GC]   Path: %s\n", exePath);

    HMODULE hMod = LoadLibraryExW(exePath, NULL,
                                  LOAD_LIBRARY_AS_IMAGE_RESOURCE |
                                      LOAD_LIBRARY_AS_DATAFILE);
    if (!hMod) {
      printf("[GC]   LoadLibraryExW failed (err=%lu)\n", GetLastError());
      return false;
    }
    uintptr_t fileBase = (uintptr_t)hMod & ~(uintptr_t)3;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fileBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
      FreeLibrary(hMod);
      return false;
    }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(fileBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
      FreeLibrary(hMod);
      return false;
    }

    auto &expDD =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDD.VirtualAddress) {
      FreeLibrary(hMod);
      return false;
    }

    IMAGE_EXPORT_DIRECTORY *expDir =
        (IMAGE_EXPORT_DIRECTORY *)(fileBase + expDD.VirtualAddress);
    DWORD *names = (DWORD *)(fileBase + expDir->AddressOfNames);
    WORD *ordinals = (WORD *)(fileBase + expDir->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(fileBase + expDir->AddressOfFunctions);

    printf("[GC]   %lu named exports\n", expDir->NumberOfNames);

    uint32_t targetRVA = 0;
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
      const char *name = (const char *)(fileBase + names[i]);
      if (strcmp(name, "il2cpp_gchandle_get_target") == 0) {
        targetRVA = funcs[ordinals[i]];
        printf("[GC]   Found! RVA=0x%X\n", targetRVA);
        break;
      }
    }
    FreeLibrary(hMod);
    if (!targetRVA)
      return false;

    /* Read function code — follow JMP thunks */
    uintptr_t funcAddr = gameAssembly + targetRVA;
    uint8_t code[512] = {};
    ReadRaw(funcAddr, code, sizeof(code));

    /* If first instruction is JMP (E9), follow it */
    if (code[0] == 0xE9) {
      int32_t jmpDelta = *(int32_t *)(code + 1);
      uintptr_t realFunc = funcAddr + 5 + jmpDelta;
      printf("[GC]   JMP thunk -> real function at 0x%llX\n",
             (uint64_t)realFunc);
      funcAddr = realFunc;
      memset(code, 0, sizeof(code));
      ReadRaw(funcAddr, code, sizeof(code));
    }

    printf("[GC]   Code @ 0x%llX: ", (uint64_t)funcAddr);
    for (int k = 0; k < 48; k++)
      printf("%02X ", code[k]);
    printf("\n");

    if (TryExtractTableFromCode(funcAddr, code, 500))
      return true;

    printf("[GC]   Function parsed but table not found yet\n");
    return false;
  }

  /* ── Method A2: Read PE exports from MEMORY via driver (Win11 safe) ── */

  bool FindGCTableFromMemory() {
    printf("[GC] Method A2: Reading PE exports from game memory (driver)...\n");

    // Read DOS header from GameAssembly.dll in target process
    IMAGE_DOS_HEADER dos = {};
    if (!ReadRaw(gameAssembly, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
      printf("[GC]   Failed to read DOS header\n");
      return false;
    }

    // Read NT headers
    IMAGE_NT_HEADERS64 nt = {};
    if (!ReadRaw(gameAssembly + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
      printf("[GC]   Failed to read NT headers\n");
      return false;
    }

    auto &expDD = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDD.VirtualAddress || !expDD.Size) {
      printf("[GC]   No export directory\n");
      return false;
    }

    // Read export directory
    IMAGE_EXPORT_DIRECTORY expDir = {};
    if (!ReadRaw(gameAssembly + expDD.VirtualAddress, &expDir, sizeof(expDir))) {
      printf("[GC]   Failed to read export directory\n");
      return false;
    }

    printf("[GC]   %lu named exports\n", expDir.NumberOfNames);

    // Read name RVA array, ordinal array, and function RVA array
    DWORD numNames = expDir.NumberOfNames;
    if (numNames > 10000) numNames = 10000; // sanity

    std::vector<DWORD> nameRVAs(numNames);
    std::vector<WORD> ordinals(numNames);
    std::vector<DWORD> funcRVAs(expDir.NumberOfFunctions > 10000 ? 10000 : expDir.NumberOfFunctions);

    if (!ReadRaw(gameAssembly + expDir.AddressOfNames, nameRVAs.data(), numNames * sizeof(DWORD)) ||
        !ReadRaw(gameAssembly + expDir.AddressOfNameOrdinals, ordinals.data(), numNames * sizeof(WORD)) ||
        !ReadRaw(gameAssembly + expDir.AddressOfFunctions, funcRVAs.data(), funcRVAs.size() * sizeof(DWORD))) {
      printf("[GC]   Failed to read export arrays\n");
      return false;
    }

    // Find il2cpp_gchandle_get_target
    uint32_t targetRVA = 0;
    for (DWORD i = 0; i < numNames; i++) {
      char exportName[64] = {};
      ReadRaw(gameAssembly + nameRVAs[i], exportName, sizeof(exportName) - 1);
      if (strcmp(exportName, "il2cpp_gchandle_get_target") == 0) {
        if (ordinals[i] < funcRVAs.size())
          targetRVA = funcRVAs[ordinals[i]];
        printf("[GC]   Found! RVA=0x%X\n", targetRVA);
        break;
      }
    }
    if (!targetRVA) {
      printf("[GC]   Export not found\n");
      return false;
    }

    // Read function code from memory — follow JMP thunks
    uintptr_t funcAddr = gameAssembly + targetRVA;
    uint8_t code[512] = {};
    ReadRaw(funcAddr, code, sizeof(code));

    if (code[0] == 0xE9) {
      int32_t jmpDelta = *(int32_t *)(code + 1);
      uintptr_t realFunc = funcAddr + 5 + jmpDelta;
      printf("[GC]   JMP thunk -> real function at 0x%llX\n", (uint64_t)realFunc);
      funcAddr = realFunc;
      memset(code, 0, sizeof(code));
      ReadRaw(funcAddr, code, sizeof(code));
    }

    printf("[GC]   Code @ 0x%llX: ", (uint64_t)funcAddr);
    for (int k = 0; k < 48; k++)
      printf("%02X ", code[k]);
    printf("\n");

    if (TryExtractTableFromCode(funcAddr, code, 500))
      return true;

    printf("[GC]   Function parsed but table not found yet\n");
    return false;
  }

  /* ── Method B: Find through decrypt function CALL targets ── */

  bool FindGCTableFromDecryptFn() {
    printf("[GC] Method B: Parsing decrypt functions...\n");

    const uintptr_t decryptRVAs[] = {
        0xc96b50, // entity_list_decryption
        0xb558a0, // client_entities_decryption
        0xc6f030, // player_eyes_decryption
    };

    for (auto rva : decryptRVAs) {
      uintptr_t fnAddr = gameAssembly + rva;
      uint8_t code[512] = {};
      if (!ReadRaw(fnAddr, code, sizeof(code)))
        continue;
      if (code[0] == 0x00 && code[1] == 0x00)
        continue;

      printf("[GC]   Decrypt fn @ RVA 0x%llX\n", (uint64_t)rva);

      for (int i = 0; i < 500; i++) {
        if (code[i] != 0xE8)
          continue;
        int32_t callDelta = *(int32_t *)(code + i + 1);
        uintptr_t callTarget = fnAddr + i + 5 + callDelta;
        if (callTarget < gameAssembly || callTarget > gameAssembly + 0x20000000)
          continue;

        printf("[GC]   CALL @ +%d -> 0x%llX\n", i, (uint64_t)callTarget);

        /* Read target function, follow JMP if needed */
        uint8_t targetCode[512] = {};
        ReadRaw(callTarget, targetCode, sizeof(targetCode));

        if (targetCode[0] == 0xE9) {
          int32_t jd = *(int32_t *)(targetCode + 1);
          uintptr_t real = callTarget + 5 + jd;
          printf("[GC]     -> follows JMP to 0x%llX\n", (uint64_t)real);
          callTarget = real;
          ReadRaw(callTarget, targetCode, sizeof(targetCode));
        }

        if (TryExtractTableFromCode(callTarget, targetCode, 500))
          return true;
      }
    }

    printf("[GC]   Not found via decrypt functions\n");
    return false;
  }

  /* ── Method C: Scan globals near the bitmap for the objects array ── */

  bool FindGCTableNearBitmap() {
    if (!bitmapGlobalAddr)
      return false;

    printf("[GC] Method C: Scanning globals near bitmap (0x%llX)...\n",
           (uint64_t)bitmapGlobalAddr);

    /* Scan ±0x200 bytes around the bitmap global for pointer-to-objects-array
     */
    for (int delta = -0x200; delta <= 0x200; delta += 8) {
      if (delta == 0)
        continue; /* skip the bitmap global itself */
      uintptr_t scanAddr = bitmapGlobalAddr + delta;
      uintptr_t val = Read<uintptr_t>(scanAddr);
      if (!IsValidPtr(val))
        continue;

      /* Check first few entries: should be aligned ptrs or NULL */
      uintptr_t e0 = Read<uintptr_t>(val);
      uintptr_t e1 = Read<uintptr_t>(val + 8);
      uintptr_t e2 = Read<uintptr_t>(val + 16);

      bool ok0 = (e0 == 0 || IsAlignedPtr(e0));
      bool ok1 = (e1 == 0 || IsAlignedPtr(e1));
      bool ok2 = (e2 == 0 || IsAlignedPtr(e2));

      /* At least 2 of 3 entries should be valid (or null), and not ALL null */
      int validCount = (e0 != 0 && IsAlignedPtr(e0)) +
                       (e1 != 0 && IsAlignedPtr(e1)) +
                       (e2 != 0 && IsAlignedPtr(e2));

      if (ok0 && ok1 && ok2 && validCount >= 1) {
        printf("[GC]   +0x%X: val=0x%llX  [0]=0x%llX [1]=0x%llX [2]=0x%llX\n",
               delta, (uint64_t)val, (uint64_t)e0, (uint64_t)e1, (uint64_t)e2);

        gcHandleTable = val;
        printf("[GC] ==> Handle table (near bitmap): 0x%llX\n",
               (uint64_t)gcHandleTable);
        return true;
      }
    }

    printf("[GC]   No objects array found near bitmap\n");
    return false;
  }

  /* ── Master: try all methods ── */

  bool FindGCHandleTable() {
    if (FindGCTableFromDisk())
      return true;
    if (FindGCTableFromMemory())
      return true;
    if (FindGCTableFromDecryptFn())
      return true;
    /* Even if we didn't find a flat table, bitmapGlobalAddr may have been
     * set — that's the base of the per-type handle array which is all we need
     */
    if (bitmapGlobalAddr) {
      printf("[GC] Using bitmap base as type array: 0x%llX\n",
             (uint64_t)bitmapGlobalAddr);
      return true;
    }
    return false;
  }

  /*
   * Resolve a GC handle based on actual il2cpp_gchandle_get_target disassembly:
   *
   *   mov ebx, ecx          ; handle is 32-bit
   *   lea rax, [rip+BASE]   ; rax = base of type array in .bss
   *   and ecx, 7            ; type = handle & 7
   *   shr ebx, 3            ; index = handle >> 3
   *   dec ecx               ; type_idx = type - 1
   *   lea rdx, [rcx+rcx*4]  ; rdx = type_idx * 5
   *   lea rdi, [rax+rdx*8]  ; rdi = base + type_idx * 40
   *
   * So each handle type has a 40-byte (5 qword) record.
   * Record layout (likely):
   *   +0x00: bitmap pointer (allocation bitmap)
   *   +0x08: objects array pointer (Il2CppObject**)
   *   +0x10: capacity / metadata
   *   +0x18: metadata
   *   +0x20: metadata
   */
  uintptr_t ResolveGCHandle(uintptr_t rawHandle) {
    if (!rawHandle)
      return 0;

    uint32_t handle = (uint32_t)(rawHandle & 0xFFFFFFFF);
    if (handle == 0)
      return 0;

    uint32_t type = handle & 7;
    uint32_t index = handle >> 3;

    if (type == 0 || type > 4)
      return 0; /* types are 1-4 typically */

    static int gcDbgCount = 0;
    bool verbose = (gcDbgCount++ < 5);

    /* Method 1: Per-type record table (bitmapGlobalAddr) */
    if (bitmapGlobalAddr) {
      /* Record address = base + (type-1) * 40 */
      uintptr_t recordAddr = bitmapGlobalAddr + (uintptr_t)(type - 1) * 40;

      /* Read all 5 qwords of the record */
      uintptr_t record[5] = {};
      ReadRaw(recordAddr, record, sizeof(record));

      if (verbose) {
        printf("[GCR] handle=0x%X type=%u idx=%u record@0x%llX\n", handle, type,
               index, (uint64_t)recordAddr);
        for (int i = 0; i < 5; i++)
          printf("[GCR]   [%d] = 0x%llX\n", i, (uint64_t)record[i]);
      }

      /* Try fields in order: [1] objects array first, then [4], [0], [2], [3]
       * Field[0] is typically the bitmap — it can contain values that
       * look like valid pointers but are actually bitmap entries. */
      static const int fieldOrder[] = {1, 4, 0, 2, 3};
      for (int fi = 0; fi < 5; fi++) {
        int field = fieldOrder[fi];
        uintptr_t objArrayPtr = record[field];
        if (!IsValidPtr(objArrayPtr))
          continue;

        uintptr_t target = Read<uintptr_t>(objArrayPtr + (uintptr_t)index * 8);
        if (IsValidPtr(target)) {
          if (verbose) {
            printf("[GCR]   field[%d]=0x%llX -> [%u]=0x%llX VALID!\n", field,
                   (uint64_t)objArrayPtr, index, (uint64_t)target);
          }
          return target;
        }
      }
    }

    /* Method 2: Flat table fallback (gcHandleTable) */
    if (gcHandleTable && index < 0x200000) {
      uintptr_t target = Read<uintptr_t>(gcHandleTable + (uintptr_t)index * 8);
      if (IsValidPtr(target)) {
        if (verbose)
          printf("[GCR] flat table: handle=0x%X idx=%u -> 0x%llX VALID!\n",
                 handle, index, (uint64_t)target);
        return target;
      }
    }

    if (verbose)
      printf("[GCR]   No valid resolution found (bitmap=0x%llX flat=0x%llX)\n",
             (uint64_t)bitmapGlobalAddr, (uint64_t)gcHandleTable);
    return 0;
  }

  /* ── Decrypt constant extraction from game code ────────── */
  /*
   * Scan a decrypt function for XOR/ROL/ROR/ADD/SUB with immediates.
   * This lets us dynamically discover the correct constants for any build.
   */

  void DumpDecryptFunction(const char *name, uintptr_t rva) {
    uintptr_t fnAddr = gameAssembly + rva;
    uint8_t code[512] = {};
    if (!ReadRaw(fnAddr, code, sizeof(code)))
      return;

    printf("\n[DECRYPT] === %s @ RVA 0x%llX (VA 0x%llX) ===\n", name,
           (uint64_t)rva, (uint64_t)fnAddr);

    /* Print full hex dump (first 256 bytes) */
    for (int row = 0; row < 256; row += 16) {
      printf("[DECRYPT] +%03X: ", row);
      for (int col = 0; col < 16; col++)
        printf("%02X ", code[row + col]);
      printf("\n");
    }

    /* Scan for arithmetic instructions with 32-bit immediates */
    printf("[DECRYPT] Detected operations:\n");

    for (int i = 0; i < 250; i++) {
      /* Check for REX prefix (41 = R8-R15) */
      bool hasREX = (code[i] == 0x41);
      int base = hasREX ? i + 1 : i;

      /* XOR eax, imm32 (opcode 35) */
      if (!hasREX && code[base] == 0x35 && base + 5 <= 256) {
        uint32_t imm = *(uint32_t *)(code + base + 1);
        printf("[DECRYPT]   +%03X: XOR eax, 0x%08X\n", i, imm);
      }
      /* SUB eax, imm32 (opcode 2D) */
      if (!hasREX && code[base] == 0x2D && base + 5 <= 256) {
        uint32_t imm = *(uint32_t *)(code + base + 1);
        printf("[DECRYPT]   +%03X: SUB eax, 0x%08X\n", i, imm);
      }
      /* ADD eax, imm32 (opcode 05) */
      if (!hasREX && code[base] == 0x05 && base + 5 <= 256) {
        uint32_t imm = *(uint32_t *)(code + base + 1);
        printf("[DECRYPT]   +%03X: ADD eax, 0x%08X\n", i, imm);
      }

      /* Group 1: 81 /r rm32, imm32 */
      if (code[base] == 0x81 && base + 6 <= 256) {
        static const char *regs[] = {"eax", "ecx", "edx", "ebx",
                                     "esp", "ebp", "esi", "edi"};
        static const char *rregs[] = {"r8d",  "r9d",  "r10d", "r11d",
                                      "r12d", "r13d", "r14d", "r15d"};
        static const char *ops[] = {"ADD", "OR",  "ADC", "SBB",
                                    "AND", "SUB", "XOR", "CMP"};
        uint8_t modrm = code[base + 1];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm = modrm & 7;
        if (mod == 3) {
          uint32_t imm = *(uint32_t *)(code + base + 2);
          const char *rn = hasREX ? rregs[rm] : regs[rm];
          printf("[DECRYPT]   +%03X: %s %s, 0x%08X\n", i, ops[reg], rn, imm);
        }
      }

      /* Group 2: C1 /r rm32, imm8 (ROL/ROR/SHL/SHR/SAR) */
      if (code[base] == 0xC1 && base + 3 <= 256) {
        static const char *regs[] = {"eax", "ecx", "edx", "ebx",
                                     "esp", "ebp", "esi", "edi"};
        static const char *rregs[] = {"r8d",  "r9d",  "r10d", "r11d",
                                      "r12d", "r13d", "r14d", "r15d"};
        static const char *sops[] = {"ROL", "ROR", "RCL", "RCR",
                                     "SHL", "SHR", "SAL", "SAR"};
        uint8_t modrm = code[base + 1];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm = modrm & 7;
        if (mod == 3) {
          uint8_t imm = code[base + 2];
          const char *rn = hasREX ? rregs[rm] : regs[rm];
          printf("[DECRYPT]   +%03X: %s %s, %d\n", i, sops[reg], rn, imm);
        }
      }
    }
    printf("[DECRYPT] === END ===\n\n");
  }

  void AnalyzeDecryptFunctions() {
    printf("\n[*] Analyzing decrypt functions for constants...\n");
    DumpDecryptFunction("entity_list_fn", 0xc96b50);
    DumpDecryptFunction("client_entities_fn", 0xb558a0);
  }

public:
  RustSDK(DriverComm *driver) : drv(driver) {}

  bool IsAttached() const { return attached && pid != 0; }
  DWORD GetPID() const { return pid; }
  uintptr_t GetGameAssemblyBase() const { return gameAssembly; }
  
  // GC table status getters for debug overlay
  uintptr_t GetGCBitmapAddr() const { return bitmapGlobalAddr; }
  uintptr_t GetGCHandleTable() const { return gcHandleTable; }

  /* ── Attach to Rust process ──────────────────────────────── */

  bool Attach() {
    attached = false;
    entityBuffer = 0;
    entityCount = 0;
    dbgFrame = 0;

    printf("[*] Searching for RustClient.exe...\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
      return false;

    PROCESSENTRY32W pe = {sizeof(pe)};
    pid = 0;
    if (Process32FirstW(snap, &pe)) {
      do {
        if (_wcsicmp(pe.szExeFile, L"RustClient.exe") == 0) {
          pid = pe.th32ProcessID;
          break;
        }
      } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!pid) {
      printf("[!] RustClient.exe not found\n");
      return false;
    }
    printf("[+] RustClient.exe PID: %lu\n", pid);

    printf("[*] Getting GameAssembly.dll base...\n");
    gameAssembly = drv->GetModuleBase(pid, L"GameAssembly.dll");
    if (!gameAssembly) {
      printf("[!] GameAssembly.dll not found\n");
      return false;
    }
    printf("[+] GameAssembly.dll base: 0x%llX\n", (uint64_t)gameAssembly);

    attached = true;
    printf("[+] Attached successfully!\n");

    printf("[*] Looking for GC handle table...\n");
    if (FindGCHandleTable()) {
      printf("[+] GC handle table found at 0x%llX\n", (uint64_t)gcHandleTable);
    } else {
      printf("[!] GC handle table not found\n");
    }

    /* Dump decrypt function code to extract correct constants */
    AnalyzeDecryptFunctions();

    /* ── IL2CPP runtime resolver: auto-detect offsets ────── */
    if (resolver.Initialize(drv, pid, gameAssembly)) {
      RuntimePopulateOffsets();
      CalibrateMovementEncryption();
    } else {
      printf("[!] IL2CPP resolver failed — using hardcoded offsets\n");
    }

    return true;
  }

  /* Populate offsets namespace from runtime resolver */
  void RuntimePopulateOffsets() {
    if (!resolver.Good())
      return;
    printf("[IL2CPP] Populating offsets from runtime metadata...\n");
    int ok = 0, fail = 0;

    auto resolve = [&](int &dst, const char *cls, const char *fld,
                       const char *ns = "") {
      int v = resolver.Field(cls, fld, ns);
      if (v >= 0) {
        if (dst != v)
          printf("[IL2CPP]   %s::%s = 0x%X (was 0x%X)\n", cls, fld, v, dst);
        dst = v;
        ok++;
      } else {
        printf("[IL2CPP]   %s::%s FAILED (keep 0x%X)\n", cls, fld, dst);
        fail++;
      }
    };

    // BaseCombatEntity
    resolve(offsets::BaseCombatEntity::lifestate, "BaseCombatEntity",
            "lifestate");
    resolve(offsets::BaseCombatEntity::model, "BaseCombatEntity", "model");
    resolve(offsets::BaseCombatEntity::_health, "BaseCombatEntity", "_health");
    resolve(offsets::BaseCombatEntity::_maxHealth, "BaseCombatEntity",
            "_maxHealth");

    // BasePlayer
    resolve(offsets::BasePlayer::playerFlags, "BasePlayer", "playerFlags");
    resolve(offsets::BasePlayer::displayName_, "BasePlayer", "_displayName");
    resolve(offsets::BasePlayer::playerModel, "BasePlayer", "playerModel");
    resolve(offsets::BasePlayer::clactiveitem, "BasePlayer", "clActiveItem");
    resolve(offsets::BasePlayer::inventory, "BasePlayer", "inventory");
    resolve(offsets::BasePlayer::playerInput, "BasePlayer", "playerInput");
    resolve(offsets::BasePlayer::eyes, "BasePlayer", "eyes");
    resolve(offsets::BasePlayer::currentTeam, "BasePlayer", "currentTeam");
    resolve(offsets::BasePlayer::userId, "BasePlayer", "userID");
    resolve(offsets::BasePlayer::metabolism, "BasePlayer", "metabolism");
    resolve(offsets::BasePlayer::BaseMovement, "BasePlayer", "movement");
    resolve(offsets::BasePlayer::ModelState, "BasePlayer", "modelState");

    // BaseProjectile
    resolve(offsets::BaseProjectile::recoilProperties, "BaseProjectile",
            "recoil");
    resolve(offsets::BaseProjectile::automatic, "BaseProjectile", "automatic");
    resolve(offsets::BaseProjectile::primaryMagazine, "BaseProjectile",
            "primaryMagazine");
    resolve(offsets::BaseProjectile::projectileVelocityScale, "BaseProjectile",
            "projectileVelocityScale");
    resolve(offsets::BaseProjectile::aimCone, "BaseProjectile", "aimCone");
    resolve(offsets::BaseProjectile::hipAimCone, "BaseProjectile",
            "hipAimCone");
    resolve(offsets::BaseProjectile::aimconePenaltyPerShot, "BaseProjectile",
            "aimconePenaltyPerShot");
    resolve(offsets::BaseProjectile::aimConePenaltyMax, "BaseProjectile",
            "aimConePenaltyMax");
    resolve(offsets::BaseProjectile::stancePenaltyScale, "BaseProjectile",
            "stancePenaltyScale");
    resolve(offsets::BaseProjectile::numShotsFired, "BaseProjectile",
            "numShotsFired");

    // RecoilProperties
    resolve(offsets::RecoilProperties::recoilYawMin, "RecoilProperties",
            "recoilYawMin");
    resolve(offsets::RecoilProperties::recoilYawMax, "RecoilProperties",
            "recoilYawMax");
    resolve(offsets::RecoilProperties::recoilPitchMin, "RecoilProperties",
            "recoilPitchMin");
    resolve(offsets::RecoilProperties::recoilPitchMax, "RecoilProperties",
            "recoilPitchMax");

    // PlayerInventory / ItemContainer / Item
    resolve(offsets::PlayerInventory::belt, "PlayerInventory", "containerBelt");
    resolve(offsets::PlayerInventory::containerMain, "PlayerInventory",
            "containerMain");
    resolve(offsets::ItemContainer::itemlist, "ItemContainer", "itemList");
    resolve(offsets::item::item_definition, "Item", "info");
    resolve(offsets::item::held_entity, "Item", "heldEntity");
    resolve(offsets::item::amount, "Item", "amount");
    resolve(offsets::item::item_uid, "Item", "uid");

    // ItemDefinition
    resolve(offsets::ItemDefinition::ShortName, "ItemDefinition", "shortname");
    resolve(offsets::ItemDefinition::category, "ItemDefinition", "category");

    // PlayerModel
    resolve(offsets::PlayerModel::position, "PlayerModel", "position");
    resolve(offsets::PlayerModel::new_velocity, "PlayerModel", "newVelocity");
    resolve(offsets::PlayerModel::isVisible, "PlayerModel", "isVisible");
    resolve(offsets::PlayerModel::InGesture, "PlayerModel", "InGesture");
    resolve(offsets::PlayerModel::CurrentGestureConfig, "PlayerModel", "CurrentGestureConfig");
    resolve(offsets::GestureConfig::PlayerModelLayer, "GestureConfig", "PlayerModelLayer");

    // ConVar.Terrain
    resolve(offsets::Terrain::drawTreeDistance, "Terrain", "drawTreeDistance");
    resolve(offsets::Terrain::drawGrassDistance, "Terrain",
            "drawGrassDistance");

    // PlayerInput / PlayerEyes
    resolve(offsets::PlayerInput::bodyAngles, "PlayerInput", "bodyAngles");
    resolve(offsets::PlayerEyes::body_rotation, "PlayerEyes", "bodyRotation");
    resolve(offsets::PlayerEyes::view_offset, "PlayerEyes", "viewOffset");

    // Model
    resolve(offsets::Model::boneTransforms, "Model", "boneTransforms");

    // FlintStrikeWeapon
    resolve(offsets::FlintStrikeWeapon::successFraction, "FlintStrikeWeapon",
            "successFraction");

    // PlayerWalkMovement — resolve spiderman offset only
    {
      auto tryResolve = [&](int &dst, const char *cls,
                            std::initializer_list<const char *> names) {
        for (auto *n : names) {
          int v = resolver.Field(cls, n);
          if (v >= 0) {
            if (dst != v)
              printf("[IL2CPP]   %s::%s = 0x%X (was 0x%X)\n", cls, n, v, dst);
            dst = v;
            ok++;
            return;
          }
        }
        printf("[IL2CPP]   %s::{%s,...} FAILED (keep 0x%X)\n", cls,
               *names.begin(), dst);
        fail++;
      };
      tryResolve(offsets::PlayerWalkMovement::spiderman,
                 "PlayerWalkMovement",
                 {"<MaxAngleWalking>k__BackingField", "MaxAngleWalking", "maxAngleWalking"});
    }

    // BaseMelee
    resolve(offsets::BaseMelee::maxDistance, "BaseMelee", "maxDistance");
    resolve(offsets::BaseMelee::attackRadius, "BaseMelee", "attackRadius");

    // ModelState (ProtoBuf: field might be "flags_" or "flags")
    {
      int v = resolver.Field("ModelState", "flags_");
      if (v < 0)
        v = resolver.Field("ModelState", "flags");
      if (v >= 0) {
        if (offsets::ModelState::flags != v)
          printf("[IL2CPP]   ModelState::flags = 0x%X (was 0x%X)\n", v,
                 offsets::ModelState::flags);
        offsets::ModelState::flags = v;
        ok++;
      } else {
        printf("[IL2CPP]   ModelState::flags FAILED (keep 0x%X)\n",
               offsets::ModelState::flags);
        fail++;
      }
    }

    printf("[IL2CPP] Offset population: %d resolved, %d failed\n", ok, fail);

    // ── Resolve static TypeInfo pointers ──
    printf("[IL2CPP] Resolving static class pointers...\n");

    auto resolveTI = [&](auto &dst, const char *cls, const char *ns = "") {
      uint64_t rva = resolver.FindTypeInfoRVA(cls, ns);
      if (rva) {
        if ((uint64_t)dst != rva)
          printf("[IL2CPP]   %s TypeInfo: 0x%llX (was 0x%llX)\n", cls, rva,
                 (uint64_t)dst);
        dst = rva;
      } else {
        printf("[IL2CPP]   %s TypeInfo: FAILED\n", cls);
      }
    };

    resolveTI(offsets::basenetworkable_pointer, "BaseNetworkable");
    resolveTI(offsets::camera_pointer, "MainCamera");
    resolveTI(offsets::tod_sky_pointer, "TOD_Sky");
    resolveTI(offsets::convar_graphics_pointer, "Graphics", "ConVar");
    resolveTI(offsets::convar_terrain_pointer, "Terrain", "ConVar");

    printf("[IL2CPP] Static pointer resolution complete\n");
  }

  /* ── Read camera view matrix ─────────────────────────────── */

  uintptr_t cachedCamBuf = 0; /* cached camera buffer to avoid re-traversing */

  bool GetViewMatrix(ViewMatrix &vm) {
    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::camera_pointer);
    if (!typeInfo)
      return false;

    uintptr_t staticFields =
        Read<uintptr_t>(typeInfo + offsets::BaseCamera::static_fields);
    if (!staticFields)
      return false;

    uintptr_t instance =
        Read<uintptr_t>(staticFields + offsets::BaseCamera::wrapper_class);
    if (!instance)
      return false;

    uintptr_t buf =
        Read<uintptr_t>(instance + offsets::BaseCamera::parent_static_fields);
    if (!buf)
      return false;

    cachedCamBuf = buf; /* cache for GetCameraPosition */

    bool ok =
        ReadRaw(buf + offsets::BaseCamera::matrix, &vm, sizeof(ViewMatrix));

    static bool camDbgOnce = false;
    if (!camDbgOnce) {
      camDbgOnce = true;
      printf("[CAM] Chain: TypeInfo=0x%llX -> static=0x%llX -> inst=0x%llX -> "
             "buf=0x%llX\n",
             (uint64_t)typeInfo, (uint64_t)staticFields, (uint64_t)instance,
             (uint64_t)buf);
      printf("[CAM] ViewMatrix[0]: %.3f %.3f %.3f %.3f\n", vm.m[0][0],
             vm.m[0][1], vm.m[0][2], vm.m[0][3]);
    }
    return ok;
  }

  Vec3 GetCameraPosition() {
    if (!cachedCamBuf)
      return {};
    return Read<Vec3>(cachedCamBuf + offsets::BaseCamera::position);
  }

  /* ── Decrypt-and-resolve helper ────────────────────────────
   *
   * All Rust encrypted fields follow the same pattern:
   *   1. The field stores a WRAPPER OBJECT pointer
   *   2. wrapper+0x14: flag byte (non-zero = encrypted)
   *   3. wrapper+0x18: 8 bytes of encrypted data
   *   4. Decrypt the 2 dwords using field-specific constants
   *   5. The decrypted value is a GC handle
   *   6. Resolve GC handle → actual object pointer
   */
  typedef uintptr_t (*DecryptFn)(uintptr_t);

  /* ── il2cpp_get_handle: resolve GC handle to object pointer ── */
  uintptr_t il2cpp_get_handle(uintptr_t handle) {
    if (!handle)
      return 0;
    // Try GC handle table first
    uintptr_t resolved = ResolveGCHandle(handle);
    if (IsValidPtr(resolved))
      return resolved;
    // If handle itself looks like a valid pointer, return it directly
    if (IsValidPtr(handle))
      return handle;
    return 0;
  }

  /* ── Decrypt client_entities (UPDATE patch) ── */
  uintptr_t decrypt_client_entities(uintptr_t a1) {
    if (!IsValidPtr(a1)) {
      printf("[DECRYPT] client_entities: Invalid wrapper pointer 0x%llX\n", (uint64_t)a1);
      return 0;
    }
    
    static int dcDbg = 0;
    bool verbose = (dcDbg++ < 15);

    /* Lazy retry: if GC handle table wasn't found during Attach, try again now.
     * The game may not have fully initialized its GC tables at attach time. */
    if (!bitmapGlobalAddr && !gcHandleTable) {
      static int retryCount = 0;
      static ULONGLONG lastRetry = 0;
      ULONGLONG now = GetTickCount64();
      if (retryCount < 5 && (now - lastRetry > 5000 || lastRetry == 0)) {
        lastRetry = now;
        retryCount++;
        printf("[DECRYPT] GC table missing — retry #%d...\n", retryCount);
        FindGCHandleTable();
        if (bitmapGlobalAddr || gcHandleTable)
          printf("[DECRYPT] GC table found on retry! bitmap=0x%llX flat=0x%llX\n",
                 (uint64_t)bitmapGlobalAddr, (uint64_t)gcHandleTable);
      }
    }

    /* Try multiple wrapper offsets: some game versions store the encrypted
     * value at +0x10, +0x18, or +0x20 within the wrapper struct */
    static const int wrapperOffsets[] = { 0x18, 0x10, 0x20, 0x28 };
    
    for (int oi = 0; oi < 4; oi++) {
      int off = wrapperOffsets[oi];
      uintptr_t encrypted = Read<uintptr_t>(a1 + off);
      if (!encrypted)
        continue;
      
      uintptr_t decrypted = RustDecrypt::DecryptClientEntities(encrypted);
      if (!decrypted)
        continue;
      
      uintptr_t result = il2cpp_get_handle(decrypted);
      if (IsValidPtr(result)) {
        if (verbose && off != 0x18)
          printf("[DECRYPT] client_entities: found at wrapper+0x%X (not default 0x18)\n", off);
        return result;
      }
      
      /* Also try the raw encrypted value as a direct pointer (no decrypt needed) */
      if (IsValidPtr(encrypted)) {
        /* Validate: a real client_entities object should have a pointer at +0x10 */
        uintptr_t probe = Read<uintptr_t>(encrypted + 0x10);
        if (IsValidPtr(probe)) {
          if (verbose)
            printf("[DECRYPT] client_entities: direct pointer at wrapper+0x%X = 0x%llX\n",
                   off, (uint64_t)encrypted);
          return encrypted;
        }
      }
    }

    if (verbose) {
      printf("[DECRYPT] client_entities FAILED: wrapper=0x%llX bitmap=0x%llX flat=0x%llX\n",
             (uint64_t)a1, (uint64_t)bitmapGlobalAddr, (uint64_t)gcHandleTable);
      /* Dump wrapper contents for remote debugging */
      printf("[DECRYPT]   wrapper dump:");
      for (int d = 0; d <= 0x28; d += 8) {
        uintptr_t v = Read<uintptr_t>(a1 + d);
        printf(" +0x%X=0x%llX", d, (uint64_t)v);
      }
      printf("\n");
    }
    
    return 0;
  }

  /* ── Decrypt entity_list (UPDATE patch) ── */
  uintptr_t decrypt_entity_list(uintptr_t a1) {
    static const int offsets[] = { 0x18, 0x10, 0x20, 0x28 };
    for (int off : offsets) {
      uintptr_t encrypted = Read<uintptr_t>(a1 + off);
      if (!encrypted) continue;
      
      uintptr_t decrypted = RustDecrypt::DecryptEntityList(encrypted);
      if (decrypted) {
        uintptr_t result = il2cpp_get_handle(decrypted);
        if (IsValidPtr(result)) return result;
      }
      
      /* Direct pointer fallback */
      if (IsValidPtr(encrypted)) {
        uintptr_t probe = Read<uintptr_t>(encrypted + 0x10);
        if (IsValidPtr(probe) || Read<int>(encrypted + 0x18) > 0)
          return encrypted;
      }
    }
    return 0;
  }

  uintptr_t DecryptAndResolve(uintptr_t wrapperAddr, DecryptFn decrypt) {
    if (!wrapperAddr || !IsValidPtr(wrapperAddr))
      return 0;

    /* Read the encrypted 8 bytes from wrapper+0x18 */
    uintptr_t encrypted = Read<uintptr_t>(wrapperAddr + 0x18);
    if (!encrypted)
      return 0;

    /* Apply the decrypt function */
    uintptr_t decrypted = decrypt(encrypted);

    /* The result is a GC handle — resolve it */
    uint32_t handle = (uint32_t)(decrypted & 0xFFFFFFFF);
    if (handle == 0)
      return 0;

    uintptr_t resolved = ResolveGCHandle(handle);

    static int dcrDbg = 0;
    if (dcrDbg++ < 20) {
      printf("[DCR] wrapper=0x%llX enc=0x%llX dec=0x%llX handle=0x%X -> 0x%llX "
             "%s\n",
             (uint64_t)wrapperAddr, (uint64_t)encrypted, (uint64_t)decrypted,
             handle, (uint64_t)resolved,
             IsValidPtr(resolved) ? "VALID" : "INVALID");
    }

    return resolved;
  }

  /* ── Refresh entity list cache ─────────────────────────────
   *
   * Chain (from dump, UPDATE patch):
   *   GA + 0xD7F41D0 -> TypeInfo
   *   TypeInfo + 0xB8 -> staticFields
   *   staticFields + 0x20 -> wrapper1 (client_entities encrypted)
   *   decrypt client_entities(wrapper1) -> clientEntities
   *   clientEntities + 0x10 -> wrapper2 (entity_list encrypted)
   *   decrypt entity_list(wrapper2) -> entityList
   *   entityList + 0x18 -> buffer (Il2CppArray of entity pointers)
   *   buffer + 0x18 -> count
   *   buffer + 0x20 + i*8 -> entity pointer
   */

  bool RefreshEntityList() {
    entityBuffer = 0;
    entityCount = 0;
    isPlayerCache.clear();
    dbgFrame++;

    bool verbose = (dbgFrame % 300 == 0); // Every 5 seconds at 60fps
    
    // Track consecutive failures
    static int consecutiveFails = 0;
    static ULONGLONG lastResetTime = 0;
    
    if (verbose) {
      printf("[ENT] Frame %d: Refreshing entity list...\n", dbgFrame);
    }

    // Step 1: TypeInfo
    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::basenetworkable_pointer);
    entDbg.typeInfo = typeInfo;
    if (verbose)
      printf("[ENT] step1 typeInfo=0x%llX\n", (uint64_t)typeInfo);
    if (!typeInfo) {
      entDbg.lastFailStep = 1;
      consecutiveFails++;
      return false;
    }

    // Step 2: static fields from BaseNetworkable TypeInfo
    uintptr_t staticFields =
        Read<uintptr_t>(typeInfo + offsets::BaseNetworkable::static_fields);
    entDbg.staticFields = staticFields;
    if (verbose)
      printf("[ENT] step2 staticFields=0x%llX (typeInfo=0x%llX+0x%X)\n", 
             (uint64_t)staticFields, (uint64_t)typeInfo, offsets::BaseNetworkable::static_fields);
    if (!staticFields) {
      entDbg.lastFailStep = 2;
      consecutiveFails++;
      return false;
    }

    // Step 3: client_entities wrapper at staticFields+0x20
    uintptr_t wrapper1 =
        Read<uintptr_t>(staticFields + offsets::BaseNetworkable::client_entities);
    entDbg.wrapper1 = wrapper1;
    if (verbose)
      printf("[ENT] step3 wrapper1=0x%llX (staticFields=0x%llX+0x%X)\n", 
             (uint64_t)wrapper1, (uint64_t)staticFields, offsets::BaseNetworkable::client_entities);
    if (!IsValidPtr(wrapper1)) {
      entDbg.lastFailStep = 3;
      consecutiveFails++;
      return false;
    }

    // Step 3b: decrypt client_entities
    uintptr_t clientEntities = decrypt_client_entities(wrapper1);
    entDbg.clientEntities = clientEntities;
    if (verbose)
      printf("[ENT] step3b clientEntities=0x%llX\n", (uint64_t)clientEntities);
    if (!IsValidPtr(clientEntities)) {
      entDbg.lastFailStep = 4;
      consecutiveFails++;
      return false;
    }

    // Step 4: entity_list wrapper at clientEntities+0x10
    uintptr_t wrapper2 =
        Read<uintptr_t>(clientEntities + offsets::BaseNetworkable::entity_list);
    entDbg.wrapper2 = wrapper2;
    if (verbose)
      printf("[ENT] step4 wrapper2=0x%llX\n", (uint64_t)wrapper2);
    if (!IsValidPtr(wrapper2)) {
      entDbg.lastFailStep = 5;
      consecutiveFails++;
      return false;
    }

    // Step 4b: decrypt entity_list
    uintptr_t entityList = decrypt_entity_list(wrapper2);
    entDbg.entityList = entityList;
    if (verbose)
      printf("[ENT] step4b entityList=0x%llX\n", (uint64_t)entityList);
    if (!IsValidPtr(entityList)) {
      entDbg.lastFailStep = 6;
      consecutiveFails++;
      return false;
    }

    // Step 5: buffer (BufferList) at entityList+0x10
    uintptr_t bufferList =
        Read<uintptr_t>(entityList + offsets::BaseNetworkable::buffer_list);
    entDbg.bufferList = bufferList;
    if (verbose)
      printf("[ENT] step5 bufferList=0x%llX\n", (uint64_t)bufferList);
    if (!IsValidPtr(bufferList)) {
      entDbg.lastFailStep = 7;
      consecutiveFails++;
      return false;
    }

    // Step 6: count from bufferList+0x18, inner array from bufferList+0x10
    int count = Read<int>(bufferList + 0x18);
    uintptr_t entityArray = Read<uintptr_t>(bufferList + 0x10);
    entDbg.rawCount = count;
    entDbg.entityArray = entityArray;
    if (verbose)
      printf("[ENT] step6 entityArray=0x%llX count=%d\n", (uint64_t)entityArray,
             count);
    if (!IsValidPtr(entityArray) || count <= 0 || count > 50000) {
      entDbg.lastFailStep = 8;
      consecutiveFails++;
      return false;
    }

    entityBuffer = entityArray;
    entityCount = count;
    entDbg.lastFailStep = 99; // success

    if (verbose) {
      printf("[ENT] SUCCESS: %d entities\n", count);
      for (int i = 0; i < 5 && i < count; i++) {
        uintptr_t ent = Read<uintptr_t>(entityArray + 0x20 + (uintptr_t)i * 8);
        if (IsValidPtr(ent)) {
          std::string cn = ReadClassName(ent);
          printf("[ENT]   [%d] 0x%llX '%s'\n", i, (uint64_t)ent, cn.c_str());
        } else {
          printf("[ENT]   [%d] 0x%llX (invalid)\n", i, (uint64_t)ent);
        }
      }
    }

    consecutiveFails = 0;
    return true;
  }

  int GetEntityCount() const { return entityCount; }
  uintptr_t GetEntityBufferAddr() const { return entityBuffer; }

  /* Debug helpers for external access */
  bool ReadRawPublic(uintptr_t addr, void *buf, size_t sz) {
    return ReadRaw(addr, buf, sz);
  }

  /* ── Read a single entity address from the buffer ─────────── */

  uintptr_t GetEntity(int index) {
    // Debug: Show first few calls
    static int getEntityInternalDebugCount = 0;
    if (getEntityInternalDebugCount < 3) {
      printf("[GETENTITY_INTERNAL] index=%d buffer=0x%llX count=%d\n", 
             index, (uint64_t)entityBuffer, entityCount);
      getEntityInternalDebugCount++;
    }
    
    if (!entityBuffer || index < 0 || index >= entityCount)
      return 0;
    uintptr_t result = Read<uintptr_t>(entityBuffer + 0x20 + (uintptr_t)index * 8);
    
    // Debug: Show first few results
    static int resultDebugCount = 0;
    if (resultDebugCount < 3) {
      printf("[GETENTITY_RESULT] index=%d result=0x%llX\n", index, (uint64_t)result);
      resultDebugCount++;
    }
    
    return result;
  }

  /* ── Read IL2CPP class name from an entity ─────────────────
   *
   * IL2CPP object layout:
   *   entity + 0x00 = Il2CppClass* klass
   *   klass  + 0x10 = const char* name
   *   klass  + 0x18 = const char* namespaze
   *   klass  + 0x30 = Il2CppClass* parent
   */
  std::string ReadClassName(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return "";
    uintptr_t klass = Read<uintptr_t>(entity);
    if (!IsValidPtr(klass))
      return "";
    uintptr_t namePtr = Read<uintptr_t>(klass + 0x10);
    if (!IsValidPtr(namePtr))
      return "";
    char buf[64] = {};
    ReadRaw(namePtr, buf, 63);
    buf[63] = 0;
    return std::string(buf);
  }

  /* ── Read world position from any entity (not just players) ── */

  // Debug: track last entity position probe for debug panel
  struct EntityPosDebug {
    uintptr_t entity = 0;
    int methodUsed = 0; // 0=none, 1=chain, 2=model, 3=scan
    uintptr_t chainA = 0, chainB = 0, chainC = 0, chainD = 0;
    Vec3 result = {};
  } entPosDbg;

  Vec3 ReadEntityPosition(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return {};
    entPosDbg = {};
    entPosDbg.entity = entity;

    uintptr_t native = Read<uintptr_t>(entity + 0x10); // m_CachedPtr
    entPosDbg.chainA = native;
    if (!native || !IsValidPtr(native))
      return {};

    uintptr_t gameObj = Read<uintptr_t>(native + 0x30); // native GameObject
    entPosDbg.chainB = gameObj;

    // ── Method 1 (reference chain): gameObj+0x30 → objectData+0x8 →
    // transformInternal ── Then: transformInternal+0x38 → data, data+0x90 →
    // cached world position Fallback: CalcWorldPos from
    // transformInternal+0x38/+0x40
    if (gameObj && IsValidPtr(gameObj)) {
      uintptr_t objectData = Read<uintptr_t>(gameObj + 0x30);
      if (objectData && IsValidPtr(objectData)) {
        uintptr_t transformInternal = Read<uintptr_t>(objectData + 0x8);
        entPosDbg.chainC = transformInternal;
        if (transformInternal && IsValidPtr(transformInternal)) {
          uintptr_t data = Read<uintptr_t>(transformInternal + 0x38);
          entPosDbg.chainD = data;
          if (data && IsValidPtr(data)) {
            // Fast path: read cached world position at data+0x90
            Vec3 pos = Read<Vec3>(data + 0x90);
            if (pos.x != 0.f || pos.y != 0.f || pos.z != 0.f) {
              entPosDbg.result = pos;
              entPosDbg.methodUsed = 1;
              return pos;
            }
            // Fallback: hierarchy walk via CalcWorldPos
            unsigned int index = Read<unsigned int>(transformInternal + 0x40);
            if (index < 5000) {
              Vec3 hpos = CalcWorldPos((int)index, data);
              if (hpos.x != 0.f || hpos.y != 0.f || hpos.z != 0.f) {
                entPosDbg.result = hpos;
                entPosDbg.methodUsed = 3;
                return hpos;
              }
            }
          }
        }
      }
    }

    // ── Method 2: Model → root bone (works for players/animals with bone
    // transforms) ──
    uintptr_t model = Read<uintptr_t>(entity + offsets::BaseEntity::baseModel);
    if (model && IsValidPtr(model)) {
      uintptr_t boneArray =
          Read<uintptr_t>(model + offsets::Model::boneTransforms);
      if (boneArray && IsValidPtr(boneArray)) {
        int boneCount = Read<int>(boneArray + 0x18);
        if (boneCount > 0 && boneCount < 200) {
          uintptr_t rootBone = Read<uintptr_t>(boneArray + 0x20);
          if (rootBone && IsValidPtr(rootBone)) {
            Vec3 pos = ReadTransformPosition(rootBone);
            if (pos.x != 0.f || pos.y != 0.f || pos.z != 0.f) {
              entPosDbg.result = pos;
              entPosDbg.methodUsed = 2;
              return pos;
            }
          }
        }
      }
    }

    static bool failLogOnce = false;
    if (!failLogOnce) {
      failLogOnce = true;
      std::string cn = ReadClassName(entity);
      printf("[Pos] All methods failed for class='%s' native=0x%llX "
             "gameObj=0x%llX\n",
             cn.c_str(), (uint64_t)native, (uint64_t)gameObj);
    }

    return {};
  }

  /* ── Read the Unity native object name (prefab name) ───────
   *
   * Chain: entity + 0x10 = m_CachedPtr (native Unity Object*)
   *        nativeObj + 0x30 = native GameObject*
   *        gameObject + 0x60 = char* name (UTF-8)
   */
  std::string ReadObjectName(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return "";
    uintptr_t native = Read<uintptr_t>(entity + 0x10);
    if (!native || !IsValidPtr(native))
      return "";
    uintptr_t gameObject = Read<uintptr_t>(native + 0x30);
    if (!gameObject || !IsValidPtr(gameObject))
      return "";
    uintptr_t namePtr = Read<uintptr_t>(gameObject + 0x60);
    if (!namePtr || !IsValidPtr(namePtr))
      return "";
    char buf[128] = {};
    ReadRaw(namePtr, buf, 127);
    buf[127] = 0;
    return std::string(buf);
  }

  /* ── Read player name from BasePlayer ───────────────────── */

  std::string ReadPlayerName(uintptr_t player) {
    if (!player || !IsValidPtr(player))
      return "";
    
    // Use the correct _displayName offset (0x3E8)
    uintptr_t namePtr = Read<uintptr_t>(player + 0x3E8);
    if (namePtr && IsValidPtr(namePtr)) {
      std::wstring wname = ReadString(namePtr);
      std::string playerName(wname.begin(), wname.end());
      
      if (!playerName.empty() && playerName[0] >= 32 && playerName[0] <= 126) {
        return playerName;
      }
    }
    
    // Fallback to working ReadPlayerDetails
    PlayerData data = {};
    if (ReadPlayerDetails(player, data)) {
      std::string fallbackName(data.name.begin(), data.name.end());
      return fallbackName;
    }
    
    return "";
  }

  /* ── Check if entity is a BasePlayer ─────────────────────── */

  // Cache: entity address → isPlayer result (cleared on RefreshEntityList)
  std::unordered_map<uintptr_t, bool> isPlayerCache;

  bool IsPlayer(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return false;

    // Check cache first — avoids expensive class name reads
    auto it = isPlayerCache.find(entity);
    if (it != isPlayerCache.end())
      return it->second;
    
    bool result = false;

    /* Method 1: Try class name first */
    std::string name = ReadClassName(entity);
    
    if (name == "BasePlayer" || name == "NPCPlayer" || name == "ScientistNPC" ||
        name == "HTNPlayer" || name == "NPCMurderer" || name == "HumanNPC" ||
        name == "GingerbreadNPC") {
      result = true;
    }
    
    if (!result) {
      /* Method 2: Fallback - check for player-specific fields */
      uintptr_t playerModel = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
      uintptr_t eyes = Read<uintptr_t>(entity + offsets::BasePlayer::eyes);
      uintptr_t inventory = Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
      
      if (IsValidPtr(playerModel) && IsValidPtr(eyes) && IsValidPtr(inventory)) {
        result = true;
      }
    }

    isPlayerCache[entity] = result;
    return result;
  }

  /* ── Check if entity is a Projectile ─────────────────────── */

  bool IsProjectile(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return false;
    std::string name = ReadClassName(entity);
    return (name == "Projectile");
  }

  /* ── Read player data ────────────────────────────────────── */

  bool ReadPlayer(uintptr_t entity, PlayerData &out) {
    out.address = entity;
    static int dbgPlayerPrintCount = 0;

    uintptr_t playerModel =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!playerModel)
      return false;

    out.position = Read<Vec3>(playerModel + offsets::PlayerModel::position);

    if (out.position.x == 0.f && out.position.y == 0.f && out.position.z == 0.f)
      return false;

    // Check ModelState flags for crouch (bit 0x4) to get correct head height
    float eyeHeight = 1.5f; // standing head center (~1.5m, not eye level 1.6m)
    uintptr_t modelState =
        Read<uintptr_t>(entity + offsets::BasePlayer::ModelState);
    if (modelState && IsValidPtr(modelState)) {
      int msFlags = Read<int>(modelState + offsets::ModelState::flags);
      if (msFlags & 4)
        eyeHeight = 1.0f; // crouching head center
    }
    out.headPos =
        Vec3(out.position.x, out.position.y + eyeHeight, out.position.z);

    uintptr_t namePtr =
        Read<uintptr_t>(entity + 0x3E8);  // _displayName correct offset
    out.name = ReadString(namePtr);

    out.teamID = Read<uint64_t>(entity + offsets::BasePlayer::currentTeam);

    out.flags = Read<uint32_t>(entity + offsets::BasePlayer::playerFlags);
    out.isSleeping = (out.flags & 16) != 0; // PlayerFlags.IsSleeping
    out.isWounded = (out.flags & 64) != 0;  // PlayerFlags.Wounded

    out.lifestate =
        Read<uint32_t>(entity + offsets::BaseCombatEntity::lifestate);

    // Use PlayerModel::isVisible (frustum check) for responsive visibility
    uintptr_t pm = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (pm) {
      out.isVisible = Read<bool>(pm + offsets::PlayerModel::isVisible);
    } else {
      out.isVisible = false;
    }

    if (dbgVerbose() && dbgPlayerPrintCount < 5) {
      char nameBuf[128] = {};
      WideCharToMultiByte(CP_UTF8, 0, out.name.c_str(), -1, nameBuf,
                          sizeof(nameBuf), nullptr, nullptr);
      printf("[PLR] 0x%llX | pos(%.1f, %.1f, %.1f) | name='%s' | flags=0x%X\n",
             (uint64_t)entity, out.position.x, out.position.y, out.position.z,
             nameBuf, out.flags);
      dbgPlayerPrintCount++;
    }
    if (dbgVerbose() && dbgFrame % 300 == 1) {
      dbgPlayerPrintCount = 0;
    }

    out.health = Read<float>(entity + offsets::BaseCombatEntity::_health);
    out.maxHealth = Read<float>(entity + offsets::BaseCombatEntity::_maxHealth);

    return true;
  }

  /* ── World to Screen ─────────────────────────────────────── */

  static bool WorldToScreen(const Vec3 &world, const ViewMatrix &vm,
                            int screenW, int screenH, Vec2 &out) {
    float w = vm.m[0][3] * world.x + vm.m[1][3] * world.y +
              vm.m[2][3] * world.z + vm.m[3][3];
    if (w < 0.001f)
      return false;

    float invW = 1.0f / w;

    float sx = vm.m[0][0] * world.x + vm.m[1][0] * world.y +
               vm.m[2][0] * world.z + vm.m[3][0];

    float sy = vm.m[0][1] * world.x + vm.m[1][1] * world.y +
               vm.m[2][1] * world.z + vm.m[3][1];

    out.x = (screenW * 0.5f) + (screenW * 0.5f) * sx * invW;
    out.y = (screenH * 0.5f) - (screenH * 0.5f) * sy * invW;

    return (out.x >= -50.f && out.x <= screenW + 50.f && out.y >= -50.f &&
            out.y <= screenH + 50.f);
  }

  /* ── Write helper ───────────────────────────────────────── */

  template <typename T> bool Write(uintptr_t addr, const T &value) {
    if (!addr || !IsValidPtr(addr)) return false;
    return drv->Write<T>(pid, addr, value);
  }

  /* ── Read Unity Transform world position (cached hierarchy) ── */

  Vec3 ReadTransformPosition(uintptr_t transform) {
    if (!transform || !IsValidPtr(transform))
      return {};
    uintptr_t pInternal = Read<uintptr_t>(transform + 0x10);
    if (!pInternal)
      return {};
    TransformAccess ta = Read<TransformAccess>(pInternal + 0x38);
    if (!ta.hierarchyAddr || ta.index < 0 || ta.index > 5000)
      return {};
    return CalcWorldPos(ta.index, ta.hierarchyAddr);
  }

  /* ── Read real-time projectile position ──────────────────── */

  Vec3 ReadProjectilePosition(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity))
      return {};
    // Projectile.currentPosition offset is 0x160
    return Read<Vec3>(entity + 0x160);
  }

  /* ── Read player skeleton bones (batched + cached hierarchy) ── */

  int lastBoneCount = 0; // debug
  int lastBoneValid = 0; // debug
  std::string boneDebug; // debug: chain failure info

  bool ReadPlayerBones(uintptr_t entity, PlayerData &out) {
    out.bones.clear();
    lastBoneCount = 0;
    lastBoneValid = 0;

    // Step 1: get model pointer
    uintptr_t playerModel =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    uintptr_t baseModel =
        Read<uintptr_t>(entity + offsets::BaseCombatEntity::model);

    // Try BOTH models, prefer playerModel
    uintptr_t model = 0;
    uintptr_t boneArray = 0;
    int boneCount = 0;

    // Try playerModel first
    if (playerModel && IsValidPtr(playerModel)) {
      uintptr_t ba =
          Read<uintptr_t>(playerModel + offsets::Model::boneTransforms);
      if (ba && IsValidPtr(ba)) {
        int bc = Read<int>(ba + 0x18);
        if (bc > 0 && bc < 200) {
          model = playerModel;
          boneArray = ba;
          boneCount = bc;
        }
      }
    }
    // Fallback to base model
    if (!model && baseModel && IsValidPtr(baseModel)) {
      uintptr_t ba =
          Read<uintptr_t>(baseModel + offsets::Model::boneTransforms);
      if (ba && IsValidPtr(ba)) {
        int bc = Read<int>(ba + 0x18);
        if (bc > 0 && bc < 200) {
          model = baseModel;
          boneArray = ba;
          boneCount = bc;
        }
      }
    }

    if (!model) {
      char db[256];
      snprintf(db, sizeof(db), "FAIL: pModel=0x%llX base=0x%llX",
               (uint64_t)playerModel, (uint64_t)baseModel);
      boneDebug = db;
      return false;
    }

    lastBoneCount = boneCount;

    // Step 2: bones we need for the skeleton
    static const int wantedBones[] = {
        1,  // pelvis
        2,  // l_hip
        3,  // l_knee
        4,  // l_foot
        13, // r_hip
        14, // r_knee
        15, // r_foot
        18, // spine1
        20, // spine2
        21, // spine3
        22, // spine4
        47, // head
        24, // l_upperarm
        25, // l_forearm
        26, // l_hand
        55, // r_upperarm
        56, // r_forearm
        57, // r_hand
    };
    static constexpr int numWanted = 18;

    // Resize to hold max bone index we need + 1
    int maxNeeded = 58; // indices 0..57
    if (boneCount < maxNeeded)
      maxNeeded = boneCount;
    out.bones.resize(maxNeeded, Vec3(0, 0, 0));

    // Step 3: batch-read all bone transform pointers in one call
    // Then cache hierarchy once so CalcWorldPos uses fast path
    uintptr_t transformPtrs[58] = {};
    int readCount = (boneCount < 58) ? boneCount : 58;
    ReadRaw(boneArray + 0x20, transformPtrs, readCount * sizeof(uintptr_t));

    // Cache the hierarchy from the first valid bone so CalcWorldPos is O(1) per bone
    bool hierarchyCached = false;
    for (int i = 0; i < numWanted && !hierarchyCached; i++) {
      int boneIdx = wantedBones[i];
      if (boneIdx >= readCount) continue;
      uintptr_t transform = transformPtrs[boneIdx];
      if (!transform || !IsValidPtr(transform)) continue;
      uintptr_t pInternal = Read<uintptr_t>(transform + 0x10);
      if (!pInternal) continue;
      TransformAccess ta = Read<TransformAccess>(pInternal + 0x38);
      if (ta.hierarchyAddr && ta.index >= 0 && ta.index < 5000) {
        CacheHierarchy(ta.hierarchyAddr);
        hierarchyCached = true;
      }
    }

    int validCount = 0;
    for (int i = 0; i < numWanted; i++) {
      int boneIdx = wantedBones[i];
      if (boneIdx >= readCount)
        continue;

      uintptr_t transform = transformPtrs[boneIdx];
      if (!transform || !IsValidPtr(transform))
        continue;

      Vec3 pos = ReadTransformPosition(transform);
      if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
        continue;

      out.bones[boneIdx] = pos;
      validCount++;
    }

    // Step 4: override headPos with real bone 47 if valid
    if (out.bones.size() > 47) {
      Vec3 headBone = out.bones[47];
      if (!(headBone.x == 0.f && headBone.y == 0.f && headBone.z == 0.f)) {
        out.headPos = headBone;
        // Adjust to head center (bone 47 is top of skull)
        out.headPos.y -= 0.08f;
      }
    }

    lastBoneValid = validCount;

    char db[256];
    snprintf(db, sizeof(db), "cnt=%d valid=%d model=0x%llX", boneCount,
             validCount, (uint64_t)model);
    boneDebug = db;

    if (validCount < 3) {
      out.bones.clear();
      return false;
    }
    return true;
  }

  /* ── Reduce bone flickering by disabling SpineIK ────── */

  // Rate-limit: only write once per second per entity to reduce driver load
  std::unordered_map<uintptr_t, uint64_t> boneFlickerLastWrite;

  void ReduceBoneFlicker(uintptr_t entity) {
    if (!entity || !IsValidPtr(entity)) return;

    uint64_t now = GetTickCount64();
    auto it = boneFlickerLastWrite.find(entity);
    if (it != boneFlickerLastWrite.end() && (now - it->second) < 1000)
      return; // Already written recently
    boneFlickerLastWrite[entity] = now;

    uintptr_t playerModel = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!playerModel || !IsValidPtr(playerModel)) return;

    // Set InGesture = true to stop SpineIK from rotating bones
    // This alone is sufficient — avoids dereferencing CurrentGestureConfig which can be null/invalid
    Write<bool>(playerModel + offsets::PlayerModel::InGesture, true);
  }

  /* ── Weapon bullet speed + gravity for prediction ────── */

  float GetWeaponBulletSpeed(uintptr_t heldEntity) {
    if (!heldEntity || !IsValidPtr(heldEntity))
      return 375.0f;

    // Read projectileVelocityScale from BaseProjectile
    float velocityScale = Read<float>(
        heldEntity + offsets::BaseProjectile::projectileVelocityScale);
    if (velocityScale <= 0.01f || velocityScale > 10.0f)
      velocityScale = 1.0f;

    // Try reading ammo velocity through magazine chain
    float ammoVelocity = 0.0f;
    std::string ammoShortName = GetAmmoShortName(heldEntity);
    
    uintptr_t magazine =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::primaryMagazine);
    if (magazine && IsValidPtr(magazine)) {
      uintptr_t ammoType =
          Read<uintptr_t>(magazine + offsets::Magazine::ammoType);
      if (ammoType && IsValidPtr(ammoType)) {
        // ItemDefinition → itemMods array → find ItemModProjectile
        uintptr_t itemMods =
            Read<uintptr_t>(ammoType + offsets::ItemDefinition::itemMods);
        if (itemMods && IsValidPtr(itemMods)) {
          int modCount = Read<int>(itemMods + 0x18);
          if (modCount > 0 && modCount <= 20) {
            for (int i = 0; i < modCount; i++) {
              uintptr_t mod = Read<uintptr_t>(itemMods + 0x20 + i * 8);
              if (!mod || !IsValidPtr(mod))
                continue;
              float vel = Read<float>(
                  mod + offsets::ItemModProjectile::projectileVelocity);
              if (vel > 10.0f && vel < 2000.0f) {
                ammoVelocity = vel;
                break;
              }
            }
          }
        }
      }
    }

    // If dynamic reading failed, use hardcoded ammo velocities
    if (ammoVelocity < 10.0f) {
      // Hardcoded velocities for common ammo types (m/s)
      if (ammoShortName == "ammo.rifle") ammoVelocity = 375.0f;
      else if (ammoShortName == "ammo.pistol") ammoVelocity = 300.0f;
      else if (ammoShortName == "ammo.smg") ammoVelocity = 300.0f;  // Handmade SMG
      else if (ammoShortName == "ammo.shotgun") ammoVelocity = 100.0f;
      else if (ammoShortName == "ammo.arrow") ammoVelocity = 50.0f;
      else if (ammoShortName == "ammo.crossbow") ammoVelocity = 50.0f;
      else if (ammoShortName == "ammo.handmade.shell") ammoVelocity = 100.0f;
      else if (ammoShortName == "ammo.pistol.fire") ammoVelocity = 300.0f;
      else if (ammoShortName == "ammo.smg.fire") ammoVelocity = 300.0f;
      else if (ammoShortName == "ammo.rifle.explosive") ammoVelocity = 375.0f;
      else if (ammoShortName == "ammo.rifle.hv") ammoVelocity = 450.0f;
      else if (ammoShortName == "ammo.rifle.incendiary") ammoVelocity = 375.0f;
      else {
        // Debug: log unknown ammo type
        static int logCount = 0;
        if (logCount++ < 10) {
          printf("[VEL] Unknown ammo type '%s', using fallback 375 m/s\n", ammoShortName.c_str());
        }
        ammoVelocity = 375.0f;  // Default fallback
      }
    }

    return ammoVelocity * velocityScale;
  }

  std::string GetAmmoShortName(uintptr_t heldEntity) {
    if (!heldEntity || !IsValidPtr(heldEntity))
      return "";
    uintptr_t magazine =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::primaryMagazine);
    if (!magazine || !IsValidPtr(magazine))
      return "";
    uintptr_t ammoType =
        Read<uintptr_t>(magazine + offsets::Magazine::ammoType);
    if (!ammoType || !IsValidPtr(ammoType))
      return "";
    uintptr_t shortNamePtr =
        Read<uintptr_t>(ammoType + offsets::ItemDefinition::ShortName);
    if (!shortNamePtr || !IsValidPtr(shortNamePtr))
      return "";
    std::wstring wname = ReadString(shortNamePtr, 32);
    if (wname.empty())
      return "";
    std::string narrow(wname.begin(), wname.end());
    return narrow;
  }

  float GetWeaponDrag(uintptr_t heldEntity) {
    if (!heldEntity || !IsValidPtr(heldEntity))
      return 0.001f;

    // Try reading drag from ammo's ItemModProjectile
    // projectileDrag is typically at offset 0x48 on ItemModProjectile
    uintptr_t magazine =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::primaryMagazine);
    if (magazine && IsValidPtr(magazine)) {
      uintptr_t ammoType =
          Read<uintptr_t>(magazine + offsets::Magazine::ammoType);
      if (ammoType && IsValidPtr(ammoType)) {
        uintptr_t itemMods =
            Read<uintptr_t>(ammoType + offsets::ItemDefinition::itemMods);
        if (itemMods && IsValidPtr(itemMods)) {
          int modCount = Read<int>(itemMods + 0x18);
          if (modCount > 0 && modCount <= 20) {
            for (int i = 0; i < modCount; i++) {
              uintptr_t mod = Read<uintptr_t>(itemMods + 0x20 + i * 8);
              if (!mod || !IsValidPtr(mod))
                continue;
              // Check if this mod has a valid projectileVelocity (confirms it's
              // ItemModProjectile)
              float vel = Read<float>(
                  mod + offsets::ItemModProjectile::projectileVelocity);
              if (vel > 10.0f && vel < 2000.0f) {
                // Read drag at offset 0x48 (after projectileVelocity at 0x40)
                float d = Read<float>(mod + 0x48);
                if (d > 0.0001f && d < 2.0f)
                  return d;
                break;
              }
            }
          }
        }
      }
    }
    // Realistic default: Rust bullets have very low drag (~0.001)
    return 0.001f;
  }

  float GetWeaponGravity(uintptr_t heldEntity) {
    if (!heldEntity || !IsValidPtr(heldEntity))
      return 1.0f;

    // Try reading gravityModifier from ammo's ItemModProjectile
    // projectileGravityModifier is typically at offset 0x4C on
    // ItemModProjectile
    uintptr_t magazine =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::primaryMagazine);
    if (magazine && IsValidPtr(magazine)) {
      uintptr_t ammoType =
          Read<uintptr_t>(magazine + offsets::Magazine::ammoType);
      if (ammoType && IsValidPtr(ammoType)) {
        uintptr_t itemMods =
            Read<uintptr_t>(ammoType + offsets::ItemDefinition::itemMods);
        if (itemMods && IsValidPtr(itemMods)) {
          int modCount = Read<int>(itemMods + 0x18);
          if (modCount > 0 && modCount <= 20) {
            for (int i = 0; i < modCount; i++) {
              uintptr_t mod = Read<uintptr_t>(itemMods + 0x20 + i * 8);
              if (!mod || !IsValidPtr(mod))
                continue;
              float vel = Read<float>(
                  mod + offsets::ItemModProjectile::projectileVelocity);
              if (vel > 10.0f && vel < 2000.0f) {
                float g = Read<float>(mod + 0x4C);
                if (g > 0.01f && g < 10.0f)
                  return g;
                break;
              }
            }
          }
        }
      }
    }
    return 1.0f;
  }

  /* ── Read active projectiles from ListComponent<Projectile> ── */

  struct ProjectileInfo {
    uintptr_t address;
    Vec3 position;
    Vec3 velocity;
  };

  // Read all projectiles owned by localPlayer from the game's projectile list
  int ReadLocalProjectiles(uintptr_t localPlayer, ProjectileInfo *outBuf,
                           int maxCount) {
    if (!localPlayer || maxCount <= 0)
      return 0;

    // Resolve ListComponent<Projectile> static pool:
    // TypeInfo → static_fields → pool (BufferList<Projectile>)
    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::ListComponent_Projectile_c);
    if (!typeInfo || !IsValidPtr(typeInfo))
      return 0;

    uintptr_t staticFields = Read<uintptr_t>(typeInfo + 0xB8);
    if (!staticFields || !IsValidPtr(staticFields))
      return 0;

    // pool is the first static field (BufferList<Projectile>)
    uintptr_t pool = Read<uintptr_t>(staticFields + 0x00);
    if (!pool || !IsValidPtr(pool))
      return 0;

    // BufferList<T>: buffer at +0x10, count at +0x18
    uintptr_t buffer = Read<uintptr_t>(pool + 0x10);
    int count = Read<int>(pool + 0x18);
    if (!buffer || !IsValidPtr(buffer) || count <= 0 || count > 256)
      return 0;

    int found = 0;
    for (int i = 0; i < count && found < maxCount; i++) {
      uintptr_t proj = Read<uintptr_t>(buffer + 0x20 + i * 8);
      if (!proj || !IsValidPtr(proj))
        continue;

      // Check owner matches local player
      uintptr_t owner = Read<uintptr_t>(proj + offsets::Projectile::owner);
      if (owner != localPlayer)
        continue;

      // Read position and velocity
      Vec3 pos = Read<Vec3>(proj + offsets::Projectile::currentPosition);
      Vec3 vel = Read<Vec3>(proj + offsets::Projectile::currentVelocity);

      // Sanity check - position should be near the game world (not
      // zero/garbage)
      if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
        continue;
      if (fabsf(pos.x) > 10000.f || fabsf(pos.y) > 10000.f ||
          fabsf(pos.z) > 10000.f)
        continue;

      outBuf[found].address = proj;
      outBuf[found].position = pos;
      outBuf[found].velocity = vel;
      found++;
    }
    return found;
  }

  /* ── No-spread: scale aimcone on held weapon ────────── */

  struct SpreadCache {
    uintptr_t weapon = 0;
    float aimCone = 0, hipAimCone = 0;
    float penaltyPerShot = 0, penaltyMax = 0;
    float stancePenalty = 0, aimSway = 0, aimSwaySpeed = 0;
  };
  SpreadCache cachedSpread;

  bool ApplyNoSpread(uintptr_t localPlayer, float spreadPct) {
    if (!localPlayer || !IsValidPtr(localPlayer))
      return false;

    uintptr_t weapon = GetActiveWeaponBaseProjectile(localPlayer);
    if (!weapon)
      return false;

    // Cache original spread values when weapon changes
    if (cachedSpread.weapon != weapon) {
      cachedSpread.weapon = weapon;
      cachedSpread.aimCone =
          Read<float>(weapon + offsets::BaseProjectile::aimCone);
      cachedSpread.hipAimCone =
          Read<float>(weapon + offsets::BaseProjectile::hipAimCone);
      cachedSpread.penaltyPerShot =
          Read<float>(weapon + offsets::BaseProjectile::aimconePenaltyPerShot);
      cachedSpread.penaltyMax =
          Read<float>(weapon + offsets::BaseProjectile::aimConePenaltyMax);
      cachedSpread.stancePenalty =
          Read<float>(weapon + offsets::BaseProjectile::stancePenaltyScale);
      cachedSpread.aimSway =
          Read<float>(weapon + offsets::BaseProjectile::aimSway);
      cachedSpread.aimSwaySpeed =
          Read<float>(weapon + offsets::BaseProjectile::aimSwaySpeed);
    }

    // Scale: 0% = zero spread, 100% = original
    float scale = spreadPct / 100.0f;
    if (scale < 0.0f)
      scale = 0.0f;
    if (scale > 1.0f)
      scale = 1.0f;

    Write<float>(weapon + offsets::BaseProjectile::aimCone,
                 cachedSpread.aimCone * scale);
    Write<float>(weapon + offsets::BaseProjectile::hipAimCone,
                 cachedSpread.hipAimCone * scale);
    Write<float>(weapon + offsets::BaseProjectile::aimconePenaltyPerShot,
                 cachedSpread.penaltyPerShot * scale);
    Write<float>(weapon + offsets::BaseProjectile::aimConePenaltyMax,
                 cachedSpread.penaltyMax * scale);
    Write<float>(weapon + offsets::BaseProjectile::stancePenaltyScale,
                 cachedSpread.stancePenalty * scale);
    Write<float>(weapon + offsets::BaseProjectile::aimSway,
                 cachedSpread.aimSway * scale);
    Write<float>(weapon + offsets::BaseProjectile::aimSwaySpeed,
                 cachedSpread.aimSwaySpeed * scale);
    if (scale == 0.0f) {
      Write<int>(weapon + offsets::BaseProjectile::numShotsFired, 0);
    }

    return true;
  }

  bool RestoreSpread(uintptr_t localPlayer) {
    if (!localPlayer || !IsValidPtr(localPlayer))
      return false;
    if (cachedSpread.weapon == 0)
      return false;

    uintptr_t weapon = GetActiveWeaponBaseProjectile(localPlayer);
    if (!weapon || weapon != cachedSpread.weapon)
      return false;

    Write<float>(weapon + offsets::BaseProjectile::aimCone,
                 cachedSpread.aimCone);
    Write<float>(weapon + offsets::BaseProjectile::hipAimCone,
                 cachedSpread.hipAimCone);
    Write<float>(weapon + offsets::BaseProjectile::aimconePenaltyPerShot,
                 cachedSpread.penaltyPerShot);
    Write<float>(weapon + offsets::BaseProjectile::aimConePenaltyMax,
                 cachedSpread.penaltyMax);
    Write<float>(weapon + offsets::BaseProjectile::stancePenaltyScale,
                 cachedSpread.stancePenalty);
    Write<float>(weapon + offsets::BaseProjectile::aimSway,
                 cachedSpread.aimSway);
    Write<float>(weapon + offsets::BaseProjectile::aimSwaySpeed,
                 cachedSpread.aimSwaySpeed);

    cachedSpread.weapon = 0;
    return true;
  }

  /* ── No-recoil: scale recoil on held weapon ──────────── */

  struct RecoilCache {
    uintptr_t weapon = 0;
    float yawMin = 0, yawMax = 0, pitchMin = 0, pitchMax = 0;
    float nYawMin = 0, nYawMax = 0, nPitchMin = 0, nPitchMax = 0;
    bool hasNew = false;
  };
  RecoilCache cachedRecoil;

  bool WriteRecoilScaled(uintptr_t addr, float original, float reductionPct) {
    float scale = 1.0f - (reductionPct / 100.0f); // 100% reduction → 0 scale
    float target = original * scale;
    bool ok = Write<float>(addr, target);
    return ok;
  }

  // Verify a write by reading back — returns true if the value matches
  bool VerifyWrite(uintptr_t addr, float expected) {
    float readback = Read<float>(addr);
    return (readback == expected);
  }

  bool ApplyNoRecoil(uintptr_t localPlayer) {
    if (!localPlayer || !IsValidPtr(localPlayer))
      return false;

    uintptr_t heldEntity = GetActiveWeaponBaseProjectile(localPlayer);
    if (!heldEntity)
      return false;

    uintptr_t recoilPtr =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::recoilProperties);
    if (!recoilPtr || !IsValidPtr(recoilPtr)) {
      static int dbgCount = 0;
      if (dbgCount++ % 600 == 0) {
        printf("[NR] recoilPtr FAIL: weapon=0x%llX +0x%X -> 0x%llX\n",
               (uint64_t)heldEntity, offsets::BaseProjectile::recoilProperties, (uint64_t)recoilPtr);
      }
      return false;
    }

    // Cache original recoil values when weapon changes
    if (cachedRecoil.weapon != heldEntity) {
      cachedRecoil.weapon = heldEntity;
      cachedRecoil.yawMin =
          Read<float>(recoilPtr + offsets::RecoilProperties::recoilYawMin);
      cachedRecoil.yawMax =
          Read<float>(recoilPtr + offsets::RecoilProperties::recoilYawMax);
      cachedRecoil.pitchMin =
          Read<float>(recoilPtr + offsets::RecoilProperties::recoilPitchMin);
      cachedRecoil.pitchMax =
          Read<float>(recoilPtr + offsets::RecoilProperties::recoilPitchMax);

      printf("[NR] Cached recoil: yaw=[%.2f,%.2f] pitch=[%.2f,%.2f] ptr=0x%llX\n",
             cachedRecoil.yawMin, cachedRecoil.yawMax,
             cachedRecoil.pitchMin, cachedRecoil.pitchMax, (uint64_t)recoilPtr);

      uintptr_t newRecoil =
          Read<uintptr_t>(recoilPtr + offsets::RecoilProperties::new_recoil);
      cachedRecoil.hasNew = (newRecoil && IsValidPtr(newRecoil));
      if (cachedRecoil.hasNew) {
        cachedRecoil.nYawMin =
            Read<float>(newRecoil + offsets::RecoilProperties::recoilYawMin);
        cachedRecoil.nYawMax =
            Read<float>(newRecoil + offsets::RecoilProperties::recoilYawMax);
        cachedRecoil.nPitchMin =
            Read<float>(newRecoil + offsets::RecoilProperties::recoilPitchMin);
        cachedRecoil.nPitchMax =
            Read<float>(newRecoil + offsets::RecoilProperties::recoilPitchMax);
        printf("[NR] New recoil: yaw=[%.2f,%.2f] pitch=[%.2f,%.2f] ptr=0x%llX\n",
               cachedRecoil.nYawMin, cachedRecoil.nYawMax,
               cachedRecoil.nPitchMin, cachedRecoil.nPitchMax, (uint64_t)newRecoil);
      }
    }

    float pct = g_recoilControl;
    float scale = 1.0f - (pct / 100.0f);
    int writeOk = 0, writeFail = 0;

    if (WriteRecoilScaled(recoilPtr + offsets::RecoilProperties::recoilYawMin,
                          cachedRecoil.yawMin, pct)) writeOk++; else writeFail++;
    if (WriteRecoilScaled(recoilPtr + offsets::RecoilProperties::recoilYawMax,
                          cachedRecoil.yawMax, pct)) writeOk++; else writeFail++;
    if (WriteRecoilScaled(recoilPtr + offsets::RecoilProperties::recoilPitchMin,
                          cachedRecoil.pitchMin, pct)) writeOk++; else writeFail++;
    if (WriteRecoilScaled(recoilPtr + offsets::RecoilProperties::recoilPitchMax,
                          cachedRecoil.pitchMax, pct)) writeOk++; else writeFail++;

    if (cachedRecoil.hasNew) {
      uintptr_t newRecoil =
          Read<uintptr_t>(recoilPtr + offsets::RecoilProperties::new_recoil);
      if (newRecoil && IsValidPtr(newRecoil)) {
        if (WriteRecoilScaled(newRecoil + offsets::RecoilProperties::recoilYawMin,
                              cachedRecoil.nYawMin, pct)) writeOk++; else writeFail++;
        if (WriteRecoilScaled(newRecoil + offsets::RecoilProperties::recoilYawMax,
                              cachedRecoil.nYawMax, pct)) writeOk++; else writeFail++;
        if (WriteRecoilScaled(newRecoil + offsets::RecoilProperties::recoilPitchMin,
                              cachedRecoil.nPitchMin, pct)) writeOk++; else writeFail++;
        if (WriteRecoilScaled(newRecoil + offsets::RecoilProperties::recoilPitchMax,
                              cachedRecoil.nPitchMax, pct)) writeOk++; else writeFail++;
      }
    }

    // Periodic read-back verification to confirm writes actually persist
    static int verifyCount = 0;
    if (verifyCount++ % 300 == 0) {
      float readback = Read<float>(recoilPtr + offsets::RecoilProperties::recoilYawMin);
      float expected = cachedRecoil.yawMin * scale;
      bool persisted = (fabsf(readback - expected) < 0.001f);
      printf("[NR] Write %d ok, %d fail | readback=%.3f expected=%.3f %s\n",
             writeOk, writeFail, readback, expected,
             persisted ? "PERSISTED" : "REVERTED (game overwrote!)");
      if (!persisted && writeFail == 0) {
        printf("[NR] >>> Writes succeed but game REVERTS them — server-authoritative recoil\n");
      }
    }

    return (writeFail == 0);
  }

  bool RestoreRecoil(uintptr_t localPlayer) {
    if (!localPlayer || !IsValidPtr(localPlayer))
      return false;
    if (cachedRecoil.weapon == 0)
      return false;

    uintptr_t heldEntity = GetActiveWeaponBaseProjectile(localPlayer);
    if (!heldEntity)
      return false;

    uintptr_t recoilPtr =
        Read<uintptr_t>(heldEntity + offsets::BaseProjectile::recoilProperties);
    if (!recoilPtr || !IsValidPtr(recoilPtr))
      return false;

    // Only restore if this is the same weapon we cached
    if (cachedRecoil.weapon != heldEntity)
      return false;

    Write<float>(recoilPtr + offsets::RecoilProperties::recoilYawMin,
                 cachedRecoil.yawMin);
    Write<float>(recoilPtr + offsets::RecoilProperties::recoilYawMax,
                 cachedRecoil.yawMax);
    Write<float>(recoilPtr + offsets::RecoilProperties::recoilPitchMin,
                 cachedRecoil.pitchMin);
    Write<float>(recoilPtr + offsets::RecoilProperties::recoilPitchMax,
                 cachedRecoil.pitchMax);

    if (cachedRecoil.hasNew) {
      uintptr_t newRecoil =
          Read<uintptr_t>(recoilPtr + offsets::RecoilProperties::new_recoil);
      if (newRecoil && IsValidPtr(newRecoil)) {
        Write<float>(newRecoil + offsets::RecoilProperties::recoilYawMin,
                     cachedRecoil.nYawMin);
        Write<float>(newRecoil + offsets::RecoilProperties::recoilYawMax,
                     cachedRecoil.nYawMax);
        Write<float>(newRecoil + offsets::RecoilProperties::recoilPitchMin,
                     cachedRecoil.nPitchMin);
        Write<float>(newRecoil + offsets::RecoilProperties::recoilPitchMax,
                     cachedRecoil.nPitchMax);
      }
    }

    cachedRecoil.weapon = 0; // invalidate cache
    return true;
  }

  /* ── Find local player (closest to camera) ─────────────── */

  uintptr_t FindLocalPlayer() {
    Vec3 camPos = GetCameraPosition();
    if (camPos.x == 0.f && camPos.y == 0.f && camPos.z == 0.f) {
      return 0;
    }

    uintptr_t best = 0;
    float bestDist = 5.0f;

    int count = GetEntityCount();

    for (int i = 0; i < count && i < 100; i++) {
      uintptr_t ent = GetEntity(i);
      
      if (!ent || !IsValidPtr(ent)) {
        continue;
      }
      
      // Check if it's a player first
      if (!IsPlayer(ent)) {
        continue;
      }
      
      // Get position
      uintptr_t pm = Read<uintptr_t>(ent + offsets::BasePlayer::playerModel);
      if (!pm) {
        continue;
      }

      Vec3 pos = Read<Vec3>(pm + offsets::PlayerModel::position);
      float d = (pos - camPos).Length();
      
      if (d < bestDist) {
        bestDist = d;
        best = ent;
      }
    }
    
    return best;
  }

  /* ── GetLocalPlayer (cached, refreshed periodically) ──── */

  uintptr_t GetLocalPlayer() {
    ULONGLONG now = GetTickCount64();
    
    // Refresh every 2 seconds or if we don't have a local player
    if (!cachedLocalPlayer || (now - lastLocalRefresh) > 2000) {
      lastLocalRefresh = now;
      cachedLocalPlayer = FindLocalPlayer();
    }
    
    return cachedLocalPlayer;
  }

  // Check if player is currently in a server (has a valid local player)
  bool IsInServer() {
    uintptr_t local = GetLocalPlayer();
    return local != 0 && IsValidPtr(local);
  }

  // Force clear cached state (call on server change / disconnect)
  void InvalidateCache() {
    cachedLocalPlayer = 0;
    lastLocalRefresh = 0;
    entityBuffer = 0;
    entityCount = 0;
  }

  /* ── Get decrypted PlayerEyes pointer ────────────────── */

  uintptr_t GetPlayerEyes(uintptr_t player) {
    if (!player || !IsValidPtr(player))
      return 0;

    // Read encrypted eyes (may be wrapper or inline encrypted)
    uintptr_t raw = Read<uintptr_t>(player + offsets::BasePlayer::eyes);
    if (!raw)
      return 0;

    // Try wrapper pattern: wrapper → +0x18 → encrypted payload → decrypt → GC
    // resolve
    if (IsValidPtr(raw)) {
      uintptr_t encPayload = Read<uintptr_t>(raw + 0x18);
      if (encPayload) {
        uintptr_t dec = _dec_eyes(encPayload);
        uintptr_t resolved = il2cpp_get_handle(dec);
        if (resolved && IsValidPtr(resolved))
          return resolved;
      }
    }

    // Fallback: try raw value as inline encrypted
    uintptr_t dec = _dec_eyes(raw);
    uintptr_t resolved = il2cpp_get_handle(dec);
    if (resolved && IsValidPtr(resolved))
      return resolved;

    // Last fallback: try raw as direct pointer
    if (IsValidPtr(raw))
      return raw;

    return 0;
  }

  /* ── Projectile detection ─────────────────────────── */

  std::vector<uintptr_t> GetProjectiles() {
    std::vector<uintptr_t> projectiles;
    
    // Use the new ProjectileList chain
    uintptr_t projectileList = ReadChain(gameAssembly + 0xD7D92C0, {
      0x10,    // projectile list field
      0x18     // final offset
    });
    
    if (!IsValidPtr(projectileList)) {
      return projectiles;
    }
    
    int projectileCount = Read<int>(projectileList + 0x18);
    uintptr_t projectileBuffer = Read<uintptr_t>(projectileList + 0x10);
    
    if (!IsValidPtr(projectileBuffer) || projectileCount <= 0 || projectileCount > 1000) {
      return projectiles;
    }
    
    // Read all projectiles
    for (int i = 0; i < projectileCount && i < 100; i++) {
      uintptr_t projectile = Read<uintptr_t>(projectileBuffer + (uintptr_t)i * 8);
      if (IsValidPtr(projectile)) {
        // Verify it's actually a projectile by checking class name
        std::string className = ReadClassName(projectile);
        if (className == "Projectile") {
          projectiles.push_back(projectile);
        }
      }
    }
    
    return projectiles;
  }

  /* ── Public read/write templates ──────────────────────── */

  template <typename T> T ReadVal(uintptr_t addr) { return Read<T>(addr); }

  template <typename T> bool WriteVal(uintptr_t addr, const T &value) {
    return Write<T>(addr, value);
  }

  /* ── Movement field encryption (auto-calibrated from game binary) ── */
  // Each encrypted field has unique encrypt/decrypt ops extracted at runtime.
  // edi = (uint32_t)(movementPtr) is used as per-instance key (sub eax,edi).

  // Dynamic encryption entry: ops extracted from setter method machine code
  struct DynMovField {
    int offset = 0;                      // field offset in PlayerWalkMovement
    std::vector<DcrStep> encOps;         // encrypt operations (from setter)
    bool calibrated = false;
    const char* setterName = nullptr;    // IL2CPP setter method name
    const char* fieldName = nullptr;     // field name for IL2CPP offset resolution
  };

  static constexpr int MAX_DYN_MOV = 24;
  DynMovField dynMov[MAX_DYN_MOV];
  int dynMovCount = 0;
  bool movCalibrated = false;

  // Apply encrypt operations forward (same order as game setter)
  static uint32_t ApplyEncOps(uint32_t v, const std::vector<DcrStep>& ops) {
    for (auto& s : ops) {
      switch (s.op) {
      case DcrOp::ADD: v += s.val; break;
      case DcrOp::SUB: v -= s.val; break;
      case DcrOp::XOR: v ^= s.val; break;
      case DcrOp::ROL: v = _rotl(v, s.val); break;
      case DcrOp::ROR: v = _rotr(v, s.val); break;
      }
    }
    return v;
  }

  // Apply decrypt operations (reverse order, inverse ops)
  static uint32_t ApplyDecOps(uint32_t v, const std::vector<DcrStep>& ops) {
    for (int i = (int)ops.size() - 1; i >= 0; i--) {
      auto& s = ops[i];
      switch (s.op) {
      case DcrOp::ADD: v -= s.val; break;
      case DcrOp::SUB: v += s.val; break;
      case DcrOp::XOR: v ^= s.val; break;
      case DcrOp::ROL: v = _rotr(v, s.val); break;
      case DcrOp::ROR: v = _rotl(v, s.val); break;
      }
    }
    return v;
  }

  // Register a movement field for auto-calibration
  void RegisterMovField(int offset, const char* setterName, const char* fieldName) {
    if (dynMovCount >= MAX_DYN_MOV) return;
    auto& f = dynMov[dynMovCount++];
    f.offset = offset;
    f.setterName = setterName;
    f.fieldName = fieldName;
    f.calibrated = false;
  }

  // Auto-calibrate all movement encryption from game binary
  bool CalibrateMovementEncryption() {
    if (movCalibrated) return true;
    if (!resolver.Good()) {
#ifndef DISABLE_OUTPUT
      printf("[MOVEMENT] IL2CPP resolver not ready, can't calibrate\n");
#endif
      return false;
    }

#ifndef DISABLE_OUTPUT
    printf("[MOVEMENT] Auto-calibrating encryption from game binary...\n");
#endif

    // Register only the movement fields we actually use
    if (dynMovCount == 0) {
      RegisterMovField(offsets::PlayerWalkMovement::spiderman,
                        "set_MaxAngleWalking", "MaxAngleWalking");
    }

    int ok = 0, fail = 0;
    for (int i = 0; i < dynMovCount; i++) {
      auto& f = dynMov[i];
      // Try primary setter name
      uintptr_t code = resolver.MethodNative("PlayerWalkMovement", f.setterName);

      // Try alternate naming conventions if primary fails
      if (!code) {
        // Try lowercase first letter: set_gravity, set_gravityMultiplier, etc.
        char altName[128];
        snprintf(altName, sizeof(altName), "set_%c%s",
                 tolower(f.fieldName[0]), f.fieldName + 1);
        code = resolver.MethodNative("PlayerWalkMovement", altName);
      }
      if (!code) {
        // Try with underscore prefix: set__gravity
        char altName[128];
        snprintf(altName, sizeof(altName), "set__%c%s",
                 tolower(f.fieldName[0]), f.fieldName + 1);
        code = resolver.MethodNative("PlayerWalkMovement", altName);
      }

      if (!code) {
#ifndef DISABLE_OUTPUT
        printf("[MOVEMENT]   %s: setter not found\n", f.setterName);
#endif
        fail++;
        continue;
      }

      std::vector<DcrStep> ops;
      if (!resolver.ExtractOpsFromNative(code, ops) || ops.empty()) {
        #ifndef DISABLE_OUTPUT
      printf("[MOVEMENT]   %s: no encrypt ops found at 0x%llX\n",
               f.setterName, (uint64_t)code);
#endif
        fail++;
        continue;
      }

      f.encOps = std::move(ops);
      f.calibrated = true;
      ok++;

      #ifndef DISABLE_OUTPUT
      printf("[MOVEMENT]   %s (0x%X): %d ops extracted [",
             f.setterName, f.offset, (int)f.encOps.size());
      for (size_t j = 0; j < f.encOps.size(); j++) {
        auto& s = f.encOps[j];
        const char* opn[] = {"ADD","SUB","XOR","ROL","ROR"};
        printf("%s%s 0x%X", j?", ":"", opn[(int)s.op], s.val);
      }
      printf("]\n");
#endif
    }

#ifndef DISABLE_OUTPUT
    printf("[MOVEMENT] Calibration: %d/%d fields OK\n", ok, ok + fail);
#endif
    movCalibrated = (ok > 0);
    return movCalibrated;
  }

  // Find the DynMovField for a given field offset
  DynMovField* FindDynMov(int fieldOffset) {
    for (int i = 0; i < dynMovCount; i++) {
      if (dynMov[i].offset == fieldOffset && dynMov[i].calibrated)
        return &dynMov[i];
    }
    return nullptr;
  }

  bool WriteMovementFloat(uintptr_t movementPtr, int fieldOffset, float value) {
    if (!movementPtr || movementPtr < 0x10000 || movementPtr > 0x7FFFFFFFFFFF || !IsValidPtr(movementPtr))
      return false;
    if (fieldOffset < 0 || fieldOffset > 0x200)
      return false;

    // Ensure calibration has been attempted
    if (!movCalibrated) CalibrateMovementEncryption();

    uint32_t edi = (uint32_t)(movementPtr & 0xFFFFFFFF);
    uint32_t raw; memcpy(&raw, &value, 4);

    DynMovField* f = FindDynMov(fieldOffset);
    if (f) {
      uint32_t encrypted = ApplyEncOps(raw, f->encOps);
      encrypted -= edi;  // per-instance key subtraction
#ifndef DISABLE_OUTPUT
      static int dbgMov = 0;
      if (dbgMov++ % 300 == 0) {
        printf("[MOVEMENT] Write: offset=0x%X val=%.2f raw=0x%08X enc=0x%08X edi=0x%08X\n",
               fieldOffset, value, raw, encrypted, edi);
      }
#endif
      return Write<uint32_t>(movementPtr + fieldOffset, encrypted);
    }

    // No calibrated encryption for this offset - write raw
    static bool warnedRaw = false;
    if (!warnedRaw) {
      printf("[MOVEMENT] WARNING: no calibrated encryption for offset 0x%X, writing raw\n", fieldOffset);
      warnedRaw = true;
    }
    return Write<float>(movementPtr + fieldOffset, value);
  }

  float ReadMovementFloat(uintptr_t movementPtr, int fieldOffset) {
    if (!movementPtr) return 0.0f;
    if (!movCalibrated) CalibrateMovementEncryption();

    uint32_t edi = (uint32_t)(movementPtr & 0xFFFFFFFF);
    uint32_t enc = Read<uint32_t>(movementPtr + fieldOffset);

    DynMovField* f = FindDynMov(fieldOffset);
    if (f) {
      uint32_t dec = enc + edi;  // reverse per-instance key subtraction
      dec = ApplyDecOps(dec, f->encOps);
      float result; memcpy(&result, &dec, 4);
      return result;
    }

    // No calibrated decryption - return raw float
    float result; memcpy(&result, &enc, 4);
    return result;
  }

  /* ── Bulk bone positions (for aimbot wrapper) ─────────── */

  int GetBonePositions(uintptr_t entity, Vec3 *outBones, int maxBones) {
    if (!entity || !IsValidPtr(entity))
      return 0;

    // Try playerModel first (animated bones), fall back to base model
    uintptr_t model =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!model || !IsValidPtr(model))
      model = Read<uintptr_t>(entity + offsets::BaseCombatEntity::model);
    if (!model || !IsValidPtr(model))
      return 0;

    uintptr_t boneArray =
        Read<uintptr_t>(model + offsets::Model::boneTransforms);
    if (!boneArray || !IsValidPtr(boneArray))
      return 0;

    int boneCount = Read<int>(boneArray + 0x18);
    if (boneCount <= 0 || boneCount > 200)
      return 0;
    if (boneCount > maxBones)
      boneCount = maxBones;

    memset(outBones, 0, sizeof(Vec3) * maxBones);

    /* Read all transform pointers in one batch */
    std::vector<uintptr_t> bonePtrs(boneCount);
    if (!ReadArray<uintptr_t>(boneArray + 0x20, bonePtrs.data(), boneCount))
      return 0;

    int valid = 0;
    for (int i = 0; i < boneCount; i++) {
      uintptr_t boneEntity = bonePtrs[i];
      if (!boneEntity || !IsValidPtr(boneEntity))
        continue;
      Vec3 pos = ReadTransformPosition(boneEntity);
      if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
        continue;
      outBones[i] = pos;
      valid++;
    }
    return valid;
  }

  /* ── Get active weapon (BaseProjectile) ───────────────── */

  /* ── Decrypt clactiveitem → held entity ─────────────────── */
  std::vector<std::string> aiProbeLog;

  static uintptr_t _dec_inventory(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x -= 0x600B999Cu;
      x ^= 0xE017EC85u;
      x = (x << 6) | (x >> 26);
      p[i] = x;
    }
    return v;
  }
  static uintptr_t _dec_eyes(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x += 0x5A59459Fu;
      x = (x << 1) | (x >> 31);
      x += 0x533DF48Au;
      x = (x << 5) | (x >> 27);
      p[i] = x;
    }
    return v;
  }
  static uintptr_t _dec_client(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x = (x << 12) | (x >> 20);
      x += 0x73400338u;
      x = (x << 9) | (x >> 23);
      p[i] = x;
    }
    return v;
  }
  static uintptr_t _dec_entlist(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x = (x << 20) | (x >> 12);
      x ^= 0xDA2510F8u;
      x = (x << 4) | (x >> 28);
      x ^= 0xFD0B1AB6u;
      p[i] = x;
    }
    return v;
  }
  static uintptr_t _dec_newce(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x = (x << 5) | (x >> 27);
      x -= 0x0E7ED9B4u;
      x ^= 0x1F6ABC70u;
      x += 0x27EAFFD5u;
      p[i] = x;
    }
    return v;
  }
  static uintptr_t _dec_newel(uintptr_t v) {
    uint32_t *p = (uint32_t *)&v;
    for (int i = 0; i < 2; i++) {
      uint32_t x = p[i];
      x += 0xFA6E5A7Du;
      x = (x << 21) | (x >> 11);
      x += 0x16D2B296u;
      p[i] = x;
    }
    return v;
  }

  uintptr_t DecryptActiveItem(uintptr_t player) {
    if (!player || !IsValidPtr(player))
      return 0;

    uintptr_t rawEnc =
        Read<uintptr_t>(player + offsets::BasePlayer::clactiveitem);
    if (!rawEnc)
      return 0;

    static bool logged = false;

    typedef uintptr_t (*Fn)(uintptr_t);
    struct Try {
      const char *name;
      Fn fn;
    };
    Try tries[] = {
        {"Inventory", _dec_inventory}, {"Eyes", _dec_eyes},
        {"ClientEnt", _dec_client},    {"EntityList", _dec_entlist},
        {"NewCE", _dec_newce},         {"NewEL", _dec_newel},
    };

    auto probe = [&](uintptr_t enc, const char *prefix) -> uintptr_t {
      for (auto &t : tries) {
        uintptr_t dec = t.fn(enc);
        uintptr_t res = il2cpp_get_handle(dec);
        if (!logged) {
          char lb[256];
          snprintf(lb, sizeof(lb), "[AIPROBE] %s%s dec=0x%llX res=0x%llX %s",
                   prefix, t.name, (uint64_t)dec, (uint64_t)res,
                   IsValidPtr(res) ? "VALID" : "bad");
          aiProbeLog.push_back(lb);
        }
        if (IsValidPtr(res)) {
          logged = true;
          return res;
        }
        if (IsValidPtr(dec)) {
          logged = true;
          return dec;
        }
      }
      return 0;
    };

    // Pass 1: treat rawEnc as the encrypted payload directly
    uintptr_t r = probe(rawEnc, "");
    if (r)
      return r;

    // Pass 2: treat rawEnc as a wrapper pointer, read +0x18 as payload
    if (IsValidPtr(rawEnc)) {
      uintptr_t inner = Read<uintptr_t>(rawEnc + 0x18);
      if (inner && inner != rawEnc) {
        r = probe(inner, "wrap+");
        if (r)
          return r;
      }
    }

    if (!logged) {
      logged = true;
      char lb[256];
      snprintf(lb, sizeof(lb), "[AIPROBE] rawEnc=0x%llX all failed",
               (uint64_t)rawEnc);
      aiProbeLog.push_back(lb);
    }
    return 0;
  }

  
  /* ── FOV changer (Convar.Graphics static field) ─────────────────── */
  // Auto-probing: tries multiple decrypt methods + offsets to find working combo
  
  // Decrypt method 0: XOR, ADD, ROL1 (encrypt_0x518 — from forum decrypt block)
  static float fovDec0(uint32_t enc) {
    uint32_t v = enc;
    v ^= 0x31A4D432u;          // xor
    v += 0x2D4D0EE2u;          // add
    v = (v << 1) | (v >> 31);  // ROL 1
    float f; memcpy(&f, &v, 4); return f;
  }
  static uint32_t fovEnc0(float value) {
    uint32_t v; memcpy(&v, &value, 4);
    v = (v >> 1) | (v << 31);  // ROR 1 (reverse ROL)
    v -= 0x2D4D0EE2u;          // reverse add
    v ^= 0x31A4D432u;          // reverse xor
    return v;
  }
  // Decrypt method 1: ROR4, ADD, XOR
  static float fovDec1(uint32_t enc) {
    uint32_t v = enc;
    v = (v >> 4) | (v << 28); v += 0x385A4AEFu; v ^= 0xC4027EBDu;
    float f; memcpy(&f, &v, 4); return f;
  }
  static uint32_t fovEnc1(float value) {
    uint32_t v; memcpy(&v, &value, 4);
    v ^= 0xC4027EBDu; v -= 0x385A4AEFu; v = (v << 4) | (v >> 28); return v;
  }
  // Decrypt method 2: XOR, ROL3, ADD
  static float fovDec2(uint32_t enc) {
    uint32_t v = enc; v ^= 0x31A4D432u;
    v = (v << 3) | (v >> 29); v += 0x2D4D0EE2u;
    float f; memcpy(&f, &v, 4); return f;
  }
  static uint32_t fovEnc2(float value) {
    uint32_t v; memcpy(&v, &value, 4);
    v -= 0x2D4D0EE2u; v = (v >> 3) | (v << 29); v ^= 0x31A4D432u; return v;
  }
  // Decrypt method 3: raw float (no encryption)
  static float fovDec3(uint32_t enc) {
    float f; memcpy(&f, &enc, 4); return f;
  }
  static uint32_t fovEnc3(float value) {
    uint32_t v; memcpy(&v, &value, 4); return v;
  }
  
  // BaseMovement encryption functions (methods 4-8)
  // Method 4: encrypt_0x70
  static float fovDec4(uint32_t enc) {
    uint32_t eax = enc;
    eax = (eax >> 0x0B) | (eax << 0x15);
    eax ^= 0x11456947;
    eax = (eax >> 0x18) | (eax << 0x08);
    eax += 0x7FA7902F;
    float f; memcpy(&f, &eax, 4); return f;
  }
  static uint32_t fovEnc4(float value) {
    uint32_t eax; memcpy(&eax, &value, 4);
    eax -= 0x7FA7902F;
    eax = (eax << 0x18) | (eax >> 0x08);
    eax ^= 0x11456947;
    eax = (eax << 0x0B) | (eax >> 0x15);
    return eax;
  }
  
  // Method 5: encrypt_0x78
  static float fovDec5(uint32_t enc) {
    uint32_t eax = enc;
    eax += 0x7A01AFDA;
    eax ^= 0xBE2377E1;
    eax = (eax >> 0x12) | (eax << 0x0E);
    float f; memcpy(&f, &eax, 4); return f;
  }
  static uint32_t fovEnc5(float value) {
    uint32_t eax; memcpy(&eax, &value, 4);
    eax = (eax << 0x12) | (eax >> 0x0E);
    eax ^= 0xBE2377E1;
    eax -= 0x7A01AFDA;
    return eax;
  }
  
  // Method 6: encrypt_0x80
  static float fovDec6(uint32_t enc) {
    uint32_t eax = enc;
    eax += 0x92CC5E66;
    eax = (eax >> 0x05) | (eax << 0x1B);
    eax += 0x68124071;
    eax = (eax >> 0x0E) | (eax << 0x12);
    float f; memcpy(&f, &eax, 4); return f;
  }
  static uint32_t fovEnc6(float value) {
    uint32_t eax; memcpy(&eax, &value, 4);
    eax = (eax << 0x0E) | (eax >> 0x12);
    eax -= 0x68124071;
    eax = (eax >> 0x05) | (eax << 0x1B);
    eax -= 0x92CC5E66;
    return eax;
  }
  
  // Method 7: encrypt_0x88
  static float fovDec7(uint32_t enc) {
    uint32_t eax = enc;
    eax ^= 0x6368A31F;
    eax = (eax >> 0x1B) | (eax << 0x05);
    eax += 0x191C5CC5;
    float f; memcpy(&f, &eax, 4); return f;
  }
  static uint32_t fovEnc7(float value) {
    uint32_t eax; memcpy(&eax, &value, 4);
    eax -= 0x191C5CC5;
    eax = (eax << 0x1B) | (eax >> 0x05);
    eax ^= 0x6368A31F;
    return eax;
  }
  
  // Method 8: encrypt_0x90
  static float fovDec8(uint32_t enc) {
    uint32_t eax = enc;
    eax ^= 0x3C6FA7C9;
    eax -= 0x7722EB9B;
    eax = (eax >> 0x0C) | (eax << 0x14);
    float f; memcpy(&f, &eax, 4); return f;
  }
  static uint32_t fovEnc8(float value) {
    uint32_t eax; memcpy(&eax, &value, 4);
    eax = (eax << 0x0C) | (eax >> 0x14);
    eax += 0x7722EB9B;
    eax ^= 0x3C6FA7C9;
    return eax;
  }
  
  int fovMethod = -1;     // -1 = not calibrated
  int fovFieldOff = 0;    // calibrated offset within static fields
  
  // Dynamic FOV encryption extracted from game binary
  std::vector<DcrStep> fovDynEncOps;  // encrypt ops from setter
  bool fovDynReady = false;
  
  // Dynamic enc/dec using extracted ops (no per-instance key for static fields)
  float fovDynDec(uint32_t enc) {
    if (!fovDynReady) { float f; memcpy(&f, &enc, 4); return f; }
    uint32_t v = ApplyDecOps(enc, fovDynEncOps);
    float f; memcpy(&f, &v, 4); return f;
  }
  uint32_t fovDynEnc(float value) {
    if (!fovDynReady) { uint32_t v; memcpy(&v, &value, 4); return v; }
    uint32_t v; memcpy(&v, &value, 4);
    return ApplyEncOps(v, fovDynEncOps);
  }
  
  // Try to extract FOV encryption from game binary via IL2CPP
  bool ExtractFovEncryption() {
    if (fovDynReady) return true;
    if (!resolver.Good()) return false;
    
    // Try multiple possible setter names for _fov field
    const char* setterNames[] = {
      "set__fov", "set_fov", "set_Fov", "set__Fov"
    };
    uintptr_t code = 0;
    for (auto* name : setterNames) {
      code = resolver.MethodNative("Graphics", name, "ConVar");
      if (code) {
        printf("[FOV] Found setter '%s' at 0x%llX\n", name, (uint64_t)code);
        break;
      }
    }
    if (!code) {
      printf("[FOV] Dynamic extraction: setter not found\n");
      return false;
    }
    
    std::vector<DcrStep> ops;
    if (!resolver.ExtractOpsFromNative(code, ops) || ops.empty()) {
      printf("[FOV] Dynamic extraction: no ops found\n");
      return false;
    }
    
    fovDynEncOps = std::move(ops);
    fovDynReady = true;
    printf("[FOV] Dynamic encryption extracted: %d ops [", (int)fovDynEncOps.size());
    for (size_t j = 0; j < fovDynEncOps.size(); j++) {
      auto& s = fovDynEncOps[j];
      const char* opn[] = {"ADD","SUB","XOR","ROL","ROR"};
      printf("%s%s 0x%X", j?", ":"", opn[(int)s.op], s.val);
    }
    printf("]\n");
    return true;
  }
  
  typedef float (*FovDecFn)(uint32_t);
  typedef uint32_t (*FovEncFn)(float);
  
  struct FovMethodEntry { const char* name; FovDecFn dec; FovEncFn enc; };
  static constexpr int FOV_METHOD_COUNT = 9;
  FovMethodEntry fovMethods[FOV_METHOD_COUNT] = {
    {"XOR+ADD+ROL1", fovDec0, fovEnc0},
    {"ROR4+ADD+XOR", fovDec1, fovEnc1},
    {"XOR+ROL3+ADD", fovDec2, fovEnc2},
    {"Raw float",    fovDec3, fovEnc3},
    {"BaseMov_0x70", fovDec4, fovEnc4},
    {"BaseMov_0x78", fovDec5, fovEnc5},
    {"BaseMov_0x80", fovDec6, fovEnc6},
    {"BaseMov_0x88", fovDec7, fovEnc7},
    {"BaseMov_0x90", fovDec8, fovEnc8},
  };
  
  int fovWrapperInnerOff = 0x10; // offset of encrypted value within wrapper object
  uintptr_t fovWrapperAddr = 0;  // cached wrapper object address
  
  bool CalibrateFOV(uintptr_t sf) {
    printf("[FOV] Auto-calibrating (wrapper-aware)...\n");
    
    // The _fov field is an Encrypted<float> wrapper object (reference type).
    // sf+0x518 contains a POINTER to the wrapper; encrypted uint32 is inside it.
    // Try reading sf+0x518 as pointer first, then probe wrapper offsets.
    
    // Phase 1: Try wrapper approach at known offset 0x518
    uintptr_t wrapper = Read<uintptr_t>(sf + offsets::Graphic::fov);
    if (wrapper && IsValidPtr(wrapper) && wrapper >= 0x10000 && wrapper <= 0x7FFFFFFFFFFF) {
      printf("[FOV] sf+0x%X -> wrapper=0x%llX\n", offsets::Graphic::fov, (uint64_t)wrapper);
      
      // Try offsets within wrapper: +0x10 (first field), +0x14, +0x18, +0x1C, +0x20
      for (int innerOff = 0x10; innerOff <= 0x28; innerOff += 4) {
        uint32_t enc = Read<uint32_t>(wrapper + innerOff);
        if (enc == 0) continue;
        for (int m = 0; m < FOV_METHOD_COUNT; m++) {
          float val = fovMethods[m].dec(enc);
          if (val >= 60.0f && val <= 90.0f) {
            uint32_t testEnc = fovMethods[m].enc(val);
            float testDec = fovMethods[m].dec(testEnc);
            if (fabsf(testDec - val) < 0.01f) {
              fovMethod = m;
              fovFieldOff = offsets::Graphic::fov;
              fovWrapperInnerOff = innerOff;
              fovWrapperAddr = wrapper;
              printf("[FOV] CALIBRATED (wrapper): method=%s wrapper+0x%X (cur=%.1f enc=0x%08X)\n",
                     fovMethods[m].name, innerOff, val, enc);
              return true;
            }
          }
        }
      }
      // Dump wrapper contents for debugging
      printf("[FOV] Wrapper probe failed. Dumping wrapper contents:\n");
      for (int d = 0x00; d <= 0x30; d += 4) {
        uint32_t v = Read<uint32_t>(wrapper + d);
        float fv; memcpy(&fv, &v, 4);
        printf("[FOV]   wrapper+0x%02X = 0x%08X (%.4f)\n", d, v, fv);
      }
    } else {
      printf("[FOV] sf+0x%X = 0x%llX (not a valid wrapper ptr)\n", 
             offsets::Graphic::fov, (uint64_t)wrapper);
    }
    
    // Phase 2: Scan all static field pointers for wrapper objects containing valid FOV
    printf("[FOV] Phase 2: scanning sf pointers for wrapper with valid FOV...\n");
    for (int off = 0x000; off <= 0x800; off += 8) {
      uintptr_t ptr = Read<uintptr_t>(sf + off);
      if (!ptr || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF || !IsValidPtr(ptr)) continue;
      
      for (int innerOff = 0x10; innerOff <= 0x20; innerOff += 4) {
        uint32_t enc = Read<uint32_t>(ptr + innerOff);
        if (enc == 0) continue;
        for (int m = 0; m < FOV_METHOD_COUNT; m++) {
          float val = fovMethods[m].dec(enc);
          if (val >= 60.0f && val <= 90.0f) {
            uint32_t testEnc = fovMethods[m].enc(val);
            float testDec = fovMethods[m].dec(testEnc);
            if (fabsf(testDec - val) < 0.01f) {
              fovMethod = m;
              fovFieldOff = off;
              fovWrapperInnerOff = innerOff;
              fovWrapperAddr = ptr;
              printf("[FOV] CALIBRATED (scan): sf+0x%X->wrapper+0x%X method=%s (cur=%.1f enc=0x%08X)\n",
                     off, innerOff, fovMethods[m].name, val, enc);
              return true;
            }
          }
        }
      }
    }
    
    // Phase 3: Direct inline scan (legacy — in case it's stored as raw encrypted uint32)
    printf("[FOV] Phase 3: scanning for direct inline encrypted value...\n");
    for (int off = 0x000; off <= 0x800; off += 4) {
      uint32_t enc = Read<uint32_t>(sf + off);
      if (enc == 0) continue;
      for (int m = 0; m < FOV_METHOD_COUNT; m++) {
        float val = fovMethods[m].dec(enc);
        if (val >= 60.0f && val <= 90.0f) {
          uint32_t testEnc = fovMethods[m].enc(val);
          float testDec = fovMethods[m].dec(testEnc);
          if (fabsf(testDec - val) < 0.01f) {
            fovMethod = m;
            fovFieldOff = off;
            fovWrapperAddr = 0; // direct mode
            printf("[FOV] CALIBRATED (direct): method=%s sf+0x%X (cur=%.1f enc=0x%08X)\n",
                   fovMethods[m].name, off, val, enc);
            return true;
          }
        }
      }
    }
    
    printf("[FOV] All calibration phases FAILED\n");
    fovMethod = 0;
    fovFieldOff = offsets::Graphic::fov;
    fovWrapperAddr = 0;
    return false;
  }

  // One-time name scan for Graphics TypeInfo if the RVA is stale
  bool fovNameScanDone = false;
  
  uintptr_t ResolveGraphicsTypeInfo() {
    uintptr_t typeInfo = Read<uintptr_t>(gameAssembly + offsets::convar_graphics_pointer);
    static int d0 = 0;
    if (d0++ % 600 == 0) {
      printf("[FOV] GA+0x%llX = 0x%llX\n", (uint64_t)offsets::convar_graphics_pointer, (uint64_t)typeInfo);
      if (typeInfo && IsValidPtr(typeInfo)) {
        uintptr_t namePtr = Read<uintptr_t>(typeInfo + 0x10);
        if (namePtr && IsValidPtr(namePtr)) {
          char nameBuf[16] = {};
          ReadRaw(namePtr, nameBuf, 15);
          nameBuf[15] = 0;
          printf("[FOV]   name='%s'\n", nameBuf);
        }
      }
    }
    
    if (typeInfo && IsValidPtr(typeInfo) && typeInfo >= 0x10000 && typeInfo <= 0x7FFFFFFFFFFF) {
      // Verify it's actually Graphics by checking static fields exist
      uintptr_t sf = Read<uintptr_t>(typeInfo + 0xB8);
      if (sf && IsValidPtr(sf) && sf >= 0x10000 && sf <= 0x7FFFFFFFFFFF)
        return typeInfo;
    }
    
    if (fovNameScanDone) return 0;
    fovNameScanDone = true;
    
    printf("[FOV] convar_graphics_pointer stale, doing name scan...\n");
    const size_t CHUNK = 0x100000;
    uint8_t* chunk = new (std::nothrow) uint8_t[CHUNK];
    if (!chunk) return 0;
    
    // "Graphics" as uint64_t LE: G=47 r=72 a=61 p=70 h=68 i=69 c=63 s=73
    const uint64_t GFX_SIG = 0x7363696870617247ULL;
    
    for (uint64_t scanOff = 0xD000000; scanOff < 0xE200000; scanOff += CHUNK) {
      size_t rd = (size_t)min((uint64_t)CHUNK, (uint64_t)0xE200000 - scanOff);
      if (!ReadRaw(gameAssembly + scanOff, chunk, rd)) continue;
      
      for (size_t j = 0; j + 8 <= rd; j += 8) {
        uintptr_t candidate = *(uintptr_t*)(chunk + j);
        if (!candidate || candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
        
        uintptr_t namePtr = Read<uintptr_t>(candidate + 0x10);
        if (!namePtr || namePtr < 0x10000) continue;
        
        uint64_t nameVal = Read<uint64_t>(namePtr);
        if (nameVal != GFX_SIG) continue;
        
        // Check namespace at +0x18 is "ConVar"
        uintptr_t nsPtr = Read<uintptr_t>(candidate + 0x18);
        if (!nsPtr || nsPtr < 0x10000) continue;
        uint64_t nsVal = Read<uint64_t>(nsPtr);
        // "ConVar\0\0" LE = 0x000072615665634FULL  ... let me just check first 6 chars
        char nsBuf[8] = {};
        memcpy(nsBuf, &nsVal, 8);
        if (memcmp(nsBuf, "ConVar", 6) != 0) continue;
        
        uint64_t foundRVA = scanOff + j;
        printf("[FOV] Name scan FOUND ConVar.Graphics at GA+0x%llX (klass=0x%llX)\n",
               foundRVA, (uint64_t)candidate);
        offsets::convar_graphics_pointer = foundRVA;
        offsets::Graphic::Base = foundRVA;
        delete[] chunk;
        return candidate;
      }
    }
    delete[] chunk;
    printf("[FOV] Name scan: ConVar.Graphics not found\n");
    return 0;
  }

  // Cached FOV state
  uintptr_t fovEncAddr = 0;       // Address of the encrypted uint32 (legacy)
  uintptr_t fovSimpleAddr = 0;    // Address for simple raw float write (reference approach)
  bool fovInitialized = false;
  bool fovIsWrapper = false;
  bool fovUseSimple = false;      // true = use simple raw float write (reference project approach)
  uint32_t fovWrapperFieldOff = 0; // offset within sf for wrapper pointer
  uint32_t fovInnerOff = 0;       // offset within wrapper for encrypted value

  bool InitializeFOV() {
    printf("[FOV] InitializeFOV() called\n");
    // Step 1: Get TypeInfo
    uintptr_t typeInfo = Read<uintptr_t>(gameAssembly + offsets::convar_graphics_pointer);
    if (!typeInfo || typeInfo < 0x10000 || typeInfo > 0x7FFFFFFFFFFF) {
      printf("[FOV] TypeInfo invalid (GA+0x%llX = 0x%llX)\n",
             (uint64_t)offsets::convar_graphics_pointer, (uint64_t)typeInfo);
      return false;
    }
    printf("[FOV] TypeInfo = 0x%llX\n", typeInfo);

    // Step 2: Get static fields
    uintptr_t sf = Read<uintptr_t>(typeInfo + offsets::Graphic::StaticFields);
    if (!sf || sf < 0x10000 || sf > 0x7FFFFFFFFFFF) {
      printf("[FOV] static_fields invalid (TypeInfo+0xB8 = 0x%llX)\n", (uint64_t)sf);
      return false;
    }
    printf("[FOV] static_fields = 0x%llX\n", sf);

    // ── Phase 0: Try DYNAMIC encryption extracted from game binary ──
    if (ExtractFovEncryption()) {
      // Scan static fields for a value that decrypts to valid FOV with extracted ops
      for (int off = 0x10; off <= 0x800; off += 4) {
        uint32_t enc = Read<uint32_t>(sf + off);
        if (enc == 0) continue;
        float val = fovDynDec(enc);
        if (val >= 60.0f && val <= 90.0f) {
          uint32_t reEnc = fovDynEnc(val);
          float reCheck = fovDynDec(reEnc);
          if (fabsf(reCheck - val) < 0.01f) {
            fovEncAddr = sf + off;
            fovIsWrapper = false;
            fovInitialized = true;
            fovMethod = -2; // dynamic method marker
            printf("[FOV] INITIALIZED (dynamic IL2CPP): sf+0x%X fov=%.1f enc=0x%08X\n",
                   off, val, enc);
            return true;
          }
        }
      }
      // Also try wrapper approach with dynamic decrypt
      for (int off = 0x10; off <= 0x800; off += 8) {
        uintptr_t ptr = Read<uintptr_t>(sf + off);
        if (!ptr || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF || !IsValidPtr(ptr)) continue;
        for (int innerOff = 0x10; innerOff <= 0x20; innerOff += 4) {
          uint32_t enc = Read<uint32_t>(ptr + innerOff);
          if (enc == 0) continue;
          float val = fovDynDec(enc);
          if (val >= 60.0f && val <= 90.0f) {
            uint32_t reEnc = fovDynEnc(val);
            float reCheck = fovDynDec(reEnc);
            if (fabsf(reCheck - val) < 0.01f) {
              fovEncAddr = ptr + innerOff;
              fovIsWrapper = true;
              fovWrapperFieldOff = off;
              fovInnerOff = innerOff;
              fovWrapperAddr = ptr;
              fovInitialized = true;
              fovMethod = -2;
              printf("[FOV] INITIALIZED (dynamic wrapper): sf+0x%X->+0x%X fov=%.1f\n",
                     off, innerOff, val);
              return true;
            }
          }
        }
      }
      printf("[FOV] Dynamic ops extracted but no matching value found, trying other methods...\n");
    }

    // ── Phase 1: Try SIMPLE approach (raw float at small offsets) ──
    int simpleOffsets[] = { 0x18, 0x1C, 0x20, 0x24 };
    for (int sOff : simpleOffsets) {
      float rawFov = Read<float>(sf + sOff);
      if (rawFov >= 30.0f && rawFov <= 150.0f) {
        printf("[FOV] Simple raw float at sf+0x%X = %.1f (looks valid!)\n", sOff, rawFov);
        fovSimpleAddr = sf + sOff;
        fovUseSimple = true;
        fovInitialized = true;
        printf("[FOV] INITIALIZED (simple raw float): addr=0x%llX fov=%.1f offset=0x%X\n",
               (uint64_t)fovSimpleAddr, rawFov, sOff);
        return true;
      }
    }

    // Phase 2: Try hardcoded decrypt methods on the known FOV offset
    uint64_t raw64 = Read<uint64_t>(sf + offsets::Graphic::fov);
    uint32_t raw32 = (uint32_t)(raw64 & 0xFFFFFFFF);
    printf("[FOV] sf+0x%X = 0x%llX (raw32=0x%08X)\n", offsets::Graphic::fov, raw64, raw32);

    for (int m = 0; m < FOV_METHOD_COUNT; m++) {
      float testFov = fovMethods[m].dec(raw32);
      printf("[FOV] Method %d (%s): 0x%08X -> %.2f\n", m, fovMethods[m].name, raw32, testFov);
      if (testFov >= 30.0f && testFov <= 150.0f) {
        uint32_t reEnc = fovMethods[m].enc(testFov);
        float reCheck = fovMethods[m].dec(reEnc);
        if (fabsf(reCheck - testFov) < 0.01f) {
          fovEncAddr = sf + offsets::Graphic::fov;
          fovIsWrapper = false;
          fovInitialized = true;
          fovMethod = m;
          printf("[FOV] CALIBRATED (direct): method=%s offset=0x%X fov=%.1f\n",
                 fovMethods[m].name, offsets::Graphic::fov, testFov);
          return true;
        }
      }
    }

    // Try A: Direct inline — try method 0 explicitly as fallback
    {
      float directFov = fovDec0(raw32);
      printf("[FOV] Fallback direct decrypt: 0x%08X -> %.2f\n", raw32, directFov);
      if (directFov >= 30.0f && directFov <= 150.0f) {
        // Round-trip verify
        uint32_t reEnc = fovEnc0(directFov);
        float reCheck = fovDec0(reEnc);
        if (fabsf(reCheck - directFov) < 0.01f) {
          fovEncAddr = sf + offsets::Graphic::fov;
          fovIsWrapper = false;
          fovInitialized = true;
          printf("[FOV] INITIALIZED (direct inline): addr=0x%llX fov=%.1f\n",
                 (uint64_t)fovEncAddr, directFov);
          return true;
        }
      }
    }

    // Try B: Wrapper — sf+0x518 is a pointer, encrypted value inside wrapper
    uintptr_t wrapper = (uintptr_t)raw64;
    if (wrapper && wrapper >= 0x10000 && wrapper <= 0x7FFFFFFFFFFF && IsValidPtr(wrapper)) {
      printf("[FOV] Trying wrapper at 0x%llX\n", (uint64_t)wrapper);
      // Scan inner offsets 0x10 to 0x30
      for (uint32_t innerOff = 0x10; innerOff <= 0x30; innerOff += 4) {
        uint32_t enc = Read<uint32_t>(wrapper + innerOff);
        if (enc == 0) continue;
        float val = fovDec0(enc);
        if (val >= 30.0f && val <= 150.0f) {
          uint32_t reEnc = fovEnc0(val);
          float reCheck = fovDec0(reEnc);
          if (fabsf(reCheck - val) < 0.01f) {
            fovEncAddr = wrapper + innerOff;
            fovIsWrapper = true;
            fovWrapperFieldOff = offsets::Graphic::fov;
            fovInnerOff = innerOff;
            fovInitialized = true;
            printf("[FOV] INITIALIZED (wrapper): wrapper+0x%X addr=0x%llX fov=%.1f\n",
                   innerOff, (uint64_t)fovEncAddr, val);
            return true;
          }
        }
        printf("[FOV]   wrapper+0x%X: enc=0x%08X dec=%.2f\n", innerOff, enc, val);
      }
      // Dump wrapper for debugging
      printf("[FOV] Wrapper scan failed. Dumping:\n");
      for (uint32_t d = 0x00; d <= 0x30; d += 4) {
        uint32_t v = Read<uint32_t>(wrapper + d);
        printf("[FOV]   +0x%02X = 0x%08X\n", d, v);
      }
    }

    // Try C: Scan nearby static fields for any value that decrypts to valid FOV
    printf("[FOV] Phase C: scanning static fields for FOV...\n");
    for (int off = 0x500; off <= 0x600; off += 4) {
      uint32_t enc = Read<uint32_t>(sf + off);
      if (enc == 0) continue;
      float val = fovDec0(enc);
      if (val >= 30.0f && val <= 150.0f) {
        uint32_t reEnc = fovEnc0(val);
        float reCheck = fovDec0(reEnc);
        if (fabsf(reCheck - val) < 0.01f) {
          printf("[FOV] FOUND at sf+0x%X: enc=0x%08X fov=%.1f\n", off, enc, val);
          fovEncAddr = sf + off;
          fovIsWrapper = false;
          fovInitialized = true;
          return true;
        }
      }
    }

    // Try D: Scan static field pointers for wrapper objects
    printf("[FOV] Phase D: scanning static field pointers for wrapper...\n");
    for (int off = 0x500; off <= 0x600; off += 8) {
      uintptr_t ptr = Read<uintptr_t>(sf + off);
      if (!ptr || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;
      for (uint32_t innerOff = 0x10; innerOff <= 0x20; innerOff += 4) {
        uint32_t enc = Read<uint32_t>(ptr + innerOff);
        if (enc == 0) continue;
        float val = fovDec0(enc);
        if (val >= 30.0f && val <= 150.0f) {
          uint32_t reEnc = fovEnc0(val);
          float reCheck = fovDec0(reEnc);
          if (fabsf(reCheck - val) < 0.01f) {
            printf("[FOV] FOUND wrapper at sf+0x%X->+0x%X: fov=%.1f\n", off, innerOff, val);
            fovEncAddr = ptr + innerOff;
            fovIsWrapper = true;
            fovWrapperFieldOff = off;
            fovInnerOff = innerOff;
            fovInitialized = true;
            return true;
          }
        }
      }
    }

    printf("[FOV] All initialization phases FAILED\n");
    return false;
  }

  void ApplyFOV(float fovValue) {
    static ULONGLONG lastInitAttempt = 0;
    static int initFails = 0;

    if (!fovInitialized) {
      ULONGLONG now = GetTickCount64();
      if (now - lastInitAttempt < 3000) return;
      lastInitAttempt = now;
      if (!InitializeFOV()) {
        initFails++;
        if (initFails % 5 == 1)
          printf("[FOV] Init failed (attempt %d)\n", initFails);
        return;
      }
    }

    // ── Simple raw float approach (from reference project) ──
    if (fovUseSimple) {
      float curFov = Read<float>(fovSimpleAddr);
      static int dbg = 0;
      if (dbg++ % 1800 == 0)
        printf("[FOV] simple: cur=%.1f target=%.1f addr=0x%llX\n",
               curFov, fovValue, (uint64_t)fovSimpleAddr);
      if (curFov < 1.0f || curFov > 300.0f) {
        printf("[FOV] Simple read bad (%.1f), reinitializing\n", curFov);
        fovInitialized = false;
        fovUseSimple = false;
        return;
      }
      Write<float>(fovSimpleAddr, fovValue);
      return;
    }

    // ── Encrypted approach (fallback) ──
    // For wrapper mode, re-read the wrapper pointer each frame (GC can move)
    if (fovIsWrapper) {
      uintptr_t typeInfo = Read<uintptr_t>(gameAssembly + offsets::convar_graphics_pointer);
      if (!typeInfo) { fovInitialized = false; return; }
      uintptr_t sf = Read<uintptr_t>(typeInfo + offsets::Graphic::StaticFields);
      if (!sf) { fovInitialized = false; return; }
      uintptr_t wrapper = Read<uintptr_t>(sf + fovWrapperFieldOff);
      if (!wrapper || wrapper < 0x10000 || wrapper > 0x7FFFFFFFFFFF) {
        fovInitialized = false;
        return;
      }
      fovEncAddr = wrapper + fovInnerOff;
    }

    // Read, decrypt, verify, write — use dynamic ops if available
    uint32_t curEnc = Read<uint32_t>(fovEncAddr);
    float curFov;
    uint32_t newEnc;

    if (fovMethod == -2 && fovDynReady) {
      curFov = fovDynDec(curEnc);
      newEnc = fovDynEnc(fovValue);
    } else {
      int m = (fovMethod >= 0 && fovMethod < FOV_METHOD_COUNT) ? fovMethod : 0;
      curFov = fovMethods[m].dec(curEnc);
      newEnc = fovMethods[m].enc(fovValue);
    }

    static int dbg2 = 0;
    if (dbg2++ % 1800 == 0)
      printf("[FOV] cur=%.1f target=%.1f enc=0x%08X addr=0x%llX method=%d\n",
             curFov, fovValue, curEnc, (uint64_t)fovEncAddr, fovMethod);

    // Sanity check
    if (curFov < 1.0f || curFov > 300.0f) {
      printf("[FOV] Bad decrypt (%.1f), reinitializing\n", curFov);
      fovInitialized = false;
      return;
    }

    Write<uint32_t>(fovEncAddr, newEnc);
  }

  /* ── Time changer (set TOD_Sky cycle hour) ──────────── */

  // Validate a candidate TOD_Sky instance by checking Cycle.Hour is in [0,24]
  bool ValidateTodSky(uintptr_t candidate) {
    if (!candidate || !IsValidPtr(candidate)) return false;
    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) return false;
    uintptr_t cycle = Read<uintptr_t>(candidate + offsets::TodSky::TOD_CycleParameters);
    if (!cycle || !IsValidPtr(cycle)) return false;
    if (cycle < 0x10000 || cycle > 0x7FFFFFFFFFFF) return false;
    float h = Read<float>(cycle + offsets::TodSky::Cycle::hour);
    return (h >= 0.f && h <= 24.f);
  }

  uintptr_t ResolveTodSky() {
    static uintptr_t cachedInst = 0;
    static ULONGLONG lastAttempt = 0;
    static int failCount = 0;

    // Return cached if still valid
    if (cachedInst && ValidateTodSky(cachedInst))
      return cachedInst;
    cachedInst = 0;

    // Rate-limit resolution attempts
    ULONGLONG now = GetTickCount64();
    ULONGLONG cooldown = (failCount > 10) ? 15000 : 3000;
    if (now - lastAttempt < cooldown) return 0;
    lastAttempt = now;

    // Direct chain from forum: GA+TodSky_c → +0xB8 → +0x28 → +0x10 → +0x20
    uintptr_t inst = ReadChain(gameAssembly + offsets::TodSky::Class, {
      (uint32_t)offsets::TodSky::static_fields,          // +0xB8
      (uint32_t)offsets::TodSky::instance,               // +0x28
      (uint32_t)offsets::TodSky::parent_static_fields,   // +0x10
      (uint32_t)offsets::TodSky::unk                     // +0x20
    });

    if (inst && ValidateTodSky(inst)) {
      cachedInst = inst;
      failCount = 0;
      static bool logged = false;
      if (!logged) {
        printf("[TOD] Resolved TOD_Sky via direct chain: 0x%llX\n", (uint64_t)inst);
        logged = true;
      }
      return inst;
    }

    // Fallback: try GC handle resolve on the raw pointer from chain
    uintptr_t raw = ReadChain(gameAssembly + offsets::TodSky::Class, {
      (uint32_t)offsets::TodSky::static_fields,
      (uint32_t)offsets::TodSky::instance
    });
    if (raw && raw >= 0x10000 && raw <= 0x7FFFFFFFFFFF) {
      uintptr_t resolved = il2cpp_get_handle(raw);
      if (resolved && IsValidPtr(resolved) && ValidateTodSky(resolved)) {
        cachedInst = resolved;
        failCount = 0;
        printf("[TOD] Resolved TOD_Sky via GC handle: 0x%llX\n", (uint64_t)resolved);
        return resolved;
      }
    }

    failCount++;
    if (failCount % 5 == 1)
      printf("[TOD] ResolveTodSky failed (attempt %d)\n", failCount);
    return 0;
  }

  bool timeProgressionFrozen = false;

  void FreezeTimeProgression(uintptr_t todSkyInst) {
    if (timeProgressionFrozen)
      return;
    if (!todSkyInst || todSkyInst < 0x10000 || todSkyInst > 0x7FFFFFFFFFFF)
      return;

    // Try to disable time progression via TOD_Components → Time → ProgressTime
    uintptr_t components =
        Read<uintptr_t>(todSkyInst + offsets::TodSky::TOD_Components);
    if (components && IsValidPtr(components) && components >= 0x10000 && components <= 0x7FFFFFFFFFFF) {
      uintptr_t todTime =
          Read<uintptr_t>(components + offsets::TodSky::Components::Time);
      if (todTime && IsValidPtr(todTime) && todTime >= 0x10000 && todTime <= 0x7FFFFFFFFFFF) {
        Write<uint8_t>(todTime + offsets::TodSky::Time::ProgressTime, 0);
        timeProgressionFrozen = true;
        printf("[TOD] Froze time progression\n");
      }
    }
  }

  void UnfreezeTimeProgression() {
    if (!timeProgressionFrozen)
      return;

    uintptr_t inst = ResolveTodSky();
    if (!inst || inst < 0x10000 || inst > 0x7FFFFFFFFFFF) {
      timeProgressionFrozen = false;
      return;
    }

    uintptr_t components =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_Components);
    if (components && IsValidPtr(components) && components >= 0x10000 && components <= 0x7FFFFFFFFFFF) {
      uintptr_t todTime =
          Read<uintptr_t>(components + offsets::TodSky::Components::Time);
      if (todTime && IsValidPtr(todTime) && todTime >= 0x10000 && todTime <= 0x7FFFFFFFFFFF) {
        Write<uint8_t>(todTime + offsets::TodSky::Time::ProgressTime, 1);
      }
    }
    timeProgressionFrozen = false;
    printf("[TOD] Restored time progression\n");
  }

  void ApplyTimeChanger(float hour) {
    uintptr_t inst = ResolveTodSky();
    if (!inst || inst < 0x10000 || inst > 0x7FFFFFFFFFFF) {
      static int d = 0;
      if (d++ % 600 == 0) printf("[TC] ResolveTodSky failed\n");
      return;
    }

    // Freeze time progression so the game doesn't fight our writes
    FreezeTimeProgression(inst);

    uintptr_t cycle =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_CycleParameters);
    if (!cycle || !IsValidPtr(cycle) || cycle < 0x10000 || cycle > 0x7FFFFFFFFFFF)
      return;

    // Read-before-write: only write if the hour differs (reduces driver spam +
    // flicker)
    float curHour = Read<float>(cycle + offsets::TodSky::Cycle::hour);
    if (fabsf(curHour - hour) > 0.01f) {
      Write<float>(cycle + offsets::TodSky::Cycle::hour, hour);
    }
  }

  /* ── Bright night (modify TOD_Sky night parameters) ──── */

  struct NightCache {
    bool cached = false;
    float lightIntensity = 0;
    float ambientMultiplier = 0;
    float saturation = 0;
  };
  NightCache cachedNight;

  void ApplyBrightNight(float intensity) {
    // Safety: clamp intensity to reasonable range
    if (intensity < 0.0f) intensity = 0.0f;
    if (intensity > 10.0f) intensity = 10.0f;
    
    uintptr_t inst = ResolveTodSky();
    if (!inst || inst < 0x10000 || inst > 0x7FFFFFFFFFFF)
      return;

    // Night parameters
    uintptr_t night =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_NightParameters);
    if (night && IsValidPtr(night) && night >= 0x10000 && night <= 0x7FFFFFFFFFFF) {
      // Cache originals on first apply
      if (!cachedNight.cached) {
        cachedNight.lightIntensity =
            Read<float>(night + offsets::TodSky::Night::lightIntensity);
        cachedNight.ambientMultiplier =
            Read<float>(night + offsets::TodSky::Night::ambientMultiplier);
        uintptr_t ambient =
            Read<uintptr_t>(inst + offsets::TodSky::TOD_AmbientParameters);
        if (ambient && IsValidPtr(ambient) && ambient >= 0x10000 && ambient <= 0x7FFFFFFFFFFF)
          cachedNight.saturation = Read<float>(ambient + 0x14);
        cachedNight.cached = true;
      }

      float curLI = Read<float>(night + offsets::TodSky::Night::lightIntensity);
      if (fabsf(curLI - intensity) > 0.01f) {
        Write<float>(night + offsets::TodSky::Night::lightIntensity, intensity);
        Write<float>(night + offsets::TodSky::Night::ambientMultiplier,
                     intensity);
      }
    }

    // Ambient parameters
    uintptr_t ambient =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_AmbientParameters);
    if (ambient && IsValidPtr(ambient) && ambient >= 0x10000 && ambient <= 0x7FFFFFFFFFFF) {
      float curSat = Read<float>(ambient + 0x14);
      if (fabsf(curSat - 0.0f) > 0.01f) {
        Write<float>(ambient + 0x14, 0.0f); // Saturation
      }
    }
  }

  void RestoreBrightNight() {
    if (!cachedNight.cached)
      return;
    uintptr_t inst = ResolveTodSky();
    if (!inst || inst < 0x10000 || inst > 0x7FFFFFFFFFFF)
      return;

    uintptr_t night =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_NightParameters);
    if (night && IsValidPtr(night) && night >= 0x10000 && night <= 0x7FFFFFFFFFFF) {
      Write<float>(night + offsets::TodSky::Night::lightIntensity,
                   cachedNight.lightIntensity);
      Write<float>(night + offsets::TodSky::Night::ambientMultiplier,
                   cachedNight.ambientMultiplier);
    }

    uintptr_t ambient =
        Read<uintptr_t>(inst + offsets::TodSky::TOD_AmbientParameters);
    if (ambient && IsValidPtr(ambient) && ambient >= 0x10000 && ambient <= 0x7FFFFFFFFFFF) {
      Write<float>(ambient + 0x14, cachedNight.saturation);
    }

    cachedNight.cached = false;
  }

  /* ── Terrain remover (zero tree/grass draw distances) ──── */

  void ApplyTerrainRemover(bool enable) {
    static bool dbgOnce = false;
    if (!offsets::convar_terrain_pointer) {
      if (!dbgOnce) {
        printf("[Terrain] FAIL: convar_terrain_pointer=0\n");
        dbgOnce = true;
      }
      return;
    }
    if (!offsets::Terrain::drawTreeDistance &&
        !offsets::Terrain::drawGrassDistance) {
      if (!dbgOnce) {
        printf("[Terrain] FAIL: drawTreeDistance=0 drawGrassDistance=0 "
               "(offsets not resolved)\n");
        dbgOnce = true;
      }
      return;
    }

    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::convar_terrain_pointer);
    if (!typeInfo || !IsValidPtr(typeInfo)) {
      if (!dbgOnce) {
        printf("[Terrain] FAIL: typeInfo=0 (GA+0x%llX)\n",
               (uint64_t)offsets::convar_terrain_pointer);
        dbgOnce = true;
      }
      return;
    }
    uintptr_t sf = Read<uintptr_t>(typeInfo + offsets::Terrain::StaticFields);
    if (!sf || !IsValidPtr(sf)) {
      if (!dbgOnce) {
        printf("[Terrain] FAIL: staticFields=0\n");
        dbgOnce = true;
      }
      return;
    }

    if (!dbgOnce) {
      printf("[Terrain] OK: typeInfo=0x%llX sf=0x%llX treeOff=0x%X "
             "grassOff=0x%X\n",
             (uint64_t)typeInfo, (uint64_t)sf,
             offsets::Terrain::drawTreeDistance,
             offsets::Terrain::drawGrassDistance);
      dbgOnce = true;
    }

    if (enable) {
      if (offsets::Terrain::drawTreeDistance)
        Write<float>(sf + offsets::Terrain::drawTreeDistance, 0.0f);
      if (offsets::Terrain::drawGrassDistance)
        Write<float>(sf + offsets::Terrain::drawGrassDistance, 0.0f);
    } else {
      if (offsets::Terrain::drawTreeDistance)
        Write<float>(sf + offsets::Terrain::drawTreeDistance, 2500.0f);
      if (offsets::Terrain::drawGrassDistance)
        Write<float>(sf + offsets::Terrain::drawGrassDistance, 300.0f);
    }
  }

  /* ── Split read helpers for esp_renderer.cpp ──────────── */

  bool ReadPlayerPositionAndLifestate(uintptr_t entity, Vec3 &pos,
                                      Vec3 &headPos, uint32_t &lifestate) {
    uintptr_t playerModel =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!playerModel)
      return false;
    pos = Read<Vec3>(playerModel + offsets::PlayerModel::position);
    if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f)
      return false;

    // Improved fallback: Check ModelState flags for crouch (bit 4)
    float eyeHeight =
        1.55f; // Standard standing eye height (approx center of head)
    uintptr_t modelState =
        Read<uintptr_t>(entity + offsets::BasePlayer::ModelState);
    if (modelState && IsValidPtr(modelState)) {
      int msFlags = Read<int>(modelState + offsets::ModelState::flags);
      if (msFlags & (1 << 2)) // Crouch bit
        eyeHeight = 1.05f;
      else if (msFlags & (1 << 3)) // Crawl bit
        eyeHeight = 0.45f;
    }
    headPos = Vec3(pos.x, pos.y + eyeHeight, pos.z);

    lifestate = Read<uint32_t>(entity + offsets::BaseCombatEntity::lifestate);
    return true;
  }

  bool ReadPlayerDetails(uintptr_t entity, PlayerData &out,
                         bool *isLocal = nullptr) {
    uintptr_t namePtr =
        Read<uintptr_t>(entity + 0x3E8);  // _displayName correct offset
    out.name = ReadString(namePtr);
    out.teamID = Read<uint64_t>(entity + offsets::BasePlayer::currentTeam);
    out.flags = Read<uint32_t>(entity + offsets::BasePlayer::playerFlags);
    out.isSleeping = (out.flags & 16) != 0;
    out.isWounded = (out.flags & 64) != 0;
    // Use PlayerModel::isVisible (frustum check) for responsive visibility
    uintptr_t pm =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (pm) {
      out.isVisible = Read<bool>(pm + offsets::PlayerModel::isVisible);
    } else {
      out.isVisible = false;
    }
    if (isLocal) {
      uintptr_t local = GetLocalPlayer();
      *isLocal = (entity == local);
    }
    out.health = Read<float>(entity + offsets::BaseCombatEntity::_health);
    out.maxHealth = Read<float>(entity + offsets::BaseCombatEntity::_maxHealth);

    return true;
  }

  /* ── Read hotbar (belt) item short names ──────────────────── */
  std::vector<std::string> ReadHotbarItems(uintptr_t entity) {
    std::vector<std::string> items;
    const int MAX_BELT_SLOTS = 6;

    static bool hotbarDbgOnce = false;

    /* Step 1: Read inventory wrapper and decrypt */
    uintptr_t wrapper =
        Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
    if (!wrapper) {
      if (!hotbarDbgOnce) {
        hotbarDbgOnce = true;
        printf("[Hotbar] FAIL: wrapper=0 at entity+0x%X\n",
               offsets::BasePlayer::inventory);
      }
      return items;
    }

    uintptr_t inventory = 0;
    if (IsValidPtr(wrapper)) {
      uintptr_t encPayload = Read<uintptr_t>(wrapper + 0x18);
      if (encPayload) {
        uintptr_t dec = RustDecrypt::DecryptPlayerInventory(encPayload);
        inventory = il2cpp_get_handle(dec);
      }
      if (!hotbarDbgOnce) {
        printf("[Hotbar] wrapper=0x%llX encPayload=0x%llX inventory=0x%llX\n",
               (uint64_t)wrapper, (uint64_t)Read<uintptr_t>(wrapper + 0x18),
               (uint64_t)inventory);
      }
    }
    if (!IsValidPtr(inventory) && wrapper) {
      uintptr_t dec = RustDecrypt::DecryptPlayerInventory(wrapper);
      inventory = il2cpp_get_handle(dec);
      if (!hotbarDbgOnce) {
        printf("[Hotbar] Fallback: dec=0x%llX inventory=0x%llX\n",
               (uint64_t)dec, (uint64_t)inventory);
      }
    }
    if (!IsValidPtr(inventory)) {
      if (!hotbarDbgOnce) {
        hotbarDbgOnce = true;
        printf("[Hotbar] FAIL: inventory invalid after decrypt\n");
      }
      return items;
    }

    /* Step 2: containerBelt from PlayerInventory */
    uintptr_t belt =
        Read<uintptr_t>(inventory + offsets::PlayerInventory::belt);
    if (!IsValidPtr(belt)) {
      if (!hotbarDbgOnce) {
        hotbarDbgOnce = true;
        printf("[Hotbar] FAIL: belt invalid at inventory+0x%X\n",
               offsets::PlayerInventory::belt);
      }
      return items;
    }

    /* Step 3: itemList (C# List<Item>) from ItemContainer */
    uintptr_t itemList =
        Read<uintptr_t>(belt + offsets::ItemContainer::itemlist);
    if (!IsValidPtr(itemList)) {
      if (!hotbarDbgOnce) {
        hotbarDbgOnce = true;
        printf("[Hotbar] FAIL: itemList invalid at belt+0x%X\n",
               offsets::ItemContainer::itemlist);
      }
      return items;
    }

    /* IL2CPP List<T>: _items array at +0x10, _size at +0x18 */
    uintptr_t itemsArray = Read<uintptr_t>(itemList + 0x10);
    int count = Read<int>(itemList + 0x18);
    if (!IsValidPtr(itemsArray) || count <= 0) {
      if (!hotbarDbgOnce) {
        hotbarDbgOnce = true;
        printf("[Hotbar] FAIL: itemsArray=0x%llX count=%d\n",
               (uint64_t)itemsArray, count);
      }
      return items;
    }
    if (count > MAX_BELT_SLOTS)
      count = MAX_BELT_SLOTS;

    if (!hotbarDbgOnce) {
      printf("[Hotbar] SUCCESS: inventory=0x%llX belt=0x%llX itemList=0x%llX "
             "count=%d\n",
             (uint64_t)inventory, (uint64_t)belt, (uint64_t)itemList, count);
    }

    /* Step 4: Read each item's short name */
    for (int i = 0; i < count; i++) {
      uintptr_t item = Read<uintptr_t>(itemsArray + 0x20 + (uintptr_t)i * 8);
      if (!IsValidPtr(item)) {
        items.push_back("");
        continue;
      }

      uintptr_t itemDef =
          Read<uintptr_t>(item + offsets::item::item_definition);
      if (!IsValidPtr(itemDef)) {
        items.push_back("");
        continue;
      }

      uintptr_t shortNamePtr =
          Read<uintptr_t>(itemDef + offsets::ItemDefinition::ShortName);
      if (!IsValidPtr(shortNamePtr)) {
        items.push_back("");
        continue;
      }

      std::wstring wname = ReadString(shortNamePtr, 32);
      if (wname.empty()) {
        items.push_back("");
        continue;
      }

      /* Convert wstring to narrow string */
      std::string narrow(wname.begin(), wname.end());
      items.push_back(narrow);

      if (!hotbarDbgOnce) {
        printf("[Hotbar]   slot[%d] = '%s'\n", i, narrow.c_str());
      }
    }

    if (!hotbarDbgOnce)
      hotbarDbgOnce = true;
    return items;
  }

  /* ── Read wear (clothing) item short names ──────────────────── */
  std::vector<std::string> ReadWearItems(uintptr_t entity) {
    std::vector<std::string> items;
    const int MAX_WEAR_SLOTS = 7;

    uintptr_t wrapper =
        Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
    if (!wrapper)
      return items;

    uintptr_t inventory = 0;
    if (IsValidPtr(wrapper)) {
      uintptr_t encPayload = Read<uintptr_t>(wrapper + 0x18);
      if (encPayload) {
        uintptr_t dec = RustDecrypt::DecryptPlayerInventory(encPayload);
        inventory = il2cpp_get_handle(dec);
      }
    }
    if (!IsValidPtr(inventory) && wrapper) {
      uintptr_t dec = RustDecrypt::DecryptPlayerInventory(wrapper);
      inventory = il2cpp_get_handle(dec);
    }
    if (!IsValidPtr(inventory))
      return items;

    uintptr_t wear =
        Read<uintptr_t>(inventory + offsets::PlayerInventory::clothingbelt);
    if (!IsValidPtr(wear))
      return items;

    uintptr_t itemList =
        Read<uintptr_t>(wear + offsets::ItemContainer::itemlist);
    if (!IsValidPtr(itemList))
      return items;

    uintptr_t itemsArray = Read<uintptr_t>(itemList + 0x10);
    int count = Read<int>(itemList + 0x18);
    if (!IsValidPtr(itemsArray) || count <= 0)
      return items;
    if (count > MAX_WEAR_SLOTS)
      count = MAX_WEAR_SLOTS;

    for (int i = 0; i < count; i++) {
      uintptr_t item = Read<uintptr_t>(itemsArray + 0x20 + (uintptr_t)i * 8);
      if (!IsValidPtr(item)) {
        items.push_back("");
        continue;
      }

      uintptr_t itemDef =
          Read<uintptr_t>(item + offsets::item::item_definition);
      if (!IsValidPtr(itemDef)) {
        items.push_back("");
        continue;
      }

      uintptr_t shortNamePtr =
          Read<uintptr_t>(itemDef + offsets::ItemDefinition::ShortName);
      if (!IsValidPtr(shortNamePtr)) {
        items.push_back("");
        continue;
      }

      std::wstring wname = ReadString(shortNamePtr, 32);
      if (wname.empty()) {
        items.push_back("");
        continue;
      }

      std::string narrow(wname.begin(), wname.end());
      items.push_back(narrow);
    }

    return items;
  }

  /* ── Silent Aim Functions ─────────────────────────────────── */

  Vec4 ToQuat(const Vec3 &euler) {
    float pitch = euler.x * 0.0174532925199433f;
    float yaw = euler.y * 0.0174532925199433f;
    float cy = cosf(yaw * 0.5f);
    float sy = sinf(yaw * 0.5f);
    float cp = cosf(pitch * 0.5f);
    float sp = sinf(pitch * 0.5f);
    Vec4 q;
    q.w = cy * cp;
    q.y = sy * cp;
    q.x = cy * sp;
    q.z = -sy * sp;
    return q;
  }

  bool SetBodyRotation(uintptr_t player, const Vec3 &angles) {
    try {
      if (!player || !IsValidPtr(player))
        return false;
      uintptr_t eyes = GetPlayerEyes(player);
      if (!eyes || !IsValidPtr(eyes))
        return false;
      // Validate eyes is real: read existing quaternion and check it's normalized-ish
      float qx = Read<float>(eyes + offsets::PlayerEyes::body_rotation + 0x0);
      float qy = Read<float>(eyes + offsets::PlayerEyes::body_rotation + 0x4);
      float qz = Read<float>(eyes + offsets::PlayerEyes::body_rotation + 0x8);
      float qw = Read<float>(eyes + offsets::PlayerEyes::body_rotation + 0xC);
      float mag = qx*qx + qy*qy + qz*qz + qw*qw;
      if (mag < 0.5f || mag > 2.0f) return false; // not a valid quaternion
      Vec4 quat = ToQuat(angles);
      Write<float>(eyes + offsets::PlayerEyes::body_rotation + 0x0, quat.x);
      Write<float>(eyes + offsets::PlayerEyes::body_rotation + 0x4, quat.y);
      Write<float>(eyes + offsets::PlayerEyes::body_rotation + 0x8, quat.z);
      Write<float>(eyes + offsets::PlayerEyes::body_rotation + 0xC, quat.w);
      return true;
    } catch (...) {
      return false;
    }
  }

  /* ── Chams Functions (cached) ──────────────────────────────
   * Phase 1: BuildChamsCache — walks the full pointer chain ONCE per entity,
   *   collects all matBase addresses. This is the expensive part (~5 reads per
   *   renderer) but only runs when cache is empty or stale.
   * Phase 2: ApplyChamsCached — pure writes to cached addresses. Zero reads.
   *   This is what runs every cycle and is extremely lightweight.
   */

  // Build cache: walk entity → playerModel → SMM → renderers → matBase
  // Returns list of direct matBase addresses to write to
  std::vector<uintptr_t> BuildChamsCache(uintptr_t entity, bool debug = false) {
    std::vector<uintptr_t> addrs;
    if (!entity || !IsValidPtr(entity))
      return addrs;

    uintptr_t playerModel =
        Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!playerModel || !IsValidPtr(playerModel)) {
      if (debug) printf("[Chams] FAIL: playerModel=0 (ent=0x%llX +0x%X)\n", (uint64_t)entity, offsets::BasePlayer::playerModel);
      return addrs;
    }

    uintptr_t smm =
        Read<uintptr_t>(playerModel + offsets::PlayerModel::SkinnedMultiMesh);
    if (!smm || !IsValidPtr(smm)) {
      if (debug) printf("[Chams] FAIL: smm=0 (pModel=0x%llX +0x%X)\n", (uint64_t)playerModel, offsets::PlayerModel::SkinnedMultiMesh);
      return addrs;
    }

    uintptr_t renderersList = Read<uintptr_t>(
        smm + offsets::PlayerModel::SkinnedRenderersList);
    if (!renderersList || !IsValidPtr(renderersList)) {
      if (debug) printf("[Chams] FAIL: renderersList=0 (smm=0x%llX +0x%X)\n", (uint64_t)smm, offsets::PlayerModel::SkinnedRenderersList);
      return addrs;
    }

    int count = Read<int>(renderersList + 0x18);
    if (count <= 0 || count > 128) {
      if (debug) printf("[Chams] FAIL: count=%d (rl=0x%llX)\n", count, (uint64_t)renderersList);
      return addrs;
    }
    if (count > 100) count = 100; // safety cap — need all renderers including clothing/armor

    uintptr_t itemsArray = Read<uintptr_t>(renderersList + 0x10);
    if (!itemsArray || !IsValidPtr(itemsArray)) {
      if (debug) printf("[Chams] FAIL: itemsArray=0 (rl=0x%llX)\n", (uint64_t)renderersList);
      return addrs;
    }

    if (debug) printf("[Chams] Chain OK: ent=0x%llX pModel=0x%llX smm=0x%llX rl=0x%llX items=0x%llX count=%d\n",
                       (uint64_t)entity, (uint64_t)playerModel, (uint64_t)smm,
                       (uint64_t)renderersList, (uint64_t)itemsArray, count);

    addrs.reserve(count * 4); // each renderer can have multiple material slots
    for (int i = 0; i < count; i++) {
      uintptr_t renderer = Read<uintptr_t>(itemsArray + 0x20 + (i * 0x8));
      if (!renderer || !IsValidPtr(renderer))
        continue;

      uintptr_t nativeObj = Read<uintptr_t>(renderer + 0x10);
      if (!nativeObj || !IsValidPtr(nativeObj))
        continue;

      // dynamic_array at nativeObj+0x148:
      //   +0x00: uintptr_t base (pointer to material ID array)
      //   +0x10: size/capacity (this offset was verified working previously)
      uintptr_t matBase = Read<uintptr_t>(nativeObj + 0x148);
      int matSize = Read<int>(nativeObj + 0x148 + 0x10);
      if (!matBase || !IsValidPtr(matBase) || matSize < 1 || matSize > 8)
        continue;

      // Cache ALL material slot addresses for this renderer
      for (uint32_t m = 0; m < matSize; m++) {
        addrs.push_back(matBase + (m * 0x4));
      }
    }
    return addrs;
  }

  // Get ANY held entity for the local player (not just weapons)
  uintptr_t GetActiveWeaponBaseProjectile(uintptr_t player) {
    if (!player || !IsValidPtr(player))
      return 0;

    // Full decrypt: inventory → belt → find active item → held_entity
    static int weaponDebugCount = 0;
    uintptr_t encActiveItem = Read<uintptr_t>(player + offsets::BasePlayer::clactiveitem);
    uint32_t activeUID = 0;
    if (encActiveItem) {
      uintptr_t dec = RustDecrypt::DecryptClActiveItem(encActiveItem);
      activeUID = (uint32_t)(dec & 0xFFFFFFFF);
    }

    uintptr_t wrapper = Read<uintptr_t>(player + offsets::BasePlayer::inventory);
    if (!wrapper) return 0;

    uintptr_t inventory = 0;
    if (IsValidPtr(wrapper)) {
      uintptr_t encPayload = Read<uintptr_t>(wrapper + 0x18);
      if (encPayload) {
        uintptr_t dec = RustDecrypt::DecryptPlayerInventory(encPayload);
        inventory = il2cpp_get_handle(dec);
      }
    }
    if (!IsValidPtr(inventory) && wrapper) {
      uintptr_t dec = RustDecrypt::DecryptPlayerInventory(wrapper);
      inventory = il2cpp_get_handle(dec);
    }
    if (!IsValidPtr(inventory)) return 0;

    uintptr_t belt = Read<uintptr_t>(inventory + offsets::PlayerInventory::belt);
    if (!IsValidPtr(belt)) return 0;
    uintptr_t itemList = Read<uintptr_t>(belt + offsets::ItemContainer::itemlist);
    if (!IsValidPtr(itemList)) return 0;

    uintptr_t itemsArray = Read<uintptr_t>(itemList + 0x10);
    int count = Read<int>(itemList + 0x18);
    if (!IsValidPtr(itemsArray) || count <= 0) return 0;
    if (count > 6) count = 6;

    for (int i = 0; i < count; i++) {
      uintptr_t item = Read<uintptr_t>(itemsArray + 0x20 + (uintptr_t)i * 8);
      if (!item || !IsValidPtr(item)) continue;

      if (activeUID != 0) {
        uint32_t itemUID = Read<uint32_t>(item + offsets::item::item_uid);
        if (itemUID != activeUID) continue;
      }

      // Try primary held_entity offset (0x40)
      uintptr_t heldEnt = Read<uintptr_t>(item + offsets::item::held_entity);
      if (heldEnt && IsValidPtr(heldEnt)) {
        if (weaponDebugCount < 3) {
          printf("[WEAPON] Found via held_entity (0x%X): 0x%llX\n",
                 offsets::item::held_entity, (uint64_t)heldEnt);
          weaponDebugCount++;
        }
        return heldEnt;
      }
      // Try secondary held_entity offset (0xb0)
      heldEnt = Read<uintptr_t>(item + offsets::item::held_entity_2);
      if (heldEnt && IsValidPtr(heldEnt)) {
        if (weaponDebugCount < 3) {
          printf("[WEAPON] Found via held_entity_2 (0x%X): 0x%llX\n",
                 offsets::item::held_entity_2, (uint64_t)heldEnt);
          weaponDebugCount++;
        }
        return heldEnt;
      }
    }
    return 0;
  }

  // Read a narrow ASCII string from a native Unity name pointer.
  // Reads in 8-byte chunks to minimize driver calls.
  std::string ReadNarrowString(uintptr_t addr, int maxLen = 32) {
    if (!addr || !IsValidPtr(addr)) return "";
    char buf[40] = {0};
    if (maxLen > 32) maxLen = 32;
    for (int i = 0; i < maxLen; i += 8) {
      uint64_t chunk = Read<uint64_t>(addr + i);
      memcpy(buf + i, &chunk, 8);
    }
    buf[maxLen] = 0;
    for (int i = 0; i < maxLen; i++) {
      if (buf[i] == 0 || buf[i] < 0x20 || buf[i] > 0x7E) {
        buf[i] = 0;
        break;
      }
    }
    return std::string(buf);
  }

  // Reference code's GetComponentsInChildren - recursive walk with string name checks.
  // Finds SkinnedMeshRenderer components by checking native component type names.
  // Each found renderer is paired with isHand flag based on GameObject name.
  void VMGetComponentsInChildren(uintptr_t gameObject,
      std::vector<std::pair<uintptr_t, bool>>& renderers, int depth = 0) {
    if (!gameObject || !IsValidPtr(gameObject) || depth > 3) return;

    uintptr_t componentList = Read<uintptr_t>(gameObject + 0x30);
    int componentSize = Read<int>(gameObject + 0x40);
    if (componentSize < 0 || componentSize > 128) return;
    if (componentSize > 16) componentSize = 16; // safety cap

    for (int j = 0; j < componentSize; j++) {
      uintptr_t component = Read<uintptr_t>(componentList + (0x10 * j + 0x8));
      if (!component || !IsValidPtr(component)) continue;

      uintptr_t componentInst = Read<uintptr_t>(component + 0x28);
      if (!componentInst || !IsValidPtr(componentInst)) continue;
      uintptr_t componentObject = Read<uintptr_t>(componentInst + 0x0);
      if (!componentObject || !IsValidPtr(componentObject)) continue;
      uintptr_t componentName = Read<uintptr_t>(componentObject + 0x10);
      if (!componentName || !IsValidPtr(componentName)) continue;

      std::string name = ReadNarrowString(componentName, 24);

      if (name == "SkinnedMeshRenderer") {
        // Check GO name for "hand" to distinguish hand vs weapon
        uintptr_t goNamePtr = Read<uintptr_t>(gameObject + 0x60);
        std::string goName = ReadNarrowString(goNamePtr, 32);
        bool isHand = (goName.find("hand") != std::string::npos);
        renderers.push_back({component, isHand});
      }
      if (name == "Transform") {
        uintptr_t childList = Read<uintptr_t>(component + 0x70);
        int childSize = Read<int>(component + 0x80);
        if (childSize < 0 || childSize > 128) continue;
        if (childSize > 12) childSize = 12; // safety cap

        for (int i = 0; i < childSize; i++) {
          uintptr_t childTransform = Read<uintptr_t>(childList + (0x8 * i));
          if (!childTransform || !IsValidPtr(childTransform)) continue;
          uintptr_t childGO = Read<uintptr_t>(childTransform + 0x30);
          if (!childGO || !IsValidPtr(childGO)) continue;
          VMGetComponentsInChildren(childGO, renderers, depth + 1);
        }
      }
    }
  }

  // Reference code's ProcessSkinnedMeshRenderer — reads material chain and writes material ID.
  // Self-healing: if viewmodel is destroyed, reads return 0 → writes are skipped.
  // Returns number of materials written (0 means renderer is dead/stale).
  int VMProcessRenderer(uintptr_t renderer, unsigned int materialId) {
    if (!renderer || !IsValidPtr(renderer)) return 0;
    // Custom Galaxy (999999) is disabled — use wireframe fallback
    if (materialId == 999999) materialId = 1348630;
    int written = 0;
    for (uint32_t idx = 0; idx < 2; idx++) {
      uintptr_t renderEntry = Read<uintptr_t>(renderer + 0x20 + (idx * 0x8));
      if (!renderEntry || !IsValidPtr(renderEntry)) continue;
      uintptr_t unityObj = Read<uintptr_t>(renderEntry + 0x10);
      if (!unityObj || !IsValidPtr(unityObj)) continue;
      uintptr_t matBase = Read<uintptr_t>(unityObj + 0x148);
      int matSz = Read<int>(unityObj + 0x148 + 0x10);
      if (!matBase || !IsValidPtr(matBase) || matSz < 1 || matSz > 5) continue;
      for (int m = 0; m < matSz; m++) {
        Write<unsigned int>(matBase + (m * 0x4), materialId);
        written++;
      }
    }
    return written;
  }

  // Build VM chams: find renderer component pointers via reference approach.
  // Returns renderer pointers (NOT material addresses). Each cycle we re-read
  // the material chain via VMProcessRenderer — self-healing if viewmodel dies.
  std::vector<uintptr_t> BuildVMChamsRenderers(uintptr_t heldEntity, bool debug = false) {
    std::vector<uintptr_t> result;
    if (!heldEntity || !IsValidPtr(heldEntity)) return result;

    // Chain: try both offsets (0x250 ours, 0x228 reference)
    uintptr_t gameObject = 0;
    const int vmOffsets[] = { offsets::HeldEntity::viewModel, 0x228 };
    for (int vmOff : vmOffsets) {
      uintptr_t vm = Read<uintptr_t>(heldEntity + vmOff);
      if (!vm || !IsValidPtr(vm)) continue;
      uintptr_t inst = Read<uintptr_t>(vm + 0x28);
      if (!inst || !IsValidPtr(inst)) continue;
      uintptr_t native = Read<uintptr_t>(inst + 0x10);
      if (!native || !IsValidPtr(native)) continue;
      uintptr_t go = Read<uintptr_t>(native + 0x30);
      if (!go || !IsValidPtr(go)) continue;
      gameObject = go;
      if (debug) printf("[VMChams] Chain OK (off=0x%X): go=0x%llX\n", vmOff, (uint64_t)go);
      break;
    }
    if (!gameObject) {
      if (debug) printf("[VMChams] FAIL: no viewModel chain\n");
      return result;
    }

    // Find renderer components via recursive walk
    std::vector<std::pair<uintptr_t, bool>> renderers;
    VMGetComponentsInChildren(gameObject, renderers);
    if (debug) printf("[VMChams] Found %d renderers\n", (int)renderers.size());

    for (auto& r : renderers) {
      result.push_back(r.first);
    }
    return result;
  }

  // Apply from cache: single canary read + batched scatter write.
  // 1 read + 1 driver call per entity instead of N individual writes.
  // Returns 0 if canary detects stale memory (caller should evict entry).
  int ApplyChamsCached(const std::vector<uintptr_t> &matAddrs,
                       unsigned int materialId) {
    if (matAddrs.empty()) return 0;

    // Canary: read first AND last address — valid material IDs are small (<2000000)
    unsigned int canary = Read<unsigned int>(matAddrs[0]);
    if (canary > 2000000 && canary != materialId)
      return 0; // stale — entity was likely freed/reallocated
    if (matAddrs.size() > 1) {
      unsigned int canary2 = Read<unsigned int>(matAddrs.back());
      if (canary2 > 2000000 && canary2 != materialId)
        return 0; // last slot also stale
    }

    // Build scatter list and send as single batched driver call
    std::vector<SCATTER_WRITE_ENTRY> entries(matAddrs.size());
    for (size_t i = 0; i < matAddrs.size(); i++) {
      entries[i].address = matAddrs[i];
      entries[i].value = materialId;
      entries[i]._pad = 0;
    }
    if (drv->WriteScatter(pid, entries.data(), entries.size()))
      return (int)matAddrs.size();

    // Fallback: individual writes if scatter not supported (old driver)
    int applied = 0;
    for (const auto &addr : matAddrs) {
      Write<unsigned int>(addr, materialId);
      applied++;
    }
    return applied;
  }

  // Custom galaxy disabled — the addr-0x148 reverse math was fundamentally
  // broken (matBase is a heap pointer, not nativeObj+0x148) and wrote floats
  // to garbage addresses causing game crashes.  Fall back to material swap.
  int ApplyCustomGalaxy(const std::vector<uintptr_t> &matAddrs) {
    // Use wireframe as a safe visual-only fallback (no color writes)
    return ApplyChamsCached(matAddrs, 1348630);
  }

public:
  /* ── Layer Removal (Culling Mask) ────────────────────────── */

  enum LayerMasks : int {
    Layer_Default = 1,
    Layer_TransparentFX = 2,
    Layer_Ignore_Raycast = 4,
    Layer_Water = 16,
    Layer_UI = 32,
    Layer_Deployed = 256,
    Layer_Ragdoll = 512,
    Layer_Invisible = 1024,
    Layer_AI = 2048,
    Layer_Player_Movement = 4096,
    Layer_Vehicle_Detailed = 8192,
    Layer_Game_Trace = 16384,
    Layer_Vehicle_World = 32768,
    Layer_World = 65536,
    Layer_Player_Server = 131072,
    Layer_Trigger = 262144,
    Layer_Player_Model_Rendering = 524288,
    Layer_Physics_Projectile = 1048576,
    Layer_Construction = 2097152,
    Layer_Construction_Socket = 4194304,
    Layer_Terrain = 8388608,
    Layer_Transparent = 16777216,
    Layer_Clutter = 33554432,
    Layer_Debris = 67108864,
    Layer_Vehicle_Large = 134217728,
    Layer_Prevent_Movement = 268435456,
    Layer_Prevent_Building = 536870912,
    Layer_Tree = 1073741824,
  };

  int GetCullingMask() {
    if (!cachedCamBuf)
      return -1;
    return Read<int>(cachedCamBuf + offsets::BaseCamera::cullingMask);
  }

  bool SetCullingMask(int mask) {
    try {
      if (!cachedCamBuf)
        return false;
      Write<int>(cachedCamBuf + offsets::BaseCamera::cullingMask, mask);
      return true;
    } catch (...) {
      return false;
    }
  }

  void SetLayerVisible(int layer, bool visible) {
    int mask = GetCullingMask();
    if (mask == -1)
      return;
    if (visible)
      mask |= layer;
    else
      mask &= ~layer;
    SetCullingMask(mask);
  }

  void ApplyRemoveLayers() {
    SetLayerVisible(Layer_Tree, false);
    SetLayerVisible(Layer_Clutter, false);
    SetLayerVisible(Layer_Debris, false);
    SetLayerVisible(Layer_Construction, false);
  }

  void RestoreLayers(int defaultMask) { SetCullingMask(defaultMask); }

  /* ── Time of Day & FOV Changer (using your provided code) ───────────────── */

  bool InitializeTimeSystem() {
    // Chain from forum: GA+TodSky_c → +0xB8 → +0x28 → +0x10 → +0x20
    UINT64 TodSkyTypeInfo = Read<UINT64>(gameAssembly + offsets::TodSky::Class);
    if (!TodSkyTypeInfo) {
      printf("[TIME] Failed to get TOD_Sky TypeInfo (GA+0x%llX)\n", (uint64_t)offsets::TodSky::Class);
      return false;
    }
    printf("[TIME] TypeInfo = 0x%llX\n", TodSkyTypeInfo);

    UINT64 sf = Read<UINT64>(TodSkyTypeInfo + offsets::TodSky::static_fields); // +0xB8
    if (!sf) {
      printf("[TIME] Failed to get static_fields (+0xB8)\n");
      return false;
    }
    printf("[TIME] static_fields = 0x%llX\n", sf);

    UINT64 inst_raw = Read<UINT64>(sf + offsets::TodSky::instance); // +0x28
    if (!inst_raw) {
      printf("[TIME] Failed to get instance (+0x28)\n");
      return false;
    }
    printf("[TIME] instance_raw = 0x%llX\n", inst_raw);

    UINT64 step3 = Read<UINT64>(inst_raw + offsets::TodSky::parent_static_fields); // +0x10
    if (!step3) {
      printf("[TIME] Failed at chain step +0x10\n");
      return false;
    }
    printf("[TIME] step3 (+0x10) = 0x%llX\n", step3);

    UINT64 Instance = Read<UINT64>(step3 + offsets::TodSky::unk); // +0x20
    if (!Instance) {
      printf("[TIME] Failed at chain step +0x20\n");
      return false;
    }
    printf("[TIME] Instance (+0x20) = 0x%llX\n", Instance);

    // Validate: check Cycle.Hour is in [0,24]
    UINT64 cycle = Read<UINT64>(Instance + offsets::TodSky::TOD_CycleParameters);
    if (cycle) {
      float h = Read<float>(cycle + offsets::TodSky::Cycle::hour);
      printf("[TIME] Validation: Cycle=0x%llX Hour=%.2f\n", cycle, h);
      if (h < 0.f || h > 24.f) {
        printf("[TIME] WARNING: Hour %.2f out of range, instance may be wrong\n", h);
        return false;
      }
    } else {
      printf("[TIME] WARNING: Cycle pointer is null, instance may be wrong\n");
      return false;
    }

    todSkyInstance = Instance;
    printf("[TIME] TOD_Sky system initialized (instance: 0x%llX)\n", todSkyInstance);
    return true;
  }

  bool SetTimeOfDay(float hour) {
    if (!todSkyInstance) {
      if (!InitializeTimeSystem()) return false;
    }

    UINT64 Cycle = Read<UINT64>(todSkyInstance + offsets::TodSky::TOD_CycleParameters);
    if (!Cycle) {
      printf("[TIME] Failed to get Cycle parameters\n");
      return false;
    }

    // Set the hour (0-24)
    Write<float>(Cycle + offsets::TodSky::Cycle::hour, hour);
    return true;
  }

  bool SetBrightness(float intensity) {
    if (!todSkyInstance) {
      if (!InitializeTimeSystem()) return false;
    }

    UINT64 Night = Read<UINT64>(todSkyInstance + offsets::TodSky::TOD_NightParameters);
    if (!Night) {
      printf("[TIME] Failed to get Night parameters\n");
      return false;
    }

    UINT64 Ambient = Read<UINT64>(todSkyInstance + offsets::TodSky::TOD_AmbientParameters);
    if (!Ambient) {
      printf("[TIME] Failed to get Ambient parameters\n");
      return false;
    }

    // Modify night light intensity and ambient multiplier
    Write<float>(Night + offsets::TodSky::Night::lightIntensity, intensity);
    Write<float>(Night + offsets::TodSky::Night::ambientMultiplier, intensity);
    return true;
  }

  bool SetSkyColor(float r, float g, float b) {
    if (!todSkyInstance) {
      if (!InitializeTimeSystem()) return false;
    }

    UINT64 Day = Read<UINT64>(todSkyInstance + offsets::TodSky::TOD_DayParameters);
    if (!Day) {
      printf("[TIME] Failed to get Day parameters\n");
      return false;
    }

    UINT64 SkyColor = Read<UINT64>(Day + 0x48);
    if (!SkyColor) {
      printf("[TIME] Failed to get SkyColor\n");
      return false;
    }

    UINT64 SkyGradient = Read<UINT64>(SkyColor + 0x20);
    if (!SkyGradient) {
      printf("[TIME] Failed to get SkyGradient\n");
      return false;
    }

    // Set sky color (RGB)
    Write<float>(SkyGradient + 0x00, r); // Red
    Write<float>(SkyGradient + 0x04, g); // Green  
    Write<float>(SkyGradient + 0x08, b); // Blue
    printf("[TIME] Set sky color to RGB(%.2f, %.2f, %.2f)\n", r, g, b);
    return true;
  }

  bool SetNightSkyColor(float r, float g, float b) {
    if (!todSkyInstance) {
      if (!InitializeTimeSystem()) return false;
    }

    UINT64 Night = Read<UINT64>(todSkyInstance + offsets::TodSky::TOD_NightParameters);
    if (!Night) {
      printf("[TIME] Failed to get Night parameters\n");
      return false;
    }

    UINT64 NightSkyColor = Read<UINT64>(Night + 0x34);
    if (!NightSkyColor) {
      printf("[TIME] Failed to get NightSkyColor\n");
      return false;
    }

    UINT64 NightSkyGradient = Read<UINT64>(NightSkyColor + 0x10);
    if (!NightSkyGradient) {
      printf("[TIME] Failed to get NightSkyGradient\n");
      return false;
    }

    // Set night sky color (RGB)
    Write<float>(NightSkyGradient + 0x00, r); // Red
    Write<float>(NightSkyGradient + 0x04, g); // Green
    Write<float>(NightSkyGradient + 0x08, b); // Blue
    printf("[TIME] Set night sky color to RGB(%.2f, %.2f, %.2f)\n", r, g, b);
    return true;
  }

  bool SetCustomFOV(float fov) {
    ApplyFOV(fov);
    return fovInitialized;
  }

private:
  UINT64 todSkyInstance = 0;
};
