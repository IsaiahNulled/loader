#pragma once
//again I left comments to make it easy for you guys to paste 
#include <TlHelp32.h>
#include <Windows.h>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <unordered_map>
#include <vector>


#include "memory.h"
#include "rust_offsets.h"

// basic math types 

struct Vec3 {
  float x, y, z;
  Vec3() : x(0), y(0), z(0) {}
  Vec3(float x, float y, float z) : x(x), y(y), z(z) {}

  Vec3 operator-(const Vec3 &o) const { return {x - o.x, y - o.y, z - o.z}; }
  Vec3 operator+(const Vec3 &o) const { return {x + o.x, y + o.y, z + o.z}; }
  Vec3 operator*(float s) const { return {x * s, y * s, z * s}; }
  float Length() const { return sqrtf(x * x + y * y + z * z); }
  bool is_empty() const { return x == 0.f && y == 0.f && z == 0.f; }
};

struct Vec4 {
  float x, y, z, w;
  Vec4() : x(0), y(0), z(0), w(1) {}
  Vec4(float x, float y, float z, float w) : x(x), y(y), z(z), w(w) {}

  Vec3 operator*(const Vec3 &rhs) const {
    float x2 = x * 2.f, y2 = y * 2.f, z2 = z * 2.f;
    float xx = x * x2, yy = y * y2, zz = z * z2;
    float xy = x * y2, xz = x * z2, yz = y * z2;
    float wx = w * x2, wy = w * y2, wz = w * z2;
    Vec3 res;
    res.x = (1.f - (yy + zz)) * rhs.x + (xy - wz) * rhs.y + (xz + wy) * rhs.z;
    res.y = (xy + wz) * rhs.x + (1.f - (xx + zz)) * rhs.y + (yz - wx) * rhs.z;
    res.z = (xz - wy) * rhs.x + (yz + wx) * rhs.y + (1.f - (xx + yy)) * rhs.z;
    return res;
  }
};

struct Vec2 {
  float x, y;
};

struct ViewMatrix {
  float m[4][4];
};

// player info

struct PlayerData {
  uintptr_t address;
  Vec3 position;
  Vec3 headPos;
  std::wstring name;
  uint64_t teamID;
  uint32_t flags;
  uint32_t lifestate;
  bool isVisible;
  bool isSleeping;
  bool isWounded;
  float distance;
  float health;
  float maxHealth;
  std::vector<std::string> hotbarItems;
  std::vector<std::string> wearItems;
};

// decrypt helpers

namespace RustDecrypt {

static uintptr_t DecryptClientEntities_Method1(uintptr_t enc) {
  uint32_t *p = (uint32_t *)&enc;
  for (int i = 0; i < 2; i++) {
    uint32_t v = p[i];
    v += 0xF1B06211u;
    uint32_t t = v;
    v = (v << 14) | (t >> 18);
    v ^= 0x24383967u;
    v -= 0x5801F290u;
    p[i] = v;
  }
  return enc;
}

static uintptr_t DecryptClientEntities_Method4(uintptr_t enc) { return enc; }

static uintptr_t DecryptClientEntities(uintptr_t enc, bool reset = false) {
  static int lastMethod = 0;
  if (reset) {
    lastMethod = 0;
    return 0;
  }

  // try method 1 first then direct
  uintptr_t r = DecryptClientEntities_Method1(enc);
  uint32_t h = (uint32_t)(r & 0xFFFFFFFF);
  if (h != 0 && h < 0x10000000)
    return r;

  return DecryptClientEntities_Method4(enc);
}

static uintptr_t DecryptEntityList(uintptr_t enc, bool reset = false) {
  if (reset)
    return 0;
  uint32_t *p = (uint32_t *)&enc;
  for (int i = 0; i < 2; i++) {
    uint32_t v = p[i], t = v;
    v = (t >> 19) | (v << 13);
    v -= 0x48F9C02Eu;
    v ^= 0x6CCF6779u;
    p[i] = v;
  }
  return enc;
}

static uintptr_t DecryptPlayerInventory(uintptr_t enc) {
  uint32_t *p = (uint32_t *)&enc;
  for (int i = 0; i < 2; i++) {
    uint32_t v = p[i];
    v += 0x59558B36u;
    v ^= 0x2D277853u;
    v += 0x19F01F38u;
    uint32_t t = v;
    v = v + v;
    v |= (t >> 31);
    p[i] = v;
  }
  return enc;
}

} // rustdecrypt namespace - a jew was here :)

// pointer validation

inline bool IsValidPtr(uintptr_t p) {
  return p > 0x10000ULL && p < 0x7FFFFFFFFFFF;
}

// main SDK class

class RustSDK {
private:
  MemoryReader *mem;
  DWORD pid = 0;
  uintptr_t gameAssembly = 0;
  bool attached = false;

  uintptr_t entityBuffer = 0;
  int entityCount = 0;
  uintptr_t cachedLocalPlayer = 0;
  ULONGLONG lastLocalRefresh = 0;
  uintptr_t cachedCamBuf = 0;

  // gc handle resolution data
  uintptr_t gcHandleTable = 0;
  uintptr_t bitmapGlobalAddr = 0;

  // player cache to avoid repeated class name reads
  std::unordered_map<uintptr_t, bool> isPlayerCache;

  template <typename T> T Read(uintptr_t addr) {
    return mem->Read<T>(pid, addr);
  }

  bool ReadRaw(uintptr_t addr, void *buf, size_t sz) {
    return mem->ReadMemory(pid, addr, buf, sz);
  }

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

  uintptr_t ReadChain(uintptr_t base, const std::vector<uint32_t> &offs) {
    uintptr_t addr = base;
    for (auto off : offs) {
      addr = Read<uintptr_t>(addr + off);
      if (!addr)
        return 0;
    }
    return addr;
  }

  static bool IsAlignedPtr(uintptr_t p) {
    return IsValidPtr(p) && (p & 7) == 0;
  }

  // gc handle resolution - this is really really cursed but it works

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
      uintptr_t val = Read<uintptr_t>(refAddr);

      if (IsValidPtr(val)) {
        uintptr_t t0 = Read<uintptr_t>(val);
        uintptr_t t1 = Read<uintptr_t>(val + 8);
        bool isBitmap = (t0 > 0x7FFFFFFFFFFF || t1 > 0x7FFFFFFFFFFF);
        if (isBitmap) {
          bitmapGlobalAddr = refAddr;
          continue;
        }
        bool t0ok = (t0 == 0 || IsAlignedPtr(t0));
        bool t1ok = (t1 == 0 || IsAlignedPtr(t1));
        if (t0ok && t1ok && (t0 != 0 || t1 != 0)) {
          gcHandleTable = val;
          printf("[GC] Handle table: 0x%llX\n", (uint64_t)gcHandleTable);
          return true;
        }
      }

      if (IsValidPtr(val)) {
        for (int off = 0; off <= 0x18; off += 8) {
          uintptr_t inner = Read<uintptr_t>(val + off);
          if (!IsValidPtr(inner))
            continue;
          uintptr_t e0 = Read<uintptr_t>(inner);
          uintptr_t e1 = Read<uintptr_t>(inner + 8);
          if ((e0 == 0 || IsAlignedPtr(e0)) && (e1 == 0 || IsAlignedPtr(e1)) &&
              (e0 || e1)) {
            gcHandleTable = inner;
            printf("[GC] Handle table (deref): 0x%llX\n",
                   (uint64_t)gcHandleTable);
            return true;
          }
        }
      }
    }
    return false;
  }

  bool FindGCTableFromMemory() {
    printf("[GC] Reading PE exports from game memory...\n");
    IMAGE_DOS_HEADER dos = {};
    if (!ReadRaw(gameAssembly, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE)
      return false;
    IMAGE_NT_HEADERS64 nt = {};
    if (!ReadRaw(gameAssembly + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE)
      return false;

    auto &expDD = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDD.VirtualAddress)
      return false;

    IMAGE_EXPORT_DIRECTORY expDir = {};
    if (!ReadRaw(gameAssembly + expDD.VirtualAddress, &expDir, sizeof(expDir)))
      return false;

    DWORD numNames = expDir.NumberOfNames;
    if (numNames > 10000)
      numNames = 10000;
    std::vector<DWORD> nameRVAs(numNames);
    std::vector<WORD> ordinals(numNames);
    std::vector<DWORD> funcRVAs(
        expDir.NumberOfFunctions > 10000 ? 10000 : expDir.NumberOfFunctions);

    if (!ReadRaw(gameAssembly + expDir.AddressOfNames, nameRVAs.data(),
                 numNames * sizeof(DWORD)) ||
        !ReadRaw(gameAssembly + expDir.AddressOfNameOrdinals, ordinals.data(),
                 numNames * sizeof(WORD)) ||
        !ReadRaw(gameAssembly + expDir.AddressOfFunctions, funcRVAs.data(),
                 funcRVAs.size() * sizeof(DWORD)))
      return false;

    uint32_t targetRVA = 0;
    for (DWORD i = 0; i < numNames; i++) {
      char exportName[64] = {};
      ReadRaw(gameAssembly + nameRVAs[i], exportName, sizeof(exportName) - 1);
      if (strcmp(exportName, "il2cpp_gchandle_get_target") == 0) {
        if (ordinals[i] < funcRVAs.size())
          targetRVA = funcRVAs[ordinals[i]];
        break;
      }
    }
    if (!targetRVA)
      return false;

    uintptr_t funcAddr = gameAssembly + targetRVA;
    uint8_t code[512] = {};
    ReadRaw(funcAddr, code, sizeof(code));
    if (code[0] == 0xE9) {
      int32_t jd = *(int32_t *)(code + 1);
      funcAddr = funcAddr + 5 + jd;
      memset(code, 0, sizeof(code));
      ReadRaw(funcAddr, code, sizeof(code));
    }
    return TryExtractTableFromCode(funcAddr, code, 500);
  }

  bool FindGCHandleTable() {
    if (FindGCTableFromMemory())
      return true;
    if (bitmapGlobalAddr)
      return true;
    return false;
  }

  uintptr_t ResolveGCHandle(uintptr_t rawHandle) {
    if (!rawHandle)
      return 0;
    uint32_t handle = (uint32_t)(rawHandle & 0xFFFFFFFF);
    if (handle == 0)
      return 0;
    uint32_t type = handle & 7;
    uint32_t index = handle >> 3;
    if (type == 0 || type > 4)
      return 0;

    if (bitmapGlobalAddr) {
      uintptr_t recordAddr = bitmapGlobalAddr + (uintptr_t)(type - 1) * 40;
      uintptr_t record[5] = {};
      ReadRaw(recordAddr, record, sizeof(record));
      static const int fieldOrder[] = {1, 4, 0, 2, 3};
      for (int fi = 0; fi < 5; fi++) {
        uintptr_t objArrayPtr = record[fieldOrder[fi]];
        if (!IsValidPtr(objArrayPtr))
          continue;
        uintptr_t target = Read<uintptr_t>(objArrayPtr + (uintptr_t)index * 8);
        if (IsValidPtr(target))
          return target;
      }
    }

    if (gcHandleTable && index < 0x200000) {
      uintptr_t target = Read<uintptr_t>(gcHandleTable + (uintptr_t)index * 8);
      if (IsValidPtr(target))
        return target;
    }
    return 0;
  }

  uintptr_t il2cpp_get_handle(uintptr_t handle) {
    if (!handle)
      return 0;
    uintptr_t resolved = ResolveGCHandle(handle);
    if (IsValidPtr(resolved))
      return resolved;
    if (IsValidPtr(handle))
      return handle;
    return 0;
  }

  // entity decrypts

  uintptr_t decrypt_client_entities(uintptr_t a1) {
    if (!IsValidPtr(a1))
      return 0;
    static const int wrapperOffsets[] = {0x18, 0x10, 0x20, 0x28};
    for (int off : wrapperOffsets) {
      uintptr_t encrypted = Read<uintptr_t>(a1 + off);
      if (!encrypted)
        continue;
      uintptr_t decrypted = RustDecrypt::DecryptClientEntities(encrypted);
      if (decrypted) {
        uintptr_t result = il2cpp_get_handle(decrypted);
        if (IsValidPtr(result))
          return result;
      }
      if (IsValidPtr(encrypted)) {
        uintptr_t probe = Read<uintptr_t>(encrypted + 0x10);
        if (IsValidPtr(probe))
          return encrypted;
      }
    }
    return 0;
  }

  uintptr_t decrypt_entity_list(uintptr_t a1) {
    static const int offs[] = {0x18, 0x10, 0x20, 0x28};
    for (int off : offs) {
      uintptr_t encrypted = Read<uintptr_t>(a1 + off);
      if (!encrypted)
        continue;
      uintptr_t decrypted = RustDecrypt::DecryptEntityList(encrypted);
      if (decrypted) {
        uintptr_t result = il2cpp_get_handle(decrypted);
        if (IsValidPtr(result))
          return result;
      }
      if (IsValidPtr(encrypted)) {
        uintptr_t probe = Read<uintptr_t>(encrypted + 0x10);
        if (IsValidPtr(probe) || Read<int>(encrypted + 0x18) > 0)
          return encrypted;
      }
    }
    return 0;
  }

  // class name reading

  std::string ReadClassName(uintptr_t entity) {
    if (!IsValidPtr(entity))
      return "";
    uintptr_t klass = Read<uintptr_t>(entity);
    if (!IsValidPtr(klass))
      return "";
    uintptr_t namePtr = Read<uintptr_t>(klass + 0x10);
    if (!IsValidPtr(namePtr))
      return "";
    char buf[64] = {};
    ReadRaw(namePtr, buf, 63);
    return std::string(buf);
  }

  bool IsPlayer(uintptr_t entity) {
    if (!IsValidPtr(entity))
      return false;
    auto it = isPlayerCache.find(entity);
    if (it != isPlayerCache.end())
      return it->second;

    bool result = false;
    std::string name = ReadClassName(entity);
    if (name == "BasePlayer" || name == "NPCPlayer" || name == "ScientistNPC" ||
        name == "HTNPlayer" || name == "NPCMurderer" || name == "HumanNPC")
      result = true;

    if (!result) {
      uintptr_t pm = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
      uintptr_t eyes = Read<uintptr_t>(entity + offsets::BasePlayer::eyes);
      uintptr_t inv = Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
      if (IsValidPtr(pm) && IsValidPtr(eyes) && IsValidPtr(inv))
        result = true;
    }
    isPlayerCache[entity] = result;
    return result;
  }

  uintptr_t FindLocalPlayer() {
    Vec3 camPos = GetCameraPosition();
    if (camPos.is_empty())
      return 0;
    uintptr_t best = 0;
    float bestDist = 5.0f;
    int count = GetEntityCount();
    for (int i = 0; i < count && i < 100; i++) {
      uintptr_t ent = GetEntity(i);
      if (!IsValidPtr(ent))
        continue;
      if (!IsPlayer(ent))
        continue;
      uintptr_t pm = Read<uintptr_t>(ent + offsets::BasePlayer::playerModel);
      if (!pm)
        continue;
      Vec3 pos = Read<Vec3>(pm + offsets::PlayerModel::position);
      float d = (pos - camPos).Length();
      if (d < bestDist) {
        bestDist = d;
        best = ent;
      }
    }
    return best;
  }

public:
  RustSDK(MemoryReader *reader) : mem(reader) {}

  bool IsAttached() const { return attached && pid != 0; }
  DWORD GetPID() const { return pid; }
  uintptr_t GetGameAssemblyBase() const { return gameAssembly; }
  int GetEntityCount() const { return entityCount; }
  uintptr_t GetEntityBufferAddr() const { return entityBuffer; }

  // attachment and initialization

  bool Attach() {
    attached = false;
    entityBuffer = 0;
    entityCount = 0;

    printf("[*] Searching for RustClient.exe...\n");
    pid = FindProcessByName(L"RustClient.exe");
    if (!pid) {
      printf("[!] RustClient.exe not found\n");
      return false;
    }
    printf("[+] RustClient.exe PID: %lu\n", pid);

    if (!mem->Init(pid))
      return false;

    printf("[*] Getting GameAssembly.dll base...\n");
    gameAssembly = mem->GetModuleBase(pid, L"GameAssembly.dll");
    if (!gameAssembly) {
      printf("[!] GameAssembly.dll not found\n");
      return false;
    }
    printf("[+] GameAssembly.dll base: 0x%llX\n", (uint64_t)gameAssembly);

    attached = true;
    printf("[+] Attached successfully!\n");

    printf("[*] Looking for GC handle table...\n");
    if (FindGCHandleTable())
      printf("[+] GC handle table found\n");
    else
      printf("[!] GC handle table not found\n");

    return true;
  }

  // entity list reading

  bool RefreshEntityList() {
    entityBuffer = 0;
    entityCount = 0;
    isPlayerCache.clear();

    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::basenetworkable_pointer);
    if (!typeInfo)
      return false;
    uintptr_t staticFields =
        Read<uintptr_t>(typeInfo + offsets::BaseNetworkable::static_fields);
    if (!staticFields)
      return false;
    uintptr_t wrapper1 = Read<uintptr_t>(
        staticFields + offsets::BaseNetworkable::client_entities);
    if (!IsValidPtr(wrapper1))
      return false;

    uintptr_t clientEntities = decrypt_client_entities(wrapper1);
    if (!IsValidPtr(clientEntities))
      return false;

    uintptr_t wrapper2 =
        Read<uintptr_t>(clientEntities + offsets::BaseNetworkable::entity_list);
    if (!IsValidPtr(wrapper2))
      return false;
    uintptr_t entityList = decrypt_entity_list(wrapper2);
    if (!IsValidPtr(entityList))
      return false;

    uintptr_t bufferList =
        Read<uintptr_t>(entityList + offsets::BaseNetworkable::buffer_list);
    if (!IsValidPtr(bufferList))
      return false;

    int count = Read<int>(bufferList + 0x18);
    uintptr_t entityArray = Read<uintptr_t>(bufferList + 0x10);
    if (!IsValidPtr(entityArray) || count <= 0 || count > 50000)
      return false;

    entityBuffer = entityArray;
    entityCount = count;
    return true;
  }

  uintptr_t GetEntity(int index) {
    if (!entityBuffer || index < 0 || index >= entityCount)
      return 0;
    return Read<uintptr_t>(entityBuffer + 0x20 + (uintptr_t)index * 8);
  }

  // vm and camera

  bool GetViewMatrix(ViewMatrix &vm) {
    uintptr_t typeInfo =
        Read<uintptr_t>(gameAssembly + offsets::camera_pointer);
    if (!typeInfo)
      return false;
    uintptr_t sf =
        Read<uintptr_t>(typeInfo + offsets::BaseCamera::static_fields);
    if (!sf)
      return false;
    uintptr_t inst = Read<uintptr_t>(sf + offsets::BaseCamera::wrapper_class);
    if (!inst)
      return false;
    uintptr_t buf =
        Read<uintptr_t>(inst + offsets::BaseCamera::parent_static_fields);
    if (!buf)
      return false;
    cachedCamBuf = buf;
    return ReadRaw(buf + offsets::BaseCamera::viewMatrix, &vm,
                   sizeof(ViewMatrix));
  }

  Vec3 GetCameraPosition() {
    if (!cachedCamBuf)
      return {};
    return Read<Vec3>(cachedCamBuf + offsets::BaseCamera::position);
  }

  uintptr_t GetLocalPlayer() {
    ULONGLONG now = GetTickCount64();
    if (!cachedLocalPlayer || (now - lastLocalRefresh) > 2000) {
      lastLocalRefresh = now;
      cachedLocalPlayer = FindLocalPlayer();
    }
    return cachedLocalPlayer;
  }

  // w2s

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

  //player data reading

  bool ReadPlayerPositionAndLifestate(uintptr_t entity, Vec3 &pos,
                                      Vec3 &headPos, uint32_t &lifestate) {
    uintptr_t pm = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    if (!pm)
      return false;
    pos = Read<Vec3>(pm + offsets::PlayerModel::position);
    if (pos.is_empty())
      return false;

    float eyeHeight = 1.55f;
    uintptr_t ms = Read<uintptr_t>(entity + offsets::BasePlayer::ModelState);
    if (ms && IsValidPtr(ms)) {
      int flags = Read<int>(ms + offsets::ModelState::flags);
      if (flags & (1 << 2))
        eyeHeight = 1.05f;
      else if (flags & (1 << 3))
        eyeHeight = 0.45f;
    }
    headPos = Vec3(pos.x, pos.y + eyeHeight, pos.z);
    lifestate = Read<uint32_t>(entity + offsets::BaseCombatEntity::lifestate);
    return true;
  }

  bool ReadPlayerDetails(uintptr_t entity, PlayerData &out) {
    uintptr_t namePtr = Read<uintptr_t>(entity + 0x3E8);
    out.name = ReadString(namePtr);
    out.teamID = Read<uint64_t>(entity + offsets::BasePlayer::currentTeam);
    out.flags = Read<uint32_t>(entity + offsets::BasePlayer::playerFlags);
    out.isSleeping = (out.flags & 16) != 0;
    out.isWounded = (out.flags & 64) != 0;
    uintptr_t pm = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
    out.isVisible =
        pm ? Read<bool>(pm + offsets::PlayerModel::isVisible) : false;
    out.health = Read<float>(entity + offsets::BaseCombatEntity::_health);
    out.maxHealth = Read<float>(entity + offsets::BaseCombatEntity::_maxHealth);
    return true;
  }

  // hotbar items

  std::vector<std::string> ReadHotbarItems(uintptr_t entity) {
    std::vector<std::string> items;
    const int MAX_BELT = 6;

    uintptr_t wrapper =
        Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
    if (!wrapper)
      return items;

    uintptr_t inventory = 0;
    if (IsValidPtr(wrapper)) {
      uintptr_t enc = Read<uintptr_t>(wrapper + 0x18);
      if (enc) {
        uintptr_t dec = RustDecrypt::DecryptPlayerInventory(enc);
        inventory = il2cpp_get_handle(dec);
      }
    }
    if (!IsValidPtr(inventory) && wrapper) {
      uintptr_t dec = RustDecrypt::DecryptPlayerInventory(wrapper);
      inventory = il2cpp_get_handle(dec);
    }
    if (!IsValidPtr(inventory))
      return items;

    uintptr_t belt =
        Read<uintptr_t>(inventory + offsets::PlayerInventory::belt);
    if (!IsValidPtr(belt))
      return items;
    uintptr_t itemList =
        Read<uintptr_t>(belt + offsets::ItemContainer::itemlist);
    if (!IsValidPtr(itemList))
      return items;
    uintptr_t itemsArray = Read<uintptr_t>(itemList + 0x10);
    int count = Read<int>(itemList + 0x18);
    if (!IsValidPtr(itemsArray) || count <= 0)
      return items;
    if (count > MAX_BELT)
      count = MAX_BELT;

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
      uintptr_t snPtr =
          Read<uintptr_t>(itemDef + offsets::ItemDefinition::ShortName);
      if (!IsValidPtr(snPtr)) {
        items.push_back("");
        continue;
      }
      std::wstring wname = ReadString(snPtr, 32);
      if (wname.empty()) {
        items.push_back("");
        continue;
      }
      items.push_back(std::string(wname.begin(), wname.end()));
    }
    return items;
  }

  // wear items

  std::vector<std::string> ReadWearItems(uintptr_t entity) {
    std::vector<std::string> items;
    const int MAX_WEAR = 7;

    uintptr_t wrapper =
        Read<uintptr_t>(entity + offsets::BasePlayer::inventory);
    if (!wrapper)
      return items;

    uintptr_t inventory = 0;
    if (IsValidPtr(wrapper)) {
      uintptr_t enc = Read<uintptr_t>(wrapper + 0x18);
      if (enc) {
        uintptr_t dec = RustDecrypt::DecryptPlayerInventory(enc);
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
    if (count > MAX_WEAR)
      count = MAX_WEAR;

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
      uintptr_t snPtr =
          Read<uintptr_t>(itemDef + offsets::ItemDefinition::ShortName);
      if (!IsValidPtr(snPtr)) {
        items.push_back("");
        continue;
      }
      std::wstring wname = ReadString(snPtr, 32);
      if (wname.empty()) {
        items.push_back("");
        continue;
      }
      items.push_back(std::string(wname.begin(), wname.end()));
    }
    return items;
  }

  // generic value reader - for any other data you want to read that doesn't have a dedicated function, just provide the address and type and it will return the value

  template <typename T> T ReadVal(uintptr_t addr) { return Read<T>(addr); }
};
