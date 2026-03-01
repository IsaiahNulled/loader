# Complete Visual Check (VisCheck) Code

This document contains ALL the code used for the visual check (vischeck) feature in the cheat.

## Overview
The vischeck system uses PhysX raycasting to determine if a player is visible from the local player's camera position. It replaces the simple frustum check (`PlayerModel::isVisible`) with actual geometry-based visibility detection.

## 1. Configuration & Settings

### globals.h
```cpp
// Visual check toggle
inline bool g_espVisCheck = false;
```

### config_manager.cpp
```cpp
// Load vischeck setting from config
g_espVisCheck = cfg->get<checkbox_t>("Vischeck").enabled;

// Save vischeck setting to config
if (key == "vischeck")
  g_espVisCheck = (std::stoi(val) != 0);
```

### framework/helpers/config.cpp
```cpp
// UI checkbox for vischeck
add_option<checkbox_t>("Vischeck");
```

## 2. Player Data Structure

### rust_sdk.h
```cpp
struct PlayerData {
  uintptr_t address;
  Vec3 position;
  Vec3 headPos; /* position + eye offset */
  std::wstring name;
  uint64_t teamID;
  uint32_t flags;
  uint32_t lifestate;
  bool isVisible;        // <<< VISIBILITY RESULT
  bool isSleeping;
  bool isWounded;
  float distance;
  float health;
  float maxHealth;
  std::vector<Vec3> bones; /* world-space bone positions */
  // ... other fields
};
```

## 3. Core Visibility Check Logic

### esp_renderer.cpp (main integration)
```cpp
// PhysX-based visibility check (replaces frustum-only isVisible)
if (g_espVisCheck && g_PhysX.HasActors() && !isLocal && !player.bones.empty()) {
  // Raycast from local camera to target's head/bones
  static const int vischeckedBones[] = {47, 22, 1}; // head, spine4, pelvis
  player.isVisible = g_PhysX.AnyBoneVisible(
      localPos, player.bones, vischeckedBones, 3);
}
```

### esp_renderer.cpp (PhysX initialization)
```cpp
// Initialize PhysX scene reader for vischecks
if (!g_PhysX.HasActors()) {
  g_PhysX.Init(g_SDK, &g_Driver, g_SDK->GetPID());
}

// Periodically refresh PhysX actor cache (every 5s)
if (g_espVisCheck) {
  static ULONGLONG lastPhysXRefresh = 0;
  if (now - lastPhysXRefresh >= 5000 || lastPhysXRefresh == 0) {
    g_PhysX.CacheActors();
    lastPhysXRefresh = now;
  }
}
```

## 4. PhysX Raycasting Engine

### physx.hpp (core visibility functions)
```cpp
/* ── Visibility check: is 'target' visible from 'eye'? ──── */
bool IsVisible(Vec3 eye, Vec3 target) {
    if (eye.is_empty() || target.is_empty()) return true;
    auto hit = Linecast(eye, target);
    if (!hit.didHit) return true;
    /* If the hit is very close to the target, it's still "visible"
     * (hit the target's own collider or close geometry) */
    float targetDist = (target - eye).Length();
    return hit.distance >= (targetDist - 0.5f);
}

/* ── Per-bone visibility check ───────────────────────────── */
bool CheckBoneVisible(Vec3 eye, Vec3 bonePos) {
    return IsVisible(eye, bonePos);
}

/* ── Check if any bone on a player is visible ────────────── */
bool AnyBoneVisible(Vec3 eye, const std::vector<Vec3> &bones,
                    const int *boneIndices, int numBones)
{
    for (int i = 0; i < numBones; i++) {
        int idx = boneIndices[i];
        if (idx >= (int)bones.size()) continue;
        if (bones[idx].is_empty()) continue;
        if (IsVisible(eye, bones[idx])) return true;
    }
    return false;
}
```

### physx.hpp (raycast implementation)
```cpp
/* ── Linecast (from → to) ────────────────────────────────── */
HitResult Linecast(Vec3 from, Vec3 to) {
    if (from.is_empty() || to.is_empty()) return {};
    Vec3 dir = (to - from).normalize();
    float dist = (to - from).Length();
    return Raycast(from, dir, dist);
}

/* ── Raycast ─────────────────────────────────────────────── */
HitResult Raycast(Vec3 origin, Vec3 direction, float maxDist) {
    HitResult hit;
    if (origin.is_empty() || direction.is_empty() || maxDist <= 0) return hit;

    float closestT = maxDist;
    std::lock_guard<std::mutex> lock(m_actorsMutex);
    for (const auto& actor : *m_actors) {
        if (!actor.bvhRoot) continue;
        float tmin, tmax;
        if (!actor.bounds.intersects(origin, direction, tmin, tmax)) continue;
        raycastBVH(actor.bvhRoot.get(), origin, direction, closestT, hit, actor.triangles);
    }
    return hit;
}
```

## 5. ESP Rendering with VisCheck

### esp_renderer.cpp (name coloring)
```cpp
ImU32 nameColor;
if (g_espVisCheck)
  nameColor = player.isVisible ? IM_COL32(0, 255, 0, 255) : IM_COL32(255, 0, 0, 255);
else
  nameColor = color;
```

### esp_renderer.cpp (skeleton coloring)
```cpp
ImU32 skelColor;
if (g_espVisCheck) {
  // Per-bone visibility coloring: green = visible, red = not visible
  skelColor = player.isVisible ? IM_COL32(0, 255, 0, 255) : IM_COL32(255, 0, 0, 255);
} else {
  skelColor = color;
}
```

## 6. Fallback Frustum Check (when vischeck disabled)

### rust_sdk.h (original Unity frustum check)
```cpp
// Use PlayerModel::isVisible (frustum check) for responsive visibility
uintptr_t pm = Read<uintptr_t>(entity + offsets::BasePlayer::playerModel);
if (pm) {
  out.isVisible = Read<bool>(pm + offsets::PlayerModel::isVisible);
} else {
  out.isVisible = false;
}
```

### rust_offsets.h (PlayerModel::isVisible offset)
```cpp
namespace PlayerModel {
    inline int isVisible = 0x26C;     // NEW (bool)
    // ... other offsets
}
```

## 7. How It Works

1. **When vischeck is enabled**: 
   - PhysX scene is read from game memory via kernel driver
   - Triangle meshes are cached in a BVH (Bounding Volume Hierarchy)
   - For each player, raycast from local camera to 3 key bones (head, spine4, pelvis)
   - If any raycast hits nothing or only hits very close geometry, player is marked visible

2. **When vischeck is disabled**:
   - Falls back to Unity's `PlayerModel::isVisible` which only checks frustum culling
   - Much faster but less accurate (can't see through walls)

3. **Visual feedback**:
   - Visible players: GREEN names/skeleton
   - Not visible players: RED names/skeleton

## 8. Performance Notes

- PhysX actor cache refreshes every 5 seconds to keep geometry up-to-date
- Only 3 bones are checked per player (head, spine4, pelvis) for balance of accuracy vs performance
- BVH acceleration structure makes raycasts very fast
- Mutex-protected for thread safety when reading actor cache

## 9. Requirements

- PhysX system must be initialized (`g_PhysX.Init()`)
- Driver access for reading PhysX scene memory
- Bone data must be available (`player.bones`)
- Local player position for ray origin

This is the complete vischeck implementation from configuration to rendering.
