#include "globals.h"
#include <cmath>

// Convert Euler angles (pitch, yaw, roll) to Quaternion for
// PlayerEyes.bodyRotation
static Vec4 ToQuat(float pitch, float yaw, float roll) {
  const double pi = 3.14159265358979323846;
  double heading = pitch * (pi / 180.0);
  double attitude = yaw * (pi / 180.0);
  double bank = roll * (pi / 180.0);

  double c1 = cos(heading / 2.0);
  double s1 = sin(heading / 2.0);
  double c2 = cos(attitude / 2.0);
  double s2 = sin(attitude / 2.0);
  double c3 = cos(bank / 2.0);
  double s3 = sin(bank / 2.0);
  double c1c2 = c1 * c2;
  double s1s2 = s1 * s2;

  float qw = (float)(c1c2 * c3 - s1s2 * s3);
  float qx = (float)(c1c2 * s3 + s1s2 * c3);
  float qy = (float)(s1 * c2 * c3 + c1 * s2 * s3);
  float qz = (float)(c1 * s2 * c3 - s1 * c2 * s3);

  // Swizzle to match Rust's Unity coordinate system
  return Vec4(qy, qz, -qx, qw);
}

// Draw the FOV circle on screen so the user can see the aimbot range.
void DrawFOVCircle() {
  if (!Vars::Aim::enabled || !g_SDK || !g_SDK->IsAttached())
    return;

  ImDrawList *draw = ImGui::GetBackgroundDrawList();
  float cx = (float)(g_ScreenW / 2);
  float cy = (float)(g_ScreenH / 2);
  draw->AddCircle(ImVec2(cx, cy), Vars::Aim::fov, IM_COL32(255, 255, 255, 120),
                  64, 1.0f);
}

// Core aimbot logic: find the closest player inside the FOV circle,
// read their bone position, compute the aim angle, and write it back.
void RunAimbot() {
  if (!Vars::Aim::enabled || !g_SDK || !g_SDK->IsAttached())
    return;

  // Reset debug state each frame
  g_aimDbg = {};

  bool keyHeld = (GetAsyncKeyState(Vars::Aim::aimKey) & 0x8000) != 0;
  g_aimDbg.keyHeld = keyHeld;

  if (!keyHeld) {
    g_aimbotTarget = 0;
    return;
  }

  std::uintptr_t local = g_SDK->GetLocalPlayer();

  if (!local || g_ViewMatrix.m[3][3] == 0.0f) {
    g_aimbotTarget = 0;
    return;
  }

  float cx = (float)(g_ScreenW / 2);
  float cy = (float)(g_ScreenH / 2);

  // Target locking: if we already have a target, stick with it unless it's invalid
  std::uintptr_t bestTarget = 0;
  float bestScreenDist = Vars::Aim::fov;
  int bestBoneIdx = Vars::Aim::targetBone;
  int checked = 0, passedW2S = 0;

  // Check if current target is still valid
  if (g_aimbotTarget != 0) {
    bool targetValid = false;
    {
      std::lock_guard<std::mutex> lock(g_DataMutex);
      for (const auto &player : g_cachedPlayers) {
        if (player.address == g_aimbotTarget && player.address != local &&
            !player.isSleeping && player.lifestate == 0 &&
            (player.teamID == 0 || player.teamID != g_LocalTeam)) {
          
          // Get held entity from local player
          uintptr_t heldEntity = g_SDK->GetActiveWeaponBaseProjectile(local);
          if (!heldEntity) continue;
          
          // Try reading ammo velocity through magazine chain (direct from game)
          float ammoVelocity = 0.0f;
          std::string ammoShortName = g_SDK->GetAmmoShortName(heldEntity);
          
          uintptr_t magazine =
              g_SDK->ReadVal<uintptr_t>(heldEntity + offsets::BaseProjectile::primaryMagazine);
          if (magazine && IsValidPtr(magazine)) {
            uintptr_t ammoType =
                g_SDK->ReadVal<uintptr_t>(magazine + offsets::Magazine::ammoType);
            if (ammoType && IsValidPtr(ammoType)) {
              // ItemDefinition → itemMods array → find ItemModProjectile
              uintptr_t itemMods =
                  g_SDK->ReadVal<uintptr_t>(ammoType + offsets::ItemDefinition::itemMods);
              if (itemMods && IsValidPtr(itemMods)) {
                int modCount = g_SDK->ReadVal<int>(itemMods + 0x18);
                if (modCount > 0 && modCount <= 20) {
                  for (int i = 0; i < modCount; i++) {
                    uintptr_t mod = g_SDK->ReadVal<uintptr_t>(itemMods + 0x20 + i * 8);
                    if (!mod || !IsValidPtr(mod))
                      continue;
                    
                    // Check if this looks like ItemModProjectile by reading velocity
                    float vel = g_SDK->ReadVal<float>(
                        mod + offsets::ItemModProjectile::projectileVelocity);
                    if (vel > 10.0f && vel < 2000.0f) {
                      ammoVelocity = vel;
                      // Debug: log successful velocity reading
                      static int logCount = 0;
                      if (logCount++ < 5) {
                        printf("[VEL] Successfully read velocity %0.1f m/s for ammo '%s'\n", vel, ammoShortName.c_str());
                      }
                      break;
                    }
                  }
                }
              }
            }
          }
          
          // Check if target is still in FOV
          Vec3 aimWorldPos = player.headPos;
          if ((int)player.bones.size() > Vars::Aim::targetBone) {
            Vec3 b = player.bones[Vars::Aim::targetBone];
            if (b.x != 0)
              aimWorldPos = b;
          }

          Vec2 boneScreen;
          if (RustSDK::WorldToScreen(aimWorldPos, g_ViewMatrix, g_ScreenW,
                                     g_ScreenH, boneScreen)) {
            float dx = boneScreen.x - cx;
            float dy = boneScreen.y - cy;
            float screenDist = sqrtf(dx * dx + dy * dy);
            if (screenDist <= Vars::Aim::fov) {
              bestTarget = g_aimbotTarget;
              bestScreenDist = screenDist;
              targetValid = true;
              checked++;
              passedW2S++;
            }
          }
          break;
        }
      }
    }
    
    // If current target is still valid, keep it
    if (targetValid) {
      g_aimDbg.playersChecked = checked;
      g_aimDbg.playersPassedW2S = passedW2S;
      g_aimDbg.bestTarget = bestTarget;
      g_aimDbg.bestScreenDist = bestScreenDist;
    } else {
      // Target is invalid, clear it and find new one
      g_aimbotTarget = 0;
    }
  }

  // Only find new target if we don't have one
  if (g_aimbotTarget == 0) {
    {
      std::lock_guard<std::mutex> lock(g_DataMutex);

      // Multi-bone targets: Head(47), Neck(22), Chest(21), Pelvis(1)
      static const int multiBones[] = {47, 22, 21, 1};

      for (const auto &player : g_cachedPlayers) {
        if (player.address == local)
          continue;
        if (player.isSleeping || player.lifestate != 0)
          continue;
        if (player.teamID != 0 && player.teamID == g_LocalTeam)
          continue;
        checked++;

        // If multi-bone is enabled, scan all listed bones and pick the best one
        if (Vars::Aim::multiBone) {
          for (int boneID : multiBones) {
            Vec3 boneW = {};
            if ((int)player.bones.size() > boneID) {
              boneW = player.bones[boneID];
            }

            // Fallback to headPos if specific bone isn't in cache
            if (boneW.x == 0 && boneID == 47)
              boneW = player.headPos;
            if (boneW.x == 0)
              continue;

            Vec2 boneScreen;
            if (RustSDK::WorldToScreen(boneW, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                       boneScreen)) {
              float dx = boneScreen.x - cx;
              float dy = boneScreen.y - cy;
              float screenDist = sqrtf(dx * dx + dy * dy);

              if (screenDist < bestScreenDist) {
                bestScreenDist = screenDist;
                bestTarget = player.address;
                bestBoneIdx = boneID;
              }
            }
          }
        } else {
          // Single-bone logic
          int targetID = Vars::Aim::targetBone;
          Vec3 aimWorldPos = player.headPos; // Default fallback
          if ((int)player.bones.size() > targetID) {
            Vec3 b = player.bones[targetID];
            if (b.x != 0)
              aimWorldPos = b;
          }

          Vec2 boneScreen;
          if (RustSDK::WorldToScreen(aimWorldPos, g_ViewMatrix, g_ScreenW,
                                     g_ScreenH, boneScreen)) {
            passedW2S++;
            float dx = boneScreen.x - cx;
            float dy = boneScreen.y - cy;
            float screenDist = sqrtf(dx * dx + dy * dy);

            if (screenDist < bestScreenDist) {
              bestScreenDist = screenDist;
              bestTarget = player.address;
              bestBoneIdx = targetID;
            }
          }
        }
      }
    }
  }

  g_aimDbg.playersChecked = checked;
  g_aimDbg.playersPassedW2S = passedW2S;
  g_aimDbg.bestTarget = bestTarget;
  g_aimDbg.bestScreenDist = bestScreenDist;

  if (!bestTarget) {
    g_aimbotTarget = 0;
    return;
  }

  g_aimbotTarget = bestTarget;

  // Read the target's bone position (rate-limited to reduce driver spam)
  static ULONGLONG lastAimRead = 0;
  static Vec3 cachedBonePos = {};
  static std::uintptr_t cachedAimTarget = 0;
  ULONGLONG aimNow = GetTickCount64();

  if (bestTarget != cachedAimTarget || aimNow - lastAimRead >= 2) {
    BasePlayer bp(bestTarget, g_SDK);
    BoneList aimBone = (BoneList)bestBoneIdx;

    Vec3 readPos = bp.GetBonePosition(aimBone);

    // Fallback: use cached player bones if live reading fails
    if (readPos.x == 0.0f) {
      std::lock_guard<std::mutex> lock(g_DataMutex);
      for (const auto &p : g_cachedPlayers) {
        if (p.address == bestTarget) {
          if ((int)p.bones.size() > bestBoneIdx)
            readPos = p.bones[bestBoneIdx];
          if (readPos.x == 0)
            readPos = p.headPos;
          break;
        }
      }
    }

    // Only cache valid positions
    if (readPos.x != 0.0f)
      cachedBonePos = readPos;

    cachedAimTarget = bestTarget;
    lastAimRead = aimNow;
  }

  Vec3 bonePos = cachedBonePos;
  g_aimDbg.bonePos = bonePos;

  // Invalid bone -> give up this frame
  if (bonePos.x == 0.0f && bonePos.y == 0.0f && bonePos.z == 0.0f) {
    g_aimbotTarget = 0;
    return;
  }

  Vec3 camPos = g_SDK->GetCameraPosition();

  // Optional prediction (uses actual weapon bullet speed)
  static bool usePrediction = false;
  usePrediction = cfg->get<checkbox_t>("Aimbot Prediction").enabled;
  if (usePrediction) {
    // ── Velocity estimation with smoothing ──
    // Uses target BASE position (feet) for delta, not bone (avoids animation
    // noise)
    static std::uintptr_t velCacheTarget = 0;
    static Vec3 velSmoothed = {};
    static Vec3 prevBasePos = {};
    static ULONGLONG prevPosTick = 0;
    static bool hasPrevPos = false;

    // If target changed, reset velocity cache
    if (bestTarget != velCacheTarget) {
      velSmoothed = {};
      prevBasePos = {};
      prevPosTick = 0;
      hasPrevPos = false;
      velCacheTarget = bestTarget;
    }

    // Get target's base position from cached player data (smooth, no anim
    // noise)
    Vec3 targetBasePos = {};
    {
      std::lock_guard<std::mutex> lock(g_DataMutex);
      for (const auto &p : g_cachedPlayers) {
        if (p.address == bestTarget) {
          targetBasePos = p.position;
          break;
        }
      }
    }

    // Try reading velocity from PlayerModel memory
    BasePlayer enemy(bestTarget, g_SDK);
    Vec3 velocity = enemy.GetVelocity();
    bool gotMemoryVel =
        !(velocity.x == 0.f && velocity.y == 0.f && velocity.z == 0.f);

    // If memory read returned zero, estimate from base position delta
    if (!gotMemoryVel && hasPrevPos) {
      float dx = targetBasePos.x - prevBasePos.x;
      float dy = targetBasePos.y - prevBasePos.y;
      float dz = targetBasePos.z - prevBasePos.z;
      float posDelta = sqrtf(dx * dx + dy * dy + dz * dz);

      // Only compute delta if position actually changed (avoid zero on stale
      // frames)
      if (posDelta > 0.01f) {
        ULONGLONG dtMs = aimNow - prevPosTick;
        if (dtMs > 0 && dtMs < 500) {
          float dt = (float)dtMs / 1000.0f;
          velocity.x = dx / dt;
          velocity.y = dy / dt;
          velocity.z = dz / dt;
        }
      }
    }

    // Only update prev position when base position genuinely changed
    if (!hasPrevPos || sqrtf((targetBasePos.x - prevBasePos.x) *
                                 (targetBasePos.x - prevBasePos.x) +
                             (targetBasePos.y - prevBasePos.y) *
                                 (targetBasePos.y - prevBasePos.y) +
                             (targetBasePos.z - prevBasePos.z) *
                                 (targetBasePos.z - prevBasePos.z)) > 0.01f) {
      prevBasePos = targetBasePos;
      prevPosTick = aimNow;
      hasPrevPos = true;
    }

    // Clamp insane velocity values (Rust: sprint ~5.5 m/s, horse ~14 m/s)
    float velMag = sqrtf(velocity.x * velocity.x + velocity.y * velocity.y +
                         velocity.z * velocity.z);
    if (velMag > 15.0f) {
      float scale = 15.0f / velMag;
      velocity.x *= scale;
      velocity.y *= scale;
      velocity.z *= scale;
    }

    // Distance to target (used for adaptive smoothing)
    float dx3 = bonePos.x - camPos.x;
    float dy3 = bonePos.y - camPos.y;
    float dz3 = bonePos.z - camPos.z;
    float targetDist = sqrtf(dx3 * dx3 + dy3 * dy3 + dz3 * dz3);

    // Adaptive velocity smoothing — close targets need fast response
    // At <20m: lerp ~0.9 (near-instant), at >100m: lerp ~0.4 (smooth)
    bool hasVelocityData =
        (velocity.x != 0.f || velocity.y != 0.f || velocity.z != 0.f);
    if (hasVelocityData) {
      float distFactor = targetDist / 100.0f; // 0 at point blank, 1 at 100m
      if (distFactor > 1.0f)
        distFactor = 1.0f;
      float lerpFactor = 0.9f - distFactor * 0.5f; // 0.9 close, 0.4 far
      velSmoothed.x += (velocity.x - velSmoothed.x) * lerpFactor;
      velSmoothed.y += (velocity.y - velSmoothed.y) * lerpFactor;
      velSmoothed.z += (velocity.z - velSmoothed.z) * lerpFactor;
    }
    // Slowly decay smoothed velocity if no data for a while (target stopped)
    else if (hasPrevPos && (aimNow - prevPosTick) > 200) {
      velSmoothed.x *= 0.9f;
      velSmoothed.y *= 0.9f;
      velSmoothed.z *= 0.9f;
    }

    // Read actual bullet speed, drag, and gravity from held weapon
    float bulletSpeed = 375.0f;
    float drag = 0.001f;
    float gravMod = 1.0f;
    uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(local);
    if (weapon) {
      bulletSpeed = g_SDK->GetWeaponBulletSpeed(weapon);
      drag = g_SDK->GetWeaponDrag(weapon);
      gravMod = g_SDK->GetWeaponGravity(weapon);
    }

    bonePos = BasePlayer::CalculatePrediction(camPos, bonePos, velSmoothed,
                                              bulletSpeed, drag, gravMod);
  }

  // Compute the angle from camera to target
  Vec3 delta = bonePos - camPos;
  float dist = delta.Length();
  if (dist < 0.001f)
    return;

  float pitch = -asinf(delta.y / dist) * (180.0f / 3.14159265f);
  float yaw = atan2f(delta.x, delta.z) * (180.0f / 3.14159265f);

  Vec2 curAngles = myLocalPlayer.GetBA();

  g_aimDbg.aimAngles = Vec3(pitch, yaw, 0);
  g_aimDbg.curAngles = Vec3(curAngles.x, curAngles.y, 0);

  // Normal aimbot: smooth interpolation toward the target angle
  // Cubic curve: 0.1 = rage (snaps ~73%/frame), 0.7+ = human-like (~2.7%/frame)
  float s = Vars::Aim::smooth;
  if (s < 0.0f)
    s = 0.0f;
  if (s > 1.0f)
    s = 1.0f;
  float smoothFactor = (1.0f - s) * (1.0f - s) * (1.0f - s); // cubic falloff
  if (smoothFactor < 0.005f)
    smoothFactor = 0.005f;

  // Boost smooth factor for close targets so aimbot keeps up with fast angular
  // movement dist is already computed above
  if (dist < 50.0f) {
    float closeBoost =
        1.0f + (50.0f - dist) / 50.0f * 2.0f; // up to 3x at point blank
    smoothFactor *= closeBoost;
    if (smoothFactor > 1.0f)
      smoothFactor = 1.0f;
  }

  float dpitch = pitch - curAngles.x;
  float dyaw = yaw - curAngles.y;
  while (dyaw > 180.0f)
    dyaw -= 360.0f;
  while (dyaw < -180.0f)
    dyaw += 360.0f;

  Vec2 newAngles;
  newAngles.x = curAngles.x + dpitch * smoothFactor;
  newAngles.y = curAngles.y + dyaw * smoothFactor;
  if (newAngles.x > 89.0f)
    newAngles.x = 89.0f;
  if (newAngles.x < -89.0f)
    newAngles.x = -89.0f;

  g_aimDbg.writeAttempted = true;

  // Silent aim: directly set body rotation instead of input angles
  if (Vars::Aim::silentAim && g_SDK && g_SDK->IsAttached()) {
    uintptr_t localPlayer = g_SDK->GetLocalPlayer();
    if (localPlayer) {
      Vec3 aimAngles(pitch, yaw, 0);
      g_SDK->SetBodyRotation(localPlayer, aimAngles);
    }
  } else {
    // Normal aimbot: use input angles
    myLocalPlayer.SetBA(newAngles);
  }
}
