/*
 * aimbot_wrapper.h - Wrapper for BasePlayer and LocalPlayer classes
 * Uses Vec3/Vec2 from rust_sdk.h - no dependency on myMath.h
 */

#ifndef AIMBOT_WRAPPER_H
#define AIMBOT_WRAPPER_H

#include "rust_sdk.h"
#include <vector>


/* Bone list enum matching the bone IDs from earlier */
enum BoneList {
    head = 47,
    spine1 = 18,
    spine2 = 20,
    spine3 = 21,
    spine4 = 22,
    r_upperarm = 55,
    r_forearm = 56,
    r_hand = 57,
    l_upperarm = 24,
    l_forearm = 25,
    l_hand = 26,
    l_breast = 77,
    r_breast = 78,
    pelvis = 1,
    l_hip = 2,
    r_hip = 13,
    l_knee = 3,
    r_knee = 14,
    l_foot = 4,
    r_foot = 15
};

/* Vars namespace is defined in globals.h (inline variables) */

/* BasePlayer wrapper class */
class BasePlayer {
private:
    std::uintptr_t m_addr = 0;
    RustSDK* m_sdk = nullptr;
    Vec3 m_bones[85] = {};
    bool m_bonesValid = false;
    Vec3 m_velocity = {};
    bool m_velocityValid = false;
    uint32_t m_lifestate = 0;

    void UpdateBones() {
        if (!m_addr || !m_sdk) return;
        m_bonesValid = (m_sdk->GetBonePositions(m_addr, m_bones, 85) > 0);
    }

    void UpdateVelocity() {
        if (!m_sdk || !IsValidPtr(m_addr)) return;
        std::uintptr_t playerModel = m_sdk->ReadVal<std::uintptr_t>(m_addr + Offsets::BasePlayer::playerModel);
        if (IsValidPtr(playerModel)) {
            // Use new_velocity (0x21C) which is the smoothed/current velocity
            m_velocity = m_sdk->ReadVal<Vec3>(playerModel + Offsets::PlayerModel::new_velocity);
            // Fallback to velocity (0x204) if new_velocity is zero
            if (m_velocity.x == 0.f && m_velocity.y == 0.f && m_velocity.z == 0.f)
                m_velocity = m_sdk->ReadVal<Vec3>(playerModel + Offsets::PlayerModel::velocity);
            m_velocityValid = true;
        }
    }

public:
    BasePlayer() : m_sdk(nullptr) {}
    BasePlayer(std::uintptr_t addr, RustSDK* sdk) : m_addr(addr), m_sdk(sdk) {}

    void set_addr(std::uintptr_t addr) { m_addr = addr; m_bonesValid = false; m_velocityValid = false; }
    std::uintptr_t get_addr() const { return m_addr; }

    bool IsDead() {
        if (!m_sdk || !IsValidPtr(m_addr)) return true;
        if (m_lifestate == 0) {
            m_lifestate = m_sdk->ReadVal<uint32_t>(m_addr + Offsets::BaseCombatEntity::lifestate);
        }
        return m_lifestate != 0;
    }

    Vec3 GetBonePosition(BoneList bone) {
        if (!m_bonesValid) UpdateBones();
        int boneIdx = (int)bone;
        if (boneIdx >= 0 && boneIdx < 85 && m_bonesValid) {
            return m_bones[boneIdx];
        }
        return Vec3(0.0f, 0.0f, 0.0f);
    }

    Vec3 GetVelocity() {
        if (!m_velocityValid) UpdateVelocity();
        return m_velocity;
    }

    /* Prediction: iterative bullet-time solve with velocity lead + gravity compensation.
       Matches Rust projectile physics: drag decays speed, gravity pulls bullet down. */
    static Vec3 CalculatePrediction(const Vec3& localPos, const Vec3& targetPos, const Vec3& targetVelocity,
                                     float bulletSpeed, float drag = 0.001f, float gravityMod = 1.0f) {
        if (bulletSpeed < 1.0f) return targetPos;

        const float gravity = 9.81f * gravityMod;

        // Iterative solve: refine bullet travel time with gravity IN the loop
        Vec3 predicted = targetPos;
        float bulletTime = 0.0f;

        for (int iter = 0; iter < 4; iter++) {
            // Compute horizontal distance to predicted target (ignore Y for bullet time)
            float dx = predicted.x - localPos.x;
            float dz = predicted.z - localPos.z;
            float horizDist = sqrtf(dx * dx + dz * dz);
            if (horizDist < 0.01f) return targetPos;

            // Compute bullet travel time accounting for drag
            // For low drag (bullets): nearly constant speed, t ≈ dist / speed
            // For high drag (arrows): use exponential decay model
            if (drag > 0.01f) {
                // d(t) = (v0/drag) * (1 - e^(-drag*t)), solve iteratively
                float eDrag = (bulletTime > 0.001f) ? expf(-drag * bulletTime) : 0.0f;
                float avgSpeed = (bulletTime > 0.001f)
                    ? (bulletSpeed / drag) * (1.0f - eDrag) / bulletTime
                    : bulletSpeed;
                if (avgSpeed < 50.0f) avgSpeed = 50.0f;
                bulletTime = horizDist / avgSpeed;
            } else {
                // Negligible drag — simple distance / speed
                bulletTime = horizDist / bulletSpeed;
            }
            if (bulletTime > 2.0f) bulletTime = 2.0f;

            // Predict where the target will be after bulletTime
            predicted.x = targetPos.x + targetVelocity.x * bulletTime;
            predicted.y = targetPos.y + targetVelocity.y * bulletTime;
            predicted.z = targetPos.z + targetVelocity.z * bulletTime;

            // Gravity compensation inside the loop: aim higher by bullet drop amount
            // drop = 0.5 * g * t^2, so we raise aim point by that much
            float drop = 0.5f * gravity * bulletTime * bulletTime;
            predicted.y += drop;
        }

        return predicted;
    }
};

/* LocalPlayer wrapper class */
class LocalPlayer {
private:
    RustSDK* m_sdk = nullptr;
    std::uintptr_t m_addr = 0;
    Vec3 m_bones[85] = {};
    bool m_bonesValid = false;
    ViewMatrix m_viewMatrix = {};
    bool m_viewMatrixValid = false;

    void UpdateBones() {
        if (!m_addr || !m_sdk) return;
        m_bonesValid = (m_sdk->GetBonePositions(m_addr, m_bones, 85) > 0);
    }

    void UpdateViewMatrix() {
        if (!m_sdk) return;
        m_viewMatrixValid = m_sdk->GetViewMatrix(m_viewMatrix);
    }

public:
    void Update() {
        if (m_sdk) m_addr = m_sdk->GetLocalPlayer();
    }

    Vec2 GetBA() {  /* Body Angles / View Angles */
        Vec2 zero = { 0.0f, 0.0f };
        if (!m_sdk || !IsValidPtr(m_addr)) return zero;
        std::uintptr_t playerInput = m_sdk->ReadVal<std::uintptr_t>(m_addr + Offsets::BasePlayer::playerInput);
        if (!IsValidPtr(playerInput)) return zero;
        Vec3 angles = m_sdk->ReadVal<Vec3>(playerInput + Offsets::PlayerInput::bodyAngles);
        Vec2 result = { angles.x, angles.y };
        return result;
    }

    void SetBA(const Vec2& angles) {
        if (!m_sdk || !IsValidPtr(m_addr)) return;
        std::uintptr_t playerInput = m_sdk->ReadVal<std::uintptr_t>(m_addr + Offsets::BasePlayer::playerInput);
        if (!IsValidPtr(playerInput)) return;
        // Sanity: verify read-back angles are in valid range before writing
        Vec3 currentAngles = m_sdk->ReadVal<Vec3>(playerInput + Offsets::PlayerInput::bodyAngles);
        if (currentAngles.x < -90.f || currentAngles.x > 90.f ||
            currentAngles.y < -360.f || currentAngles.y > 360.f) return;
        Vec3 newAngles(angles.x, angles.y, currentAngles.z);
        m_sdk->WriteVal(playerInput + Offsets::PlayerInput::bodyAngles, newAngles);
    }

    void SetRA(const Vec2& recoilAngles) {  /* Recoil Angles - zero them */
        if (!m_sdk || !IsValidPtr(m_addr)) return;
        std::uintptr_t baseProjectile = m_sdk->GetActiveWeaponBaseProjectile(m_addr);
        if (!IsValidPtr(baseProjectile)) return;
        std::uintptr_t recoilProps = m_sdk->ReadVal<std::uintptr_t>(baseProjectile + Offsets::BaseProjectile::recoilProperties);
        if (!IsValidPtr(recoilProps)) return;
        float zero = 0.0f;
        m_sdk->WriteVal(recoilProps + Offsets::RecoilProperties::recoilYawMin, zero);
        m_sdk->WriteVal(recoilProps + Offsets::RecoilProperties::recoilYawMax, zero);
        m_sdk->WriteVal(recoilProps + Offsets::RecoilProperties::recoilPitchMin, zero);
        m_sdk->WriteVal(recoilProps + Offsets::RecoilProperties::recoilPitchMax, zero);
    }

    bool WorldToScreen(const Vec3& world, Vec2* screen) {
        if (!m_sdk) return false;
        if (!m_viewMatrixValid) UpdateViewMatrix();
        if (!m_viewMatrixValid) return false;
        
        Vec2 screenVec;
        bool ok = RustSDK::WorldToScreen(world, m_viewMatrix, 
            Vars::Config::ScreenWidth, Vars::Config::ScreenHigh, screenVec);
        if (ok && screen) {
            screen->x = screenVec.x;
            screen->y = screenVec.y;
        }
        return ok;
    }

    Vec3 GetBonePosition(BoneList bone) {
        if (!m_bonesValid) UpdateBones();
        int boneIdx = (int)bone;
        if (boneIdx >= 0 && boneIdx < 85 && m_bonesValid) {
            return m_bones[boneIdx];
        }
        return Vec3(0.0f, 0.0f, 0.0f);
    }

    class ActiveWeapon {
    private:
        RustSDK* m_sdk = nullptr;
        std::uintptr_t m_playerAddr = 0;
        std::uintptr_t m_weaponAddr = 0;
        uint32_t m_weaponId = 0;

        void UpdateWeapon() {
            if (!m_sdk || !m_playerAddr) return;
            m_weaponAddr = m_sdk->GetActiveWeaponBaseProjectile(m_playerAddr);
            if (m_weaponAddr) {
                std::uintptr_t item = m_sdk->ReadVal<std::uintptr_t>(m_weaponAddr - 0xD8);
                if (item) {
                    std::uintptr_t itemDef = m_sdk->ReadVal<std::uintptr_t>(item + Offsets::Item::itemDefinition);
                    if (itemDef) {
                        m_weaponId = 0;
                    }
                }
            }
        }

    public:
        ActiveWeapon(RustSDK* sdk, std::uintptr_t playerAddr) : m_sdk(sdk), m_playerAddr(playerAddr) {
            UpdateWeapon();
        }

        uint32_t GetID() {
            UpdateWeapon();
            return m_weaponId;
        }
    };

    ActiveWeapon* myActiveWeapon;

    LocalPlayer(RustSDK* sdk) : m_sdk(sdk), myActiveWeapon(nullptr) {
        if (sdk) {
            m_addr = sdk->GetLocalPlayer();
            if (m_addr) {
                myActiveWeapon = new ActiveWeapon(sdk, m_addr);
            }
        }
    }

    LocalPlayer() : m_sdk(nullptr), myActiveWeapon(nullptr), m_addr(0) {}

    ~LocalPlayer() {
        if (myActiveWeapon) {
            delete myActiveWeapon;
            myActiveWeapon = nullptr;
        }
    }

    LocalPlayer& operator=(const LocalPlayer& other) {
        if (this != &other) {
            if (myActiveWeapon) {
                delete myActiveWeapon;
                myActiveWeapon = nullptr;
            }
            m_sdk = other.m_sdk;
            m_addr = other.m_addr;
            m_bonesValid = false;
            m_viewMatrixValid = false;
            if (m_sdk && m_addr) {
                myActiveWeapon = new ActiveWeapon(m_sdk, m_addr);
            }
        }
        return *this;
    }
};

/* Global local player instance is defined in globals.h */

#endif // AIMBOT_WRAPPER_H
