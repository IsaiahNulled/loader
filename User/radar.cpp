#include "globals.h"

static ImVec2 CalcRadarPoint(const Vec3& targetPos, const Vec3& localPos,
                              float localYaw, float radarRadius, float radarRange)
{
    float dx = targetPos.x - localPos.x;
    float dz = targetPos.z - localPos.z;

    float yawRad = localYaw * (3.14159265f / 180.0f);
    float cosYaw = cosf(yawRad);
    float sinYaw = sinf(yawRad);

    float rx = dz * sinYaw - dx * cosYaw;
    float rz = dz * cosYaw + dx * sinYaw;

    // Circular clamping
    float dist = sqrtf(rx * rx + rz * rz);
    if (dist > radarRange) {
        float f = radarRange / dist;
        rx *= f;
        rz *= f;
    }

    // Map to screen pixels: (value / range) * radius
    float scale = radarRadius / radarRange;
    return ImVec2(rx * scale, rz * scale);
}

void DrawRadar(const Vec3& localPos, float localYaw)
{
    if (!g_espRadar) return;

    ImGui::SetNextWindowPos(ImVec2(20, 100), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(220, 220), ImGuiCond_FirstUseEver);

    if (!ImGui::Begin("Radar", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize   | ImGuiWindowFlags_NoBackground))
    {
        ImGui::End();
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 winPos = ImGui::GetWindowPos();
    ImVec2 winSize = ImGui::GetWindowSize();
    ImVec2 center(winPos.x + winSize.x * 0.5f, winPos.y + winSize.y * 0.5f);
    float radius = winSize.x * 0.5f - 5.0f; // Padding

    // Circular Background (Black, ~35% Opacity -> 90/255)
    draw->AddCircleFilled(center, radius, IM_COL32(0, 0, 0, 90), 64);
    draw->AddCircle(center, radius, IM_COL32(255, 255, 255, 60), 64, 1.0f); // Outline

    // Vision Cone (approx 90 deg)
    // Local player is always center, facing UP (because we rotate the world)
    // Draw a filled arc/sector from -45 to +45 degrees
    draw->PathLineTo(center);
    draw->PathArcTo(center, radius, -3.14159f/2.0f - 0.785f, -3.14159f/2.0f + 0.785f, 32);
    draw->PathFillConvex(IM_COL32(255, 255, 255, 15));

    // Grid lines (50m, 75m, 100m)
    const float radarRange = 150.0f;
    float scaleConfig[] = { 50.0f, 75.0f, 100.0f };

    for (float dist : scaleConfig) {
        if (dist >= radarRange) continue;
        float r = (dist / radarRange) * radius;
        draw->AddCircle(center, r, IM_COL32(255, 255, 255, 30), 48, 1.0f);
        
        // Small text label
        char buf[16]; snprintf(buf, 16, "%.0fm", dist);
        ImVec2 ts = ImGui::CalcTextSize(buf);
        // Draw label to the right of the ring
        draw->AddText(ImVec2(center.x + r + 2, center.y - ts.y / 2), IM_COL32(255, 255, 255, 150), buf);
    }

    // Crosshairs (faint)
    draw->AddLine(ImVec2(center.x - radius, center.y), ImVec2(center.x + radius, center.y), IM_COL32(255, 255, 255, 20));
    draw->AddLine(ImVec2(center.x, center.y - radius), ImVec2(center.x, center.y + radius), IM_COL32(255, 255, 255, 20));

    // Player dots
    {
        std::lock_guard<std::mutex> lock(g_DataMutex);
        for (const auto& player : g_cachedPlayers)
        {
            if (player.address == g_SDK->GetLocalPlayer()) continue;
            if (player.isSleeping && !g_espShowSleepers) continue;

            ImVec2 rel = CalcRadarPoint(player.position, localPos, localYaw, radius, radarRange);
            ImVec2 p(center.x + rel.x, center.y - rel.y);

            ImU32 col = COL_ENEMY;
            if (player.teamID != 0 && player.teamID == g_LocalTeam) col = COL_TEAM;

            // Small dot (radius 2.5) with outline
            draw->AddCircleFilled(p, 2.5f, col);
            if (player.isVisible)
                draw->AddCircle(p, 3.5f, IM_COL32(255, 255, 255, 200), 12, 1.0f);
        }
    }

    // Self marker (center triangle)
    // Pointing up because radar rotates the world around us
    draw->AddTriangleFilled(
        ImVec2(center.x, center.y - 4),
        ImVec2(center.x - 3, center.y + 3),
        ImVec2(center.x + 3, center.y + 3),
        IM_COL32(255, 255, 255, 255));

    ImGui::End();
}

void RenderFOVArrows(const Vec3& localPos, float localYaw)
{
    if (!g_espFOVArrows) return;

    ImDrawList* draw = ImGui::GetForegroundDrawList();
    ImVec2 center(g_ScreenW / 2.0f, g_ScreenH / 2.0f);
    float radius = 150.0f;

    std::lock_guard<std::mutex> lock(g_DataMutex);
    for (const auto& player : g_cachedPlayers)
    {
        if (player.address == g_SDK->GetLocalPlayer()) continue;
        if (player.isSleeping || player.lifestate != 0) continue;

        Vec2 screen;
        if (RustSDK::WorldToScreen(player.position, g_ViewMatrix, g_ScreenW, g_ScreenH, screen))
            continue;   // already visible on screen

        float angle = atan2f(player.position.z - localPos.z,
                             player.position.x - localPos.x);
        float yawRad = localYaw * (3.14159265f / 180.0f);
        float relAngle = angle + yawRad - (3.14159265f / 2.0f);

        ImVec2 arrowPos(center.x + cosf(relAngle) * radius,
                        center.y - sinf(relAngle) * radius);

        float sz = 10.0f;
        ImVec2 p1(arrowPos.x + cosf(relAngle)        * sz,
                  arrowPos.y - sinf(relAngle)        * sz);
        ImVec2 p2(arrowPos.x + cosf(relAngle + 2.0f) * sz,
                  arrowPos.y - sinf(relAngle + 2.0f) * sz);
        ImVec2 p3(arrowPos.x + cosf(relAngle - 2.0f) * sz,
                  arrowPos.y - sinf(relAngle - 2.0f) * sz);

        draw->AddTriangleFilled(p1, p2, p3, COL_ENEMY);
    }
}
