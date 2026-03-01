
#include "globals.h"

// fill player cache

void FillPlayerCache(std::vector<PlayerData> &buffer) {
  buffer.clear();
  if (!g_SDK || !g_SDK->IsAttached())
    return;
  if (!g_SDK->RefreshEntityList())
    return;

  Vec3 camPos = g_SDK->GetCameraPosition();
  uintptr_t localPlayer = g_SDK->GetLocalPlayer();
  int count = g_SDK->GetEntityCount();

  for (int i = 0; i < count; i++) {
    uintptr_t entity = g_SDK->GetEntity(i);
    if (!IsValidPtr(entity))
      continue;

    PlayerData player = {};
    player.address = entity;

    Vec3 pos, headPos;
    uint32_t lifestate = 0;
    if (!g_SDK->ReadPlayerPositionAndLifestate(entity, pos, headPos, lifestate))
      continue;
    if (lifestate != 0)
      continue; // only alive players

    player.position = pos;
    player.headPos = headPos;
    player.lifestate = lifestate;

    float distance = (pos - camPos).Length();
    player.distance = distance;
    if (distance > 500.f)
      continue;

    if (!g_SDK->ReadPlayerDetails(entity, player))
      continue;

    bool isLocal = (entity == localPlayer);

    // reads hotbar/clothing
    if (!isLocal && distance < 100.0f) {
      player.hotbarItems = g_SDK->ReadHotbarItems(entity);
      player.wearItems = g_SDK->ReadWearItems(entity);
    }

    // Track local team
    if (isLocal && player.teamID != 0)
      g_LocalTeam = player.teamID;

    buffer.push_back(player);
  }
}

//worker thread

void WorkerThreadRoutine() {
  printf("[Worker] Thread started\n");
  std::vector<PlayerData> backBuffer;

  while (!g_ShutdownRequested.load()) {
    FillPlayerCache(backBuffer);

	// swap back buffer with main thread
    {
      std::lock_guard<std::mutex> lock(g_DataMutex);
      g_cachedPlayers = backBuffer;
    }

    Sleep(g_espRefreshMs);
  }
  printf("[Worker] Thread exiting\n");
}

// checks if game is focused

static bool IsGameInFocus() {
  HWND fg = GetForegroundWindow();
  if (!fg)
    return false;
  DWORD fgPid = 0;
  GetWindowThreadProcessId(fg, &fgPid);
  return (g_SDK && fgPid == g_SDK->GetPID());
}

//main hotbar esp rendering

void RenderHotbarESP() {
  if (!g_SDK || !g_SDK->IsAttached())
    return;
  if (!g_espEnabled || !g_espHotbar)
    return;
  if (!IsGameInFocus())
    return;

  if (!g_SDK->GetViewMatrix(g_ViewMatrix))
    return;

  ImDrawList *draw = ImGui::GetForegroundDrawList();

  // watermark
  {
    float fps = ImGui::GetIO().Framerate;
    char fpsBuf[64];
    snprintf(fpsBuf, sizeof(fpsBuf), "  |  FPS: %.0f", fps);
    const char *title = "skidmarked isaiah";
    ImVec2 titleSize = ImGui::CalcTextSize(title);
    ImVec2 fpsSize = ImGui::CalcTextSize(fpsBuf);
    float totalW = titleSize.x + fpsSize.x + 16.f;
    draw->AddRectFilled(ImVec2(5, 5),
                        ImVec2(5 + totalW + 8, 5 + titleSize.y + 6),
                        IM_COL32(0, 0, 0, 220), 4.0f);
    draw->AddText(ImVec2(9, 8), IM_COL32(255, 255, 255, 255), title);
    draw->AddText(ImVec2(9 + titleSize.x, 8), IM_COL32(180, 180, 180, 255),
                  fpsBuf);
  }

  // snapshot player cache for rendering
  std::vector<PlayerData> renderPlayers;
  {
    std::lock_guard<std::mutex> lock(g_DataMutex);
    renderPlayers = g_cachedPlayers;
  }

  // finds closest player with hotbar items os
  float scrCX = (float)(g_ScreenW / 2);
  float scrCY = (float)(g_ScreenH / 2);
  float bestDist = 400.f; // screen pixel radius
  const PlayerData *hotbarTarget = nullptr;

  for (const auto &p : renderPlayers) {
    if (p.hotbarItems.empty() && p.wearItems.empty())
      continue;
    if (p.address == g_SDK->GetLocalPlayer())
      continue;
    Vec2 hs;
    if (!RustSDK::WorldToScreen(p.headPos, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                hs))
      continue;
    float d = sqrtf((hs.x - scrCX) * (hs.x - scrCX) +
                    (hs.y - scrCY) * (hs.y - scrCY));
    if (d < bestDist) {
      bestDist = d;
      hotbarTarget = &p;
    }
  }

  if (!hotbarTarget) {
    g_PlayerCount = (int)renderPlayers.size();
    return;
  }

  if (g_FontESP)
    ImGui::PushFont(g_FontESP);

  // helps to draw item slots
  auto drawItemRow = [&](const std::vector<std::string> &items, int maxSlots,
                         float slotSize, float slotPad, float panelX,
                         float panelY, float panelW, float panelH,
                         float rounding) {
    draw->AddRectFilled(ImVec2(panelX, panelY),
                        ImVec2(panelX + panelW, panelY + panelH),
                        IM_COL32(30, 30, 30, 160), rounding);
    draw->AddRect(ImVec2(panelX, panelY),
                  ImVec2(panelX + panelW, panelY + panelH),
                  IM_COL32(80, 80, 80, 100), rounding);

    int count = (int)items.size();
    if (count > maxSlots)
      count = maxSlots;
    float innerPad = 6.f;
    float slotsStartX = panelX + innerPad;
    float slotsStartY = panelY + innerPad;

    for (int s = 0; s < count; s++) {
      float sx = slotsStartX + s * (slotSize + slotPad);
      float sy = slotsStartY;

      draw->AddRectFilled(ImVec2(sx, sy), ImVec2(sx + slotSize, sy + slotSize),
                          IM_COL32(40, 40, 40, 180), 4.f);
      draw->AddRect(ImVec2(sx, sy), ImVec2(sx + slotSize, sy + slotSize),
                    IM_COL32(90, 90, 90, 120), 4.f);

      if (!items[s].empty()) {
        const std::string &sn = items[s];

		// try to find icon for shortname
        auto iconIt = g_ItemIcons.find(sn);
        if (iconIt != g_ItemIcons.end() && iconIt->second) {
          float ip = 3.f;
          draw->AddImage((ImTextureID)iconIt->second, ImVec2(sx + ip, sy + ip),
                         ImVec2(sx + slotSize - ip, sy + slotSize - ip));
        } else {
          // fallback to shortname
          std::string abbr = sn;
          size_t dot = abbr.find('.');
          if (dot != std::string::npos)
            abbr = abbr.substr(dot + 1);
          if (abbr.length() > 6)
            abbr = abbr.substr(0, 6);
          ImVec2 ts = ImGui::CalcTextSize(abbr.c_str());
          draw->AddText(ImVec2(sx + (slotSize - ts.x) * 0.5f,
                               sy + (slotSize - ts.y) * 0.5f),
                        IM_COL32(200, 200, 200, 220), abbr.c_str());
        }

        const char *countLabel = "x1";
        ImVec2 cs = ImGui::CalcTextSize(countLabel);
        float cx = sx + (slotSize - cs.x) * 0.5f;
        float cy = sy + slotSize - cs.y - 1.f;
        draw->AddText(ImVec2(cx + 1, cy + 1), IM_COL32(0, 0, 0, 180),
                      countLabel);
        draw->AddText(ImVec2(cx, cy), IM_COL32(255, 255, 255, 220), countLabel);
      }
    }
  };

  // layout calculations
  const auto &beltItems = hotbarTarget->hotbarItems;
  const auto &wearItems = hotbarTarget->wearItems;

  const float hotbarSlotSize = 48.f;
  const float hotbarSlotPad = 4.f;
  const float wearSlotSize = 52.f;
  const float wearSlotPad = 4.f;
  const float panelPad = 12.f;
  const float panelRound = 8.f;
  const float rowGap = 6.f;

  int beltCount = (int)beltItems.size();
  if (beltCount > 6)
    beltCount = 6;
  int wearCount = (int)wearItems.size();
  if (wearCount > 7)
    wearCount = 7;

  float hotbarPanelW = beltCount > 0
                           ? (beltCount * hotbarSlotSize +
                              (beltCount - 1) * hotbarSlotPad + panelPad)
                           : 0;
  float hotbarPanelH = beltCount > 0 ? (hotbarSlotSize + panelPad) : 0;
  float wearPanelW = wearCount > 0 ? (wearCount * wearSlotSize +
                                      (wearCount - 1) * wearSlotPad + panelPad)
                                   : 0;
  float wearPanelH = wearCount > 0 ? (wearSlotSize + panelPad) : 0;

  float baseY = 32.f;

  // player name label
  char nameBuf[128] = {};
  WideCharToMultiByte(CP_UTF8, 0, hotbarTarget->name.c_str(), -1, nameBuf,
                      sizeof(nameBuf), nullptr, nullptr);

  ImVec2 nameSize = ImGui::CalcTextSize(nameBuf);
  float namePillW = nameSize.x + 16.f;
  float namePillH = nameSize.y + 8.f;
  float namePillX = scrCX - namePillW * 0.5f;
  float namePillY = baseY;

  draw->AddRectFilled(ImVec2(namePillX, namePillY),
                      ImVec2(namePillX + namePillW, namePillY + namePillH),
                      IM_COL32(30, 30, 30, 180), namePillH * 0.5f);
  draw->AddRect(ImVec2(namePillX, namePillY),
                ImVec2(namePillX + namePillW, namePillY + namePillH),
                IM_COL32(100, 100, 100, 100), namePillH * 0.5f);
  draw->AddText(ImVec2(scrCX - nameSize.x * 0.5f, namePillY + 4.f),
                IM_COL32(255, 255, 255, 255), nameBuf);

  float currentY = namePillY + namePillH + rowGap;

  // hotbar row
  if (beltCount > 0) {
    float px = scrCX - hotbarPanelW * 0.5f;
    drawItemRow(beltItems, 6, hotbarSlotSize, hotbarSlotPad, px, currentY,
                hotbarPanelW, hotbarPanelH, panelRound);
    currentY += hotbarPanelH + rowGap;
  }

  // clothing row
  if (wearCount > 0) {
    float px = scrCX - wearPanelW * 0.5f;
    drawItemRow(wearItems, 7, wearSlotSize, wearSlotPad, px, currentY,
                wearPanelW, wearPanelH, panelRound);
  }

  if (g_FontESP)
    ImGui::PopFont();

  g_PlayerCount = (int)renderPlayers.size();
}
