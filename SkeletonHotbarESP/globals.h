#pragma once


#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

#include <d3d11.h>

#include "rust_sdk.h"

// ImGui headers
#include "imgui.h"

// global variables

inline RustSDK *g_SDK = nullptr;
inline ViewMatrix g_ViewMatrix = {};
inline int g_ScreenW = 0;
inline int g_ScreenH = 0;

//player cache

inline std::mutex g_DataMutex;
inline std::vector<PlayerData> g_cachedPlayers;

// esp state

inline bool g_espEnabled = true;
inline bool g_espHotbar = true;
inline int g_PlayerCount = 0;

//local player team ID (for friend/enemy coloring)

inline uint64_t g_LocalTeam = 0;

//fonts

inline ImFont *g_FontDefault = nullptr;
inline ImFont *g_FontESP = nullptr;

//item imes 

inline std::unordered_map<std::string, ID3D11ShaderResourceView *> g_ItemIcons;

//shutdwon flag

inline std::atomic<bool> g_ShutdownRequested(false);

// esp refresh rate (in ms) - 33ms = ~30fps, 16ms = ~60fps. adjust as needed, but keep in mind that lower values will increase CPU usage and may cause stuttering on lower-end systems.

inline const int g_espRefreshMs = 33;
