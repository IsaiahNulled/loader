#pragma once
#include <windows.h>
/*
 * globals.h
 * Shared state, config variables, and forward declarations used across all
 * modules.
 */

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mmsystem.h>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <tlhelp32.h>
#include <unordered_map>
#include <vector>

#include <d3d11.h>

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui/backends/imgui_impl_dx11.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "winmm.lib")

#include "driver_comm.h"
#include "font.h"
#include "icon.h"
#include "rust_sdk.h"
#include "framework/helpers/hotbar_downloader.h"

// ── Aimbot / Config Variables (must be before aimbot_wrapper.h) ───

namespace Vars {
namespace Aim {
inline float fov = 100.0f;
inline float smooth = 0.5f;
inline bool randomBone = false;
inline bool enabled = true;
inline bool silentAim = false; // Silent aim - directly sets body rotation
inline int targetBone = 47;    // head
inline int aimKey = VK_RBUTTON;
inline bool multiBone = true;
inline int multiBoneMode = 0; // 0=Closest to crosshair, 1=Sequence
} // namespace Aim
namespace Config {
inline int ScreenWidth = 1920;
inline int ScreenHigh = 1080;
} // namespace Config
} // namespace Vars

#include "aimbot_wrapper.h"

#include "framework/headers/config.h"
#include "framework/headers/includes.h"
#include "framework/headers/widgets.h"

// ── Application State ──────────────────────────────────────────────

inline HWND g_hWnd = nullptr;
inline int g_ScreenW = 0;
inline int g_ScreenH = 0;

// DirectX 11
inline ID3D11Device *g_pd3dDevice = nullptr;
inline ID3D11DeviceContext *g_pd3dContext = nullptr;
inline IDXGISwapChain *g_pSwapChain = nullptr;
inline ID3D11RenderTargetView *g_pRenderTargetView = nullptr;

// Driver & SDK
inline DriverComm g_Driver;
inline RustSDK *g_SDK = nullptr;

// PhysX scene (for visibility checks)
#include "physx.hpp"
inline PhysXScene g_PhysX;

// Subscription expiry (Unix timestamp, passed from Loader via --expiry arg)
inline long long g_SubExpiry = 0;

// Menu / overlay
inline bool g_ShowMenu = true;
inline bool g_Running = true;
inline bool g_overlayHidden = true;
inline int g_fpsCap = 0;        // 0 = uncapped
inline bool g_ShowDebug = true; // F2 toggles debug overlay

// Fonts
inline ImFont *g_FontDefault = nullptr;
inline ImFont *g_FontESP = nullptr;
inline ImFont *g_FontLogo = nullptr;
inline ImFont *g_FontMedium = nullptr;
inline ImFont *g_FontIcon = nullptr;
inline int g_MenuTab = 0;
inline std::vector<unsigned char> g_CustomFont;

// Skeleton
inline float g_espSkeletonThickness = 1.2f;

// ESP flags
inline bool g_espEnabled = true;
inline bool g_espBoxes = true;
inline bool g_espNames = true;
inline bool g_espDistance = true;
inline bool g_espSnaplines = false;
inline bool g_espHealthBar = false;
inline bool g_espSkeleton = true;
inline bool g_espVisCheck = false;
inline bool g_espShowSleepers = false;
inline bool g_espShowWounded = true;
inline bool g_espRadar = false;
inline bool g_espFOVArrows = false;
inline bool g_espHotbar = false;
inline bool g_espAnimal = false; // master animal toggle
inline bool g_espBear = true;
inline bool g_espPolarBear = true;
inline bool g_espWolf = true;
inline bool g_espBoar = true;
inline bool g_espChicken = true;
inline bool g_espHorse = true;
inline bool g_espStag = true;
inline bool g_espShark = true;
inline bool g_espDeployable = false;
inline bool g_espOre = false;
inline bool g_espHemp = false;
inline bool g_espDroppedItem = false;

// Per-ESP distance limits (0 = unlimited)
inline float g_espPlayerMaxDist = 500.0f;
inline float g_espAnimalMaxDist = 400.0f;
inline float g_espOreMaxDist = 300.0f;
inline float g_espHempMaxDist = 200.0f;
inline float g_espDropMaxDist = 150.0f;
inline float g_espDeployMaxDist = 300.0f;

// Per-ESP colors (RGBA 0-1)
inline ImVec4 g_espPlayerColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
inline ImVec4 g_espAnimalColor = ImVec4(0.8f, 0.5f, 0.2f, 1.0f);
inline ImVec4 g_espOreColor = ImVec4(0.2f, 0.8f, 1.0f, 1.0f);
inline ImVec4 g_espHempColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
inline ImVec4 g_espDropColor = ImVec4(1.0f, 1.0f, 0.3f, 1.0f);
inline ImVec4 g_espDeployColor = ImVec4(1.0f, 0.6f, 0.0f, 1.0f);

// Misc features
inline bool g_noRecoilEnabled = false;
inline float g_recoilControl =
    100.0f; // % reduction: 100 = zero recoil, 50 = half, 0 = none

// Time & Visual controls
inline bool g_timeChangerEnabled = false;
inline float g_timeHour = 12.0f;  // 12:00 noon
inline bool g_brightnessEnabled = false;
inline float g_brightnessIntensity = 1.0f;
inline bool g_skyColorEnabled = false;
inline float g_skyColorR = 0.5f, g_skyColorG = 0.8f, g_skyColorB = 1.0f;
inline bool g_nightSkyColorEnabled = false;
inline float g_nightSkyColorR = 0.1f, g_nightSkyColorG = 0.1f, g_nightSkyColorB = 0.3f;

// Legacy compatibility (mapping to new variables)
inline bool& g_brightNight = g_brightnessEnabled;
inline float& g_brightNightIntensity = g_brightnessIntensity;
inline bool& g_timeChanger = g_timeChangerEnabled;
inline bool g_noRecoilHasLocal = false;
inline bool g_noRecoilHasWeapon = false;

// Movement exploits
inline bool g_spiderman = false;

// Terrain remover
inline bool g_terrainRemover = false;

// Server join grace period: delay all WRITE operations for 10s after joining
// to let game structures fully initialize (prevents crash on server load)
inline ULONGLONG g_ServerJoinTick = 0;
constexpr ULONGLONG SERVER_LOAD_GRACE_MS = 5000; // 5 seconds
inline bool IsServerReady() {
  if (g_ServerJoinTick == 0) return false; // never joined
  return (GetTickCount64() - g_ServerJoinTick) >= SERVER_LOAD_GRACE_MS;
}

// Weapon modifiers
inline bool g_instaEoka = false;
inline bool g_noSpread = false;
inline float g_spreadScale = 0.0f; // 0% = no spread, 100% = original spread
inline bool g_reloadBar = false;

// Process hiding
inline bool g_hideUserExe = false;
inline bool g_hideLoaderExe = false;

// Reload bar state
inline bool g_isReloading = false;
inline float g_reloadProgress = 0.0f;
inline float g_reloadDuration = 0.0f;
inline ULONGLONG g_reloadStartTick = 0;
inline int g_lastAmmoCount = -1;
inline int g_curAmmo = 0;
inline int g_maxAmmo = 0;
inline bool g_autoReload = true;    // Auto-reload when ammo reaches 0
inline bool g_chams = false;
inline unsigned int g_chamsMaterialId = 1294354; // current chams material ID
inline std::string g_chamsMaterialName = "Red"; // display name
inline bool g_viewModelChams = false; // hand + weapon chams
inline unsigned int g_vmChamsMaterialId = 1294354; // view model material ID
inline std::string g_vmChamsMaterialName = "Red";

// Chams cache: store matBase write addresses per entity so we only walk the
// pointer chain once, then subsequent cycles are pure writes (zero reads).
struct ChamsCache {
  uintptr_t entity;
  std::vector<uintptr_t> matAddrs; // direct addresses to write material ID to
  ULONGLONG cacheTime;             // when this was cached
};
inline std::vector<ChamsCache> g_chamsCache;
inline std::vector<uintptr_t> g_vmRenderers; // cached renderer component pointers (re-read material chain each cycle)
inline uintptr_t g_vmCachedHeldEntity = 0;   // held entity when VM cache was built
inline uintptr_t g_localHeldEntity = 0;       // populated by worker thread (decrypted)
inline std::mutex g_chamsMutex;
inline bool g_removeLayers = false; // Remove trees/clutter/debris/construction
inline int g_defaultCullingMask = -1; // Stored default culling mask for restore

// Bullet tracers
inline bool g_bulletTracers = true;
struct TracerLine {
  static const int MAX_PTS = 64; // Increased for higher frequency updates
  Vec3 points[MAX_PTS];
  int numPoints;
  uintptr_t projectileAddr; // Added for persistent tracking
  ULONGLONG spawnTick;
};
inline std::vector<TracerLine> g_tracers;
inline std::mutex g_tracerMutex;

// Current ammo icon key (updated each frame)
inline std::string g_curAmmoIconKey;

// Aimbot
inline DWORD64 g_aimbotTarget = 0;
inline LocalPlayer myLocalPlayer;

// Aimbot debug state (populated by RunAimbot each frame)
struct AimbotDebugState {
  bool keyHeld = false;
  bool writeSuccess = false;
  int playersChecked = 0;
  int playersPassedW2S = 0;
  uintptr_t bestTarget = 0;
  float bestScreenDist = 0;
  Vec3 bonePos = {};
  Vec3 aimAngles = {};
  Vec3 curAngles = {};
  bool writeAttempted = false;
};
inline AimbotDebugState g_aimDbg;

inline std::mutex g_DebugLogMutex;
inline std::vector<std::string> g_DebugLogLines;

inline void DebugOverlayLog(const char *fmt, ...) {
  char buf[512];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;

  std::lock_guard<std::mutex> lock(g_DebugLogMutex);
  if (g_DebugLogLines.size() > 96) {
    g_DebugLogLines.erase(g_DebugLogLines.begin(),
                          g_DebugLogLines.begin() +
                              (g_DebugLogLines.size() - 96));
  }
  g_DebugLogLines.emplace_back(buf);
}

// ESP refresh rate (ms)
inline const int g_espRefreshMs = 33;

// Item icons (loaded from icons/ folder)
extern std::unordered_map<std::string, ID3D11ShaderResourceView *> g_ItemIcons;
void LoadAllItemIcons();

// Config path & status
inline std::string g_ConfigPath;
inline std::string g_ConfigStatus;
inline ULONGLONG g_ConfigStatusTime = 0;

// World entity cache (for ore, hemp, animals, deployables — read on worker
// thread)
struct WorldEntityData {
  Vec3 position;
  std::string label; // display name e.g. "Sulfur", "Hemp", "Bear"
  ImU32 color;
  std::string iconKey; // item icon key for image display (e.g. "clone.hemp")
  float dist;          // distance to local player (for fade)
};

// Player cache (front/back buffer pattern, mutex-protected)
inline std::vector<PlayerData> g_cachedPlayers;
inline std::vector<PlayerData> g_BackBuffer;
inline std::vector<WorldEntityData> g_cachedWorldEnts;
inline std::vector<WorldEntityData> g_WorldBackBuffer;
inline std::mutex g_DataMutex;
inline std::thread g_WorkerThread;
inline std::thread g_ChamsThread;

// Colors
inline ImU32 COL_ENEMY = IM_COL32(255, 60, 60, 255);
inline ImU32 COL_TEAM = IM_COL32(60, 255, 60, 255);
inline ImU32 COL_SLEEPER = IM_COL32(160, 160, 160, 180);
inline ImU32 COL_WOUNDED = IM_COL32(255, 180, 0, 255);
inline ImU32 COL_SNAP = IM_COL32(255, 255, 255, 80);
inline ImU32 COL_WHITE = IM_COL32(255, 255, 255, 255);

// View matrix & team info
inline ViewMatrix g_ViewMatrix = {};
inline uint64_t g_LocalTeam = 0;
inline int g_PlayerCount = 0;

// FPS counter
inline int g_FPS = 0;
inline int g_FrameCount = 0;
inline ULONGLONG g_FPSLastTime = 0;
inline LARGE_INTEGER g_PerfFreq = {};
inline LARGE_INTEGER g_LastFrameTime = {};

// ── Forward Declarations ───────────────────────────────────────────

void SyncConfig();
void SaveConfig(const std::string &path);
void LoadConfig(const std::string &path);
void ResetConfig();
void RenderESP();
void RenderDebugOverlay();
void RunAimbot();
void DrawFOVCircle();
void DrawRadar(const Vec3 &localPos, float localYaw);
void RenderFOVArrows(const Vec3 &localPos, float localYaw);
void FillPlayerCache(std::vector<PlayerData> &buffer);
void WorkerThreadRoutine();
void ChamsThreadRoutine();
void SetClickThrough(bool clickThrough);
std::vector<unsigned char> LoadFile(const std::string &path);

// WndProcHandler not needed — we feed ImGui input manually on Discord's overlay
