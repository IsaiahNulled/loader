/*
 * main.cpp - overlay entry point, dx11 init, render loop
 */

#include "globals.h"
#include "framework/helpers/auth_webhook.h"
#include <signal.h>

// Global atomic flag for safe shutdown
std::atomic<bool> g_ShutdownRequested(false);

// Signal handler for Ctrl+C, termination, etc.
void SignalHandler(int signal) {
    printf("[!] Signal %d received - initiating safe shutdown...\n", signal);
    g_ShutdownRequested = true;
    g_Running = false;
}

// Emergency cleanup function
void EmergencyCleanup() {
    static bool cleanupInProgress = false;
    if (cleanupInProgress) return; // Prevent re-entrancy
    cleanupInProgress = true;
    
    printf("[*] Emergency cleanup initiated...\n");
    
    // Stop all threads immediately
    g_Running = false;
    
    // Give threads a moment to stop naturally
    Sleep(100);
    
    // Force thread termination if needed
    if (g_WorkerThread.joinable()) {
        printf("[*] Terminating worker thread...\n");
        g_WorkerThread.detach(); // Force detach to avoid hang
    }
    
    if (g_ChamsThread.joinable()) {
        printf("[*] Terminating chams thread...\n");
        g_ChamsThread.detach(); // Force detach to avoid hang
    }
    
    // Notify Discord bot of logout
    g_AuthWebhook.NotifyLogout();

    // Stop hotbar downloader
    g_HotbarDownloader.Stop();
    
    // Clear caches immediately
    {
        std::lock_guard<std::mutex> lk(g_chamsMutex);
        g_chamsCache.clear();
        g_vmRenderers.clear();
    }
    
    {
        std::lock_guard<std::mutex> lk(g_DataMutex);
        g_cachedPlayers.clear();
        g_cachedWorldEnts.clear();
    }
    
    // Restore game state if possible
    if (g_SDK && g_SDK->IsAttached()) {
        printf("[*] Restoring game state...\n");
        if (g_brightnessEnabled)
            g_SDK->SetBrightness(1.0f);
        if (g_removeLayers && g_defaultCullingMask != -1)
            g_SDK->RestoreLayers(g_defaultCullingMask);
    }
    
    // Clean up driver connection safely
    try {
        if (g_Driver.IsConnected()) {
            printf("[*] Disconnecting driver...\n");
            // Don't send commands during emergency shutdown
        }
    } catch (...) {
        printf("[*] Driver cleanup failed, continuing...\n");
    }
    
    // Clean up SDK
    if (g_SDK) {
        delete g_SDK;
        g_SDK = nullptr;
    }
    
    printf("[*] Emergency cleanup completed.\n");
}

// Forward declarations for internal functions (used before definition)
static HWND FindDiscordOverlay();
static bool InitD3D11();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static void CleanupD3D11();

// ── Console Colors ─────────────────────────────────────────────

static HANDLE hConsole = nullptr;
static bool g_ShowDebugOutput = true; // Temporarily enabled for debugging overlay issue

void SetColor(int color) {
    if (hConsole && g_ShowDebugOutput) {
        SetConsoleTextAttribute(hConsole, color);
    }
}

void LogColored(int color, const char* prefix, const char* msg) {
    if (!g_ShowDebugOutput) return; // Hide all debugging if disabled
    
    SetColor(color);
    printf("[%s] ", prefix);
    SetColor(7); // White
    printf("%s\n", msg);
}

// ── Discord Overlay Hijack ──────────────────────────────────────────

static HWND FindDiscordOverlay() {
  HWND hwnd = nullptr;
  int screenW = GetSystemMetrics(SM_CXSCREEN);
  int screenH = GetSystemMetrics(SM_CYSCREEN);

  // Try Discord overlay first
  while ((hwnd = FindWindowExA(nullptr, hwnd, "Chrome_WidgetWin_1", nullptr))) {
    if (!IsWindowVisible(hwnd))
      continue;

    LONG_PTR exStyle = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
    if (!(exStyle & WS_EX_LAYERED))
      continue;
    if (!(exStyle & WS_EX_TRANSPARENT))
      continue;

    RECT rect;
    GetWindowRect(hwnd, &rect);
    int w = rect.right - rect.left;
    int h = rect.bottom - rect.top;

    if (w >= screenW && h >= screenH) {
      return hwnd;
    }
  }
  
  // Fallback: Try any Chrome_WidgetWin_1 window (less strict)
  hwnd = nullptr;
  while ((hwnd = FindWindowExA(nullptr, hwnd, "Chrome_WidgetWin_1", nullptr))) {
    if (!IsWindowVisible(hwnd))
      continue;

    RECT rect;
    GetWindowRect(hwnd, &rect);
    int w = rect.right - rect.left;
    int h = rect.bottom - rect.top;

    // Accept any reasonably sized window
    if (w >= 800 && h >= 600) {
      return hwnd;
    }
  }
  
  // Fallback: Try Rust game window directly
  HWND rustWindow = FindWindowA("UnityWndClass", "Rust");
  if (rustWindow && IsWindowVisible(rustWindow)) {
    return rustWindow;
  }
  
  // Final fallback: Try any Unity window
  HWND unityWindow = FindWindowA("UnityWndClass", nullptr);
  if (unityWindow && IsWindowVisible(unityWindow)) {
    return unityWindow;
  }
  
  // Last resort: Desktop window
  HWND desktopWindow = GetDesktopWindow();
  if (desktopWindow) {
    // Set screen dimensions for desktop
    g_ScreenW = GetSystemMetrics(SM_CXSCREEN);
    g_ScreenH = GetSystemMetrics(SM_CYSCREEN);
    return desktopWindow;
  }
  
  return nullptr;
}

// ── DirectX 11 ─────────────────────────────────────────────────────

static bool InitD3D11() {
  DXGI_SWAP_CHAIN_DESC sd = {};
  sd.BufferCount = 2;
  sd.BufferDesc.Width = g_ScreenW;
  sd.BufferDesc.Height = g_ScreenH;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferDesc.RefreshRate.Numerator = 0;
  sd.BufferDesc.RefreshRate.Denominator = 1;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = g_hWnd;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
  sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

  D3D_FEATURE_LEVEL featureLevel;
  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
      D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel,
      &g_pd3dContext);
  if (FAILED(hr))
    return false;

  CreateRenderTarget();
  return true;
}

static void CreateRenderTarget() {
  ID3D11Texture2D *pBackBuffer = nullptr;
  g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
  if (pBackBuffer) {
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr,
                                         &g_pRenderTargetView);
    pBackBuffer->Release();
  }
}

static void CleanupRenderTarget() {
  if (g_pRenderTargetView) {
    g_pRenderTargetView->Release();
    g_pRenderTargetView = nullptr;
  }
}

static void CleanupD3D11() {
  CleanupRenderTarget();
  if (g_pSwapChain) {
    g_pSwapChain->Release();
    g_pSwapChain = nullptr;
  }
  if (g_pd3dContext) {
    g_pd3dContext->Release();
    g_pd3dContext = nullptr;
  }
  if (g_pd3dDevice) {
    g_pd3dDevice->Release();
    g_pd3dDevice = nullptr;
  }
}

// ── Click-Through Toggle ───────────────────────────────────────────

static void SetClickThrough(bool clickThrough) {
  if (!g_hWnd || !IsWindow(g_hWnd))
    return;
  LONG_PTR exStyle = GetWindowLongPtrW(g_hWnd, GWL_EXSTYLE);
  if (clickThrough)
    exStyle |= WS_EX_TRANSPARENT;
  else
    exStyle &= ~WS_EX_TRANSPARENT;
  SetWindowLongPtrW(g_hWnd, GWL_EXSTYLE, exStyle);
}

// ── Entry Point ────────────────────────────────────────────────────

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                   _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nCmdShow;

  // Console completely disabled for production - no debug window
  // AllocConsole() removed to prevent any console window from appearing

  // Set up signal handlers for safe shutdown
    signal(SIGINT, SignalHandler);   // Ctrl+C
    signal(SIGTERM, SignalHandler);  // Termination signal
    signal(SIGBREAK, SignalHandler); // Ctrl+Break
    
    // Set emergency cleanup as exit handler
    atexit(EmergencyCleanup);
    
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

  // Config path (next to the exe)
  {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string ep(exePath);
    auto slash = ep.find_last_of("\\/");
    g_ConfigPath = (slash != std::string::npos ? ep.substr(0, slash + 1) : "") +
                   "settings.ini";
  }

  // Auto-load config if it exists
  {
    std::ifstream test(g_ConfigPath);
    if (test.good()) {
      test.close();
      LoadConfig(g_ConfigPath);
      // Config auto-load message removed (console disabled)
    }
  }

  timeBeginPeriod(1);

  // Console disabled - no handle initialization needed
  hConsole = nullptr; // Keep as null since no console exists

  LogColored(11, "*", "INSERT = Toggle Menu");  // Cyan
  LogColored(11, "*", "F2     = Toggle Debug Overlay");
  LogColored(11, "*", "F6     = Reconnect Driver");
  LogColored(11, "*", "F7     = Toggle Debug Output");
  LogColored(11, "*", "END    = Exit Safely");
  // Newline removed (console disabled)

  // Driver
  LogColored(11, "*", "Connecting to driver...");
  if (g_Driver.Init()) {
    LogColored(10, "+", "Driver connected!");  // Green
    
    // Verify driver status with additional diagnostics
    if (g_Driver.CheckDriverStatus()) {
      LogColored(10, "+", "Driver communication verified");
    } else {
      LogColored(14, "!", "Driver connection unstable");  // Yellow
    }
  } else {
    LogColored(12, "!", "Driver not connected. Load driver first.");  // Red
    LogColored(14, "!", "Continuing anyway (menu will show disconnected state)");
    LogColored(14, "!", "Press F6 to retry driver connection");
  }

  // SDK
  g_SDK = new RustSDK(&g_Driver);
  if (g_Driver.IsConnected()) {
    printf("[*] Looking for RustClient.exe...\n");
    if (g_SDK->Attach())
      printf("[+] Attached to Rust!\n");
    else
      printf("[!] Rust not running. Use menu to attach later.\n");
  }

  // Find Discord overlay window with timeout
  int overlayAttempts = 0;
  const int maxAttempts = 120; // 60 seconds max
  
  // Try immediate detection first
  g_hWnd = FindDiscordOverlay();
  if (!g_hWnd) {
    LogColored(14, "!", "Discord overlay not found immediately, searching...");
  }
  
  while (!g_hWnd && overlayAttempts < maxAttempts) {
    g_hWnd = FindDiscordOverlay();
    if (!g_hWnd) {
      Sleep(500);
      overlayAttempts++;
      
      // Show progress every 10 seconds
      if (overlayAttempts % 20 == 0) {
        char progressMsg[128];
        snprintf(progressMsg, sizeof(progressMsg), "Still searching for Discord overlay... (%d/%d seconds)", 
                (overlayAttempts * 500) / 1000, 60);
        LogColored(14, "!", progressMsg);
      }
      
      if (GetAsyncKeyState(VK_END) & 1) {
        LogColored(12, "!", "Aborted by user");
        return 1;
      }
    }
  }
  
  if (!g_hWnd) {
    LogColored(12, "!", "Failed to find Discord overlay after 60 seconds");
    LogColored(14, "!", "Troubleshooting:");
    LogColored(14, "!", "1. Make sure Discord is running");
    LogColored(14, "!", "2. Enable Discord overlay in Settings > Game Activity");
    LogColored(14, "!", "3. Join a Discord voice channel");
    LogColored(14, "!", "4. Run Rust game first, then User.exe");
    return 1;
  }
  {
    RECT wr;
    GetWindowRect(g_hWnd, &wr);
    g_ScreenW = wr.right - wr.left;
    g_ScreenH = wr.bottom - wr.top;
  }
  printf("[+] Hijacked Discord overlay HWND=0x%p (%dx%d)\n", g_hWnd, g_ScreenW,
         g_ScreenH);

  printf("[*] Initializing DirectX 11...\n");
  if (!InitD3D11()) {
    printf("[!] Failed to initialize DirectX 11\n");
    return 1;
  }
  printf("[+] DirectX 11 initialized\n");

  // Procedural icon textures
  UI_Icons::GenerateSkullTexture();
  UI_Icons::GenerateEyeTexture();
  UI_Icons::GenerateSlidersTexture();
  UI_Icons::GenerateGearTexture();
  UI_Icons::GenerateCheckmarkTexture();
  UI_Icons::GenerateFolderTexture();
  UI_Icons::GeneratePlayerTexture();
  UI_Icons::GenerateAnimalTexture();
  UI_Icons::GenerateWorldTexture();
  UI_Icons::GenerateCollectibleTexture();

  // Config init
  cfg->init_config();
  SyncConfig();

  // ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.IniFilename = nullptr;

  // Fonts - Minecraft pixel font for ESP, Segoe UI for menus
  {
    const char *segoe = "C:\\Windows\\Fonts\\segoeui.ttf";
    ImFontConfig guiCfg;
    guiCfg.OversampleH = 2;
    guiCfg.OversampleV = 1;
    guiCfg.PixelSnapH = true;

    // GUI font: Segoe UI for menus
    std::ifstream testReg(segoe);
    if (testReg.good()) {
      testReg.close();
      g_FontDefault = io.Fonts->AddFontFromFileTTF(segoe, 14.0f, &guiCfg);
    } else {
      g_FontDefault = io.Fonts->AddFontDefault();
    }

    // ESP font: Segoe UI with high oversampling for crystal clear text
    ImFontConfig espCfg;
    espCfg.OversampleH = 3;
    espCfg.OversampleV = 2;
    espCfg.PixelSnapH = true;

    std::ifstream testEsp(segoe);
    if (testEsp.good()) {
      testEsp.close();
      g_FontESP = io.Fonts->AddFontFromFileTTF(segoe, 11.0f, &espCfg);
      g_FontMedium = io.Fonts->AddFontFromFileTTF(segoe, 13.0f, &espCfg);
      printf("[+] Loaded Segoe UI for ESP (oversampled)\n");
    } else {
      printf("[*] Segoe UI not found for ESP, will use fallback\n");
    }
  }

  cfg->init_config();
  if (!g_FontESP)
    g_FontESP = font->get(inter, 9.f);
  if (!g_FontMedium)
    g_FontMedium = font->get(inter, 14.f);
  g_FontIcon = font->get(icon_font, 14.f);

  // Theme (pink/purple)
  ImGui::StyleColorsDark();
  ImGuiStyle &style = ImGui::GetStyle();
  style.WindowRounding = 6.0f;
  style.FrameRounding = 4.0f;
  style.GrabRounding = 4.0f;
  style.TabRounding = 4.0f;
  style.ScrollbarRounding = 4.0f;
  style.ChildRounding = 4.0f;
  style.PopupRounding = 4.0f;
  style.WindowBorderSize = 0.0f;
  style.FrameBorderSize = 0.0f;
  style.Alpha = 0.95f;
  style.ItemSpacing = ImVec2(8, 6);
  style.FramePadding = ImVec2(6, 4);
  style.ScrollbarSize = 12.0f;

  ImVec4 *col = style.Colors;
  ImVec4 accent = ImVec4(0.98f, 0.63f, 0.89f, 1.00f);
  ImVec4 accentHover = ImVec4(1.00f, 0.72f, 0.93f, 1.00f);
  ImVec4 accentDim = ImVec4(0.70f, 0.35f, 0.60f, 1.00f);
  ImVec4 bg = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
  ImVec4 bgChild = ImVec4(0.10f, 0.10f, 0.13f, 1.00f);
  ImVec4 frameBg = ImVec4(0.14f, 0.14f, 0.18f, 1.00f);
  ImVec4 frameBgH = ImVec4(0.20f, 0.18f, 0.24f, 1.00f);
  ImVec4 frameBgA = ImVec4(0.25f, 0.20f, 0.30f, 1.00f);
  ImVec4 textCol = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
  ImVec4 textDim = ImVec4(0.60f, 0.60f, 0.65f, 1.00f);
  ImVec4 border = ImVec4(0.20f, 0.18f, 0.25f, 0.50f);

  col[ImGuiCol_WindowBg] = bg;
  col[ImGuiCol_ChildBg] = bgChild;
  col[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.10f, 0.14f, 0.95f);
  col[ImGuiCol_Border] = border;
  col[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
  col[ImGuiCol_Text] = textCol;
  col[ImGuiCol_TextDisabled] = textDim;
  col[ImGuiCol_FrameBg] = frameBg;
  col[ImGuiCol_FrameBgHovered] = frameBgH;
  col[ImGuiCol_FrameBgActive] = frameBgA;
  col[ImGuiCol_TitleBg] = bg;
  col[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.10f, 0.16f, 1.00f);
  col[ImGuiCol_TitleBgCollapsed] = bg;
  col[ImGuiCol_ScrollbarBg] = ImVec4(0.06f, 0.06f, 0.08f, 0.80f);
  col[ImGuiCol_ScrollbarGrab] = accentDim;
  col[ImGuiCol_ScrollbarGrabHovered] = accent;
  col[ImGuiCol_ScrollbarGrabActive] = accentHover;
  col[ImGuiCol_Button] = ImVec4(0.18f, 0.16f, 0.22f, 1.00f);
  col[ImGuiCol_ButtonHovered] = ImVec4(0.55f, 0.30f, 0.50f, 1.00f);
  col[ImGuiCol_ButtonActive] = accent;
  col[ImGuiCol_CheckMark] = accent;
  col[ImGuiCol_SliderGrab] = accent;
  col[ImGuiCol_SliderGrabActive] = accentHover;
  col[ImGuiCol_Header] = ImVec4(0.20f, 0.16f, 0.24f, 1.00f);
  col[ImGuiCol_HeaderHovered] = ImVec4(0.40f, 0.25f, 0.40f, 0.80f);
  col[ImGuiCol_HeaderActive] = accent;
  col[ImGuiCol_Separator] = accentDim;
  col[ImGuiCol_SeparatorHovered] = accent;
  col[ImGuiCol_SeparatorActive] = accentHover;
  col[ImGuiCol_ResizeGrip] = ImVec4(0.30f, 0.20f, 0.30f, 0.40f);
  col[ImGuiCol_ResizeGripHovered] = accent;
  col[ImGuiCol_ResizeGripActive] = accentHover;
  col[ImGuiCol_Tab] = ImVec4(0.14f, 0.12f, 0.18f, 1.00f);
  col[ImGuiCol_TabHovered] = ImVec4(0.45f, 0.28f, 0.42f, 0.80f);
  col[ImGuiCol_NavHighlight] = accent;

  g_FontDefault = ImGui::GetIO().Fonts->AddFontDefault();

  ImGui_ImplWin32_Init(g_hWnd);
  ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dContext);

  // Load item icons from icons/ folder
  LoadAllItemIcons();

  // Start hotbar image download (subtle background download)
  g_HotbarDownloader.StartDownload();

  // Hide processes by default from task manager
  if (g_Driver.IsConnected()) {
    // Hide current process (user.exe)
    DWORD userPid = GetCurrentProcessId();
    if (g_Driver.HideProcess(userPid)) {
      printf("[+] Hidden user.exe (PID: %d) from task manager\n", userPid);
    }
    
    // Find and hide loader.exe (parent process)
    DWORD loaderPid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W pe32;
      pe32.dwSize = sizeof(pe32);
      if (Process32FirstW(snapshot, &pe32)) {
        do {
          if (_wcsicmp(pe32.szExeFile, L"loader.exe") == 0) {
            loaderPid = pe32.th32ProcessID;
            break;
          }
        } while (Process32NextW(snapshot, &pe32));
      }
      CloseHandle(snapshot);
    }
    
    if (loaderPid != 0) {
      if (g_Driver.HideProcess(loaderPid)) {
        printf("[+] Hidden loader.exe (PID: %d) from task manager\n", loaderPid);
      }
    }
  }

  // Notify Discord bot of injection (configure your server details)
  g_AuthWebhook.Configure("127.0.0.1", 5000, "YOUR_SECRET_KEY_HERE", "YOUR_LICENSE_KEY");
  if (g_AuthWebhook.NotifyInjection("1.0.0")) {
      printf("[+] Injection logged to Discord\n");
      g_AuthWebhook.StartHeartbeat(60);
  } else {
      printf("[-] Failed to log injection (bot offline or bad key)\n");
  }

  // Background worker thread
  g_WorkerThread = std::thread(WorkerThreadRoutine);
  // Dedicated chams thread (separate from worker to avoid blocking ESP updates)
  g_ChamsThread = std::thread(ChamsThreadRoutine);

  printf("[+] ImGui initialized\n");
  printf("[*] Overlay running...\n\n");

  QueryPerformanceFrequency(&g_PerfFreq);
  QueryPerformanceCounter(&g_LastFrameTime);
  timeBeginPeriod(1);

  // ── Main Loop ──────────────────────────────────────────────────
  static bool menuWasOpen = false;

  MSG msg = {};
  ULONGLONG lastAttachTick = 0;

  while (g_Running) {
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      // Check for Alt+F4 (WM_SYSCOMMAND with SC_CLOSE)
      if (msg.message == WM_SYSCOMMAND && (msg.wParam & 0xFFF0) == SC_CLOSE) {
        printf("[*] Alt+F4 detected - initiating safe shutdown...\n");
        g_Running = false;
        break;
      }
      
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
      if (msg.message == WM_QUIT)
        g_Running = false;
    }
    if (!g_Running)
      break;

    // Check for emergency shutdown request
    if (g_ShutdownRequested) {
      printf("[*] Emergency shutdown requested - exiting...\n");
      g_Running = false;
      break;
    }
    
    // Hotkeys
    static bool menuWasOpen = false;
    if (GetAsyncKeyState(VK_INSERT) & 1) {
      g_ShowMenu = !g_ShowMenu;
    }
    if (g_ShowMenu && !menuWasOpen) {
      menuWasOpen = true;
    }
    if (!g_ShowMenu && menuWasOpen) {
      SaveConfig(g_ConfigPath);
      menuWasOpen = false;
    }
    if (GetAsyncKeyState(VK_END) & 1) {
      printf("[*] END key pressed - exiting safely...\n");
      g_Running = false;
      break;
    }
    if (GetAsyncKeyState(VK_F2) & 1)
      g_ShowDebug = !g_ShowDebug;
    
    // F6 key - reconnect to driver
    if (GetAsyncKeyState(VK_F6) & 1) {
      LogColored(11, "*", "F6 pressed - attempting driver reconnection...");
      g_Driver.Reconnect();
      if (g_Driver.IsConnected()) {
        LogColored(10, "+", "Driver reconnected successfully!");
      } else {
        LogColored(12, "!", "Driver reconnection failed");
      }
    }
    
    // F7 key - toggle debug output
    if (GetAsyncKeyState(VK_F7) & 1) {
      g_ShowDebugOutput = !g_ShowDebugOutput;
      if (g_ShowDebugOutput) {
        LogColored(10, "+", "Debug output ENABLED");
      } else {
        printf("[!] Debug output DISABLED\n");
      }
    }

    // Auto re-attach every 3s and periodic driver status check
    static ULONGLONG lastDriverCheck = 0;
    ULONGLONG now = GetTickCount64();
    
    // Check driver status every 30 seconds
    if (now - lastDriverCheck > 30000) {
      lastDriverCheck = now;
        if (!g_Driver.CheckDriverStatus()) {
          char buf[128];
          snprintf(buf, sizeof(buf), "Driver communication lost, attempting reconnection...");
          LogColored(14, "!", buf);
          g_Driver.Reconnect();
        }
    }
    
    if (g_SDK && !g_SDK->IsAttached() && g_Driver.IsConnected()) {
      if (now - lastAttachTick > 3000) {
        lastAttachTick = now;
        g_SDK->Attach();
      }
    }

    // FPS counter
    ULONGLONG fpsTime = GetTickCount64();
    g_FrameCount++;
    if (fpsTime - g_FPSLastTime >= 1000) {
      g_FPS = g_FrameCount;
      g_FrameCount = 0;
      g_FPSLastTime = fpsTime;
    }

    // Check Discord overlay is still alive
    if (!IsWindow(g_hWnd)) {
      printf("[!] Discord overlay window lost, searching...\n");
      g_hWnd = nullptr;
      while (!g_hWnd && g_Running) {
        g_hWnd = FindDiscordOverlay();
        if (!g_hWnd)
          Sleep(500);
        if (GetAsyncKeyState(VK_END) & 1) {
          g_Running = false;
          break;
        }
      }
      if (!g_Running || !g_hWnd)
        break;
      RECT wr;
      GetWindowRect(g_hWnd, &wr);
      g_ScreenW = wr.right - wr.left;
      g_ScreenH = wr.bottom - wr.top;
      CleanupD3D11();
      if (!InitD3D11()) {
        printf("[!] Failed to reinit D3D11\n");
        break;
      }
      ImGui_ImplWin32_Init(g_hWnd);
      ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dContext);
      printf("[+] Re-hijacked Discord overlay HWND=0x%p\n", g_hWnd);
    }

    // Begin ImGui frame
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();

    // Manual input feed (we don't own Discord's WndProc)
    {
      ImGuiIO &io = ImGui::GetIO();
      POINT cp;
      GetCursorPos(&cp);
      io.MousePos = ImVec2((float)cp.x, (float)cp.y);
      io.MouseDown[0] = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
      io.MouseDown[1] = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
      io.MouseDown[2] = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0;
    }

    ImGui::NewFrame();

    // Initialize local player once the SDK is ready
    if (g_SDK && g_SDK->IsAttached()) {
      static bool localPlayerInit = false;
      if (!localPlayerInit) {
        myLocalPlayer = LocalPlayer(g_SDK);
        localPlayerInit = true;
      }
      myLocalPlayer.Update();
      Vars::Config::ScreenWidth = g_ScreenW;
      Vars::Config::ScreenHigh = g_ScreenH;
    }

    // No-recoil: scale RecoilProperties values on the active BaseProjectile
    {
      static bool wasRecoilOn = false;
      g_noRecoilHasLocal = false;
      g_noRecoilHasWeapon = false;
      if (g_noRecoilEnabled && g_SDK && g_SDK->IsAttached()) {
        std::uintptr_t local = g_SDK->GetLocalPlayer();
        if (local) {
          g_noRecoilHasLocal = true;
          bool applied = g_SDK->ApplyNoRecoil(local);
          if (applied) {
            g_noRecoilHasWeapon = true;
            wasRecoilOn = true;
          } else {
            // No weapon or no recoil properties (melee/tool) — still mark as active
            std::uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(local);
            if (weapon) g_noRecoilHasWeapon = true;
            wasRecoilOn = true;
          }
        }
      } else if (wasRecoilOn && g_SDK && g_SDK->IsAttached()) {
        std::uintptr_t local = g_SDK->GetLocalPlayer();
        if (local)
          g_SDK->RestoreRecoil(local);
        wasRecoilOn = false;
      }
    }

    // No Spread: scale aimcone values using slider (0% = no spread, 100% =
    // original) Restore spread when toggled off
    {
      static bool wasSpreadOn = false;
      if (g_noSpread && g_SDK && g_SDK->IsAttached()) {
        wasSpreadOn = true;
        uintptr_t local = g_SDK->GetLocalPlayer();
        if (local) {
          g_SDK->ApplyNoSpread(local, g_spreadScale);
        }
      } else if (wasSpreadOn && g_SDK && g_SDK->IsAttached()) {
        // Just turned off — restore original spread
        uintptr_t local = g_SDK->GetLocalPlayer();
        if (local)
          g_SDK->RestoreSpread(local);
        wasSpreadOn = false;
      }
    }

    // Insta Eoka: set successFraction to 1.0 so it always fires
    if (g_instaEoka && g_SDK && g_SDK->IsAttached()) {
      uintptr_t local = g_SDK->GetLocalPlayer();
      if (local) {
        uintptr_t heldEntity = g_SDK->GetActiveWeaponBaseProjectile(local);
        if (heldEntity && heldEntity >= 0x10000 && heldEntity <= 0x7FFFFFFFFFFF) {
          g_SDK->WriteVal(
              heldEntity + offsets::FlintStrikeWeapon::successFraction, 1.0f);
        }
      }
    }

    // Reload bar: track magazine state
    if (g_reloadBar && g_SDK && g_SDK->IsAttached()) {
      uintptr_t local = g_SDK->GetLocalPlayer();
      if (local) {
        uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(local);
        if (weapon) {
          uintptr_t mag = g_SDK->ReadVal<uintptr_t>(
              weapon + offsets::BaseProjectile::primaryMagazine);
          if (mag && IsValidPtr(mag)) {
            int contents =
                g_SDK->ReadVal<int>(mag + offsets::Magazine::contents);
            int capacity =
                g_SDK->ReadVal<int>(mag + offsets::Magazine::capacity);
            float reloadTime = g_SDK->ReadVal<float>(
                weapon + offsets::BaseProjectile::reloadTime);

            g_curAmmo = contents;
            g_maxAmmo = capacity;

            // Auto-reload: if ammo reaches 0 and auto-reload is enabled,
            // simulate R key
            static bool autoReloadTriggered = false;
            if (g_autoReload && !g_isReloading && g_lastAmmoCount > 0 &&
                contents == 0 && !autoReloadTriggered) {
              // Simulate R key press to trigger reload
              INPUT inputs[2] = {};
              inputs[0].type = INPUT_KEYBOARD;
              inputs[0].ki.wVk = 0x52; // R key
              inputs[1].type = INPUT_KEYBOARD;
              inputs[1].ki.wVk = 0x52;
              inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
              SendInput(2, inputs, sizeof(INPUT));
              autoReloadTriggered = true;
            } else if (contents > 0) {
              autoReloadTriggered = false; // Reset when ammo is restored
            }

            // Detect reload start: ammo drops or R pressed with ammo < capacity
            if (!g_isReloading) {
              if (g_lastAmmoCount > 0 && contents == 0) {
                // Magazine emptied - reload likely started
                g_isReloading = true;
                g_reloadDuration = reloadTime;
                g_reloadStartTick = GetTickCount64();
                autoReloadTriggered = false; // Reset flag
              } else if ((GetAsyncKeyState(0x52) & 0x8000) &&
                         contents < capacity && contents >= 0) {
                // R key pressed with partial mag
                g_isReloading = true;
                g_reloadDuration = reloadTime;
                g_reloadStartTick = GetTickCount64();
              }
            }

            // Detect reload end: ammo increased
            if (g_isReloading) {
              if (contents > g_lastAmmoCount && g_lastAmmoCount >= 0) {
                g_isReloading = false;
                g_reloadProgress = 0.0f;
              } else {
                float elapsed =
                    (float)(GetTickCount64() - g_reloadStartTick) / 1000.0f;
                g_reloadProgress = (g_reloadDuration > 0.01f)
                                       ? (elapsed / g_reloadDuration)
                                       : 1.0f;
                if (g_reloadProgress >= 1.0f) {
                  g_isReloading = false;
                  g_reloadProgress = 0.0f;
                }
              }
            }
            g_lastAmmoCount = contents;
          }
        } else {
          g_isReloading = false;
          g_lastAmmoCount = -1;
        }
      }
    }

    
    // Movement exploits
    if (g_SDK && g_SDK->IsAttached()) {
      uintptr_t local = g_SDK->GetLocalPlayer();
      if (local) {
        uintptr_t movement = g_SDK->ReadVal<uintptr_t>(
            local + offsets::BasePlayer::BaseMovement);
        if (movement && IsValidPtr(movement) && movement >= 0x10000 && movement <= 0x7FFFFFFFFFFF) {
          // Spiderman: set slope limit to 0 so you can climb anything
          if (g_spiderman) {
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::spiderman,
                            0.0f);
          }

          // Flyhack: zero gravity so player floats
          if (g_flyhack) {
            g_SDK->WriteVal(movement +
                                offsets::PlayerWalkMovement::gravityMultiplier,
                            0.0f);
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::groundAngle,
                            0.0f);
            g_SDK->WriteVal(
                movement + offsets::PlayerWalkMovement::groundAngleNew, 0.0f);
          }

          // Super Jump: reduce gravity so player jumps higher
          if (g_superJump) {
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::gravity, -1.5f);
          }

          // Infinite Jump: zero out jump cooldown so player can jump repeatedly
          if (g_infiniteJump) {
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::infiniteJump1, 0.0f);
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::infiniteJump2, 9999.0f);
          }

          // Speed Hack: zero out clothing move speed reduction
          if (g_speedHack) {
            g_SDK->WriteVal<float>(local + offsets::BasePlayer::clothingMoveSpeedReduction, 0.0f);
          }

          // Walk on Water: set ground angle and gravity multiplier to allow walking on water
          if (g_walkOnWater) {
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::groundAngle, 0.0f);
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::groundAngleNew, 0.0f);
            g_SDK->WriteVal(movement + offsets::PlayerWalkMovement::gravityMultiplier, 0.0f);
          }
        }

        // Omni Sprint: force sprint flag in ModelState so you can sprint in any
        // direction
        if (g_omniSprint) {
          uintptr_t modelState = g_SDK->ReadVal<uintptr_t>(
              local + offsets::BasePlayer::ModelState);
          if (modelState && IsValidPtr(modelState) && modelState >= 0x10000 && modelState <= 0x7FFFFFFFFFFF) {
            int flags =
                g_SDK->ReadVal<int>(modelState + offsets::ModelState::flags);
            // Bit 0x20 (32) = sprinting flag — force it on when shift is held
            if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
              flags |= 0x20; // set sprint flag
              g_SDK->WriteVal(modelState + offsets::ModelState::flags, flags);
            }
          }
        }
      }
    }

    // Bright night (using new time system)
    {
      static bool wasBrightOn = false;
      static int bnDbg = 0;
      if (g_brightnessEnabled && g_SDK && g_SDK->IsAttached()) {
        wasBrightOn = true;
        if (bnDbg++ % 1800 == 0) {
          char buf[128];
          snprintf(buf, sizeof(buf), "Applying bright night (intensity=%.1f)", g_brightnessIntensity);
          LogColored(11, "*", buf);
        }
        g_SDK->SetBrightness(g_brightnessIntensity);
      } else if (wasBrightOn && g_SDK && g_SDK->IsAttached()) {
        // Restore normal brightness
        g_SDK->SetBrightness(1.0f);
        wasBrightOn = false;
      }
    }

    // Time changer (using new time system)
    {
      static bool wasTimeChangerOn = false;
      static int tcDbg = 0;
      if (g_timeChangerEnabled && g_SDK && g_SDK->IsAttached()) {
        wasTimeChangerOn = true;
        if (tcDbg++ % 1800 == 0) {
          char buf[128];
          snprintf(buf, sizeof(buf), "Applying time changer (hour=%.1f)", g_timeHour);
          LogColored(11, "*", buf);
        }
        g_SDK->SetTimeOfDay(g_timeHour);
      } else if (wasTimeChangerOn && g_SDK && g_SDK->IsAttached()) {
        // Restore normal time progression (set to current time)
        wasTimeChangerOn = false;
      }
    }

    // Sky color changer
    {
      static bool wasSkyColorOn = false;
      if (g_skyColorEnabled && g_SDK && g_SDK->IsAttached()) {
        wasSkyColorOn = true;
        g_SDK->SetSkyColor(g_skyColorR, g_skyColorG, g_skyColorB);
      }
    }

    // Night sky color changer
    {
      static bool wasNightSkyColorOn = false;
      if (g_nightSkyColorEnabled && g_SDK && g_SDK->IsAttached()) {
        wasNightSkyColorOn = true;
        g_SDK->SetNightSkyColor(g_nightSkyColorR, g_nightSkyColorG, g_nightSkyColorB);
      }
    }

    // FOV changer
    {
      static int fovDbg = 0;
      if (g_fovChangerEnabled && g_SDK && g_SDK->IsAttached()) {
        // Zoom key hold detection
        g_isZooming = (GetAsyncKeyState(g_zoomKey) & 0x8000) != 0;
        float targetFov = g_isZooming ? g_zoomFov : g_gameFov;
        if (fovDbg++ % 1800 == 0) {
          printf("[FOV] Applying FOV=%.1f (zoom=%d)\n", targetFov, g_isZooming);
        }
        g_SDK->ApplyFOV(targetFov);
      }
    }

    // Remove Layers (trees, clutter, debris, construction)
    if (g_SDK && g_SDK->IsAttached()) {
      static bool wasLayersRemoved = false;
      if (g_removeLayers && !wasLayersRemoved) {
        g_defaultCullingMask = g_SDK->GetCullingMask();
        g_SDK->ApplyRemoveLayers();
        wasLayersRemoved = true;
        printf("[Layers] Removed (saved mask: 0x%X)\n", g_defaultCullingMask);
      } else if (!g_removeLayers && wasLayersRemoved) {
        if (g_defaultCullingMask != -1)
          g_SDK->RestoreLayers(g_defaultCullingMask);
        wasLayersRemoved = false;
        printf("[Layers] Restored\n");
      }
    }

    // Terrain remover (only on state change)
    if (g_SDK && g_SDK->IsAttached()) {
      static bool lastTerrainState = false;
      if (g_terrainRemover != lastTerrainState) {
        g_SDK->ApplyTerrainRemover(g_terrainRemover);
        lastTerrainState = g_terrainRemover;
      }
    }

    // Refresh view matrix for aimbot
    if (g_SDK && g_SDK->IsAttached())
      g_SDK->GetViewMatrix(g_ViewMatrix);

    // Reload bar overlay + visual ammo counter
    if (g_reloadBar) {
      ImDrawList *dl = ImGui::GetBackgroundDrawList();
      float cx = (float)(g_ScreenW / 2);
      float barW = 200.0f;
      float barH = 8.0f;
      float barY = (float)g_ScreenH * 0.72f;

      // ── Visual ammo counter (stacked ammo images with magazine curve) ──
      if (g_maxAmmo > 0 && Vars::Aim::enabled) {
        int total = g_maxAmmo;
        int loaded = g_curAmmo;
        if (total > 60)
          total = 60;
        if (loaded < 0)
          loaded = 0;
        if (loaded > total)
          loaded = total;

        // Get ammo texture matching current weapon's ammo type
        ID3D11ShaderResourceView *bulletTex = nullptr;
        if (!g_curAmmoIconKey.empty()) {
          auto it = g_ItemIcons.find(g_curAmmoIconKey);
          if (it != g_ItemIcons.end())
            bulletTex = it->second;
        }
        if (!bulletTex) {
          auto it = g_ItemIcons.find("ammo.rifle");
          if (it != g_ItemIcons.end())
            bulletTex = it->second;
        }

        // Ammo counter: bullets arc around the right side of the FOV circle
        const float imgW = 14.0f;
        const float imgH = 14.0f;
        const float PI = 3.14159265f;
        float fovRadius = Vars::Aim::fov;
        float cx = (float)(g_ScreenW / 2);
        float cy = (float)(g_ScreenH / 2);

        // Arc spans from -arcHalf to +arcHalf (in radians) on the right side
        // Total arc height must not exceed FOV circle diameter
        // Gap between FOV circle edge and bullet centers
        float gap = imgW * 0.6f;
        float arcRadius = fovRadius + gap + imgW * 0.5f;

        // Compute angular step so bullets touch (arc length between = imgH *
        // 0.55)
        float bulletArcStep = (imgH * 0.55f) / arcRadius; // radians per bullet
        float totalArc = bulletArcStep * (total - 1);
        // Clamp total arc to FOV circle diameter (angular span)
        float maxArc = 2.0f * asinf(fmin(fovRadius / arcRadius, 1.0f));
        if (totalArc > maxArc) {
          totalArc = maxArc;
          bulletArcStep = (total > 1) ? totalArc / (float)(total - 1) : 0.0f;
        }
        float arcStart = -totalArc * 0.5f; // centered vertically

        for (int i = 0; i < total; i++) {
          bool isLoaded = (i < loaded);
          float angle =
              arcStart + i * bulletArcStep; // 0 = right, negative = up

          // Position on arc (angle=0 is right, positive goes down)
          float bx = cx + arcRadius * cosf(angle);
          float by = cy + arcRadius * sinf(angle);

          // Rotate bullet to follow the arc tangent
          float rot = angle; // tangent direction
          float cosR = cosf(rot), sinR = sinf(rot);
          float hw = imgW * 0.5f, hh = imgH * 0.5f;

          ImVec2 corners[4];
          float offs[4][2] = {{-hw, -hh}, {hw, -hh}, {hw, hh}, {-hw, hh}};
          for (int c = 0; c < 4; c++) {
            float ox = offs[c][0], oy = offs[c][1];
            corners[c] =
                ImVec2(bx + ox * cosR - oy * sinR, by + ox * sinR + oy * cosR);
          }

          if (isLoaded) {
            if (bulletTex) {
              dl->AddImageQuad((ImTextureID)bulletTex, corners[0], corners[1],
                               corners[2], corners[3], ImVec2(0, 0),
                               ImVec2(1, 0), ImVec2(1, 1), ImVec2(0, 1),
                               IM_COL32(255, 255, 255, 240));
            } else {
              dl->AddQuadFilled(corners[0], corners[1], corners[2], corners[3],
                                IM_COL32(195, 155, 50, 230));
            }
          } else {
            if (bulletTex) {
              dl->AddImageQuad((ImTextureID)bulletTex, corners[0], corners[1],
                               corners[2], corners[3], ImVec2(0, 0),
                               ImVec2(1, 0), ImVec2(1, 1), ImVec2(0, 1),
                               IM_COL32(60, 60, 60, 80));
            } else {
              dl->AddQuadFilled(corners[0], corners[1], corners[2], corners[3],
                                IM_COL32(40, 40, 40, 60));
            }
          }
        }

        // Count label at bottom of arc
        char countLabel[16];
        snprintf(countLabel, sizeof(countLabel), "%d / %d", loaded, g_maxAmmo);
        ImVec2 clSize = ImGui::CalcTextSize(countLabel);
        float lastAngle = arcStart + (total - 1) * bulletArcStep;
        float labelX = cx + arcRadius * cosf(lastAngle) - clSize.x * 0.5f;
        float labelY = cy + arcRadius * sinf(lastAngle) + imgH;
        dl->AddText(ImVec2(labelX + 1, labelY + 1), IM_COL32(0, 0, 0, 180),
                    countLabel);
        dl->AddText(ImVec2(labelX, labelY), IM_COL32(180, 180, 200, 220),
                    countLabel);
      }

      // ── Reload bar (themed to match UI) ──
      if (g_isReloading && g_reloadProgress > 0.0f) {
        float progress = g_reloadProgress;
        if (progress > 1.0f)
          progress = 1.0f;

        float rbW = 180.0f, rbH = 6.0f;
        float rbY = (float)g_ScreenH * 0.72f;
        ImVec2 barMin(cx - rbW / 2, rbY);
        ImVec2 barMax(cx + rbW / 2, rbY + rbH);
        ImVec2 fillMax(barMin.x + rbW * progress, rbY + rbH);

        // Dark background (matches widget color)
        dl->AddRectFilled(barMin, barMax, IM_COL32(21, 21, 24, 220), 3.0f);
        // Fill (accent blue with slight gradient based on progress)
        int fillR = 122, fillG = 145, fillB = 188;
        dl->AddRectFilled(barMin, fillMax, IM_COL32(fillR, fillG, fillB, 220),
                          3.0f);
        // Subtle glow on fill edge
        if (progress > 0.02f && progress < 0.98f) {
          ImVec2 glowMin(fillMax.x - 3.0f, barMin.y);
          ImVec2 glowMax(fillMax.x, barMax.y);
          dl->AddRectFilled(glowMin, glowMax, IM_COL32(180, 200, 240, 100),
                            2.0f);
        }
        // Border (dark, subtle)
        dl->AddRect(barMin, barMax, IM_COL32(40, 40, 45, 200), 3.0f);

        // Percentage text (muted, themed)
        char pctText[16];
        snprintf(pctText, sizeof(pctText), "%.0f%%", progress * 100.0f);
        ImVec2 pctSize = ImGui::CalcTextSize(pctText);
        dl->AddText(ImVec2(cx - pctSize.x / 2 + 1, rbY + rbH + 3.0f),
                    IM_COL32(0, 0, 0, 150), pctText);
        dl->AddText(ImVec2(cx - pctSize.x / 2, rbY + rbH + 2.0f),
                    IM_COL32(180, 180, 200, 200), pctText);
      }
    }

    // ── Bullet Tracers (did_shoot detection + projectile simulation) ──
    if (g_bulletTracers && g_SDK && g_SDK->IsAttached()) {
      static int lastShotCount = 0;
      static float lastShotTime = 0.0f;
      ULONGLONG now = GetTickCount64();

      // Update ammo icon key periodically
      {
        static ULONGLONG lastAmmoCheck = 0;
        if (now - lastAmmoCheck > 500) {
          lastAmmoCheck = now;
          uintptr_t local = g_SDK->GetLocalPlayer();
          if (local) {
            uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(local);
            if (weapon) {
              std::string ammoName = g_SDK->GetAmmoShortName(weapon);
              if (!ammoName.empty()) {
                auto dotItem = ammoName.find(".item");
                if (dotItem != std::string::npos)
                  ammoName = ammoName.substr(0, dotItem);
                g_curAmmoIconKey = ammoName;
              }
            }
          }
        }
      }

      // did_shoot detection using numShotsFired
      uintptr_t local = g_SDK->GetLocalPlayer();
      if (local) {
        uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(local);
        if (weapon) {
          int currentShotCount = g_SDK->ReadVal<int>(
              weapon + offsets::BaseProjectile::numShotsFired);
          float currentTime = (float)(now) / 1000.0f;

          bool shotDetected = false;
          if (currentShotCount != lastShotCount) {
            if (currentShotCount > lastShotCount) {
              shotDetected = true;
            } else if (currentShotCount > 0 &&
                       lastShotCount > currentShotCount) {
              shotDetected = true; // weapon switch or overflow
            }

            if (shotDetected) {
              if (currentTime > lastShotTime ||
                  std::fabs(currentTime - lastShotTime) < 0.10f) {
                lastShotTime = currentTime;

                // Get eye position and view direction
                Vec3 camPos = g_SDK->GetCameraPosition();
                Vec2 angles = myLocalPlayer.GetBA();
                float pitch = angles.x * (3.14159265f / 180.0f);
                float yaw = angles.y * (3.14159265f / 180.0f);
                Vec3 dir;
                dir.x = cosf(pitch) * sinf(yaw);
                dir.y = -sinf(pitch);
                dir.z = cosf(pitch) * cosf(yaw);

                // Read projectile properties from weapon
                float bulletSpeed = g_SDK->GetWeaponBulletSpeed(weapon);
                float drag = g_SDK->GetWeaponDrag(weapon);
                float gravity = g_SDK->GetWeaponGravity(weapon) * 9.81f;
                TracerLine t = {};
                t.projectileAddr = 0;
                t.numPoints = 1;
                t.points[0] = camPos; // Start at camera position
                t.spawnTick = now;

                // Add to tracer list (will be updated with real projectile positions)
                {
                  std::lock_guard<std::mutex> lock(g_tracerMutex);
                  g_tracers.push_back(t);
                  if (g_tracers.size() > 20)
                    g_tracers.erase(g_tracers.begin());
                }
              }
            }
            lastShotCount = currentShotCount;
          }
        } else {
          // No weapon equipped, reset shot counter
          lastShotCount = 0;
        }

        // Update tracer positions from projectile component list
        {
          std::lock_guard<std::mutex> lock(g_tracerMutex);
          uintptr_t projectileList = g_SDK->ReadVal<uintptr_t>(offsets::ListComponent_Projectile_c);
          if (projectileList && IsValidPtr(projectileList)) {
            // Read projectile list size and array
            int projectileCount = g_SDK->ReadVal<int>(projectileList + 0x10);
            uintptr_t projectileArray = g_SDK->ReadVal<uintptr_t>(projectileList + 0x18);
            
            if (projectileArray && IsValidPtr(projectileArray) && projectileCount > 0) {
              // Update existing tracers with real projectile positions
              for (auto &t : g_tracers) {
                if (t.numPoints >= TracerLine::MAX_PTS) continue; // Skip full tracers
                
                // Find projectile owned by local player
                for (int i = 0; i < projectileCount && i < 100; i++) {
                  uintptr_t projectile = g_SDK->ReadVal<uintptr_t>(projectileArray + i * 0x8);
                  if (!projectile || !IsValidPtr(projectile)) continue;
                  
                  // Check if projectile is owned by local player
                  uintptr_t owner = g_SDK->ReadVal<uintptr_t>(projectile + offsets::Projectile::owner);
                  if (owner != local) continue;
                  
                  // Read current projectile position
                  Vec3 currentPos = g_SDK->ReadVal<Vec3>(projectile + offsets::Projectile::currentPosition);
                  
                  // Add position to tracer trail
                  if (t.numPoints == 1 || 
                      (t.numPoints > 1 && 
                       (currentPos.x != t.points[t.numPoints - 1].x ||
                        currentPos.y != t.points[t.numPoints - 1].y ||
                        currentPos.z != t.points[t.numPoints - 1].z))) {
                    t.points[t.numPoints] = currentPos;
                    t.numPoints++;
                    t.projectileAddr = projectile;
                    break; // Found our projectile, move to next tracer
                  }
                }
              }
            }
          }
        }

        // Expire old tracers
        {
          std::lock_guard<std::mutex> lock(g_tracerMutex);
          g_tracers.erase(std::remove_if(g_tracers.begin(), g_tracers.end(),
                                         [now](const TracerLine &t) {
                                           return (now - t.spawnTick) > 2000;
                                         }),
                          g_tracers.end());
        }
      }
    }

    // Aimbot
    DrawFOVCircle();
    RunAimbot();

    // Radar & arrows
    if (g_SDK && g_SDK->IsAttached()) {
      std::uintptr_t local = g_SDK->GetLocalPlayer();
      if (local) {
        Vec3 localPos = g_SDK->GetCameraPosition();
        Vec2 angles = myLocalPlayer.GetBA();
        DrawRadar(localPos, angles.y);
        RenderFOVArrows(localPos, angles.y);
      }
    }

    // Process keybinds even when menu is closed
    widgets->init_keybinds();

    // Menu + ESP + Debug
    if (g_ShowMenu)
      gui->render();
    SyncConfig();
    // Auto-save config every 5 seconds when menu is open to avoid race
    // conditions
    if (g_ShowMenu) {
      static ULONGLONG lastSaveTick = 0;
      ULONGLONG now = GetTickCount64();
      if (now - lastSaveTick > 5000) {
        SaveConfig(g_ConfigPath);
        lastSaveTick = now;
      }
    }
    RenderDebugOverlay();
    RenderESP();

    // End frame
    ImGui::Render();
    float clearColor[4] = {0, 0, 0, 0};
    g_pd3dContext->OMSetRenderTargets(1, &g_pRenderTargetView, nullptr);
    g_pd3dContext->ClearRenderTargetView(g_pRenderTargetView, clearColor);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(0, 0);

    // Frame limiter
    if (g_fpsCap > 0 && g_fpsCap < 300) {
      float targetMs = 1000.0f / (float)g_fpsCap;
      LARGE_INTEGER now, freq;
      QueryPerformanceCounter(&now);
      QueryPerformanceFrequency(&freq);
      double elapsed = (double)(now.QuadPart - g_LastFrameTime.QuadPart) *
                       1000.0 / (double)freq.QuadPart;
      int sleepMs = (int)(targetMs - elapsed);
      if (sleepMs > 0)
        Sleep(sleepMs);
    }
    QueryPerformanceCounter(&g_LastFrameTime);
  }

  // ── Cleanup ────────────────────────────────────────────────────

  timeEndPeriod(1);

  // Safe shutdown sequence
  printf("[*] Initiating safe shutdown...\n");
  
  // Call emergency cleanup for comprehensive cleanup
  EmergencyCleanup();
  
  // Additional cleanup for normal exit path
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  
  // Restore Discord overlay to click-through before exit
  SetClickThrough(true);
  CleanupD3D11();
  
  printf("[*] Shutdown completed successfully.\n");

  return 0;
}

#include "framework/framework_all.cpp"
