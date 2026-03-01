// this is the entry point for usermode

#include "globals.h"
#include "overlay.h"

// calls imgui
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"


void WorkerThreadRoutine();
void RenderHotbarESP();


static Overlay g_Overlay;
static MemoryReader g_MemReader;



extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd,
                                                             UINT msg,
                                                             WPARAM wParam,
                                                             LPARAM lParam);

LRESULT CALLBACK Overlay::WndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                  LPARAM lParam) {
  if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
    return true;

  switch (msg) {
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hWnd, msg, wParam, lParam);
}



static void InitConsole() {
  AllocConsole();
  FILE *f;
  freopen_s(&f, "CONOUT$", "w", stdout);
  freopen_s(&f, "CONOUT$", "w", stderr);
  SetConsoleTitleA("Skeleton Hotbar ESP");

  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
  printf("========================================\n");
  printf("   Skeleton Hotbar ESP (Usermode)\n");
  printf("========================================\n");
  printf("  INSERT = Toggle ESP\n");
  printf("  END    = Exit\n");
  printf("========================================\n\n");
  SetConsoleTextAttribute(hConsole,
                          FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}



int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                   _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {
  InitConsole();

  // create new sdk and attach to game
  g_SDK = new RustSDK(&g_MemReader);

  printf("[*] Waiting for RustClient.exe...\n");
  while (!g_SDK->Attach()) {
    Sleep(2000);
    printf("[*] Retrying...\n");
  }
  printf("[+] Attached to Rust!\n\n");

  // create overlay window and init D3D11
  printf("[*] Creating overlay...\n");
  if (!g_Overlay.CreateOverlayWindow(L"Skeleton Overlay")) {
    printf("[!] Failed to create overlay window\n");
    return 1;
  }
  if (!g_Overlay.InitD3D11()) {
    printf("[!] Failed to initialize D3D11\n");
    return 1;
  }

  g_ScreenW = g_Overlay.screenW;
  g_ScreenH = g_Overlay.screenH;
  printf("[+] Overlay: %dx%d\n", g_ScreenW, g_ScreenH);

  // initialize ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.IniFilename = nullptr; // No imgui.ini

  ImGui::StyleColorsDark();

  ImGui_ImplWin32_Init(g_Overlay.hWnd);
  ImGui_ImplDX11_Init(g_Overlay.pDevice, g_Overlay.pContext);

  // for loading fonts
  g_FontDefault =
      io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 14.0f);
  g_FontESP =
      io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 11.0f);
  if (!g_FontDefault)
    g_FontDefault = io.Fonts->AddFontDefault();
  if (!g_FontESP)
    g_FontESP = io.Fonts->AddFontDefault();

  printf("[+] ImGui initialized\n");

  // starting worker thread
  std::thread workerThread(WorkerThreadRoutine);
  printf("[+] Worker thread started\n\n");

  // render loop
  printf("[*] Entering render loop...\n");
  MSG msg = {};
  bool running = true;

  while (running) {
    while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
      if (msg.message == WM_QUIT) {
        running = false;
        break;
      }
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    if (!running)
      break;

    // hotkeys
    if (GetAsyncKeyState(VK_END) & 1) {
      printf("[*] END pressed — exiting...\n");
      running = false;
      break;
    }
    if (GetAsyncKeyState(VK_INSERT) & 1) {
      g_espEnabled = !g_espEnabled;
      printf("[*] ESP %s\n", g_espEnabled ? "ON" : "OFF");
    }

    // rendering frames
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    g_Overlay.BeginFrame();

    RenderHotbarESP();

    ImGui::Render();
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_Overlay.EndFrame();
  }

  // calls cleanup
  printf("[*] Cleaning up...\n");
  g_ShutdownRequested.store(true);
  if (workerThread.joinable())
    workerThread.join();

  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  g_Overlay.Cleanup();

  delete g_SDK;
  g_SDK = nullptr;

  printf("[+] Exited cleanly.\n");
  return 0;
}
