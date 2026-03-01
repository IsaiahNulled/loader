#pragma once
// using dx11 I recommend hijacking an overlay. research on unknowncheats.me and other online hacking forums.

#include <d3d11.h>
#include <dwmapi.h>
#include <dxgi.h>
#include <string>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")

class Overlay {
public:
  // window
  HWND hWnd = nullptr;
  WNDCLASSEXW wc = {};
  int screenW = 0;
  int screenH = 0;

  /* DirectX 11 */
  ID3D11Device *pDevice = nullptr;
  ID3D11DeviceContext *pContext = nullptr;
  IDXGISwapChain *pSwapChain = nullptr;
  ID3D11RenderTargetView *pRenderTargetView = nullptr;

  bool CreateOverlayWindow(const wchar_t *windowTitle = L"Overlay") {
    screenW = GetSystemMetrics(SM_CXSCREEN);
    screenH = GetSystemMetrics(SM_CYSCREEN);

    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"DwmOverlayHost";
    RegisterClassExW(&wc);

    hWnd =
        CreateWindowExW(WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
                        wc.lpszClassName, windowTitle, WS_POPUP, 0, 0, screenW,
                        screenH, nullptr, nullptr, wc.hInstance, nullptr);

    if (!hWnd)
      return false;

    // this makes window transparent
    SetLayeredWindowAttributes(hWnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

	//dwm transparency - this is what makes the window borderless and without title bar, also allows for proper alpha blending
    MARGINS margins = {-1, -1, -1, -1};
    DwmExtendFrameIntoClientArea(hWnd, &margins);

    ShowWindow(hWnd, SW_SHOWDEFAULT);
    UpdateWindow(hWnd);

    return true;
  }

  bool InitD3D11() {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Width = screenW;
    sd.BufferDesc.Height = screenH;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 0;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
        D3D11_SDK_VERSION, &sd, &pSwapChain, &pDevice, &featureLevel,
        &pContext);

    if (FAILED(hr))
      return false;

    return CreateRenderTarget();
  }

  bool CreateRenderTarget() {
    ID3D11Texture2D *pBackBuffer = nullptr;
    pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (!pBackBuffer)
      return false;

    pDevice->CreateRenderTargetView(pBackBuffer, nullptr, &pRenderTargetView);
    pBackBuffer->Release();
    return pRenderTargetView != nullptr;
  }

  void CleanupRenderTarget() {
    if (pRenderTargetView) {
      pRenderTargetView->Release();
      pRenderTargetView = nullptr;
    }
  }

  void BeginFrame() {
    float clearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    pContext->OMSetRenderTargets(1, &pRenderTargetView, nullptr);
    pContext->ClearRenderTargetView(pRenderTargetView, clearColor);
  }

  void EndFrame() { pSwapChain->Present(1, 0); }

  void Cleanup() {
    CleanupRenderTarget();
    if (pSwapChain) {
      pSwapChain->Release();
      pSwapChain = nullptr;
    }
    if (pContext) {
      pContext->Release();
      pContext = nullptr;
    }
    if (pDevice) {
      pDevice->Release();
      pDevice = nullptr;
    }
    if (hWnd) {
      DestroyWindow(hWnd);
      hWnd = nullptr;
    }
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
  }

  // forward declare WndProc so it can call member functions if needed
  static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                  LPARAM lParam);
};
