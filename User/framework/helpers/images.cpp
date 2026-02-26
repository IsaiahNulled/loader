#include <d3d11.h>
#include <vector>
#include <cmath>
#include <string>
#include <unordered_map>
#include <filesystem>
#include "../headers/includes.h"
#include "../../thirdparty/stb/stb_image.h"

// Forward declare the global device (defined in main.cpp)
extern ID3D11Device* g_pd3dDevice;

// ── Item icon texture map (shortname → SRV) ──
std::unordered_map<std::string, ID3D11ShaderResourceView*> g_ItemIcons;

static ID3D11ShaderResourceView* LoadPNGTexture(const std::string& path) {
    if (!g_pd3dDevice) return nullptr;
    int w, h, channels;
    unsigned char* data = stbi_load(path.c_str(), &w, &h, &channels, 4); // force RGBA
    if (!data) return nullptr;

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sub = {};
    sub.pSysMem = data;
    sub.SysMemPitch = w * 4;

    ID3D11Texture2D* pTex = nullptr;
    g_pd3dDevice->CreateTexture2D(&desc, &sub, &pTex);
    stbi_image_free(data);
    if (!pTex) return nullptr;

    D3D11_SHADER_RESOURCE_VIEW_DESC srv = {};
    srv.Format = desc.Format;
    srv.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srv.Texture2D.MipLevels = 1;

    ID3D11ShaderResourceView* pSRV = nullptr;
    g_pd3dDevice->CreateShaderResourceView(pTex, &srv, &pSRV);
    pTex->Release();
    return pSRV;
}

// Public function to load a single item icon
ID3D11ShaderResourceView* LoadItemIcon(const std::string& path) {
    return LoadPNGTexture(path);
}

static int LoadIconsFromDir(const std::string& dir) {
    if (!std::filesystem::exists(dir)) return 0;
    int loaded = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::string ext = entry.path().extension().string();
        if (ext != ".png" && ext != ".PNG" && ext != ".jpg" && ext != ".jpeg") continue;

        std::string shortname = entry.path().stem().string();
        if (g_ItemIcons.count(shortname)) continue; // already loaded
        ID3D11ShaderResourceView* tex = LoadPNGTexture(entry.path().string());
        if (tex) {
            g_ItemIcons[shortname] = tex;
            loaded++;
        }
    }
    return loaded;
}

void LoadAllItemIcons() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) exeDir = exeDir.substr(0, lastSlash);

    int total = 0;

    // 1) Try exe directory / images
    std::string dir1 = exeDir + "\\images";
    total += LoadIconsFromDir(dir1);

    // 2) Try two levels up (e.g. x64/Release -> User/images for dev builds)
    std::string dir2 = exeDir + "\\..\\..\\images";
    total += LoadIconsFromDir(dir2);

    // 3) Try three levels up (e.g. x64/Release -> project root/User/images)
    std::string dir3 = exeDir + "\\..\\..\\..\\images";
    total += LoadIconsFromDir(dir3);

    // 4) Try temp directory for downloaded hotbar images
    WCHAR tempPath[MAX_PATH];
    if (::GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring ws(tempPath);
        std::string tempDir(ws.begin(), ws.end());
        std::string dir4 = tempDir + "\\rust_hotbar_images";
        int hotbarLoaded = LoadIconsFromDir(dir4);
        if (hotbarLoaded > 0) {
            printf("[Icons] Loaded %d hotbar images from temp directory\n", hotbarLoaded);
            total += hotbarLoaded;
        }
    }

    if (total == 0) {
        printf("[Icons] No item icons found. Searched:\n");
        printf("[Icons]   %s\n", dir1.c_str());
        printf("[Icons]   %s\n", dir2.c_str());
        printf("[Icons]   %s\n", dir3.c_str());
        printf("[Icons] Place Rust item PNGs named by shortname (e.g. rifle.ak.png)\n");
    } else {
        printf("[Icons] Loaded %d item icons\n", total);
    }
}

namespace UI_Icons {
    ID3D11ShaderResourceView* SkullTexture = nullptr;
    ID3D11ShaderResourceView* EyeTexture = nullptr;
    ID3D11ShaderResourceView* SlidersTexture = nullptr;
    ID3D11ShaderResourceView* GearTexture = nullptr;
    ID3D11ShaderResourceView* CheckmarkTexture = nullptr;
    ID3D11ShaderResourceView* FolderTexture = nullptr;
    ID3D11ShaderResourceView* PlayerTexture = nullptr;
    ID3D11ShaderResourceView* AnimalTexture = nullptr;
    ID3D11ShaderResourceView* WorldTexture = nullptr;
    ID3D11ShaderResourceView* CollectibleTexture = nullptr;

    void GenerateSkullTexture() {
        if (SkullTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000); // ABGR (0 = transparent)

        auto set_pixel = [&](int x, int y, uint32_t color) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                pixels[y * width + x] = color;
            }
        };

        // Draw Skull (White 0xFFFFFFFF)
        // Cranium
        for (int y = 4; y < 20; y++) {
            for (int x = 6; x < 26; x++) {
                // Rounded corners logic
                float dx = (float)(x - 16);
                float dy = (float)(y - 14); // slightly lower center for top heavy
                if (dx*dx + dy*dy < 100.0f) set_pixel(x, y, 0xFFFFFFFF);
            }
        }
        
        // Jaw
        for (int y = 20; y < 26; y++) {
            for (int x = 10; x < 22; x++) {
                set_pixel(x, y, 0xFFFFFFFF);
            }
        }

        // Eyes (Transparent)
        for (int y = 14; y < 18; y++) {
            for (int x = 9; x < 14; x++) pixels[y * width + x] = 0x00000000;
            for (int x = 18; x < 23; x++) pixels[y * width + x] = 0x00000000;
        }

        // Nose (Upside down heart/triangle)
        set_pixel(15, 20, 0x00000000); set_pixel(16, 20, 0x00000000);
        set_pixel(15, 19, 0x00000000); set_pixel(16, 19, 0x00000000);
        set_pixel(14, 21, 0x00000000); set_pixel(17, 21, 0x00000000);

        // Teeth (Black lines)
        for (int x = 12; x < 21; x += 2) {
             set_pixel(x, 23, 0x00000000);
             set_pixel(x, 24, 0x00000000);
             set_pixel(x, 25, 0x00000000);
        }

        // Bullet Hole (Red/Black)
        int holeX = 20;
        int holeY = 8;
        set_pixel(holeX, holeY, 0xFF0000FF); // Red center
        set_pixel(holeX-1, holeY, 0xFF000000); // Black rim
        set_pixel(holeX+1, holeY, 0xFF000000); 
        set_pixel(holeX, holeY-1, 0xFF000000); 
        set_pixel(holeX, holeY+1, 0xFF000000); 
        set_pixel(holeX-2, holeY-2, 0xFF000000);
        set_pixel(holeX+2, holeY+2, 0xFF000000);


        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &SkullTexture);
                 pTexture->Release();
             }
        }
    }

    void GenerateEyeTexture() {
        if (EyeTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);

        auto set_pixel = [&](int x, int y, uint32_t color) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                pixels[y * width + x] = color;
            }
        };

        // Draw Eye
        // Sclera (White almond shape)
        for (int y = 8; y < 24; y++) {
            for (int x = 2; x < 30; x++) {
                float dx = (float)(x - 16) / 14.0f;
                float dy = (float)(y - 16) / 7.0f;
                if (dx*dx + dy*dy <= 1.0f) set_pixel(x, y, 0xFFFFFFFF);
            }
        }

        // Iris (Green/Human-like)
        for (int y = 10; y < 22; y++) {
            for (int x = 10; x < 22; x++) {
                float dx = (float)(x - 16);
                float dy = (float)(y - 16);
                if (dx*dx + dy*dy <= 25.0f) set_pixel(x, y, 0xFF00FF00); // Bright Green Iris
            }
        }

        // Pupil (Black)
        for (int y = 13; y < 19; y++) {
            for (int x = 13; x < 19; x++) {
                 float dx = (float)(x - 16);
                 float dy = (float)(y - 16);
                 if (dx*dx + dy*dy <= 9.0f) set_pixel(x, y, 0xFF000000);
            }
        }

        // Highlight (White reflection)
        set_pixel(18, 14, 0xFFFFFFFF);
        set_pixel(19, 14, 0xFFFFFFFF);
        set_pixel(18, 13, 0xFFFFFFFF);


        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &EyeTexture);
                 pTexture->Release();
             }
        }
    }

    void GenerateSlidersTexture() {
        if (SlidersTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);

        auto set_pixel = [&](int x, int y, uint32_t color) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                pixels[y * width + x] = color;
            }
        };

        // Draw Sliders Icon (White)
        
        // Track 1 (Top)
        int y1 = 10;
        for (int x = 4; x <= 28; x++) {
            set_pixel(x, y1, 0xFF808080); // Grey track
            set_pixel(x, y1+1, 0xFF808080);
        }
        // Knob 1 (Left-ish) - White Circle
        int k1x = 10; 
        int k1y = y1; 
        for (int y = k1y - 3; y <= k1y + 4; y++) {
            for (int x = k1x - 3; x <= k1x + 4; x++) {
                 float dx = (float)(x - k1x);
                 float dy = (float)(y - (k1y + 0.5f));
                 if (dx*dx + dy*dy <= 9.0f) set_pixel(x, y, 0xFFFFFFFF);
            }
        }


        // Track 2 (Bottom)
        int y2 = 22;
        for (int x = 4; x <= 28; x++) {
            set_pixel(x, y2, 0xFF808080); // Grey track
            set_pixel(x, y2+1, 0xFF808080);
        }
        // Knob 2 (Right-ish) - White Circle
        int k2x = 22;
        int k2y = y2;
        for (int y = k2y - 3; y <= k2y + 4; y++) {
            for (int x = k2x - 3; x <= k2x + 4; x++) {
                 float dx = (float)(x - k2x);
                 float dy = (float)(y - (k2y + 0.5f));
                 if (dx*dx + dy*dy <= 9.0f) set_pixel(x, y, 0xFFFFFFFF);
            }
        }

        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &SlidersTexture);
                 pTexture->Release();
             }
        }
    }

    void GenerateGearTexture() {
        if (GearTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);

        auto set_pixel = [&](int x, int y, uint32_t color) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                pixels[y * width + x] = color;
            }
        };

        // Gear Logic
        float center_x = 16.0f;
        float center_y = 16.0f;
        float outer_radius = 14.0f;
        float inner_radius = 6.0f;
        float tooth_depth = 4.0f;
        int num_teeth = 8;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                float dx = x - center_x;
                float dy = y - center_y;
                float dist_sq = dx*dx + dy*dy;
                float dist = sqrt(dist_sq);

                if (dist < inner_radius) {
                    // Hole inside
                    continue; // Transparent
                }

                if (dist > outer_radius) {
                    // Outside gear
                    continue;
                }

                // Check specifically for teeth
                bool pixel_filled = false;
                if (dist <= outer_radius - tooth_depth) {
                    // Main body of gear
                    pixel_filled = true;
                } else {
                    // Teeth region
                    float angle = atan2(dy, dx);
                    if (angle < 0) angle += 6.2831853f; // 0 to 2PI
                    
                    // Simple tooth logic: check angle ranges
                    float angle_step = 6.2831853f / num_teeth;
                    float local_angle = fmod(angle, angle_step);
                    
                    // Teeth width roughly half the step
                    if (local_angle < angle_step * 0.5f) {
                        pixel_filled = true;
                    }
                }

                if (pixel_filled) {
                    set_pixel(x, y, 0xFFFFFFFF);
                }
            }
        }

        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &GearTexture);
                 pTexture->Release();
             }
        }
    }

    void GenerateCheckmarkTexture() {
        if (CheckmarkTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);

        auto draw_line = [&](int x1, int y1, int x2, int y2, uint32_t color) {
            int dx = abs(x2 - x1), sx = x1 < x2 ? 1 : -1;
            int dy = -abs(y2 - y1), sy = y1 < y2 ? 1 : -1;
            int err = dx + dy, e2;
            while (true) {
                if (x1 >= 0 && x1 < width && y1 >= 0 && y1 < height) {
                    for (int ox = 0; ox < 2; ox++)
                        for (int oy = 0; oy < 2; oy++)
                            if (x1+ox < width && y1+oy < height)
                                pixels[(y1+oy) * width + (x1+ox)] = color;
                }
                if (x1 == x2 && y1 == y2) break;
                e2 = 2 * err;
                if (e2 >= dy) { err += dy; x1 += sx; }
                if (e2 <= dx) { err += dx; y1 += sy; }
            }
        };

        // Draw Checkmark
        draw_line(8, 16, 14, 22, 0xFFFFFFFF);
        draw_line(14, 22, 24, 10, 0xFFFFFFFF);

        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &CheckmarkTexture);
                 pTexture->Release();
             }
        }
    }

    void GenerateFolderTexture() {
        if (FolderTexture) return;

        const int width = 32;
        const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);

        auto set_pixel = [&](int x, int y, uint32_t color) {
            if (x >= 0 && x < width && y >= 0 && y < height) {
                pixels[y * width + x] = color;
            }
        };

        // Draw Folder Icon (White)
        // Main body
        for (int y = 14; y < 26; y++) {
            for (int x = 4; x < 28; x++) {
                set_pixel(x, y, 0xFFFFFFFF);
            }
        }
        // Tab
        for (int y = 10; y < 14; y++) {
            for (int x = 4; x < 14; x++) {
                set_pixel(x, y, 0xFFFFFFFF);
            }
        }
        // Outline/Split line (Black)
        for (int x = 4; x < 28; x++) set_pixel(x, 14, 0xFF000000);

        // Create Texture
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = pixels.data();
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;

        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) {
             g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
             if (pTexture) {
                 D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
                 srvDesc.Format = desc.Format;
                 srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
                 srvDesc.Texture2D.MipLevels = desc.MipLevels;
                 srvDesc.Texture2D.MostDetailedMip = 0;
                 g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &FolderTexture);
                 pTexture->Release();
             }
        }
    }

    // Helper for pixel-art icons with color support
    static void CreateTextureFromGrid(const std::vector<std::string>& grid, ID3D11ShaderResourceView** ppSRV, const std::unordered_map<char, uint32_t>& palette = {}) {
        if (*ppSRV) return;
        const int width = 32; const int height = 32;
        std::vector<uint32_t> pixels(width * height, 0x00000000);
        
        for (int y = 0; y < height; y++) {
            if (y >= grid.size()) break;
            const std::string& row = grid[y];
            for (int x = 0; x < width; x++) {
                if (x >= row.size()) break;
                char c = row[x];
                if (c == ' ') continue;
                
                uint32_t color = 0xFFFFFFFF; // Default white
                if (!palette.empty()) {
                    auto it = palette.find(c);
                    if (it != palette.end()) color = it->second;
                }
                pixels[y * width + x] = color;
            }
        }

        D3D11_TEXTURE2D_DESC desc = {}; desc.Width = width; desc.Height = height; desc.MipLevels = 1; desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM; desc.SampleDesc.Count = 1; desc.Usage = D3D11_USAGE_DEFAULT; desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA sub = {}; sub.pSysMem = pixels.data(); sub.SysMemPitch = desc.Width * 4;
        ID3D11Texture2D* pTexture = NULL;
        if (g_pd3dDevice) { 
            g_pd3dDevice->CreateTexture2D(&desc, &sub, &pTexture);
            if (pTexture) { 
                D3D11_SHADER_RESOURCE_VIEW_DESC srv = {}; srv.Format = desc.Format; srv.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D; srv.Texture2D.MipLevels = 1;
                g_pd3dDevice->CreateShaderResourceView(pTexture, &srv, ppSRV); 
                pTexture->Release(); 
            } 
        }
    }

    void GeneratePlayerTexture() { // Skeleton (Maximized)
        std::vector<std::string> grid = {
            "             XXXXXX             ",
            "            XX    XX            ",
            "            XX    XX            ",
            "             XXXXXX             ", // Skull
            "               XX               ",
            "               XX               ",
            "      XXXXXXXXXXXXXXXXXXXX      ", // Shoulders
            "      XX  XX  XXXX  XX  XX      ",
            "      XX  XX  XXXX  XX  XX      ",
            "      XX  XX  XXXX  XX  XX      ", // Ribs
            "      XX  XX  XXXX  XX  XX      ",
            "      XX  XX  XXXX  XX  XX      ",
            "      XXXXXXXXXXXXXXXXXXXX      ",
            "               XX               ",
            "               XX               ", // Spine
            "            XXXXXXXX            ", // Hips
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ", // Legs
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "          XX        XX          ",
            "                                ",
            "                                ",
            "                                ",
            "                                "
        };
        CreateTextureFromGrid(grid, &PlayerTexture); 
    }

    void GenerateAnimalTexture() { // Colored Bear (Maximized)
        std::unordered_map<char, uint32_t> palette = {
            {'X', 0xFF000000},
            {'o', 0xFF2D52A0} 
        };

        std::vector<std::string> grid = {
            "                                ",
            "          XXXXXXXXX             ", // Hump
            "        XXoooooooooXXXX         ",
            "       XoooooooooooooooXX       ",
            "      XooooooooooooooooooXX     ",
            "     XoooooooooooooooooooooX    ",
            "    XoooooooooooooooooooooooX   ",
            "   XoooooooooooooooooooooooooX  ",
            "   XooooooooooooooooooooooooooX ",
            "   XooooooooooooooooooooooooooX ",
            "   XooooooooooooooooooooooooooX ",
            "   XoooooooooooooooooooooooooooX",
            "   XoooooooooooooooooooooooooooX", // Body
            "   Xoooooooooooooooooooooooooooo", // Head
            "   Xoooooooooooooooooooooooooooo",
            "   Xoooooooooooooooooooooooooooo",
            "   Xoooooooooooooooooooooooooooo",
            "   XxxxxxxxXoooooooXoooooooooooo",
            "   XxxxxxxxXoooooooXoooooooooooo", // Legs start
            "   XxxxxxxxXoooooooXoooooooooooo",
            "   XxxxxxxxXoooooooXoooooooooooo",
            "    XXXXXXX XXXXXXX XXXXXXXXXXXX",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                "
        };
        CreateTextureFromGrid(grid, &AnimalTexture, palette);
    }

    void GenerateWorldTexture() { // Pixel Earth
        std::vector<std::string> grid = {
            "                                ",
            "                                ",
            "                                ",
            "           XXXXXXXXXX           ",
            "        XXXX   XX   XXXX        ",
            "      XXX      XX      XXX      ",
            "     XXX    XXXXXXXX    XXX     ",
            "    XX     XXXXXXXXXX     XX    ",
            "    XX    XXXXXXXXXXXX    XX    ",
            "   XX     XXXXXXXXXXXX     XX   ",
            "   XX    XX  XXXXXX  XX    XX   ",
            "   XX    XX  XXXXXX  XX    XX   ",
            "   XX        XXXXXX        XX   ",
            "    XX       XXXXXX       XX    ",
            "    XX        XXXX        XX    ",
            "     XXX       XX       XXX     ",
            "      XXX      XX      XXX      ",
            "        XXXX   XX   XXXX        ",
            "           XXXXXXXXXX           ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                ",
            "                                "
        };
        CreateTextureFromGrid(grid, &WorldTexture);
    }

    void GenerateCollectibleTexture() { // Hemp Leaf (Maximized)
        std::vector<std::string> grid = {
            "               XX               ",
            "              XXXX              ",
            "              XXXX              ",
            "             XX  XX             ",
            "             XX  XX             ",
            "            XX    XX            ",
            "            XX    XX            ",
            "           XX      XX           ",
            "       XXXXXX      XXXXXX       ",
            "      XX    XX    XX    XX      ",
            "     XX      XX  XX      XX     ",
            "     XX      XX  XX      XX     ",
            "    XX        XXXX        XX    ",
            "    XX        XXXX        XX    ",
            "    XX        XXXX        XX    ",
            "     XX      XXXXXX      XX     ",
            "      XXXXXXXXX  XXXXXXXXX      ",
            "           XX      XX           ",
            "           XX      XX           ",
            "           XX      XX           ",
            "           XX      XX           ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "               XX               ",
            "                                ",
            "                                ",
            "                                "
        };
        CreateTextureFromGrid(grid, &CollectibleTexture);
    }
}
