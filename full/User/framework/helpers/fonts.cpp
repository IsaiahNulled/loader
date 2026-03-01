#include "../headers/includes.h"
#include "../../imgui/imgui_freetype.h"
#include "../../imgui/backends/imgui_impl_dx11.h"

void c_font::update()
{
    if (var->gui.dpi_changed)
    {
        var->gui.dpi = var->gui.stored_dpi / 100.f;

        ImFontConfig cfg;
        cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_MonoHinting | ImGuiFreeTypeBuilderFlags_Monochrome | ImGuiFreeTypeBuilderFlags_ForceAutoHint;
        cfg.FontDataOwnedByAtlas = false;

        ImGuiIO& io = ImGui::GetIO();
        io.Fonts->Clear();

        // Custom glyph range: Cyrillic + skull symbol (U+2620)
        static const ImWchar custom_ranges[] = {
            0x0020, 0x00FF, // Basic Latin + Latin Supplement
            0x0400, 0x052F, // Cyrillic + Cyrillic Supplement
            0x2620, 0x2620, // Skull and Crossbones
            0,
        };

        for (auto& font_t : data)
        {
            font_t.font = io.Fonts->AddFontFromMemoryTTF(font_t.data.data(), font_t.data.size(), s_(font_t.size), &cfg, custom_ranges);
        }

        io.Fonts->Build();
        ImGui_ImplDX11_CreateDeviceObjects();

        var->gui.dpi_changed = false;
    }
}

ImFont* c_font::get(std::vector<unsigned char> font_data, float size)
{
    for (auto& font : data)
    {
        if (font.data == font_data && font.size == size)
        {
            return font.font;
        }
    }

    add(font_data, size);

    var->gui.dpi_changed = true;

    return get(font_data, size);
}

void c_font::add(std::vector<unsigned char> font_data, float size)
{
    data.push_back({ font_data, size, nullptr });
}