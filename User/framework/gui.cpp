#include "headers/includes.h"
#include <Shellapi.h>
#include <Windows.h>

void c_gui::render() {
  if (IsKeyPressed(ImGuiKey_9)) {
    var->gui.stored_dpi += 10;
    var->gui.dpi_changed = true;
  }
  if (IsKeyPressed(ImGuiKey_0)) {
    var->gui.stored_dpi -= 10;
    var->gui.dpi_changed = true;
  }

  gui->initialize();
  gui->set_next_window_size(s_(elements->window.size));
  gui->begin(elements->window.name, nullptr,
             window_flags_no_scrollbar | window_flags_no_scroll_with_mouse |
                 window_flags_no_bring_to_front_on_focus |
                 window_flags_no_focus_on_appearing |
                 window_flags_no_background | window_flags_no_decoration);

  {
    gui->set_style();
    gui->draw_decorations();
    widgets->init_keybinds();

    gui->easing(var->gui.tab_alpha,
                var->gui.tab_stored != var->gui.tab_current ? 0.f : 1.f, 6.f,
                static_easing);
    if (var->gui.tab_alpha < 0.01f)
      var->gui.tab_current = var->gui.tab_stored;

    var->gui.scrollbar_enabled =
        cfg->get<checkbox_t>("Enable scrollbar").enabled;

    gui->begin_content("sidebar", s_(elements->sidebar.size),
                       s_(elements->sidebar.padding),
                       s_(elements->sidebar.padding));
    {
      {
        c_window *window = gui->get_window();
        c_rect rect = window->Rect();
        draw->rect_filled(
            window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child),
            s_(elements->window.rounding), draw_flags_round_corners_left);
        draw->rect(window->DrawList, rect.Min, rect.Max,
                   draw->get_clr(clr->border), s_(elements->window.rounding),
                   draw_flags_round_corners_left);
      }

      {

        std::vector<std::pair<std::string, std::string>> tab_list = {
            {"Aimbot", "SKULL"},
            {"Visuals", "EYE"},
            {"Misc", "SLIDERS"},
            {"Lua", "GEAR"},
            {"Cloud", "FOLDER"}};

        for (int i = 0; i < tab_list.size(); ++i) {
          if (widgets->tab_button(tab_list[i].first, tab_list[i].second,
                                  i == var->gui.tab_stored)) {
            var->gui.tab_stored = i;
          }
        }
      }
    }
    gui->end_content();

    gui->sameline();

    gui->push_var(style_var_alpha, var->gui.tab_alpha);

    gui->set_pos(gui->get_pos().y + 1, pos_y);
    gui->begin_content("content", gui->content_avail() - c_vec2(0, 1),
                       s_(elements->content.padding),
                       s_(elements->content.padding));
    {
      elements->child.width =
          (gui->content_avail().x - s_(elements->content.padding.x)) / 2;

      if (var->gui.tab_current == 0) { // Aimbot (Skull)
        gui->begin_group();
        widgets->start_child("General");
        {
          widgets->checkbox("Aimbot");
          widgets->checkbox("Silent Aim");
          widgets->checkbox("Aimbot Prediction");
          widgets->dropdown("Aimbot Key");
        }
        widgets->end_child();

        widgets->start_child("Target");
        {
          widgets->dropdown("Hitboxes");
        }
        widgets->end_child();
        gui->end_group();

        gui->sameline();

        gui->begin_group();
        widgets->start_child("Settings");
        {
          widgets->slider("Aimbot FOV");
          widgets->slider("Smooth");
        }
        widgets->end_child();

        widgets->start_child("Weapon Modifiers");
        {
          widgets->checkbox("No Recoil");
          if (cfg->get<checkbox_t>("No Recoil").enabled) {
            widgets->slider("Recoil Control");
          }
          widgets->checkbox("Insta Eoka");
          widgets->checkbox("No Spread");
          if (cfg->get<checkbox_t>("No Spread").enabled) {
            widgets->slider("Spread Control");
          }
          widgets->checkbox("Reload Bar");
          widgets->checkbox("Bullet Tracers");
          widgets->checkbox("Auto Reload");
          widgets->checkbox("Third Person");
        }
        widgets->end_child();
        gui->end_group();
      } else if (var->gui.tab_current == 1) { // Visuals (Eye)
        static int espCategory = 0;           // 0=Player, 1=Animal, 2=World

        gui->begin_group();
        widgets->start_child("ESP");
        {
          widgets->checkbox("Enable ESP");
        }
        widgets->end_child();

        widgets->start_child("ESP Categories");
        {
          // Category selector buttons — clicking selects, toggle is separate
          if (widgets->tab_button("Player##cat", "PLAYER", espCategory == 0))
            espCategory = 0;
          widgets->checkbox("Enable Player ESP");

          gui->dummy(ImVec2(0, s_(2.0f)));

          if (widgets->tab_button("Animals##cat", "ANIMAL", espCategory == 1))
            espCategory = 1;
          widgets->checkbox("Animal ESP");

          gui->dummy(ImVec2(0, s_(2.0f)));

          if (widgets->tab_button("World##cat", "WORLD", espCategory == 2))
            espCategory = 2;
        }
        widgets->end_child();
        gui->end_group();

        gui->sameline();

        gui->begin_group();
        if (espCategory == 0) { // Player ESP settings
          widgets->start_child("Player ESP");
          {
            widgets->checkbox("Box");
            widgets->checkbox("Skeleton");
            if (cfg->get<checkbox_t>("Skeleton").enabled) {
              widgets->slider("Skeleton thickness");
            }
            widgets->checkbox("Vischeck");
            widgets->checkbox("Snaplines");
            widgets->checkbox("Health");
            widgets->checkbox("Name");
            widgets->checkbox("Distance");
            widgets->checkbox("Hotbar ESP");
            widgets->checkbox("Corpse");
            widgets->checkbox("Off-screen arrows");
            widgets->checkbox("Radar");
            widgets->checkbox_chams("Chams");
          }
          widgets->end_child();
        } else if (espCategory == 1) { // Animal ESP settings
          widgets->start_child("Animal ESP Settings");
          {
            widgets->checkbox("Bear");
            widgets->checkbox("Polar Bear");
            widgets->checkbox("Wolf");
            widgets->checkbox("Boar");
            widgets->checkbox("Chicken");
            widgets->checkbox("Horse");
            widgets->checkbox("Stag");
            widgets->checkbox("Shark");
          }
          widgets->end_child();
        } else if (espCategory == 2) { // World ESP settings
          widgets->start_child("World ESP");
          {
            widgets->checkbox_esp("Deployable ESP", &g_espDeployMaxDist,
                                  &g_espDeployColor);
            widgets->checkbox_esp("Ore ESP", &g_espOreMaxDist, &g_espOreColor);
            widgets->checkbox_esp("Hemp ESP", &g_espHempMaxDist,
                                  &g_espHempColor);
            widgets->checkbox_esp("Dropped Items", &g_espDropMaxDist,
                                  &g_espDropColor);
          }
          widgets->end_child();
        }
        gui->end_group();
      } else if (var->gui.tab_current == 2) { // Misc (Sliders)
        gui->begin_group();
        widgets->start_child("World");
        {
          widgets->checkbox_slider("Bright Night", &g_brightNightIntensity,
                                   1.0f, 50.0f, "%.1f");
          widgets->checkbox("Time Changer");
          if (cfg->get<checkbox_t>("Time Changer").enabled) {
            widgets->slider("Time Hour");
          }
          widgets->checkbox("FOV Changer");
          if (cfg->get<checkbox_t>("FOV Changer").enabled) {
            widgets->slider("Game FOV");
            widgets->slider("Zoom FOV");
            widgets->dropdown("Zoom Key");
          }
          widgets->checkbox("Terrain Remover");
          widgets->checkbox("Remove Layers");
        }
        widgets->end_child();
        gui->end_group();

        gui->sameline();

        gui->begin_group();
        widgets->start_child("Movement");
        {
          widgets->checkbox("Spiderman");
          widgets->checkbox("Flyhack");
          widgets->checkbox("Omni Sprint");
        }
        widgets->end_child();
        gui->end_group();
      } else if (var->gui.tab_current == 3) { // Lua (Gear) / Settings
        gui->begin_group();
        widgets->start_child("Menu Settings");
        {
          if (!widgets->slider("UI Scale")) {
            if (gui->mouse_released(0)) {
              float scale = cfg->get<slider_t>("UI Scale").callback;
              var->gui.dpi = 2.0f * scale;
              var->gui.dpi_changed = true;
            }
          }
          widgets->checkbox("Enable scrollbar");
          widgets->checkbox("Streamproof");
          widgets->slider("FPS Cap");
        }
        widgets->end_child();
        gui->end_group();

        gui->sameline();

      } else if (var->gui.tab_current == 4) // Cloud / Config
      {
        gui->begin_group();
        widgets->start_child("Subscription Status");
        {

          gui->dummy(ImVec2(0, s_(10.0f)));

          auto draw_info_widget = [&](const char *label, const char *value,
                                      ImU32 value_clr) {
            c_window *window = gui->get_window();
            ImVec2 pos = window->DC.CursorPos;
            ImVec2 size = ImVec2(gui->content_avail().x,
                                 s_(34.0f)); // Checkbox size approx
            c_rect rect = c_rect(pos, pos + size);
            c_rect inner = c_rect(rect.Min + s_(10.0f, 10.0f),
                                  rect.Max - s_(10.0f, 10.0f));

            // Background
            draw->rect_filled(window->DrawList, rect.Min, rect.Max,
                              draw->get_clr(clr->widget),
                              s_(elements->child.rounding));
            draw->rect(window->DrawList, rect.Min, rect.Max,
                       draw->get_clr(clr->border),
                       s_(elements->child.rounding));

            // Text
            draw->text_clipped(window->DrawList, font->get(inter, s_(9.0f)),
                               inner.Min, inner.Max, draw->get_clr(clr->text),
                               label, 0, 0, {0, 0.5f}); // Left, Vert Center
            draw->text_clipped(window->DrawList, font->get(inter, s_(9.0f)),
                               inner.Min, inner.Max, value_clr, value, 0, 0,
                               {1, 0.5f}); // Right, Vert Center

            gui->dummy(size);
            gui->dummy(ImVec2(0, s_(5.0f)));
          };

          draw_info_widget("Status", "Active", IM_COL32(50, 255, 50, 255));
          draw_info_widget("Remaining", "30 Days", draw->get_clr(clr->accent));
        }
        widgets->end_child();
        gui->end_group();

        gui->sameline();

        gui->begin_group();
        widgets->start_child("Configuration");
        {
          gui->dummy(ImVec2(0, s_(5.0f)));

          if (widgets->tab_button("Save Config", "FOLDER", false)) {
            SaveConfig(g_ConfigPath);
          }
          if (widgets->tab_button("Load Config", "FOLDER", false)) {
            LoadConfig(g_ConfigPath);
          }
          if (widgets->tab_button("Reset Config", "GEAR", false)) {
            ResetConfig();
          }

          // Show status message for 3 seconds after save/load
          if (!g_ConfigStatus.empty() &&
              GetTickCount64() - g_ConfigStatusTime < 3000) {
            gui->dummy(ImVec2(0, s_(5.0f)));
            draw->text(gui->window_drawlist(), font->get(inter, s_(11.0f)),
                       s_(15.0f), gui->get_screen_pos(),
                       IM_COL32(50, 255, 50, 255), g_ConfigStatus.c_str());
            gui->dummy(ImVec2(0, s_(16.0f)));
          }
        }
        widgets->end_child();
        gui->end_group();
      }
    }
    gui->end_content();

    gui->pop_var();
  }
  gui->end();
}