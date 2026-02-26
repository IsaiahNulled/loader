#include "headers/includes.h"

void c_gui::render()
{
	if (IsKeyPressed(ImGuiKey_9))
	{
		var->gui.stored_dpi += 10;
		var->gui.dpi_changed = true;
	}
    
    font->update();
	if (IsKeyPressed(ImGuiKey_0))
	{
		var->gui.stored_dpi -= 10;
		var->gui.dpi_changed = true;
	}

	gui->initialize();
	gui->set_next_window_size(s_(elements->window.size));
	gui->begin(elements->window.name, nullptr, window_flags_no_scrollbar | window_flags_no_scroll_with_mouse | window_flags_no_bring_to_front_on_focus | window_flags_no_focus_on_appearing | window_flags_no_background | window_flags_no_decoration);
	{
		gui->set_style();
		gui->draw_decorations();
		widgets->init_keybinds();

		gui->easing(var->gui.tab_alpha, var->gui.tab_stored != var->gui.tab_current ? 0.f : 1.f, 6.f, static_easing);
		if (var->gui.tab_alpha < 0.01f)
			var->gui.tab_current = var->gui.tab_stored;

		var->gui.scrollbar_enabled = cfg->get<checkbox_t>("Enable scrollbar").enabled;

		gui->begin_content("sidebar", s_(elements->sidebar.size), s_(elements->sidebar.padding), s_(elements->sidebar.padding));
		{
			{
				c_window* window = gui->get_window();
				c_rect rect = window->Rect();
				draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), s_(elements->window.rounding), draw_flags_round_corners_left);
				draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->window.rounding), draw_flags_round_corners_left);	
			}
			
			{
                /* Updated tabs for Rust Cheat */
				std::vector<std::pair<std::string, std::string>> tab_list = { {"Aimbot", "E"}, {"Visuals", "D"}, {"Misc", "C"}, {"Config", "F"} };

				for (int i = 0; i < tab_list.size(); ++i)
				{
					if (widgets->tab_button(tab_list[i].first, tab_list[i].second, i == var->gui.tab_stored))
					{
						var->gui.tab_stored = i;
					}
				}

			}

		}
		gui->end_content();

		gui->sameline();

		gui->push_var(style_var_alpha, var->gui.tab_alpha);

		gui->set_pos(gui->get_pos().y + 1, pos_y);
		gui->begin_content("content", gui->content_avail() - c_vec2(0, 1), s_(elements->content.padding), s_(elements->content.padding));
		{
			elements->child.width = (gui->content_avail().x - s_(elements->content.padding.x)) / 2;
			
            /* Tab 0: Aimbot */
            if (var->gui.tab_current == 0) {
                gui->begin_group();
                widgets->start_child("Main");
                {
                    widgets->checkbox("Aimbot");
                    widgets->slider("Aimbot FOV");
                    widgets->slider("Smooth");
                    widgets->dropdown("Hitboxes");
                }
                widgets->end_child();
                gui->end_group();
            }
            
            /* Tab 1: Visuals */
            else if (var->gui.tab_current == 1) {
                gui->begin_group();
                widgets->start_child("Players");
                {
                    widgets->checkbox("Enable ESP");
                    widgets->checkbox("Box");
                    widgets->checkbox("Skeleton");
                    widgets->checkbox("Snaplines");
                    widgets->checkbox("Health");
                    widgets->checkbox("Name");
                    widgets->checkbox("Active Weapon");
                    widgets->checkbox("Distance");
                    widgets->checkbox("Corpse");
                }
                widgets->end_child();
                gui->end_group();

                gui->sameline();

                gui->begin_group();
                widgets->start_child("World");
                {
                    widgets->checkbox("SafeZone");
                    widgets->checkbox("Hotbar");
                }
                widgets->end_child();
                gui->end_group();
            }

            /* Tab 2: Misc */
            else if (var->gui.tab_current == 2) {
                gui->begin_group();
                widgets->start_child("Main");
                {
                    widgets->checkbox("No Recoil");
                    widgets->checkbox("Spider Man");
                    widgets->checkbox("Admin Flags");
                    widgets->checkbox("Bright Night");
                    widgets->slider("Time");
                }
                widgets->end_child();
                gui->end_group();

                gui->sameline();

                gui->begin_group();
                widgets->start_child("Menu");
                {
                    if (!widgets->slider("Dpi scale"))
                    {
                        if (gui->mouse_released(0))
                        {
                            var->gui.stored_dpi = cfg->get<slider_t>("Dpi scale").callback;
                            var->gui.dpi_changed = true;
                        }
                    }
                    static c_vec4 color = clr->accent.Value;
                    widgets->colorpicker("Accent color", &color);
                    clr->accent.Value = color;

                    widgets->checkbox("Enable scrollbar");
                }
                widgets->end_child();
                gui->end_group();
            }
            
             /* Tab 3: Config (Placeholder) */
            else if (var->gui.tab_current == 3) {
                 gui->begin_group();
                 widgets->start_child("Config");
                 widgets->end_child();
                 gui->end_group();
            }

		}
		gui->end_content();

		gui->pop_var();
	}
	gui->end();
}