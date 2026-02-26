#include "../headers/includes.h"

const char* const keys[] = { "Tab", "Left", "Right", "Up", "Down", "Page Up", "Page Down", "Home", "End", "Insert", "Delete", "Backspace", "Space", "Enter", "Escape", "Ctrl", "Shift", "Alt", "Super", "Ctrl", "Shift", "Alt", "Super", "Menu", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12", "F13", "F14", "F15", "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23", "F24", "Apostrophe", "Comma", "Minus", "Period", "Slash", "Semicolon", "Equal", "Left Bracket", "Backslash", "Right Bracket", "Grave Accent", "Caps Lock", "Scroll Lock", "Num Lock", "Print Screen", "Pause", "Keypad 0", "Keypad 1", "Keypad 2", "Keypad 3", "Keypad 4", "Keypad 5", "Keypad 6", "Keypad 7", "Keypad 8", "Keypad 9", "Keypad .", "Keypad /", "Keypad *", "Keypad -", "Keypad +", "Keypad Enter", "Keypad =", "App Back", "App Forward", "Gamepad Start", "Gamepad Back", "Gamepad Face Left", "Gamepad Face Right", "Gamepad Face Up", "Gamepad Face Down", "Gamepad Dpad Left", "Gamepad Dpad Right", "Gamepad Dpad Up", "Gamepad Dpad Down", "Gamepad L1", "Gamepad R1", "Gamepad L2", "Gamepad R2", "Gamepad L3", "Gamepad R3", "Gamepad L Stick Left", "Gamepad L Stick Right", "Gamepad L Stick Up", "Gamepad L Stick Down", "Gamepad R Stick Left", "Gamepad R Stick Right", "Gamepad R Stick Up", "Gamepad R Stick Down", "Mouse 1", "Mouse 2", "Mouse 3", "Mouse 4", "Mouse 5", "Mouse Wheel X", "Mouse Wheel Y", "Ctrl", "Shift", "Alt", "Super" };

const char* get_key_name(ImGuiKey key)
{
	if (key == ImGuiKey_None)
		return "None";

	return keys[key - ImGuiKey_NamedKey_BEGIN];
}

struct keybind_state 
{
	bool open;
	float alpha;
	c_vec2 pos;
	c_vec4 hold_color, hold_text;
	c_vec4 toggle_color, toggle_text;
	c_vec4 keybind_color, keybind_text;

	bool active;
	float timer;
};

void c_widgets::init_keybinds() {

	for (auto widget : cfg->order)
	{
		if (widget.second == checkbox_type)
		{
			checkbox_t* data = &cfg->get<checkbox_t>(widget.first);

			if (data->keybind.mode == 0)
			{
				if (IsKeyDown((ImGuiKey)data->keybind.key))
				{
					data->enabled = true;
				}
				if (IsKeyReleased((ImGuiKey)data->keybind.key))
				{
					data->enabled = false;
				}
			}

			if (data->keybind.mode == 1)
			{
				if (IsKeyPressed((ImGuiKey)data->keybind.key, false))
				{
					data->enabled = !data->enabled;
				}
			}
		}
	}
}

void c_widgets::keybind(std::string name, int* key, int* mode, c_rect rect) 
{

	name = name + "##keybind";

	c_window* window = gui->get_window();
	if (window->SkipItems)
		return;

	c_id id = window->GetID(name.data());
	keybind_state* state = gui->anim_container<keybind_state>(id);

	if (rect.Contains(gui->mouse_pos()) && gui->is_window_hovered(0) && gui->mouse_clicked(1) && !state->open)
	{
		state->open = true;
		state->pos = gui->mouse_pos();
	}

	gui->easing(state->alpha, state->open ? 1.f : 0.f, 6.f, static_easing);
	gui->easing(state->hold_color, *mode == 0 ? clr->deter.Value : clr->widget.Value, 24.f, dynamic_easing);
	gui->easing(state->toggle_color, *mode == 1 ? clr->deter.Value : clr->widget.Value, 24.f, dynamic_easing);
	gui->easing(state->hold_text, *mode == 0 ? clr->white.Value : clr->text.Value, 24.f, dynamic_easing);
	gui->easing(state->toggle_text, *mode == 1 ? clr->white.Value : clr->text.Value, 24.f, dynamic_easing);
	gui->easing(state->keybind_color, state->active ? clr->deter.Value : clr->widget.Value, 24.f, dynamic_easing);
	gui->easing(state->keybind_text, state->active ? clr->white.Value : clr->text.Value, 24.f, dynamic_easing);

	gui->push_var(style_var_alpha, state->alpha);
	if (state->alpha > 0)
	{
		gui->set_next_window_size(c_vec2(rect.GetWidth() / 1.3f, 0));
		gui->set_next_window_pos(state->pos);

		gui->push_var(style_var_window_padding, s_(elements->checkbox.padding));
		gui->push_var(style_var_item_spacing, s_(elements->checkbox.padding));

		gui->begin(name, nullptr, window_flags_no_move | window_flags_no_decoration | window_flags_no_background | window_flags_always_auto_resize);
		{
			gui->set_window_focus();

			window = gui->get_window();
			rect = window->Rect();

			draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), s_(elements->child.rounding));
			draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));

			gui->invisible_button("bind", c_vec2(gui->content_avail().x, s_(30)));
			draw->rect_filled(window->DrawList, GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->keybind_color), s_(elements->child.rounding));
			draw->text_clipped(window->DrawList, font->get(inter, 12), GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->keybind_text), get_key_name((ImGuiKey)*key), 0, 0, {0.5, 0.5});

			if (gui->is_item_active() && !state->active)
			{
				state->active = true;
				state->timer = ImGui::GetTime();
			}
			else if (!gui->is_item_hovered(0) && GetIO().MouseClicked[0]) {
				state->active = false;
			}

			if (state->active) {

				if (ImGui::GetTime() - state->timer > 0.01f) {

					for (int i = 0; i < ImGuiKey_COUNT; ++i) {
						if (IsKeyPressed((ImGuiKey)i)) {
							*key = i;
							state->active = false;
						}
					}

					if (IsKeyPressed(ImGuiKey_Escape)) {
						*key = 0;
						state->active = false;
					}

				}
			}

			float next_width = (gui->content_avail().x - s_(elements->checkbox.padding.x)) / 2;

			if (gui->invisible_button("hold", c_vec2(next_width, s_(30))))
			{
				*mode = 0;
			}
			draw->rect_filled(window->DrawList, GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->hold_color), s_(elements->child.rounding));
			draw->text_clipped(window->DrawList, font->get(inter, 12), GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->hold_text), "Hold", 0, 0, { 0.5, 0.5 });

			gui->sameline();

			if (gui->invisible_button("toggle", c_vec2(next_width, s_(30))))
			{
				*mode = 1;
			}
			draw->rect_filled(window->DrawList, GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->toggle_color), s_(elements->child.rounding));
			draw->text_clipped(window->DrawList, font->get(inter, 12), GetItemRectMin(), GetItemRectMax(), draw->get_clr(state->toggle_text), "Toggle", 0, 0, { 0.5, 0.5 });
		
			if (!rect.Contains(gui->mouse_pos()) && (gui->mouse_clicked(0) || gui->mouse_clicked(1)))
			{
				state->open = false;
			}
		}
		gui->end();

		gui->pop_var(2);
	}
	gui->pop_var();
}