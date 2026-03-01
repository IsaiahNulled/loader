#include "../headers/includes.h"

struct colorpicker_ex_state {
	bool init_val;
	struct {
		bool open;
		float alpha;
	} window;
	struct {
		float h, s, v, a;
	} hsv;
};

bool colorpicker_ex(std::string name, c_vec4* color)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	colorpicker_ex_state* state = gui->anim_container<colorpicker_ex_state>(id);

	if (!state->init_val)
	{
		ImGui::ColorConvertRGBtoHSV(color->x, color->y, color->z, state->hsv.h, state->hsv.s, state->hsv.v);
		state->hsv.a = color->w;
		state->init_val = true;
	}

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->colorpicker.size));
	c_rect rect = c_rect(pos, pos + size);
	c_rect inner = c_rect(rect.Min + s_(elements->colorpicker.padding), rect.Max - s_(elements->colorpicker.padding));
	c_rect button = c_rect(inner.Max.x - s_(elements->colorpicker.button_size.x), inner.GetCenter().y - s_(elements->colorpicker.button_size.y) / 2, inner.Max.x, inner.GetCenter().y + s_(elements->colorpicker.button_size.y) / 2);

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

	if (pressed && !state->window.open)
	{
		state->window.open = true;
	}

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(elements->child.rounding));
	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));

	draw->text_clipped(window->DrawList, font->get(inter, 12), inner.Min, inner.Max, draw->get_clr(clr->white), name.data(), 0, 0, { 0, 0.5 });

	draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(*color), s_(elements->colorpicker.button_rounding));

	gui->easing(state->window.alpha, state->window.open ? 1.f : 0.f, 6.f, static_easing);

	if (state->window.alpha > 0.01f)
	{
		gui->set_next_window_size(c_vec2(button.GetWidth() * 10, 0));
		gui->set_next_window_pos(button.Min);

		gui->push_var(style_var_alpha, state->window.alpha);
		gui->push_var(style_var_window_padding, s_(elements->dropdown.window_padding));
		gui->push_var(style_var_item_spacing, s_(elements->dropdown.window_padding));

		gui->begin(std::to_string(id), nullptr, window_flags_always_auto_resize | window_flags_no_background | window_flags_no_decoration | window_flags_no_move);

		gui->set_window_focus();

		window = gui->get_window();
		rect = window->Rect();

		draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(elements->dropdown.button_rounding));
		draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->dropdown.button_rounding));

		if (!rect.Contains(gui->mouse_pos()) && gui->mouse_clicked(0))
		{
			state->window.open = false;
		}

		{
			c_rect slider_rect_button;
			c_rect slider_rect_grab;
			widgets->custom_slider("Hue", &state->hsv.h, 0.f, 1.f, &slider_rect_button, &slider_rect_grab);

			const ImColor col_hues[7] = { ImColor(255, 0, 0), ImColor(255, 255, 0), ImColor(0, 255, 0), ImColor(0, 255, 255), ImColor(0, 0, 255), ImColor(255, 0, 255), ImColor(255, 0, 0) };

			for (int i = 0; i < 6; ++i) {
				float rounding = (i == 0) || (i == 5) ? s_(elements->slider.button_rounding) : 0;
				draw_flags flags = (i == 0) ? draw_flags_round_corners_left : (i == 5) ? draw_flags_round_corners_right : 0;
				draw->rect_filled_multi_color(window->DrawList, ImVec2(roundf(slider_rect_button.Min.x + i * (slider_rect_button.GetWidth() / 6)), slider_rect_button.Min.y), ImVec2(roundf(slider_rect_button.Min.x + (i + 1) * (slider_rect_button.GetWidth() / 6)), slider_rect_button.Max.y), draw->get_clr(col_hues[i]), draw->get_clr(col_hues[i + 1]), draw->get_clr(col_hues[i + 1]), draw->get_clr(col_hues[i]), rounding, flags);
			}

			draw->rect_filled(window->DrawList, slider_rect_grab.Min, slider_rect_grab.Max, draw->get_clr(clr->white), s_(elements->slider.button_rounding));
		}

		{
			c_rect slider_rect_button;
			c_rect slider_rect_grab;
			widgets->custom_slider("Saturation", &state->hsv.s, 0.f, 1.f, &slider_rect_button, &slider_rect_grab);
			draw->rect_filled_multi_color(window->DrawList, slider_rect_button.Min, slider_rect_button.Max, draw->get_clr(c_col(255, 255, 255)), draw->get_clr(ImColor::HSV(state->hsv.h, 1.f, 1.f)), draw->get_clr(ImColor::HSV(state->hsv.h, 1.f, 1.f)), draw->get_clr(c_col(255, 255, 255)), s_(elements->slider.button_rounding));
			draw->rect_filled(window->DrawList, slider_rect_grab.Min, slider_rect_grab.Max, draw->get_clr(clr->white), s_(elements->slider.button_rounding));
		}

		{
			c_rect slider_rect_button;
			c_rect slider_rect_grab;
			widgets->custom_slider("Braightness", &state->hsv.v, 0.f, 1.f, &slider_rect_button, &slider_rect_grab);
			draw->rect_filled_multi_color(window->DrawList, slider_rect_button.Min, slider_rect_button.Max, draw->get_clr(c_col(0, 0, 0)), draw->get_clr(c_col(255, 255, 255)), draw->get_clr(c_col(255, 255, 255)), draw->get_clr(c_col(0, 0, 0)), s_(elements->slider.button_rounding));
			draw->rect_filled(window->DrawList, slider_rect_grab.Min, slider_rect_grab.Max, draw->get_clr(clr->white), s_(elements->slider.button_rounding));
		}

		{
			c_rect slider_rect_button;
			c_rect slider_rect_grab;
			widgets->custom_slider("Alpha", &state->hsv.a, 0.f, 1.f, &slider_rect_button, &slider_rect_grab);
			draw->rect_filled_multi_color(window->DrawList, slider_rect_button.Min, slider_rect_button.Max, draw->get_clr(c_col(255, 255, 255)), draw->get_clr(ImColor::HSV(state->hsv.h, 1.f, 1.f)), draw->get_clr(ImColor::HSV(state->hsv.h, 1.f, 1.f)), draw->get_clr(c_col(255, 255, 255)), s_(elements->slider.button_rounding));
			draw->rect_filled(window->DrawList, slider_rect_grab.Min, slider_rect_grab.Max, draw->get_clr(clr->white), s_(elements->slider.button_rounding));
		}

		ImGui::ColorConvertHSVtoRGB(state->hsv.h, state->hsv.s, state->hsv.v, color->x, color->y, color->z);
		color->w = state->hsv.a;

		gui->end();
		gui->pop_var(3);
	}

	return pressed;
}

bool c_widgets::colorpicker(std::string name, c_vec4* color)
{
	return colorpicker_ex(name, color);
}