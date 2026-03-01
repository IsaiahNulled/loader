#include "../headers/includes.h"

struct slider_ex_state {
	float pos = 0.f;
	c_vec4 text = {0.78f, 0.76f, 0.82f, 1.0f}; // init to visible (matches clr->text)
};

bool slider_ex(std::string name, float* callback, float vmin, float vmax, std::string format, bool custom_slider = false, c_rect* out_button = 0, c_rect* out_grab = 0)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	slider_ex_state* state = gui->anim_container< slider_ex_state>(id);

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->slider.size));
	c_rect rect = c_rect(pos, pos + size);
	c_rect inner = c_rect(rect.Min + s_(elements->slider.padding), rect.Max - s_(elements->slider.padding));
	c_rect button = c_rect(inner.GetBL() - s_(0, elements->slider.button_size), inner.GetBR());

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool held, pressed = gui->button_behavior(rect, id, nullptr, &held);

	const float normalized = ImSaturate((gui->mouse_pos().x - button.Min.x) / button.GetWidth());

	if (held)
	{
		*callback = vmin + (vmax - vmin) * normalized;
	}

	{
		c_vec4 target_text = held ? clr->white.Value : clr->text.Value;
		if (state->text.x == 0.f && state->text.y == 0.f && state->text.z == 0.f && state->text.w == 0.f)
			state->text = target_text;
		else
			gui->easing(state->text, target_text, 24.f, dynamic_easing);
	}
	gui->easing(state->pos, ImSaturate((*callback - vmin) / (vmax - vmin)), 24.f, dynamic_easing);

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(elements->child.rounding));
	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));

	draw->text_clipped(window->DrawList, font->get(inter, 12), inner.Min, inner.Max, draw->get_clr(state->text), name.data(), 0, 0, { 0, 0 });
	char value_buf[64]; gui->get_fmt(value_buf, callback, format);
	draw->text_clipped(window->DrawList, font->get(inter, 12), inner.Min, inner.Max, draw->get_clr(clr->white), value_buf, 0, 0, { 1, 0 });

	if (!custom_slider)
	{
		draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->deter), s_(elements->slider.button_rounding));
		draw->rect(window->DrawList, button.Min, button.Max, draw->get_clr(clr->border), s_(elements->slider.button_rounding));
	
		float fill_w = button.GetWidth() * state->pos;
		if (fill_w < s_(3.0f)) fill_w = s_(3.0f);
		draw->rect_filled(window->DrawList, button.Min, button.Min + c_vec2(fill_w, button.GetHeight()), draw->get_clr(clr->accent), s_(elements->slider.button_rounding));
	}

	float grab_x = button.Min.x + button.GetWidth() * state->pos;
	grab_x = ImClamp(grab_x, button.Min.x + s_(elements->slider.grab_size.x) / 2, button.Max.x - s_(elements->slider.grab_size.x) / 2);

	if (!custom_slider)
		draw->rect_filled(window->DrawList, c_vec2(grab_x - s_(elements->slider.grab_size.x) / 2, button.GetCenter().y - s_(elements->slider.grab_size.y) / 2), c_vec2(grab_x + s_(elements->slider.grab_size.x) / 2, button.GetCenter().y + s_(elements->slider.grab_size.y) / 2), draw->get_clr(clr->white), s_(elements->slider.button_rounding));

	if (custom_slider)
	{
		*out_button = button;
		*out_grab = c_rect(c_vec2(grab_x - s_(elements->slider.grab_size.x) / 2, button.GetCenter().y - s_(elements->slider.grab_size.y) / 2), c_vec2(grab_x + s_(elements->slider.grab_size.x) / 2, button.GetCenter().y + s_(elements->slider.grab_size.y) / 2));
	}

	return held;
}

bool c_widgets::custom_slider(std::string name, float* callback, float vmin, float vmax, c_rect* out_button, c_rect* out_grab)
{
	return slider_ex(name, callback, vmin, vmax, "%.2f", true, out_button, out_grab);
}

bool c_widgets::slider(std::string name)
{
	slider_t* data = &cfg->get<slider_t>(name);
	return slider_ex(data->name, &data->callback, data->vmin, data->vmax, data->format);
}