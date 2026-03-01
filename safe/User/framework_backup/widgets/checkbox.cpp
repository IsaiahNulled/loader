#include "../headers/includes.h"

struct checkbox_ex_state {
	c_vec4 text;
	float alpha;
};

bool checkbox_ex(std::string name, bool* enabled, keybind_t* keybind)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	checkbox_ex_state* state = gui->anim_container< checkbox_ex_state>(id);

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->checkbox.size));
	c_rect rect = c_rect(pos, pos + size);
	c_rect inner = c_rect(rect.Min + s_(elements->checkbox.padding), rect.Max - s_(elements->checkbox.padding));
	c_rect button = c_rect(c_vec2(inner.Min.x, inner.GetCenter().y - s_(elements->checkbox.button.y) / 2), c_vec2(inner.Min.x + s_(elements->checkbox.button.x), inner.GetCenter().y + s_(elements->checkbox.button.y) / 2));

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

	if (pressed)
		*enabled = !*enabled;

	gui->easing(state->text, *enabled ? clr->white.Value : clr->text.Value, 24.f, dynamic_easing);
	gui->easing(state->alpha, *enabled ? 1.f : 0.f, 24.f, dynamic_easing);

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(elements->child.rounding));
	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));

	draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->deter), s_(elements->checkbox.button_rounding));
	draw->rect(window->DrawList, button.Min, button.Max, draw->get_clr(clr->border), s_(elements->checkbox.button_rounding));
	draw->rect_filled(window->DrawList, button.GetCenter() - (button.GetSize() / 2) * state->alpha, button.GetCenter() + (button.GetSize() / 2) * state->alpha, draw->get_clr(clr->accent, state->alpha), s_(elements->checkbox.button_rounding));
	draw->text_clipped(window->DrawList, font->get(icon_font, 8), button.Min, button.Max, draw->get_clr(clr->white, state->alpha), "G", 0, 0, {0.5, 0.5});

	draw->text_clipped(window->DrawList, font->get(inter, 12), inner.Min + s_(elements->checkbox.button.x + elements->checkbox.padding.x, 0), inner.Max, draw->get_clr(state->text), name.data(), 0, 0, { 0, 0.5 });

	widgets->keybind(name, &keybind->key, &keybind->mode, rect);

	return pressed;
}

bool c_widgets::checkbox(std::string name)
{
	checkbox_t* data = &cfg->get<checkbox_t>(name);
	return checkbox_ex(data->name, &data->enabled, &data->keybind);
}