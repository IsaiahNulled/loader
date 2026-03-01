#include "../headers/includes.h"

struct tab_button_state {
	float alpha;
	float alpha2;
	c_vec4 icon;
};

bool c_widgets::tab_button(std::string name, std::string icon, bool is_active)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	tab_button_state* state = gui->anim_container< tab_button_state>(id);

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = s_(elements->tab_button.size);
	c_rect rect = c_rect(pos, pos + size);

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

	gui->easing(state->alpha, is_active ? 1.f : 0.f, 24.f, dynamic_easing);
	gui->easing(state->alpha2, is_active ? 1.f : 0.f, 6.f, static_easing);
	gui->easing(state->icon, is_active ? clr->accent.Value : clr->text.Value, 24.f, dynamic_easing);

	draw->rect_filled(window->DrawList, rect.GetCenter() - (rect.GetSize() / 2) * state->alpha, rect.GetCenter() + (rect.GetSize() / 2) * state->alpha, draw->get_clr(clr->widget, state->alpha2), s_(elements->tab_button.rounding));
	draw->rect(window->DrawList, rect.GetCenter() - (rect.GetSize() / 2) * state->alpha, rect.GetCenter() + (rect.GetSize() / 2) * state->alpha, draw->get_clr(clr->border, state->alpha2), s_(elements->tab_button.rounding));
	draw->text_clipped(window->DrawList, font->get(icon_font, 15), rect.Min, rect.Max, draw->get_clr(state->icon), icon.data(), 0, 0, { 0.5, 0.5 });

	return pressed;
}