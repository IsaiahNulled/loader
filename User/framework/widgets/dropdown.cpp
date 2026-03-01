#include "../headers/includes.h"

struct dropdown_ex_state {

	struct {
		bool open;
		float alpha;
	} window;

};

bool dropdown_ex(std::string name, std::string preview)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	dropdown_ex_state* state = gui->anim_container< dropdown_ex_state>(id);

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->dropdown.size));
	c_rect rect = c_rect(pos, pos + size);
	c_rect inner = c_rect(rect.Min + s_(elements->dropdown.padding), rect.Max - s_(elements->dropdown.padding));
	c_rect button = c_rect(inner.GetBL() - s_(0, elements->dropdown.button_size), inner.GetBR());

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(button, id, nullptr, nullptr);

	if (pressed && !state->window.open)
	{
		state->window.open = true;
	}

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(elements->child.rounding));
	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));

	draw->text_clipped(window->DrawList, font->get(inter, 12), inner.Min, inner.Max, draw->get_clr(clr->white), name.data(), 0, 0, { 0, 0 });

	draw->rect_filled(window->DrawList, button.Min, button.Max, draw->get_clr(clr->deter), s_(elements->dropdown.button_rounding));
	draw->rect(window->DrawList, button.Min, button.Max, draw->get_clr(clr->border), s_(elements->dropdown.button_rounding));

	draw->text_clipped(window->DrawList, font->get(inter, 12), button.Min + s_(elements->dropdown.padding.x, 0), button.Max, draw->get_clr(clr->white), preview.data(), 0, 0, { 0, 0.5 });
	draw->text_clipped(window->DrawList, font->get(icon_font, 6), button.Min, button.Max - s_(elements->dropdown.padding.x, 0), draw->get_clr(clr->text), "A", 0, 0, {1, 0.5});

	gui->easing(state->window.alpha, state->window.open ? 1.f : 0.f, 6.f, static_easing);

	if (state->window.alpha > 0.01f)
	{
		gui->set_next_window_size(c_vec2(button.GetWidth(), 0));
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

		if (!rect.Contains(gui->mouse_pos()) && (gui->mouse_clicked(0) || IsKeyPressed(ImGuiKey_MouseWheelY)))
		{
			state->window.open = false;
		}

		return true;
	}

	return false;
}

void end_dropdown_ex()
{
	gui->end();
	gui->pop_var(3);
}

struct selectable_ex_state {
	c_vec4 text = {0.78f, 0.76f, 0.82f, 1.0f};
	float alpha;
	float alpha2;
};

bool selectable_ex(std::string name, bool selected)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	selectable_ex_state* state = gui->anim_container< selectable_ex_state>(id);

	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(gui->content_avail().x, s_(30));
	c_rect rect = c_rect(pos, pos + size);

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

	gui->easing(state->text, selected ? clr->white.Value : clr->text.Value, 24.f, dynamic_easing);
	gui->easing(state->alpha, selected ? 1.f : 0.f, 24.f, dynamic_easing);
	gui->easing(state->alpha2, selected ? 1.f : 0.f, 6.f, static_easing);

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->deter, state->alpha2), s_(elements->dropdown.button_rounding));
	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border, state->alpha2), s_(elements->dropdown.button_rounding));
	draw->text_clipped(window->DrawList, font->get(inter, 12), rect.Min + s_(elements->dropdown.padding.x, 0), rect.Max, draw->get_clr(state->text), name.data(), 0, 0, {0, 0.5});

	return pressed;
}

bool c_widgets::dropdown(std::string name)
{
	dropdown_t* data = cfg->fill<dropdown_t>(name);

	bool value_changed = false;

	if (dropdown_ex(data->name, data->variants[data->callback]))
	{
		for (int i = 0; i < data->variants.size(); ++i)
		{
			if (selectable_ex(data->variants[i], i == data->callback))
			{
				data->callback = i;
				value_changed = true;
			}
			
		}

		end_dropdown_ex();
	}

	return value_changed;
}