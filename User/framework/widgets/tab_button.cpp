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
	if (icon == "SKULL" && UI_Icons::SkullTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::SkullTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "EYE" && UI_Icons::EyeTexture) {
		float size = 16.0f; 
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::EyeTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "SLIDERS" && UI_Icons::SlidersTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::SlidersTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "GEAR" && UI_Icons::GearTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::GearTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "FOLDER" && UI_Icons::FolderTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::FolderTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "PLAYER" && UI_Icons::PlayerTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::PlayerTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "ANIMAL" && UI_Icons::AnimalTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::AnimalTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "WORLD" && UI_Icons::WorldTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::WorldTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else if (icon == "COLLECTIBLE" && UI_Icons::CollectibleTexture) {
		float size = 16.0f;
		c_vec2 center = rect.GetCenter();
		c_vec2 min = center - c_vec2(size/2, size/2);
		c_vec2 max = center + c_vec2(size/2, size/2);
		window->DrawList->AddImage(UI_Icons::CollectibleTexture, min, max, ImVec2(0,0), ImVec2(1,1), draw->get_clr(state->icon));
	} else {
		ImFont* icon_f = (icon.size() > 1 && (unsigned char)icon[0] > 0x7F) ? font->get(inter, 15) : font->get(icon_font, 15);
		draw->text_clipped(window->DrawList, icon_f, rect.Min, rect.Max, draw->get_clr(state->icon), icon.data(), 0, 0, { 0.5, 0.5 });
	}

	return pressed;
}

bool c_widgets::button(std::string name)
{
	c_window* window = gui->get_window();
	if (window->SkipItems)
		return false;

	c_id id = window->GetID(name.data());
	tab_button_state* state = gui->anim_container<tab_button_state>(id);

	float width = ImGui::GetContentRegionAvail().x;
	c_vec2 pos = window->DC.CursorPos;
	c_vec2 size = c_vec2(width, s_(30.0f)); 
	c_rect rect = c_rect(pos, pos + size);

	gui->item_size(rect);
	if (!gui->item_add(rect, id))
		return false;

	bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);
	bool hovered = ImGui::IsItemHovered();

	float target = pressed ? 0.4f : (hovered ? 0.2f : 0.0f);
	gui->easing(state->alpha, target, 10.f, dynamic_easing);

	draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->widget), s_(4.0f));
	
	if (state->alpha > 0.01f)
		draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->accent, state->alpha), s_(4.0f));

	draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(4.0f));

	c_vec2 text_sz = gui->text_size(font->get(inter, 15), name.data(), 0, false, 0);
	draw->text(window->DrawList, font->get(inter, 15), s_(15.0f), rect.GetCenter() - text_sz/2, draw->get_clr(clr->text), name.data());

	return pressed;
}