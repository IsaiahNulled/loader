#include "../headers/includes.h"

void c_widgets::start_child(std::string name)
{
	gui->begin_content(name, c_vec2(elements->child.width, 0), s_(elements->child.padding), s_(elements->child.padding), window_flags_no_move, child_flags_always_auto_resize | child_flags_auto_resize_y);
	{
		c_window* window = gui->get_window();
		c_rect rect = window->Rect();
		draw->rect_filled(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->child), s_(elements->child.rounding));
		draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border), s_(elements->child.rounding));
	}
}

void c_widgets::end_child()
{
	gui->end_content();
}