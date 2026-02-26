#pragma once
#include <string>
#include <vector>
#include "imgui.h"
#include "../headers/flags.h"


class c_variables
{
public:

	struct
	{
		float dpi = 0.9f;
		int stored_dpi = 90;
		bool dpi_changed = true;
		float tab_alpha = 1.f;
		int tab_stored = 0;
		int tab_current = 0;
		bool scrollbar_enabled = true;
	} gui;

	gui_style style;

};

inline std::unique_ptr<c_variables> var = std::make_unique<c_variables>();
