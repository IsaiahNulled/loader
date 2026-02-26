#pragma once
#include <string>
#include "imgui.h"

class c_elements
{
public:

    struct 
    {
        c_text name{ "deadline" };
        c_vec2 size{ 550, 350 };
        float rounding{ 4 };
    } window;

    struct 
    {
        c_vec2 size{ 60, 350 }; 
        c_vec2 padding{ 5, 5 };
    } sidebar;

    struct 
    {
        c_vec2 padding{ 5, 5 };
    } content;

    struct {
        c_vec2 size{ 50, 50 };
        float rounding{ 3 };
    } tab_button;

    struct {
        float width{ };
        float rounding{ 3 };
        c_vec2 padding{ 5, 5 };
    } child;

    struct {
        float size{ 34 };
        c_vec2 padding{ 10, 10 };
        c_vec2 button{ 14, 14 };
        float button_rounding{ 2 };
    } checkbox;

    struct {
        float size{ 47 };
        float button_size{ 8 };
        c_vec2 grab_size{ 16, 10 };
        c_vec2 padding{ 10, 10 };
        float button_rounding{ 2 };
    } slider;

    struct {
        float size{ 10 };
        float alpha = 1.f;
        c_vec2 padding{ 5, 5 };
        float rounding{ 2 };
    } scrollbar;

    struct {
        float size{ 70 };
        float button_size{ 31 };
        float button_rounding{ 2 };
        c_vec2 padding{ 10, 10 };
        c_vec2 window_padding{ 5, 5 };
    } dropdown;

    struct {
        float size{ 32 };
        c_vec2 button_size{ 18, 10 };
        c_vec2 padding{ 10, 10 };
        float button_rounding{ 2 };
    } colorpicker;

};

inline std::unique_ptr<c_elements> elements = std::make_unique<c_elements>();
