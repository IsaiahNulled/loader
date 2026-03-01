#pragma once
#include "../headers/flags.h"
#include "../headers/includes.h"
#include <memory>


class c_colors {
public:
  c_col layout{16, 14, 22};       // Dark background matching web loader
  c_col child{22, 19, 30};        // Slightly lighter card bg
  c_col border{50, 42, 65, 100};  // Subtle purple-tinted border
  c_col widget{28, 24, 36};       // Widget background
  c_col white{255, 255, 255};
  c_col text{200, 195, 210};      // Light lavender-gray text
  c_col accent{139, 92, 246};     // Purple accent (#8B5CF6) matching web loader
  c_col deter{38, 33, 48};        // Inactive/muted elements
};

inline std::unique_ptr<c_colors> clr = std::make_unique<c_colors>();
