#pragma once
#include "../headers/flags.h"
#include "../headers/includes.h"
#include <memory>


class c_colors {
public:
  c_col layout{15, 15, 18};
  c_col child{18, 18, 21};
  c_col border{28, 28, 34, 0};
  c_col widget{21, 21, 24};
  c_col white{255, 255, 255};
  c_col text{110, 110, 129};
  c_col accent{122, 145, 188};
  c_col deter{24, 24, 27};
};

inline std::unique_ptr<c_colors> clr = std::make_unique<c_colors>();
