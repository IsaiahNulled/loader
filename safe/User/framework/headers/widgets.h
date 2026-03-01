#pragma once
#include "../headers/config.h"
#include "includes.h"

#define IMGUI_DEFINE_MATH_OPERATORS

class c_widgets {
public:
  bool tab_button(std::string name, std::string icon, bool is_active);
  bool button(std::string name);
  void start_child(std::string name);
  void end_child();
  bool checkbox(std::string name);
  bool checkbox_esp(std::string name, float *maxDist, c_vec4 *color);
  bool checkbox_slider(std::string name, float *slider_val, float min_val,
                       float max_val, const char *format);
  bool slider(std::string name);
  bool dropdown(std::string name);
  bool colorpicker(std::string name, c_vec4 *color);
  bool custom_slider(std::string name, float *callback, float vmin, float vmax,
                     c_rect *out_button, c_rect *out_grab);
  void keybind(std::string name, int *key, int *mode, c_rect rect);
  void init_keybinds();
  bool checkbox_chams(std::string name);
  bool checkbox_skeleton(std::string name, float *thickness);
};

inline std::unique_ptr<c_widgets> widgets = std::make_unique<c_widgets>();

enum notify_type { success = 0, warning = 1, error = 2 };

struct notify_state {
  int notify_id;
  std::string_view text;
  notify_type type{success};

  ImVec2 window_size{0, 0};
  float notify_alpha{0};
  bool active_notify{true};
  float notify_timer{0};
  float notify_pos{0};
};

class c_notify {
public:
  void setup_notify();

  void add_notify(std::string_view text, notify_type type);

private:
  ImVec2 render_notify(int cur_notify_value, float notify_alpha,
                       float notify_percentage, float notify_pos,
                       std::string_view text, notify_type type);

  float notify_time{15};
  int notify_count{0};

  float notify_spacing{20};
  ImVec2 notify_padding{20, 20};

  std::vector<notify_state> notifications;
};

inline std::unique_ptr<c_notify> notify = std::make_unique<c_notify>();
