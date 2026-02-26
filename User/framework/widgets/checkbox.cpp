#include "../headers/includes.h"

struct checkbox_ex_state {
  c_vec4 text;
  float alpha;
};

bool checkbox_ex(std::string name, bool *enabled, keybind_t *keybind) {
  c_window *window = gui->get_window();
  if (window->SkipItems)
    return false;

  c_id id = window->GetID(name.data());
  checkbox_ex_state *state = gui->anim_container<checkbox_ex_state>(id);

  c_vec2 pos = window->DC.CursorPos;
  c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->checkbox.size));
  c_rect rect = c_rect(pos, pos + size);
  c_rect inner = c_rect(rect.Min + s_(elements->checkbox.padding),
                        rect.Max - s_(elements->checkbox.padding));
  c_rect button =
      c_rect(c_vec2(inner.Min.x,
                    inner.GetCenter().y - s_(elements->checkbox.button.y) / 2),
             c_vec2(inner.Min.x + s_(elements->checkbox.button.x),
                    inner.GetCenter().y + s_(elements->checkbox.button.y) / 2));

  gui->item_size(rect);
  if (!gui->item_add(rect, id))
    return false;

  bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);

  if (pressed)
    *enabled = !*enabled;

  gui->easing(state->text, *enabled ? clr->white.Value : clr->text.Value, 24.f,
              dynamic_easing);
  gui->easing(state->alpha, *enabled ? 1.f : 0.f, 24.f, dynamic_easing);

  draw->rect_filled(window->DrawList, rect.Min, rect.Max,
                    draw->get_clr(clr->widget), s_(elements->child.rounding));
  draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border),
             s_(elements->child.rounding));

  draw->rect_filled(window->DrawList, button.Min, button.Max,
                    draw->get_clr(clr->deter),
                    s_(elements->checkbox.button_rounding));
  draw->rect(window->DrawList, button.Min, button.Max,
             draw->get_clr(clr->border),
             s_(elements->checkbox.button_rounding));
  draw->rect_filled(window->DrawList,
                    button.GetCenter() - (button.GetSize() / 2) * state->alpha,
                    button.GetCenter() + (button.GetSize() / 2) * state->alpha,
                    draw->get_clr(clr->accent, state->alpha),
                    s_(elements->checkbox.button_rounding));
  if (UI_Icons::CheckmarkTexture) {
    float icon_size = 12.0f;
    c_vec2 center = button.GetCenter();
    c_vec2 min = center - c_vec2(icon_size / 2, icon_size / 2);
    c_vec2 max = center + c_vec2(icon_size / 2, icon_size / 2);
    window->DrawList->AddImage(UI_Icons::CheckmarkTexture, min, max,
                               ImVec2(0, 0), ImVec2(1, 1),
                               draw->get_clr(clr->white, state->alpha));
  } else {
    draw->text_clipped(window->DrawList, font->get(icon_font, 8), button.Min,
                       button.Max, draw->get_clr(clr->white, state->alpha), "G",
                       0, 0, {0.5, 0.5});
  }

  draw->text_clipped(
      window->DrawList, font->get(inter, 12),
      inner.Min +
          s_(elements->checkbox.button.x + elements->checkbox.padding.x, 0),
      inner.Max, draw->get_clr(state->text), name.data(), 0, 0, {0, 0.5});

  widgets->keybind(name, &keybind->key, &keybind->mode, rect);

  return pressed;
}

bool c_widgets::checkbox(std::string name) {
  checkbox_t *data = &cfg->get<checkbox_t>(name);
  return checkbox_ex(data->name, &data->enabled, &data->keybind);
}

// ── ESP checkbox: right-click shows distance slider + color picker instead of
// keybind ──

struct esp_popup_state {
  bool open;
  float alpha;
  c_vec2 pos;
};

bool c_widgets::checkbox_esp(std::string name, float *maxDist, c_vec4 *color) {
  checkbox_t *data = &cfg->get<checkbox_t>(name);
  bool *enabled = &data->enabled;

  c_window *window = gui->get_window();
  if (window->SkipItems)
    return false;

  c_id id = window->GetID(name.data());
  checkbox_ex_state *state = gui->anim_container<checkbox_ex_state>(id);

  c_vec2 pos = window->DC.CursorPos;
  c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->checkbox.size));
  c_rect rect = c_rect(pos, pos + size);
  c_rect inner = c_rect(rect.Min + s_(elements->checkbox.padding),
                        rect.Max - s_(elements->checkbox.padding));
  c_rect button =
      c_rect(c_vec2(inner.Min.x,
                    inner.GetCenter().y - s_(elements->checkbox.button.y) / 2),
             c_vec2(inner.Min.x + s_(elements->checkbox.button.x),
                    inner.GetCenter().y + s_(elements->checkbox.button.y) / 2));

  gui->item_size(rect);
  if (!gui->item_add(rect, id))
    return false;

  bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);
  if (pressed)
    *enabled = !*enabled;

  gui->easing(state->text, *enabled ? clr->white.Value : clr->text.Value, 24.f,
              dynamic_easing);
  gui->easing(state->alpha, *enabled ? 1.f : 0.f, 24.f, dynamic_easing);

  // Draw checkbox body
  draw->rect_filled(window->DrawList, rect.Min, rect.Max,
                    draw->get_clr(clr->widget), s_(elements->child.rounding));
  draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border),
             s_(elements->child.rounding));

  // Toggle button
  draw->rect_filled(window->DrawList, button.Min, button.Max,
                    draw->get_clr(clr->deter),
                    s_(elements->checkbox.button_rounding));
  draw->rect(window->DrawList, button.Min, button.Max,
             draw->get_clr(clr->border),
             s_(elements->checkbox.button_rounding));
  draw->rect_filled(window->DrawList,
                    button.GetCenter() - (button.GetSize() / 2) * state->alpha,
                    button.GetCenter() + (button.GetSize() / 2) * state->alpha,
                    draw->get_clr(clr->accent, state->alpha),
                    s_(elements->checkbox.button_rounding));
  if (UI_Icons::CheckmarkTexture) {
    float icon_size = 12.0f;
    c_vec2 center = button.GetCenter();
    c_vec2 mn = center - c_vec2(icon_size / 2, icon_size / 2);
    c_vec2 mx = center + c_vec2(icon_size / 2, icon_size / 2);
    window->DrawList->AddImage(UI_Icons::CheckmarkTexture, mn, mx, ImVec2(0, 0),
                               ImVec2(1, 1),
                               draw->get_clr(clr->white, state->alpha));
  }

  // Label
  draw->text_clipped(
      window->DrawList, font->get(inter, 12),
      inner.Min +
          s_(elements->checkbox.button.x + elements->checkbox.padding.x, 0),
      inner.Max, draw->get_clr(state->text), name.data(), 0, 0, {0, 0.5});

  // Color preview swatch on the right side
  if (color) {
    float swatchSize = s_(14.0f);
    c_vec2 swatchMin =
        c_vec2(inner.Max.x - swatchSize, inner.GetCenter().y - swatchSize / 2);
    c_vec2 swatchMax =
        c_vec2(inner.Max.x, inner.GetCenter().y + swatchSize / 2);
    draw->rect_filled(window->DrawList, swatchMin, swatchMax,
                      IM_COL32((int)(color->x * 255), (int)(color->y * 255),
                               (int)(color->z * 255), (int)(color->w * 255)),
                      s_(3.0f));
    draw->rect(window->DrawList, swatchMin, swatchMax,
               draw->get_clr(clr->border), s_(3.0f));
  }

  // ── Right-click popup: distance slider + color picker ──
  std::string popupName = name + "##esp_popup";
  c_id popupId = window->GetID(popupName.data());
  esp_popup_state *pstate = gui->anim_container<esp_popup_state>(popupId);

  if (rect.Contains(gui->mouse_pos()) && gui->is_window_hovered(0) &&
      gui->mouse_clicked(1) && !pstate->open) {
    pstate->open = true;
    pstate->pos = gui->mouse_pos();
  }

  gui->easing(pstate->alpha, pstate->open ? 1.f : 0.f, 6.f, static_easing);

  gui->push_var(style_var_alpha, pstate->alpha);
  if (pstate->alpha > 0) {
    gui->set_next_window_size(c_vec2(s_(200.0f), 0));
    gui->set_next_window_pos(pstate->pos);

    gui->push_var(style_var_window_padding, s_(8, 8));
    gui->push_var(style_var_item_spacing, s_(4, 4));

    gui->begin(popupName, nullptr,
               window_flags_no_move | window_flags_no_decoration |
                   window_flags_no_background |
                   window_flags_always_auto_resize);
    {
      gui->set_window_focus();

      c_window *pw = gui->get_window();
      c_rect prect = pw->Rect();

      draw->rect_filled(pw->DrawList, prect.Min, prect.Max,
                        draw->get_clr(clr->child),
                        s_(elements->child.rounding));
      draw->rect(pw->DrawList, prect.Min, prect.Max, draw->get_clr(clr->border),
                 s_(elements->child.rounding));

      // Distance slider
      if (maxDist) {
        ImGui::PushItemWidth(-1);
        float avail = gui->content_avail().x;
        c_vec2 sliderPos = pw->DC.CursorPos;
        c_vec2 sliderSize = c_vec2(avail, s_(28.0f));

        // Label
        draw->text(pw->DrawList, font->get(inter, 10), s_(10.0f),
                   sliderPos + c_vec2(0, s_(2.0f)), draw->get_clr(clr->text),
                   "Max Distance");
        gui->dummy(c_vec2(0, s_(16.0f)));

        // Slider
        ImGui::PushID("dist_slider");
        ImGui::SetNextItemWidth(avail);
        ImGui::SliderFloat("##dist", maxDist, 50.f, 2000.f, "%.0f m");
        ImGui::PopID();

        gui->dummy(c_vec2(0, s_(4.0f)));
        ImGui::PopItemWidth();
      }

      // Color picker
      if (color) {
        draw->text(pw->DrawList, font->get(inter, 10), s_(10.0f),
                   pw->DC.CursorPos + c_vec2(0, s_(2.0f)),
                   draw->get_clr(clr->text), "Color");
        gui->dummy(c_vec2(0, s_(16.0f)));

        ImGui::PushID("clr_picker");
        float col[4] = {color->x, color->y, color->z, color->w};
        ImGui::SetNextItemWidth(gui->content_avail().x);
        if (ImGui::ColorEdit4("##color", col,
                              ImGuiColorEditFlags_NoInputs |
                                  ImGuiColorEditFlags_NoLabel |
                                  ImGuiColorEditFlags_AlphaBar)) {
          color->x = col[0];
          color->y = col[1];
          color->z = col[2];
          color->w = col[3];
        }
        ImGui::PopID();
      }

      // Close when clicking outside
      if (!prect.Contains(gui->mouse_pos()) &&
          (gui->mouse_clicked(0) || gui->mouse_clicked(1))) {
        pstate->open = false;
      }
    }
    gui->end();

    gui->pop_var(2);
  }
  gui->pop_var();

  return pressed;
}

// ── Bright Night checkbox: right-click shows intensity slider ──

bool c_widgets::checkbox_slider(std::string name, float *slider_val,
                                float min_val, float max_val,
                                const char *format) {
  checkbox_t *data = &cfg->get<checkbox_t>(name);
  bool *enabled = &data->enabled;

  c_window *window = gui->get_window();
  if (window->SkipItems)
    return false;

  c_id id = window->GetID(name.data());
  checkbox_ex_state *state = gui->anim_container<checkbox_ex_state>(id);

  c_vec2 pos = window->DC.CursorPos;
  c_vec2 size = c_vec2(gui->content_avail().x, s_(elements->checkbox.size));
  c_rect rect = c_rect(pos, pos + size);
  c_rect inner = c_rect(rect.Min + s_(elements->checkbox.padding),
                        rect.Max - s_(elements->checkbox.padding));
  c_rect button =
      c_rect(c_vec2(inner.Min.x,
                    inner.GetCenter().y - s_(elements->checkbox.button.y) / 2),
             c_vec2(inner.Min.x + s_(elements->checkbox.button.x),
                    inner.GetCenter().y + s_(elements->checkbox.button.y) / 2));

  gui->item_size(rect);
  if (!gui->item_add(rect, id))
    return false;

  bool pressed = gui->button_behavior(rect, id, nullptr, nullptr);
  if (pressed)
    *enabled = !*enabled;

  gui->easing(state->text, *enabled ? clr->white.Value : clr->text.Value, 24.f,
              dynamic_easing);
  gui->easing(state->alpha, *enabled ? 1.f : 0.f, 24.f, dynamic_easing);

  // Draw checkbox body
  draw->rect_filled(window->DrawList, rect.Min, rect.Max,
                    draw->get_clr(clr->widget), s_(elements->child.rounding));
  draw->rect(window->DrawList, rect.Min, rect.Max, draw->get_clr(clr->border),
             s_(elements->child.rounding));

  // Toggle button
  draw->rect_filled(window->DrawList, button.Min, button.Max,
                    draw->get_clr(clr->deter),
                    s_(elements->checkbox.button_rounding));
  draw->rect(window->DrawList, button.Min, button.Max,
             draw->get_clr(clr->border),
             s_(elements->checkbox.button_rounding));
  draw->rect_filled(window->DrawList,
                    button.GetCenter() - (button.GetSize() / 2) * state->alpha,
                    button.GetCenter() + (button.GetSize() / 2) * state->alpha,
                    draw->get_clr(clr->accent, state->alpha),
                    s_(elements->checkbox.button_rounding));
  if (UI_Icons::CheckmarkTexture) {
    float icon_size = 12.0f;
    c_vec2 center = button.GetCenter();
    c_vec2 mn = center - c_vec2(icon_size / 2, icon_size / 2);
    c_vec2 mx = center + c_vec2(icon_size / 2, icon_size / 2);
    window->DrawList->AddImage(UI_Icons::CheckmarkTexture, mn, mx, ImVec2(0, 0),
                               ImVec2(1, 1),
                               draw->get_clr(clr->white, state->alpha));
  }

  // Label
  draw->text_clipped(
      window->DrawList, font->get(inter, 12),
      inner.Min +
          s_(elements->checkbox.button.x + elements->checkbox.padding.x, 0),
      inner.Max, draw->get_clr(state->text), name.data(), 0, 0, {0, 0.5});

  // ── Right-click popup: intensity slider ──
  std::string popupName = name + "##slider_popup";
  c_id popupId = window->GetID(popupName.data());
  esp_popup_state *pstate = gui->anim_container<esp_popup_state>(popupId);

  if (rect.Contains(gui->mouse_pos()) && gui->is_window_hovered(0) &&
      gui->mouse_clicked(1) && !pstate->open) {
    pstate->open = true;
    pstate->pos = gui->mouse_pos();
  }

  gui->easing(pstate->alpha, pstate->open ? 1.f : 0.f, 6.f, static_easing);

  gui->push_var(style_var_alpha, pstate->alpha);
  if (pstate->alpha > 0) {
    gui->set_next_window_size(c_vec2(s_(200.0f), 0));
    gui->set_next_window_pos(pstate->pos);

    gui->push_var(style_var_window_padding, s_(8, 8));
    gui->push_var(style_var_item_spacing, s_(4, 4));

    gui->begin(popupName, nullptr,
               window_flags_no_move | window_flags_no_decoration |
                   window_flags_no_background |
                   window_flags_always_auto_resize);
    {
      gui->set_window_focus();
      c_window *pw = gui->get_window();
      c_rect prect = pw->Rect();

      draw->rect_filled(pw->DrawList, prect.Min, prect.Max,
                        draw->get_clr(clr->child),
                        s_(elements->child.rounding));
      draw->rect(pw->DrawList, prect.Min, prect.Max, draw->get_clr(clr->border),
                 s_(elements->child.rounding));

      if (slider_val) {
        ImGui::PushItemWidth(-1);
        float avail = gui->content_avail().x;
        c_vec2 sliderPos = pw->DC.CursorPos;

        // Label
        draw->text(pw->DrawList, font->get(inter, 10), s_(10.0f),
                   sliderPos + c_vec2(0, s_(2.0f)), draw->get_clr(clr->text),
                   "Intensity");
        gui->dummy(c_vec2(0, s_(16.0f)));

        // Slider
        ImGui::PushID("intens_slider");
        ImGui::SetNextItemWidth(avail);
        ImGui::SliderFloat("##intens", slider_val, min_val, max_val, format);
        ImGui::PopID();

        gui->dummy(c_vec2(0, s_(4.0f)));
        ImGui::PopItemWidth();
      }

      // Close when clicking outside
      if (!prect.Contains(gui->mouse_pos()) &&
          (gui->mouse_clicked(0) || gui->mouse_clicked(1))) {
        pstate->open = false;
      }
    }
    gui->end();
    gui->pop_var(2);
  }
  gui->pop_var();

  return pressed;
}