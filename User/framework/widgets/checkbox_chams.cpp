#include "../headers/includes.h"

// ── Chams checkbox: right-click shows material selection ──

bool c_widgets::checkbox_chams(std::string name) {
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

  // Snap text color on first frame to avoid easing from black
  {
    ImVec4 target_text = *enabled ? clr->white.Value : clr->text.Value;
    if (state->text.x == 0.f && state->text.y == 0.f && state->text.z == 0.f && state->text.w == 0.f)
      state->text = target_text;
    else
      gui->easing(state->text, target_text, 24.f, dynamic_easing);
  }
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

  // Label with current material name
  std::string label = name + " [" + g_chamsMaterialName + "]";
  draw->text_clipped(
      window->DrawList, font->get(inter, 12),
      inner.Min +
          s_(elements->checkbox.button.x + elements->checkbox.padding.x, 0),
      inner.Max, draw->get_clr(state->text), label.data(), 0, 0, {0, 0.5});

  // ── Right-click popup: material selection ──
  std::string popupName = name + "##chams_popup";
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
    gui->set_next_window_size(c_vec2(s_(180.0f), 0));
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

      // Material options shared by both sections
      const struct { const char* name; unsigned int id; } materials[] = {
        {"Red", 1294354},{"Blue", 730730},{"Wireframe", 1348630}
      };
      const int matCount = 3;

      // ═══════════════════════════════════
      // SECTION: Player Chams Material
      // ═══════════════════════════════════
      draw->text(pw->DrawList, font->get(inter, 11), s_(11.0f),
                 pw->DC.CursorPos + c_vec2(0, s_(2.0f)),
                 draw->get_clr(clr->accent), "Player Chams");
      gui->dummy(c_vec2(0, s_(16.0f)));

      for (int i = 0; i < matCount; i++) {
        c_vec2 itemPos = pw->DC.CursorPos;
        c_vec2 itemSize = c_vec2(gui->content_avail().x, s_(24.0f));
        c_rect itemRect = c_rect(itemPos, itemPos + itemSize);

        std::string itemId = popupName + "##pmat" + std::to_string(i);
        c_id matId = pw->GetID(itemId.data());

        gui->item_size(itemRect);
        if (gui->item_add(itemRect, matId)) {
          bool selected = (g_chamsMaterialId == materials[i].id);
          bool clicked = gui->button_behavior(itemRect, matId, nullptr, nullptr);

          if (selected) {
            draw->rect_filled(pw->DrawList, itemRect.Min, itemRect.Max,
                              draw->get_clr(clr->accent, 0.3f),
                              s_(elements->dropdown.button_rounding));
          }

          draw->text_clipped(pw->DrawList, font->get(inter, 12),
                             itemRect.Min + s_(8, 0), itemRect.Max,
                             draw->get_clr(selected ? clr->white : clr->text),
                             materials[i].name, 0, 0, {0, 0.5});

          if (clicked) {
            g_chamsMaterialId = materials[i].id;
            g_chamsMaterialName = materials[i].name;
          }
        }
      }

      // ── Divider ──
      gui->dummy(c_vec2(0, s_(6.0f)));
      {
        c_vec2 divStart = pw->DC.CursorPos;
        c_vec2 divEnd = c_vec2(divStart.x + gui->content_avail().x, divStart.y + s_(1.0f));
        draw->rect_filled(pw->DrawList, divStart, divEnd,
                          draw->get_clr(clr->border), 0);
      }
      gui->dummy(c_vec2(0, s_(8.0f)));

      // ═══════════════════════════════════
      // SECTION: Hand Chams
      // ═══════════════════════════════════
      {
        // Header + toggle on same line
        c_vec2 headerPos = pw->DC.CursorPos;
        draw->text(pw->DrawList, font->get(inter, 11), s_(11.0f),
                   headerPos + c_vec2(0, s_(2.0f)),
                   draw->get_clr(clr->accent), "Hand Chams");

        // Toggle button on the right side of the header
        float toggleW = s_(60.0f);
        float toggleH = s_(20.0f);
        c_vec2 togglePos = c_vec2(headerPos.x + gui->content_avail().x - toggleW, headerPos.y);
        c_rect toggleRect = c_rect(togglePos, togglePos + c_vec2(toggleW, toggleH));

        std::string vmBtnId = popupName + "##vmtoggle";
        c_id vmBtnIdVal = pw->GetID(vmBtnId.data());

        gui->item_size(c_rect(headerPos, c_vec2(headerPos.x + gui->content_avail().x, headerPos.y + toggleH)));
        if (gui->item_add(toggleRect, vmBtnIdVal)) {
          bool clicked = gui->button_behavior(toggleRect, vmBtnIdVal, nullptr, nullptr);

          draw->rect_filled(pw->DrawList, toggleRect.Min, toggleRect.Max,
                            draw->get_clr(g_viewModelChams ? clr->accent : clr->widget), s_(3.0f));
          draw->rect(pw->DrawList, toggleRect.Min, toggleRect.Max,
                     draw->get_clr(clr->border), s_(3.0f));
          draw->text_clipped(pw->DrawList, font->get(inter, 10),
                             toggleRect.Min, toggleRect.Max,
                             draw->get_clr(clr->white),
                             g_viewModelChams ? "ON" : "OFF", 0, 0, {0.5, 0.5});

          if (clicked) {
            g_viewModelChams = !g_viewModelChams;
          }
        }
        gui->dummy(c_vec2(0, s_(24.0f)));
      }

      // Hand chams material list
      const struct { const char* name; unsigned int id; } vmMaterials[] = {
        {"Red", 1294354},{"Blue", 730730},{"Wireframe", 1348630}
      };
      const int vmMatCount = 3;

      for (int i = 0; i < vmMatCount; i++) {
        c_vec2 itemPos = pw->DC.CursorPos;
        c_vec2 itemSize = c_vec2(gui->content_avail().x, s_(24.0f));
        c_rect itemRect = c_rect(itemPos, itemPos + itemSize);

        std::string itemId = popupName + "##vmat" + std::to_string(i);
        c_id matId = pw->GetID(itemId.data());

        gui->item_size(itemRect);
        if (gui->item_add(itemRect, matId)) {
          bool selected = (g_vmChamsMaterialId == vmMaterials[i].id);
          bool clicked = gui->button_behavior(itemRect, matId, nullptr, nullptr);

          if (selected) {
            draw->rect_filled(pw->DrawList, itemRect.Min, itemRect.Max,
                              draw->get_clr(clr->accent, 0.3f),
                              s_(elements->dropdown.button_rounding));
          }

          draw->text_clipped(pw->DrawList, font->get(inter, 12),
                             itemRect.Min + s_(8, 0), itemRect.Max,
                             draw->get_clr(selected ? clr->white : clr->text),
                             vmMaterials[i].name, 0, 0, {0, 0.5});

          if (clicked) {
            g_vmChamsMaterialId = vmMaterials[i].id;
            g_vmChamsMaterialName = vmMaterials[i].name;
          }
        }
      }

      gui->dummy(c_vec2(0, s_(4.0f)));

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
