#include "../headers/config.h"

void c_config::init_config()
{
    static bool init = false;

    if (!init)
    {

        /* Aimbot */
        add_option<checkbox_t>("Aimbot");
        add_option<slider_t>("Aimbot FOV", 100.f, 0.f, 500.f);
        add_option<slider_t>("Smooth", 5.f, 1.f, 20.f);

        /* Visuals */
        add_option<checkbox_t>("Enable ESP"); // Master switch
        add_option<checkbox_t>("Box");
        add_option<checkbox_t>("Skeleton");
        add_option<checkbox_t>("Snaplines");
        add_option<checkbox_t>("Health");
        add_option<checkbox_t>("Name");
        add_option<checkbox_t>("Active Weapon");
        add_option<checkbox_t>("Distance");
        add_option<checkbox_t>("Corpse");
        add_option<checkbox_t>("SafeZone");
        add_option<checkbox_t>("Hotbar");

        /* Misc */
        add_option<checkbox_t>("No Recoil");
        add_option<checkbox_t>("Spider Man");
        add_option<checkbox_t>("Admin Flags");
        add_option<checkbox_t>("Bright Night");
        add_option<slider_t>("Time", 12.f, 0.f, 24.f); // For time changer
        
        /* Menu Settings */
        add_option<checkbox_t>("Enable scrollbar");
        add_option<slider_t>("Dpi scale", 100.f, 100.f, 200.f);
        add_option<dropdown_t>("Hitboxes", 0, std::vector<std::string>{"Head", "Chest", "Body", "Arms", "Legs"}); // Keep for aimbot

        init = true;
    }
}
