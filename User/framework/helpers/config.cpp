#include "../headers/config.h"
#include <fstream>
#include <string>

void c_config::init_config()
{
    static bool init = false;

    if (!init)
    {

        add_option<checkbox_t>("Enable scrollbar", true);
        add_option<checkbox_t>("Aimbot");
        add_option<dropdown_t>("Aimbot Key", 0, std::vector<std::string>{"Right Mouse", "Left Mouse", "Side Mouse 1", "Side Mouse 2", "Shift", "Ctrl", "Alt", "C", "V", "X"});
        add_option<checkbox_t>("Triggerbot");
        add_option<dropdown_t>("Hitboxes", 0, std::vector<std::string>{"Head", "Chest", "Body", "Arms", "Legs"});
        add_option<dropdown_t>("Multipoints", 0, std::vector<std::string>{"Head", "Chest", "Body", "Arms", "Legs"});
        add_option<dropdown_t>("Points", 0, std::vector<std::string>{"1", "2", "3", "4", "5"});
        add_option<slider_t>("Aimbot FOV", 50.f, 0.f, 100.f);
        add_option<slider_t>("Smooth", 0.5f, 0.f, 1.f);
        add_option<checkbox_t>("Silent Aim");
        add_option<checkbox_t>("Aimbot Prediction");
        add_option<slider_t>("Triggerbot delay", 50.f, 0.f, 100.f);
        add_option<slider_t>("Slider", 50.f, 0.f, 100.f);
        add_option<slider_t>("UI Scale", 1.0f, 0.33f, 1.0f);

        add_option<dropdown_t>("ESP Group", 0, std::vector<std::string>{"Player", "Animals", "World", "Collectibles"});
        add_option<checkbox_t>("Enable ESP");
        add_option<checkbox_t>("Enable Player ESP");
        add_option<checkbox_t>("Box");
        add_option<checkbox_t>("Skeleton");
        add_option<slider_t>("Skeleton thickness", 1.2f, 1.f, 5.f);
        add_option<checkbox_t>("Vischeck");
        add_option<checkbox_t>("Snaplines");
        add_option<checkbox_t>("Health");
        add_option<checkbox_t>("Name");
        add_option<checkbox_t>("Distance");
        add_option<checkbox_t>("Off-screen arrows");
        add_option<checkbox_t>("Radar");
        add_option<checkbox_t>("Animal ESP");
        add_option<checkbox_t>("Bear");
        add_option<checkbox_t>("Polar Bear");
        add_option<checkbox_t>("Wolf");
        add_option<checkbox_t>("Boar");
        add_option<checkbox_t>("Chicken");
        add_option<checkbox_t>("Horse");
        add_option<checkbox_t>("Stag");
        add_option<checkbox_t>("Shark");
        add_option<checkbox_t>("Deployable ESP");
        add_option<checkbox_t>("Ore ESP");
        add_option<checkbox_t>("Hemp ESP");
        add_option<checkbox_t>("Dropped Items");
        add_option<checkbox_t>("Hotbar ESP");
        add_option<checkbox_t>("Corpse");
        add_option<checkbox_t>("Insta Eoka");
        add_option<checkbox_t>("No Spread");
        add_option<slider_t>("Spread Control", 0.f, 0.f, 100.f);
        add_option<checkbox_t>("Reload Bar");
        add_option<checkbox_t>("Bullet Tracers");
        add_option<checkbox_t>("Auto Reload");
        add_option<checkbox_t>("Chams");
        add_option<checkbox_t>("Remove Layers");
        add_option<checkbox_t>("Third Person");
        add_option<checkbox_t>("No Recoil");
        add_option<slider_t>("Recoil Control", 100.f, 0.f, 100.f);
        add_option<checkbox_t>("Bright Night");
        add_option<checkbox_t>("Time Changer");
        add_option<slider_t>("Time Hour", 12.f, 0.f, 24.f);
        add_option<checkbox_t>("FOV Changer");
        add_option<slider_t>("Game FOV", 90.f, 60.f, 150.f);
        add_option<slider_t>("Zoom FOV", 25.f, 5.f, 60.f);
        add_option<dropdown_t>("Zoom Key", 3, std::vector<std::string>{"Right Mouse", "Left Mouse", "Side Mouse 1", "Side Mouse 2", "Shift", "Ctrl", "Alt", "C", "V", "X"});
        add_option<checkbox_t>("Streamproof");
        add_option<checkbox_t>("Terrain Remover");
        add_option<slider_t>("FPS Cap", 0.f, 0.f, 300.f);

        add_option<checkbox_t>("Spiderman");
        add_option<checkbox_t>("Flyhack");
        add_option<checkbox_t>("Omni Sprint");

        init = true;
    }
}

void c_config::Save(const std::string& path) {
    std::ofstream f(path);
    if (!f.is_open()) return;
    for (auto& [name, variant] : options) {
        if (auto val = std::get_if<checkbox_t>(&variant)) {
            f << "checkbox:" << name << "=" << val->enabled << "\n";
        } else if (auto val = std::get_if<slider_t>(&variant)) {
            f << "slider:" << name << "=" << val->callback << "\n";
        } else if (auto val = std::get_if<dropdown_t>(&variant)) {
            f << "dropdown:" << name << "=" << val->callback << "\n";
        }
    }
    f.close();
}

void c_config::Load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        size_t colon = line.find(':');
        size_t eq = line.find('=');
        if (colon == std::string::npos || eq == std::string::npos) continue;
        
        std::string type = line.substr(0, colon);
        std::string name = line.substr(colon + 1, eq - (colon + 1));
        std::string valStr = line.substr(eq + 1);
        
        auto it = options.find(name);
        if (it == options.end()) continue;

        if (type == "checkbox") {
            if (auto val = std::get_if<checkbox_t>(&it->second))
                val->enabled = (std::stoi(valStr) != 0);
        } else if (type == "slider") {
            if (auto val = std::get_if<slider_t>(&it->second))
                val->callback = std::stof(valStr);
        } else if (type == "dropdown") {
            if (auto val = std::get_if<dropdown_t>(&it->second))
                val->callback = std::stoi(valStr);
        }
    }
    f.close();
}
