#include "globals.h"

// Forward declaration to ensure DriverComm is available
class DriverComm;

#include "driver_comm.h"

// Sync the ImGui config widgets into our runtime variables.
void SyncConfig() {
  // Aimbot
  Vars::Aim::enabled = cfg->get<checkbox_t>("Aimbot").enabled;
  Vars::Aim::fov = cfg->get<slider_t>("Aimbot FOV").callback;
  Vars::Aim::smooth = cfg->get<slider_t>("Smooth").callback;
  Vars::Aim::silentAim = cfg->get<checkbox_t>("Silent Aim").enabled;

  // Aimbot key mapping (dropdown index -> virtual key code)
  {
    static const int vkKeys[] = {
        VK_RBUTTON, VK_LBUTTON, VK_XBUTTON1, VK_XBUTTON2, VK_SHIFT,
        VK_CONTROL, VK_MENU,    0x43 /*C*/,  0x56 /*V*/,  0x58 /*X*/
    };
    int keyIdx = cfg->get<dropdown_t>("Aimbot Key").callback;
    if (keyIdx >= 0 && keyIdx < 10)
      Vars::Aim::aimKey = vkKeys[keyIdx];
    else
      Vars::Aim::aimKey = VK_RBUTTON;
  }

  // Hitbox selection (matches dropdown: Head, Chest, Body, Arms, Legs)
  int hitboxIdx = cfg->get<dropdown_t>("Hitboxes").callback;
  if (hitboxIdx == 0)
    Vars::Aim::targetBone = 47; // Head
  else if (hitboxIdx == 1)
    Vars::Aim::targetBone = 22; // Chest (spine4)
  else if (hitboxIdx == 2)
    Vars::Aim::targetBone = 20; // Body/Stomach (spine2)
  else if (hitboxIdx == 3)
    Vars::Aim::targetBone = 55; // Arms (r_upperarm)
  else if (hitboxIdx == 4)
    Vars::Aim::targetBone = 13; // Legs (r_hip)

  // Visuals
  g_espEnabled = cfg->get<checkbox_t>("Enable ESP").enabled;
  g_espBoxes = cfg->get<checkbox_t>("Box").enabled;
  g_espSkeleton = cfg->get<checkbox_t>("Skeleton").enabled;
  g_espSkeletonThickness = cfg->get<slider_t>("Skeleton thickness").callback;
  g_espVisCheck = cfg->get<checkbox_t>("Vischeck").enabled;
  g_espSnaplines = cfg->get<checkbox_t>("Snaplines").enabled;
  g_espHealthBar = cfg->get<checkbox_t>("Health").enabled;
  g_espNames = cfg->get<checkbox_t>("Name").enabled;
  g_espDistance = cfg->get<checkbox_t>("Distance").enabled;
  g_espShowWounded = cfg->get<checkbox_t>("Corpse").enabled;
  g_espRadar = cfg->get<checkbox_t>("Radar").enabled;
  g_espFOVArrows = cfg->get<checkbox_t>("Off-screen arrows").enabled;
  g_espAnimal = cfg->get<checkbox_t>("Animal ESP").enabled;
  g_espBear = cfg->get<checkbox_t>("Bear").enabled;
  g_espPolarBear = cfg->get<checkbox_t>("Polar Bear").enabled;
  g_espWolf = cfg->get<checkbox_t>("Wolf").enabled;
  g_espBoar = cfg->get<checkbox_t>("Boar").enabled;
  g_espChicken = cfg->get<checkbox_t>("Chicken").enabled;
  g_espHorse = cfg->get<checkbox_t>("Horse").enabled;
  g_espStag = cfg->get<checkbox_t>("Stag").enabled;
  g_espShark = cfg->get<checkbox_t>("Shark").enabled;
  g_espDeployable = cfg->get<checkbox_t>("Deployable ESP").enabled;
  g_espHotbar = cfg->get<checkbox_t>("Hotbar ESP").enabled;
  g_espOre = cfg->get<checkbox_t>("Ore ESP").enabled;
  g_espHemp = cfg->get<checkbox_t>("Hemp ESP").enabled;
  g_espDroppedItem = cfg->get<checkbox_t>("Dropped Items").enabled;

  // Weapon modifiers
  g_instaEoka = cfg->get<checkbox_t>("Insta Eoka").enabled;
  g_noSpread = cfg->get<checkbox_t>("No Spread").enabled;
  g_spreadScale = cfg->get<slider_t>("Spread Control").callback;
  g_reloadBar = cfg->get<checkbox_t>("Reload Bar").enabled;
  g_bulletTracers = cfg->get<checkbox_t>("Bullet Tracers").enabled;
  g_autoReload = cfg->get<checkbox_t>("Auto Reload").enabled;
  g_chams = cfg->get<checkbox_t>("Chams").enabled;
  // Combined terrain + layers toggle
  g_removeLayers = cfg->get<checkbox_t>("Remove Terrain").enabled;
  g_terrainRemover = g_removeLayers;

  // Movement exploits
  g_spiderman = cfg->get<checkbox_t>("Spiderman").enabled;

  // FPS cap (0 = uncapped)
  g_fpsCap = (int)cfg->get<slider_t>("FPS Cap").callback;

  // Misc
  g_noRecoilEnabled = cfg->get<checkbox_t>("No Recoil").enabled;
  g_recoilControl = cfg->get<slider_t>("Recoil Control").callback;
  g_brightNight = cfg->get<checkbox_t>("Bright Night").enabled;
  g_timeChanger = cfg->get<checkbox_t>("Time Changer").enabled;
  g_timeHour = cfg->get<slider_t>("Time Hour").callback;

    
  // Streamproof toggle (only applies when changed)
  bool streamproof = cfg->get<checkbox_t>("Streamproof").enabled;
  static bool lastStreamproof = false;
  if (streamproof != lastStreamproof) {
    if (g_hWnd && IsWindow(g_hWnd))
      SetWindowDisplayAffinity(g_hWnd,
                               streamproof ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
    lastStreamproof = streamproof;
  }
}

// ── File-based config persistence ──────────────────────────────────

void SaveConfig(const std::string &path) {
  std::ofstream f(path);
  if (!f.is_open()) {
    g_ConfigStatus = "Save failed!";
    g_ConfigStatusTime = GetTickCount64();
    return;
  }

  f << "[ESP]\n";
  f << "enabled=" << g_espEnabled << "\n";
  f << "boxes=" << g_espBoxes << "\n";
  f << "names=" << g_espNames << "\n";
  f << "distance=" << g_espDistance << "\n";
  f << "snaplines=" << g_espSnaplines << "\n";
  f << "healthbar=" << g_espHealthBar << "\n";
  f << "skeleton=" << g_espSkeleton << "\n";
  f << "vischeck=" << g_espVisCheck << "\n";
  f << "sleepers=" << g_espShowSleepers << "\n";
  f << "wounded=" << g_espShowWounded << "\n";
  f << "hotbar=" << g_espHotbar << "\n";
  f << "animal=" << g_espAnimal << "\n";
  f << "bear=" << g_espBear << "\n";
  f << "polarbear=" << g_espPolarBear << "\n";
  f << "wolf=" << g_espWolf << "\n";
  f << "boar=" << g_espBoar << "\n";
  f << "chicken=" << g_espChicken << "\n";
  f << "horse=" << g_espHorse << "\n";
  f << "stag=" << g_espStag << "\n";
  f << "shark=" << g_espShark << "\n";
  f << "deployable=" << g_espDeployable << "\n";
  f << "ore=" << g_espOre << "\n";
  f << "hemp=" << g_espHemp << "\n";
  f << "dropped=" << g_espDroppedItem << "\n";
  f << "playerdist=" << g_espPlayerMaxDist << "\n";
  f << "animaldist=" << g_espAnimalMaxDist << "\n";
  f << "oredist=" << g_espOreMaxDist << "\n";
  f << "hempdist=" << g_espHempMaxDist << "\n";
  f << "dropdist=" << g_espDropMaxDist << "\n";
  f << "deploydist=" << g_espDeployMaxDist << "\n";

  f << "[AIM]\n";
  f << "enabled=" << Vars::Aim::enabled << "\n";
  f << "fov=" << Vars::Aim::fov << "\n";
  f << "smooth=" << Vars::Aim::smooth << "\n";
  f << "silentaim=" << Vars::Aim::silentAim << "\n";
  f << "randombone=" << Vars::Aim::randomBone << "\n";
  f << "targetbone=" << Vars::Aim::targetBone << "\n";
  f << "multibone=" << Vars::Aim::multiBone << "\n";
  f << "multibonemode=" << Vars::Aim::multiBoneMode << "\n";

  f << "[WEAPON]\n";
  f << "instaeoka=" << g_instaEoka << "\n";
  f << "nospread=" << g_noSpread << "\n";
  f << "spreadscale=" << g_spreadScale << "\n";
  f << "reloadbar=" << g_reloadBar << "\n";
  f << "tracers=" << g_bulletTracers << "\n";
  f << "autoreload=" << g_autoReload << "\n";
  f << "chams=" << g_chams << "\n";
  f << "chamsmatid=" << g_chamsMaterialId << "\n";
  f << "vmchams=" << g_viewModelChams << "\n";
  f << "vmchamsmatid=" << g_vmChamsMaterialId << "\n";
  f << "removeterrain=" << g_removeLayers << "\n";

  f << "[MISC]\n";
  f << "norecoil=" << g_noRecoilEnabled << "\n";
  f << "recoilpct=" << g_recoilControl << "\n";
  f << "hidden=" << g_overlayHidden << "\n";
  f << "fpscap=" << g_fpsCap << "\n";
  f << "brightnight=" << g_brightNight << "\n";
  f << "brightnightintensity=" << g_brightNightIntensity << "\n";
  f << "timechanger=" << g_timeChangerEnabled << "\n";
  f << "timehour=" << g_timeHour << "\n";
  f << "streamproof=" << (g_hWnd ? 0 : 0) << "\n";
  
  f << "[MOVEMENT]\n";
  f << "spiderman=" << g_spiderman << "\n";

  f.close();
  g_ConfigStatus = "Config saved!";
  g_ConfigStatusTime = GetTickCount64();
  printf("[+] Config saved to %s\n", path.c_str());
}

void LoadConfig(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open()) {
    g_ConfigStatus = "No config found.";
    g_ConfigStatusTime = GetTickCount64();
    return;
  }

  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '[' || line[0] == '#')
      continue;
    auto eq = line.find('=');
    if (eq == std::string::npos)
      continue;

    std::string key = line.substr(0, eq);
    std::string val = line.substr(eq + 1);

    // ESP
    if (key == "enabled")
      g_espEnabled = (std::stoi(val) != 0);
    if (key == "boxes")
      g_espBoxes = (std::stoi(val) != 0);
    if (key == "names")
      g_espNames = (std::stoi(val) != 0);
    if (key == "distance")
      g_espDistance = (std::stoi(val) != 0);
    if (key == "snaplines")
      g_espSnaplines = (std::stoi(val) != 0);
    if (key == "healthbar")
      g_espHealthBar = (std::stoi(val) != 0);
    if (key == "skeleton")
      g_espSkeleton = (std::stoi(val) != 0);
    if (key == "vischeck")
      g_espVisCheck = (std::stoi(val) != 0);
    if (key == "sleepers")
      g_espShowSleepers = (std::stoi(val) != 0);
    if (key == "wounded")
      g_espShowWounded = (std::stoi(val) != 0);
    if (key == "hotbar")
      g_espHotbar = (std::stoi(val) != 0);
    if (key == "ore")
      g_espOre = (std::stoi(val) != 0);
    if (key == "hemp")
      g_espHemp = (std::stoi(val) != 0);
    if (key == "dropped")
      g_espDroppedItem = (std::stoi(val) != 0);
    if (key == "animal")
      g_espAnimal = (std::stoi(val) != 0);
    if (key == "bear")
      g_espBear = (std::stoi(val) != 0);
    if (key == "polarbear")
      g_espPolarBear = (std::stoi(val) != 0);
    if (key == "wolf")
      g_espWolf = (std::stoi(val) != 0);
    if (key == "boar")
      g_espBoar = (std::stoi(val) != 0);
    if (key == "chicken")
      g_espChicken = (std::stoi(val) != 0);
    if (key == "horse")
      g_espHorse = (std::stoi(val) != 0);
    if (key == "stag")
      g_espStag = (std::stoi(val) != 0);
    if (key == "shark")
      g_espShark = (std::stoi(val) != 0);
    if (key == "deployable")
      g_espDeployable = (std::stoi(val) != 0);
    if (key == "playerdist")
      g_espPlayerMaxDist = std::stof(val);
    if (key == "animaldist")
      g_espAnimalMaxDist = std::stof(val);
    if (key == "oredist")
      g_espOreMaxDist = std::stof(val);
    if (key == "hempdist")
      g_espHempMaxDist = std::stof(val);
    if (key == "dropdist")
      g_espDropMaxDist = std::stof(val);
    if (key == "deploydist")
      g_espDeployMaxDist = std::stof(val);

    // Aimbot
    if (key == "fov")
      Vars::Aim::fov = std::stof(val);
    if (key == "smooth")
      Vars::Aim::smooth = std::stof(val);
    if (key == "silentaim")
      Vars::Aim::silentAim = (std::stoi(val) != 0);
    if (key == "randombone")
      Vars::Aim::randomBone = (std::stoi(val) != 0);
    if (key == "targetbone")
      Vars::Aim::targetBone = std::stoi(val);
    if (key == "multibone")
      Vars::Aim::multiBone = (std::stoi(val) != 0);
    if (key == "multibonemode")
      Vars::Aim::multiBoneMode = std::stoi(val);

    // Weapon modifiers
    if (key == "instaeoka")
      g_instaEoka = (std::stoi(val) != 0);
    if (key == "nospread")
      g_noSpread = (std::stoi(val) != 0);
    if (key == "spreadscale")
      g_spreadScale = std::stof(val);
    if (key == "reloadbar")
      g_reloadBar = (std::stoi(val) != 0);
    if (key == "tracers")
      g_bulletTracers = (std::stoi(val) != 0);
    if (key == "autoreload")
      g_autoReload = (std::stoi(val) != 0);
    if (key == "chams")
      g_chams = (std::stoi(val) != 0);
    if (key == "chamsmatid") {
      unsigned int loadedId = (unsigned int)std::stoul(val);
      const struct { unsigned int id; const char* name; } matNames[] = {
        {1294354,"Red"},{730730,"Blue"},{1348630,"Wireframe"}
      };
      bool valid = false;
      for (auto& m : matNames) if (m.id == loadedId) { g_chamsMaterialId = loadedId; g_chamsMaterialName = m.name; valid = true; break; }
      if (!valid) { g_chamsMaterialId = 1294354; g_chamsMaterialName = "Red"; }
    }
    if (key == "vmchams")
      g_viewModelChams = (std::stoi(val) != 0);
    if (key == "vmchamsmatid") {
      unsigned int loadedId = (unsigned int)std::stoul(val);
      const struct { unsigned int id; const char* name; } matNames[] = {
        {1294354,"Red"},{730730,"Blue"},{1348630,"Wireframe"}
      };
      bool valid = false;
      for (auto& m : matNames) if (m.id == loadedId) { g_vmChamsMaterialId = loadedId; g_vmChamsMaterialName = m.name; valid = true; break; }
      if (!valid) { g_vmChamsMaterialId = 1294354; g_vmChamsMaterialName = "Red"; }
    }
    if (key == "removelayers" || key == "removeterrain")
      { g_removeLayers = (std::stoi(val) != 0); g_terrainRemover = g_removeLayers; }

    // Misc
    if (key == "norecoil")
      g_noRecoilEnabled = (std::stoi(val) != 0);
    if (key == "recoilpct")
      g_recoilControl = std::stof(val);
    if (key == "hidden")
      g_overlayHidden = (std::stoi(val) != 0);
    if (key == "fpscap")
      g_fpsCap = std::stoi(val);
    if (key == "brightnight")
      g_brightNight = (std::stoi(val) != 0);
    if (key == "brightnightintensity")
      g_brightNightIntensity = std::stof(val);
    if (key == "timechanger")
      g_timeChangerEnabled = (std::stoi(val) != 0);
    if (key == "timehour")
      g_timeHour = std::stof(val);
    
    // Movement exploits
    if (key == "spiderman")
      g_spiderman = (std::stoi(val) != 0);
  }
  f.close();

  if (g_hWnd && IsWindow(g_hWnd))
    SetWindowDisplayAffinity(g_hWnd, g_overlayHidden ? WDA_EXCLUDEFROMCAPTURE
                                                     : WDA_NONE);

  // Reverse-sync: push loaded globals back into framework config so UI checkboxes match
  cfg->get<checkbox_t>("Enable ESP").enabled = g_espEnabled;
  cfg->get<checkbox_t>("Enable Player ESP").enabled = g_espEnabled; // same master toggle
  cfg->get<checkbox_t>("Box").enabled = g_espBoxes;
  cfg->get<checkbox_t>("Skeleton").enabled = g_espSkeleton;
  cfg->get<checkbox_t>("Snaplines").enabled = g_espSnaplines;
  cfg->get<checkbox_t>("Health").enabled = g_espHealthBar;
  cfg->get<checkbox_t>("Name").enabled = g_espNames;
  cfg->get<checkbox_t>("Distance").enabled = g_espDistance;
  cfg->get<checkbox_t>("Hotbar ESP").enabled = g_espHotbar;
  cfg->get<checkbox_t>("Corpse").enabled = g_espShowWounded;
  cfg->get<checkbox_t>("Off-screen arrows").enabled = g_espFOVArrows;
  cfg->get<checkbox_t>("Radar").enabled = g_espRadar;
  cfg->get<checkbox_t>("Animal ESP").enabled = g_espAnimal;
  cfg->get<checkbox_t>("Bear").enabled = g_espBear;
  cfg->get<checkbox_t>("Polar Bear").enabled = g_espPolarBear;
  cfg->get<checkbox_t>("Wolf").enabled = g_espWolf;
  cfg->get<checkbox_t>("Boar").enabled = g_espBoar;
  cfg->get<checkbox_t>("Chicken").enabled = g_espChicken;
  cfg->get<checkbox_t>("Horse").enabled = g_espHorse;
  cfg->get<checkbox_t>("Stag").enabled = g_espStag;
  cfg->get<checkbox_t>("Shark").enabled = g_espShark;
  cfg->get<checkbox_t>("Deployable ESP").enabled = g_espDeployable;
  cfg->get<checkbox_t>("Ore ESP").enabled = g_espOre;
  cfg->get<checkbox_t>("Hemp ESP").enabled = g_espHemp;
  cfg->get<checkbox_t>("Dropped Items").enabled = g_espDroppedItem;
  cfg->get<checkbox_t>("Aimbot").enabled = Vars::Aim::enabled;
  cfg->get<slider_t>("Aimbot FOV").callback = Vars::Aim::fov;
  cfg->get<slider_t>("Smooth").callback = Vars::Aim::smooth;
  cfg->get<checkbox_t>("Silent Aim").enabled = Vars::Aim::silentAim;
  cfg->get<checkbox_t>("Insta Eoka").enabled = g_instaEoka;
  cfg->get<checkbox_t>("No Spread").enabled = g_noSpread;
  cfg->get<slider_t>("Spread Control").callback = g_spreadScale;
  cfg->get<checkbox_t>("Reload Bar").enabled = g_reloadBar;
  cfg->get<checkbox_t>("Bullet Tracers").enabled = g_bulletTracers;
  cfg->get<checkbox_t>("Auto Reload").enabled = g_autoReload;
  cfg->get<checkbox_t>("Chams").enabled = g_chams;
  cfg->get<checkbox_t>("Remove Terrain").enabled = g_removeLayers;
  cfg->get<checkbox_t>("No Recoil").enabled = g_noRecoilEnabled;
  cfg->get<slider_t>("Recoil Control").callback = g_recoilControl;
  cfg->get<checkbox_t>("Bright Night").enabled = g_brightNight;
  cfg->get<checkbox_t>("Time Changer").enabled = g_timeChangerEnabled;
  cfg->get<slider_t>("Time Hour").callback = g_timeHour;
  cfg->get<slider_t>("FPS Cap").callback = (float)g_fpsCap;
  cfg->get<checkbox_t>("Spiderman").enabled = g_spiderman;

  g_ConfigStatus = "Config loaded!";
  g_ConfigStatusTime = GetTickCount64();
  printf("[+] Config loaded from %s\n", path.c_str());
}

void ResetConfig() {
  g_espEnabled = true;
  g_espBoxes = true;
  g_espNames = true;
  g_espDistance = true;
  g_espSnaplines = false;
  g_espHealthBar = false;
  g_espSkeleton = true;
  g_espVisCheck = false;
  g_espShowSleepers = false;
  g_espShowWounded = true;
  g_espHotbar = false;
  g_espAnimal = false;
  g_espBear = true;
  g_espPolarBear = true;
  g_espWolf = true;
  g_espBoar = true;
  g_espChicken = true;
  g_espHorse = true;
  g_espStag = true;
  g_espShark = true;
  g_espDeployable = false;
  g_espOre = false;
  g_espHemp = false;
  g_espDroppedItem = false;
  g_espPlayerMaxDist = 500.0f;
  g_espAnimalMaxDist = 400.0f;
  g_espOreMaxDist = 300.0f;
  g_espHempMaxDist = 200.0f;
  g_espDropMaxDist = 150.0f;
  g_espDeployMaxDist = 300.0f;

  Vars::Aim::enabled = true;
  Vars::Aim::fov = 100.0f;
  Vars::Aim::smooth = 0.5f;
  Vars::Aim::silentAim = false;
  Vars::Aim::randomBone = true;
  Vars::Aim::targetBone = 47;
  Vars::Aim::multiBone = true;
  Vars::Aim::multiBoneMode = 0;

  g_instaEoka = false;
  g_noSpread = false;
  g_spreadScale = 0.0f;
  g_reloadBar = false;
  g_bulletTracers = true;
  g_autoReload = true;
  g_chams = false;
  g_chamsMaterialId = 763998;
  g_viewModelChams = false;
  g_vmChamsMaterialId = 763998;
  g_removeLayers = false;
  g_terrainRemover = false;

  g_noRecoilEnabled = false;
  g_recoilControl = 80.0f;
  g_overlayHidden = true;
  g_fpsCap = 0;
  g_brightNight = false;
  
  g_spiderman = false;

  g_ConfigStatus = "Reset to defaults!";
  g_ConfigStatusTime = GetTickCount64();
}

std::vector<unsigned char> LoadFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return {};

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<unsigned char> buffer(size);
  if (file.read((char *)buffer.data(), size))
    return buffer;

  return {};
}
