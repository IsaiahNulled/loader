#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>

// Hotbar image downloader - downloads and caches item images
class HotbarDownloader {
public:
    static HotbarDownloader& Get();
    
    // Start downloading hotbar images to temp folder
    void StartDownload();
    
    // Check if download is complete
    bool IsDownloadComplete() const;
    
    // Get download progress (0-100)
    int GetProgress() const;
    
    // Stop downloading
    void Stop();
    
private:
    HotbarDownloader() = default;
    ~HotbarDownloader();
    
    void DownloadThread();
    bool DownloadFile(const std::string& url, const std::string& path);
    std::string GetTempDirectory();
    
    std::thread m_downloadThread;
    mutable std::mutex m_mutex;
    bool m_running = false;
    bool m_complete = false;
    int m_progress = 0;
    
    // Common Rust item shortnames that should have icons
    std::vector<std::string> m_itemShortnames = {
        // Weapons
        "rifle.ak", "rifle.lr300", "rifle.m39", "rifle.semiauto", "rifle.bolt",
        "smg.mp5", "smg.ump", "smg.thompson", "smg.custom",
        "pistol.python", "pistol.m92", "pistol.revolver", "pistol.semiauto",
        "shotgun.pump", "shotgun.spas12", "shotgun.waterpipe", "shotgun.eoka",
        "lmg.m249", "hmlmg", "multiplegrenadelauncher",
        
        // Melee
        "knife.combat", "knife.bone", "machete", "pitchfork", "salvaged.sword",
        "spear.stone", "spear.wooden", "spear.metal",
        
        // Tools
        "axe.salvaged", "hatchet", "pickaxe", "hammer.salvaged", "torch",
        "jackhammer", "chainsaw",
        
        // Armor/Clothing
        "metal.plate.torso", "roadsign.jacket", "heavy.plate.helmet",
        "mask.balaclava", "attire.bandit", "attire.scientist",
        
        // Medical/Food
        "syringe.medical", "bandage", "small.water.bottle", "water.jug",
        "cooked.meat", "apple", "corn",
        
        // Resources
        "metal.ore", "sulfur.ore", "hq.metal.ore", "scrap",
        "wood", "stones", "cloth", "leather",
        
        // Explosives
        "explosive.timed", "explosive.satchel", "rocket.launcher",
        "ammo.rifle", "ammo.pistol", "ammo.shotgun", "ammo.smg",
        
        // Building
        "building.planner", "hammer", "repair.bench",
        
        // Misc
        "keycard.green", "keycard.blue", "keycard.red", "keycard.orange",
        "camera", "rfid.transponder", "targeting.computer"
    };
};

// Global instance
extern HotbarDownloader& g_HotbarDownloader;
