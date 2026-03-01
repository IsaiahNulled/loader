#include "globals.h"
#include "crash_log.h"
#include "images.h"
#include <filesystem>
#include <unordered_map>
namespace fs = std::filesystem;

// Wrapper around SDK entity list refresh.
static void RefreshEntityList() {
  if (!g_SDK || !g_SDK->IsAttached())
    return;
  g_SDK->RefreshEntityList();
}

// Build an up-to-date player snapshot from the SDK.
// Called from the worker thread, writes into the given back-buffer.
void FillPlayerCache(std::vector<PlayerData> &buffer) {
  CLOG_CONTEXT("FillPlayerCache");
  buffer.clear();
  if (!g_SDK || !g_SDK->IsAttached())
    return;

  int count = g_SDK->GetEntityCount();
  if (count <= 0)
    return;

  Vec3 localPos = g_SDK->GetCameraPosition();
  uintptr_t localPlayer = g_SDK->GetLocalPlayer();
  static int fillLogCount = 0;
  if (fillLogCount++ % 300 == 0) {
    CLOG("FillPlayerCache: %d entities, localPlayer=0x%llX", count, (unsigned long long)localPlayer);
  }

  for (int i = 0; i < count; i++) {
    std::uintptr_t entity = g_SDK->GetEntity(i);
    if (!entity)
      continue;
    if (!g_SDK->IsPlayer(entity))
      continue;

    Vec3 position, headPos;
    uint32_t lifestate = 0;
    if (!g_SDK->ReadPlayerPositionAndLifestate(entity, position, headPos,
                                               lifestate))
      continue;
    if (lifestate != 0)
      continue; // dead

    float distance = (position - localPos).Length();
    if (g_espPlayerMaxDist > 0.f && distance > g_espPlayerMaxDist)
      continue;

    PlayerData player;
    player.address = entity;
    player.position = position;
    player.headPos = headPos;
    player.lifestate = lifestate;
    player.distance = distance;

    bool isLocal = false;
    if (!g_SDK->ReadPlayerDetails(entity, player, &isLocal))
      continue;

    if (isLocal) {
      g_LocalTeam = player.teamID;
    }

    // Read hotbar + wear items for nearby non-local players
    if (g_espHotbar && !isLocal && distance < 200.0f) {
      player.hotbarItems = g_SDK->ReadHotbarItems(entity);
      player.wearItems = g_SDK->ReadWearItems(entity);
    }

    // Read skeleton bones for non-local players (needed for skeleton ESP and aimbot targeting)
    // Skip bones for distant players — skeleton isn't visible beyond 150m
    if ((g_espSkeleton || Vars::Aim::enabled) && entity != localPlayer && distance < 150.0f) {
      CLOG_CONTEXT("ReadPlayerBones");
      g_SDK->ReadPlayerBones(entity, player);
    }

    // PhysX-based visibility check (replaces frustum-only isVisible)
    if (g_espVisCheck && g_PhysX.HasActors() && !isLocal && !player.bones.empty()) {
      // Raycast from local camera to target's head/bones
      static const int vischeckedBones[] = {47, 22, 1}; // head, spine4, pelvis
      player.isVisible = g_PhysX.AnyBoneVisible(
          localPos, player.bones, vischeckedBones, 3);
    }

    buffer.push_back(player);
  }

}

// ── Real Projectile Tracer Tracker ─────────────────────────────────
// Scans for active Projectile entities and records their actual path.
void UpdateRealTracers() {
  // Projectile tracking is now handled in main.cpp via ReadLocalProjectiles()
  // and ammo-count fallback. The old entity-list scan was broken because:
  // 1. Projectiles are local-only components, NOT in the networked entity list
  // 2. Iterating all entities with ReadClassName() was extremely expensive
  // 3. Holding g_tracerMutex during the scan blocked the main thread
  return;
}

// ── Fill world entity cache (runs on BACKGROUND THREAD) ─────────────
// All expensive memory reads happen here, not on the render thread.
static void FillWorldCache(std::vector<WorldEntityData> &buffer) {
  buffer.clear();
  if (!g_SDK || !g_SDK->IsAttached())
    return;
  if (!g_espAnimal && !g_espDeployable && !g_espOre && !g_espHemp &&
      !g_espDroppedItem)
    return;

  int count = g_SDK->GetEntityCount();
  if (count <= 0)
    return;

  Vec3 localPos = g_SDK->GetCameraPosition();

  // Periodic dump of entity class names (every 30s) so we can always see them
  static ULONGLONG lastClassDump = 0;
  ULONGLONG nowMs = GetTickCount64();
  if (nowMs - lastClassDump >= 30000 || lastClassDump == 0) {
    lastClassDump = nowMs;
    printf("[WorldESP] === Entity class dump (%d entities) ===\n", count);
    std::unordered_map<std::string, int> classCounts;
    int emptyCount = 0, nullCount = 0;
    for (int i = 0; i < count && i < 5000; i++) {
      std::uintptr_t ent = g_SDK->GetEntity(i);
      if (!ent) {
        nullCount++;
        continue;
      }
      std::string cn = g_SDK->ReadClassName(ent);
      if (cn.empty()) {
        emptyCount++;
        continue;
      }
      classCounts[cn]++;
    }
    printf("[WorldESP]   null=%d emptyClass=%d uniqueClasses=%d\n", nullCount,
           emptyCount, (int)classCounts.size());
    for (auto &kv : classCounts) {
      printf("[WorldESP]   '%s' x%d\n", kv.first.c_str(), kv.second);
    }
    // Log object names for interesting classes
    int loggedObj = 0;
    for (int i = 0; i < count && loggedObj < 10; i++) {
      std::uintptr_t ent = g_SDK->GetEntity(i);
      if (!ent)
        continue;
      std::string cn = g_SDK->ReadClassName(ent);
      if (cn.find("Resource") != std::string::npos ||
          cn.find("Collect") != std::string::npos ||
          cn.find("Drop") != std::string::npos ||
          cn.find("Item") != std::string::npos ||
          cn.find("Ore") != std::string::npos ||
          cn.find("World") != std::string::npos ||
          cn.find("Hemp") != std::string::npos ||
          cn.find("Tree") != std::string::npos) {
        std::string on = g_SDK->ReadObjectName(ent);
        printf("[WorldESP]   -> class='%s' obj='%s'\n", cn.c_str(), on.c_str());
        loggedObj++;
      }
    }
    printf("[WorldESP] === End dump ===\n");
  }

  for (int i = 0; i < count; i++) {
    std::uintptr_t entity = g_SDK->GetEntity(i);
    if (!entity)
      continue;
    if (g_SDK->IsPlayer(entity))
      continue;

    std::string className = g_SDK->ReadClassName(entity);
    if (className.empty())
      continue;

    bool matched = false;
    ImU32 color = IM_COL32(255, 255, 255, 255);
    std::string name;
    float maxDist = 0.f; // per-category distance limit

    // Icon keys for image-based ESP
    std::string animalIcon;
    std::string droppedIcon;
    if (g_espAnimal) {
      auto ac = IM_COL32((int)(g_espAnimalColor.x * 255),
                         (int)(g_espAnimalColor.y * 255),
                         (int)(g_espAnimalColor.z * 255), 255);
      if ((className == "Bear") && g_espBear) {
        name = "Bear";
        matched = true;
        color = ac;
      } else if ((className == "Polarbear" || className == "PolarBear") &&
                 g_espPolarBear) {
        name = "Polar Bear";
        matched = true;
        color = ac;
      } else if ((className == "Wolf") && g_espWolf) {
        name = "Wolf";
        matched = true;
        color = ac;
      } else if ((className == "Boar") && g_espBoar) {
        name = "Pig";
        matched = true;
        color = ac;
      } else if ((className == "Chicken") && g_espChicken) {
        name = "Chicken";
        matched = true;
        color = ac;
      } else if ((className == "Horse" || className == "RidableHorse") &&
                 g_espHorse) {
        name = "Horse";
        matched = true;
        color = ac;
      } else if ((className == "Stag") && g_espStag) {
        name = "Stag";
        matched = true;
        color = ac;
      } else if ((className == "SimpleShark" || className == "Shark") &&
                 g_espShark) {
        name = "Shark";
        matched = true;
        color = ac;
      }
      if (matched)
        maxDist = g_espAnimalMaxDist;
    }

    // Deployables
    if (g_espDeployable && !matched) {
      auto dc = IM_COL32((int)(g_espDeployColor.x * 255),
                         (int)(g_espDeployColor.y * 255),
                         (int)(g_espDeployColor.z * 255), 255);
      if (className == "StorageContainer") {
        name = "Container";
        matched = true;
        color = dc;
      } else if (className == "SleepingBag") {
        name = "Bag";
        matched = true;
        color = dc;
      } else if (className == "ToolCupboard") {
        name = "TC";
        matched = true;
        color = dc;
      } else if (className == "Furnace") {
        name = "Furnace";
        matched = true;
        color = dc;
      }
      if (matched)
        maxDist = g_espDeployMaxDist;
    }

    // Ore nodes — sulfur, metal, stone (no tool requirement)
    if (g_espOre && !matched) {
      bool isOreClass =
          (className == "OreResourceEntity" || className == "ResourceEntity" ||
           className.find("Ore") != std::string::npos);

      if (isOreClass) {
        std::string objName = g_SDK->ReadObjectName(entity);

        if (objName.find("sulfur") != std::string::npos ||
            objName.find("Sulfur") != std::string::npos) {
          name = "Sulfur";
          color = IM_COL32(255, 230, 50, 255);
          matched = true;
          animalIcon = "sulfur.ore";
        } else if (objName.find("metal") != std::string::npos ||
                   objName.find("Metal") != std::string::npos) {
          name = "Metal";
          color = IM_COL32(140, 180, 255, 255);
          matched = true;
          animalIcon = "metal.ore";
        } else if (objName.find("stone") != std::string::npos ||
                   objName.find("Stone") != std::string::npos) {
          name = "Stone";
          color = IM_COL32(200, 200, 200, 255);
          matched = true;
          animalIcon = "stones";
        }
        if (matched)
          maxDist = g_espOreMaxDist;
      }
    }

    // Hemp & collectibles
    if (g_espHemp && !matched) {
      if (className == "CollectibleEntity" ||
          className.find("Collect") != std::string::npos) {
        std::string objName = g_SDK->ReadObjectName(entity);

        static bool loggedFirstCollectible = false;
        if (!loggedFirstCollectible) {
          loggedFirstCollectible = true;
          printf("[HempESP] Found collectible: class='%s' objName='%s'\n",
                 className.c_str(), objName.c_str());
        }

        if (objName.find("hemp") != std::string::npos ||
            objName.find("Hemp") != std::string::npos) {
          auto hc = IM_COL32((int)(g_espHempColor.x * 255),
                             (int)(g_espHempColor.y * 255),
                             (int)(g_espHempColor.z * 255), 255);
          name = "Hemp";
          color = hc;
          matched = true;
          maxDist = g_espHempMaxDist;
          // Mark for image rendering — will use clone.hemp or seed.hemp icon
        }
      }
    }

    // Dropped items / weapons
    if (g_espDroppedItem && !matched) {
      if (className == "DroppedItem" || className == "DroppedItemContainer" ||
          className == "WorldItem" ||
          className.find("Dropped") != std::string::npos) {
        std::string objName = g_SDK->ReadObjectName(entity);

        static bool loggedFirstDrop = false;
        if (!loggedFirstDrop) {
          loggedFirstDrop = true;
          printf("[DroppedESP] Found drop: class='%s' objName='%s'\n",
                 className.c_str(), objName.c_str());
        }

        // Clean up the object name for display
        if (!objName.empty()) {
          // Strip path prefixes like "assets/prefabs/..." — just show last part
          auto lastSlash = objName.rfind('/');
          if (lastSlash != std::string::npos)
            objName = objName.substr(lastSlash + 1);
          // Strip .prefab extension
          auto dotPos = objName.rfind(".prefab");
          if (dotPos != std::string::npos)
            objName = objName.substr(0, dotPos);
          // Strip .entity extension
          dotPos = objName.rfind(".entity");
          if (dotPos != std::string::npos)
            objName = objName.substr(0, dotPos);
          name = objName;

          // Try to match dropped item name to an icon
          // Direct match first (e.g. "rifle.ak" matches rifle.ak.png)
          if (g_ItemIcons.count(objName)) {
            droppedIcon = objName;
          } else {
            // Try partial match: find first icon key that starts with objName
            for (auto &kv : g_ItemIcons) {
              if (kv.first == objName || kv.first.find(objName) == 0) {
                droppedIcon = kv.first;
                break;
              }
            }
          }
        } else {
          name = "Dropped";
        }
        auto drc = IM_COL32((int)(g_espDropColor.x * 255),
                            (int)(g_espDropColor.y * 255),
                            (int)(g_espDropColor.z * 255), 255);
        color = drc;
        matched = true;
        maxDist = g_espDropMaxDist;
      }
    }

    if (!matched)
      continue;

    // Read position
    Vec3 pos = g_SDK->ReadEntityPosition(entity);

    if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f) {
      std::uintptr_t model = g_SDK->ReadVal<std::uintptr_t>(
          entity + offsets::BaseEntity::baseModel);
      if (model && IsValidPtr(model)) {
        uintptr_t boneArr =
            g_SDK->ReadVal<uintptr_t>(model + offsets::Model::boneTransforms);
        if (boneArr && IsValidPtr(boneArr)) {
          uintptr_t rootBone = g_SDK->ReadVal<uintptr_t>(boneArr + 0x20);
          if (rootBone && IsValidPtr(rootBone))
            pos = g_SDK->ReadTransformPosition(rootBone);
        }
      }
    }

    if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f) {
      static std::unordered_map<std::string, bool> loggedPosFail;
      if (!loggedPosFail[className]) {
        loggedPosFail[className] = true;
        printf("[WorldESP] WARNING: Can't read position for class='%s'\n",
               className.c_str());
      }
      continue;
    }

    float dist = (pos - localPos).Length();
    if (maxDist > 0.f && dist > maxDist)
      continue;

    WorldEntityData wd;
    wd.position = pos;
    wd.dist = dist;
    char buf[64];
    snprintf(buf, sizeof(buf), "%s [%.0fm]", name.c_str(), dist);
    wd.label = buf;
    wd.color = color;
    // Set icon keys for image rendering
    if (name == "Hemp")
      wd.iconKey = "clone.hemp";
    else if (!animalIcon.empty())
      wd.iconKey = animalIcon;
    else if (!droppedIcon.empty())
      wd.iconKey = droppedIcon;
    buffer.push_back(wd);
  }
}

// Background thread: continuously refreshes entity data and swaps it into
// the front buffer so the render thread never stalls on driver reads.
void WorkerThreadRoutine() {
  CLOG("WorkerThread started");
  bool wasInServer = false;
  static ULONGLONG lastIconReload = 0;

  while (g_Running) {
    if (g_SDK && g_SDK->IsAttached() && (g_espEnabled || Vars::Aim::enabled)) {

      // Always try to refresh entity list first (needed to find local player)
      static ULONGLONG lastEntityRefresh = 0;
      ULONGLONG now = GetTickCount64();
      if (now - lastEntityRefresh >= 500 || lastEntityRefresh == 0) {
        g_SDK->RefreshEntityList();
        lastEntityRefresh = now;
      }

      // Periodically reload icons to pick up newly downloaded hotbar images
      if (now - lastIconReload >= 30000 || lastIconReload == 0) {
        if (g_HotbarDownloader.IsDownloadComplete()) {
          // Reload icons from temp directory (this will add new ones without clearing existing)
          WCHAR tempPath[MAX_PATH];
          if (::GetTempPathW(MAX_PATH, tempPath)) {
            std::wstring ws(tempPath);
            std::string tempDir(ws.begin(), ws.end());
            std::string hotbarDir = tempDir + "\\rust_hotbar_images";
            if (fs::exists(hotbarDir)) {
              // Load only new icons (don't clear existing ones)
              int newIcons = 0;
              for (const auto& entry : fs::directory_iterator(hotbarDir)) {
                if (!entry.is_regular_file()) continue;
                std::string ext = entry.path().extension().string();
                if (ext != ".png" && ext != ".PNG" && ext != ".jpg" && ext != ".jpeg") continue;
                
                std::string shortname = entry.path().stem().string();
                if (!g_ItemIcons.count(shortname)) {
                  // Load new icon
                  ID3D11ShaderResourceView* tex = LoadItemIcon(entry.path().string());
                  if (tex) {
                    g_ItemIcons[shortname] = tex;
                    newIcons++;
                  }
                }
              }
              if (newIcons > 0) {
                printf("[Hotbar] Loaded %d new icons from download\n", newIcons);
              }
            }
          }
        }
        lastIconReload = now;
      }

      // Check if we're actually in a server (has entities + local player)
      bool inServer = (g_SDK->GetEntityCount() > 0) && g_SDK->IsInServer();

      if (!inServer) {
        // Not in a server — clear caches and wait
        if (wasInServer) {
          // Just left a server — clear everything
          g_SDK->InvalidateCache();
          {
            std::lock_guard<std::mutex> lk(g_DataMutex);
            g_cachedPlayers.clear();
            g_cachedWorldEnts.clear();
          }
          g_localHeldEntity = 0;
          wasInServer = false;
        }
        Sleep(1000); // Check less frequently when not in server
        continue;
      }

      // Detect server change (rejoined or switched servers)
      if (!wasInServer && inServer) {
        // Just joined a server — force full rescan
        g_SDK->InvalidateCache();
        g_SDK->RefreshEntityList(); // Immediate rescan after invalidation
        wasInServer = true;

        // Start grace period — delay write operations to let game structures initialize
        g_ServerJoinTick = now;
        printf("[*] Server join detected — write operations delayed %llums\n", SERVER_LOAD_GRACE_MS);

        // Initialize PhysX scene reader for vischecks
        if (!g_PhysX.HasActors()) {
          g_PhysX.Init(g_SDK, &g_Driver, g_SDK->GetPID());
        }
      }

      // Periodically refresh PhysX actor cache (every 5s)
      if (g_espVisCheck) {
        static ULONGLONG lastPhysXRefresh = 0;
        if (now - lastPhysXRefresh >= 5000 || lastPhysXRefresh == 0) {
          g_PhysX.CacheActors();
          lastPhysXRefresh = now;
        }
      }

      // High-frequency projectile tracking
      UpdateRealTracers();

      // Refresh player cache — 60Hz is plenty for smooth skeleton ESP
      static ULONGLONG lastPlayerRefresh = 0;
      if (now - lastPlayerRefresh >= 16 || lastPlayerRefresh == 0) {
        CLOG_CONTEXT("FillPlayerCache");
        FillPlayerCache(g_BackBuffer);
        {
          std::lock_guard<std::mutex> lk(g_DataMutex);
          g_cachedPlayers = g_BackBuffer;
        }
        lastPlayerRefresh = now;
      }

      // Update held entity for VM chams — Check every 500ms for quick weapon swap detection
      if (g_viewModelChams) {
        static ULONGLONG lastHeldCheck = 0;
        if (now - lastHeldCheck >= 500) {
          lastHeldCheck = now;
          uintptr_t lp = g_SDK->GetLocalPlayer();
          if (lp) {
            uintptr_t held = g_SDK->GetActiveWeaponBaseProjectile(lp);
            if (held != g_localHeldEntity) {
              g_localHeldEntity = held;
              {
                std::lock_guard<std::mutex> lk(g_chamsMutex);
                g_vmRenderers.clear();
                g_vmCachedHeldEntity = 0;
              }
            }
          }
        }
      }

      // Refresh world entity cache — low priority, every 500ms
      // Runs less frequently so it doesn't block skeleton updates
      static ULONGLONG lastWorldRefresh = 0;
      if (now - lastWorldRefresh >= 500 || lastWorldRefresh == 0) {
        FillWorldCache(g_WorldBackBuffer);
        {
          std::lock_guard<std::mutex> lock(g_DataMutex);
          g_cachedWorldEnts = g_WorldBackBuffer;
        }
        lastWorldRefresh = now;
      }
    }

    Sleep(g_espRefreshMs);
  }
}

// Dedicated chams thread: two-phase cache system
// Phase 1 (rare): walk pointer chains, cache matBase addresses (~300 reads, runs once)
// Phase 2 (frequent): pure writes to cached addresses (~20 writes, zero reads)
void ChamsThreadRoutine() {
  printf("[+] Chams thread started\n");
  unsigned int lastMatId = 0;

  while (g_Running) {
    if (!g_chams || !g_SDK || !g_SDK->IsAttached()) {
      // Chams disabled or SDK detached — clear cache
      {
        std::lock_guard<std::mutex> lk(g_chamsMutex);
        g_chamsCache.clear();
      }
      lastMatId = 0;
      Sleep(500);
      continue;
    }
    // During server load grace period, wait without clearing cache
    if (!IsServerReady()) {
      Sleep(500);
      continue;
    }

    unsigned int matId = g_chamsMaterialId;
    ULONGLONG now = GetTickCount64();

    // Check if cache needs rebuilding:
    // OPTIMIZED: Faster response for weapon swaps
    bool needsRebuild = false;
    static ULONGLONG lastBuildAttempt = 0;
    {
      std::lock_guard<std::mutex> lk(g_chamsMutex);
      if (g_chamsCache.empty()) {
        // FAST: Retry empty cache every 500ms (was 5s) for faster weapon swap response
        if (now - lastBuildAttempt >= 500) needsRebuild = true;
      } else {
        // FAST: Check if oldest cache entry is stale (>10s was 30s) for quicker updates
        for (const auto &c : g_chamsCache) {
          if (now - c.cacheTime > 10000) { needsRebuild = true; break; }
        }
        // AUTO-RECOVERY: Force rebuild if step 4 failure detected
        static ULONGLONG lastStep4Failure = 0;
        static int consecutiveFailures = 0;
        
        if (g_SDK && g_SDK->entDbg.lastFailStep == 4) {
          if (now - lastStep4Failure >= 20000) { // 20 seconds since last failure
            printf("[AUTO-RECOVERY] Step 4 failure detected for 20s - forcing entity rescan...\n");
            needsRebuild = true;
            lastStep4Failure = now;
            consecutiveFailures++;
            
            // Force entity list refresh
            g_SDK->RefreshEntityList();
            
            // Reset decryption method cache to try different methods
            RustDecrypt::ResetDecryptionCache();
            
            if (consecutiveFailures >= 3) {
              printf("[AUTO-RECOVERY] Multiple failures detected - trying aggressive rescan...\n");
              // More aggressive recovery after multiple failures
              Sleep(1000); // Give game time to stabilize
              g_SDK->InvalidateCache();
              g_SDK->RefreshEntityList();
            }
          } else if (lastStep4Failure == 0) {
            lastStep4Failure = now; // First failure detection
          }
        } else {
          // Success - reset failure counters
          if (consecutiveFailures > 0) {
            printf("[AUTO-RECOVERY] Step 4 resolved after %d attempts\n", consecutiveFailures);
          }
          consecutiveFailures = 0;
          lastStep4Failure = 0;
        }
        
        // Also check if we have new players OR weapon changes (entity count increased significantly)
        static int lastEntityCount = 0;
        int currentEntityCount = g_SDK ? g_SDK->GetEntityCount() : 0;
        if (currentEntityCount > lastEntityCount + 5) { // Significant new players
          needsRebuild = true;
          lastEntityCount = currentEntityCount;
        }
        // SMART: Check if local player weapon changed (fast detection)
        static uintptr_t lastLocalWeapon = 0;
        uintptr_t localPlayer = g_SDK ? g_SDK->GetLocalPlayer() : 0;
        if (localPlayer) {
          uintptr_t currentWeapon = g_SDK->GetActiveWeaponBaseProjectile(localPlayer);
          if (currentWeapon != lastLocalWeapon) {
            needsRebuild = true; // Weapon changed - rebuild cache immediately
            lastLocalWeapon = currentWeapon;
          }
        }
      }
    }

    if (needsRebuild) {
      lastBuildAttempt = now;
      // Phase 1: Build cache (expensive — lots of reads, but only runs rarely)
      static bool chamsFirstBuild = true;
      if (chamsFirstBuild) { printf("[Chams] Building cache (mat=%u)...\n", matId); chamsFirstBuild = false; }
      std::vector<ChamsCache> newCache;
      int entityCount = g_SDK->GetEntityCount();
      uintptr_t localPlayer = g_SDK->GetLocalPlayer();
      int cached = 0;

      for (int i = 0; i < entityCount && g_Running && g_chams; i++) {
        uintptr_t entity = g_SDK->GetEntity(i);
        if (!entity) continue;
        if (!g_SDK->IsPlayer(entity)) continue;
        if (entity == localPlayer) continue;

        bool dbg = (cached == 0); // debug first player only
        auto addrs = g_SDK->BuildChamsCache(entity, dbg);
        if (!addrs.empty()) {
          newCache.push_back({entity, std::move(addrs), now});
          cached++;
          if (dbg) printf("[Chams] First player cached: %d addrs\n", (int)newCache.back().matAddrs.size());
        }
        // FAST: Minimal delay between players during cache build (was 5ms)
        Sleep(1);
      }

      {
        std::lock_guard<std::mutex> lk(g_chamsMutex);
        g_chamsCache = std::move(newCache);
      }
      lastMatId = matId;
      printf("[Chams] Cached %d players (%d total addrs)\n", cached,
             [&]{ int t = 0; for (auto &c : g_chamsCache) t += (int)c.matAddrs.size(); return t; }());
    }

    // === View Model Chams (hands + weapon) ===
    // Reference code approach: cache renderer POINTERS, re-read material chain each cycle.
    // Self-healing: if viewmodel is destroyed, reads return 0 → writes are skipped.
    // No stale address problem — material base is always re-read fresh.
    if (g_viewModelChams && g_SDK) {
      uintptr_t curHeld = g_localHeldEntity;
      static ULONGLONG lastVMBuild = 0;

      if (curHeld && IsValidPtr(curHeld)) {
        // Check if we need to find renderers (empty cache or held entity changed)
        bool needRebuild = false;
        {
          std::lock_guard<std::mutex> lk(g_chamsMutex);
          if (g_vmRenderers.empty() || curHeld != g_vmCachedHeldEntity)
            needRebuild = true;
        }
        if (needRebuild) {
          ULONGLONG vmNow = GetTickCount64();
          if (vmNow - lastVMBuild >= 500) { // FAST: 500ms (was 3s) for instant weapon swap response
            lastVMBuild = vmNow;
            auto renderers = g_SDK->BuildVMChamsRenderers(curHeld, true);
            if (!renderers.empty()) {
              printf("[VMChams] Found %d renderers for held=0x%llX\n",
                     (int)renderers.size(), (uint64_t)curHeld);
            }
            {
              std::lock_guard<std::mutex> lk(g_chamsMutex);
              g_vmRenderers = std::move(renderers);
              g_vmCachedHeldEntity = curHeld;
            }
          }
        }
        // Apply: re-read material chain each cycle via VMProcessRenderer.
        // If viewmodel was destroyed, reads return 0 → no writes → no crash.
        {
          std::lock_guard<std::mutex> lk(g_chamsMutex);
          int totalWritten = 0;
          for (auto& rend : g_vmRenderers) {
            totalWritten += g_SDK->VMProcessRenderer(rend, g_vmChamsMaterialId);
          }
          // If all renderers returned 0 writes, viewmodel is dead → clear cache
          if (!g_vmRenderers.empty() && totalWritten == 0) {
            g_vmRenderers.clear();
            g_vmCachedHeldEntity = 0;
          }
        }
      } else {
        std::lock_guard<std::mutex> lk(g_chamsMutex);
        g_vmRenderers.clear();
        g_vmCachedHeldEntity = 0;
      }
    } else {
      std::lock_guard<std::mutex> lk(g_chamsMutex);
      g_vmRenderers.clear();
      g_vmCachedHeldEntity = 0;
    }

    // === Player Chams ===
    // Phase 2: Apply from cache — lightweight canary validation.
    // ApplyChamsCached reads ONE value (the first address) as a canary.
    // If it returns 0, the entity's memory is stale → evict it.
    {
      std::lock_guard<std::mutex> lk(g_chamsMutex);
      for (auto it = g_chamsCache.begin(); it != g_chamsCache.end(); ) {
        if (!g_Running || !g_chams) break;
        
        int written = 0;
        if (matId == 999999) {
          written = g_SDK->ApplyCustomGalaxy(it->matAddrs);
        } else {
          written = g_SDK->ApplyChamsCached(it->matAddrs, matId);
        }
        
        if (written == 0 && !it->matAddrs.empty()) {
          // Canary failed — all addresses stale, evict from cache
          it = g_chamsCache.erase(it);
          continue;
        }
        ++it;
      }
    }

    Sleep(250); // reapply every 250ms — scatter writes reduce driver load
  }

  // Cleanup
  {
    std::lock_guard<std::mutex> lk(g_chamsMutex);
    g_chamsCache.clear();
  }
  printf("[+] Chams thread exiting\n");
}

// ── World ESP: draw from cache only (no memory reads on render thread) ──

static void WorldEsp() {
  if (!g_espAnimal && !g_espDeployable && !g_espOre && !g_espHemp &&
      !g_espDroppedItem)
    return;

  ImDrawList *draw = ImGui::GetForegroundDrawList();
  if (g_FontESP)
    ImGui::PushFont(g_FontESP);

  std::lock_guard<std::mutex> lock(g_DataMutex);
  for (const auto &w : g_cachedWorldEnts) {
    // Distance fade: fully visible at >=5m, smooth fade 5m→1m, invisible at
    // <=1m
    float alpha = 1.0f;
    if (w.dist <= 1.0f)
      continue; // fully transparent, skip drawing
    if (w.dist < 5.0f) {
      alpha = (w.dist - 1.0f) / 4.0f; // linear fade: 1m=0, 5m=1
      if (alpha > 1.0f)
        alpha = 1.0f;
    }
    int alphaI = (int)(alpha * 255.0f);

    Vec2 screen;
    if (RustSDK::WorldToScreen(w.position, g_ViewMatrix, g_ScreenW, g_ScreenH,
                               screen)) {
      // If this entity has an icon image, draw it
      if (!w.iconKey.empty()) {
        auto it = g_ItemIcons.find(w.iconKey);
        if (it != g_ItemIcons.end() && it->second) {
          float imgSize = 33.0f;
          ImVec2 imgMin(screen.x - imgSize * 0.5f, screen.y - imgSize * 0.5f);
          ImVec2 imgMax(screen.x + imgSize * 0.5f, screen.y + imgSize * 0.5f);
          ImU32 imgTint = IM_COL32(255, 255, 255, alphaI);
          draw->AddImage((ImTextureID)it->second, imgMin, imgMax, ImVec2(0, 0),
                         ImVec2(1, 1), imgTint);

          // Distance text below icon
          char distBuf[32];
          snprintf(distBuf, sizeof(distBuf), "[%.0fm]", w.dist);
          ImVec2 textSize = ImGui::CalcTextSize(distBuf);
          float tx = screen.x - textSize.x * 0.5f;
          float ty = screen.y + imgSize * 0.5f + 1.f;
          draw->AddText(ImVec2(tx + 1, ty + 1),
                        IM_COL32(0, 0, 0, (int)(180 * alpha)), distBuf);
          draw->AddText(ImVec2(tx, ty),
                        IM_COL32((w.color & 0xFF), (w.color >> 8) & 0xFF,
                                 (w.color >> 16) & 0xFF, alphaI),
                        distBuf);
          continue;
        }
      }

      // Fallback: colored circle + text label
      float iconR = 5.0f;
      float textX = screen.x + iconR * 2 + 4.f;

      ImU32 cR = w.color & 0xFF, cG = (w.color >> 8) & 0xFF,
            cB = (w.color >> 16) & 0xFF;
      ImU32 fadedColor = IM_COL32(cR, cG, cB, alphaI);
      ImU32 fadedShadow = IM_COL32(0, 0, 0, (int)(180 * alpha));
      ImU32 fadedOutline = IM_COL32(0, 0, 0, (int)(160 * alpha));

      draw->AddCircleFilled(ImVec2(screen.x + iconR, screen.y + 6.f), iconR,
                            fadedColor);
      draw->AddCircle(ImVec2(screen.x + iconR, screen.y + 6.f), iconR,
                      fadedOutline, 0, 1.2f);

      draw->AddText(ImVec2(textX + 1, screen.y + 1), fadedShadow,
                    w.label.c_str());
      draw->AddText(ImVec2(textX, screen.y), fadedColor, w.label.c_str());
    }
  }

  if (g_FontESP)
    ImGui::PopFont();
}

// ── Debug Overlay ──────────────────────────────────────────────────

void RenderDebugOverlay() {
  if (!g_ShowDebug)
    return;

  ImDrawList *dl = ImGui::GetForegroundDrawList();
  float x = 10.f, y = 40.f;
  float lineH = 16.f;
  ImU32 colGreen = IM_COL32(0, 255, 0, 255);
  ImU32 colRed = IM_COL32(255, 60, 60, 255);
  ImU32 colYellow = IM_COL32(255, 255, 0, 255);
  ImU32 colWhite = IM_COL32(255, 255, 255, 255);
  ImU32 colGray = IM_COL32(180, 180, 180, 255);

  auto line = [&](const char *label, const char *val, ImU32 valCol) {
    dl->AddText(ImVec2(x, y), colGray, label);
    dl->AddText(ImVec2(x + 200, y), valCol, val);
    y += lineH;
  };

  char buf[256];

  // Background
  dl->AddRectFilled(ImVec2(x - 5, y - 5), ImVec2(x + 560, y + lineH * 54),
                    IM_COL32(0, 0, 0, 200), 4.f);

  dl->AddText(ImVec2(x, y), colWhite, "=== DEBUG PANEL (F2 to toggle) ===");
  y += lineH + 4;

  // 1. Driver
  bool drvOk = g_Driver.IsConnected();
  line("Driver:", drvOk ? "CONNECTED" : "NOT CONNECTED",
       drvOk ? colGreen : colRed);

  // 2. SDK
  bool sdkOk = g_SDK != nullptr;
  line("SDK Instance:", sdkOk ? "OK" : "NULL", sdkOk ? colGreen : colRed);

  if (!sdkOk)
    return;

  // 3. Attached
  bool att = g_SDK->IsAttached();
  snprintf(buf, sizeof(buf), "%s (PID: %u)", att ? "YES" : "NO",
           g_SDK->GetPID());
  line("Attached:", buf, att ? colGreen : colRed);

  // 4. GameAssembly base
  uintptr_t ga = g_SDK->GetGameAssemblyBase();
  snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)ga);
  line("GameAssembly.dll:", buf, ga ? colGreen : colRed);

  // 6. Entity list
  int entCount = g_SDK->GetEntityCount();
  uintptr_t entBuf = g_SDK->GetEntityBufferAddr();
  snprintf(buf, sizeof(buf), "%d (buf: 0x%llX)", entCount, (uint64_t)entBuf);
  line("Entity Count:", buf, entCount > 0 ? colGreen : colRed);

  // 6.5. GC Table status (for step 4 debugging)
  if (g_SDK) {
    // Access private members via public getters we'll add
    uintptr_t bitmapAddr = g_SDK->GetGCBitmapAddr();
    uintptr_t flatTable = g_SDK->GetGCHandleTable();
    bool gcOk = (bitmapAddr != 0 || flatTable != 0);
    
    if (bitmapAddr && flatTable) {
      snprintf(buf, sizeof(buf), "BOTH (bitmap=0x%llX flat=0x%llX)", (uint64_t)bitmapAddr, (uint64_t)flatTable);
      line("GC Table:", buf, colGreen);
    } else if (bitmapAddr) {
      snprintf(buf, sizeof(buf), "bitmap=0x%llX", (uint64_t)bitmapAddr);
      line("GC Table:", buf, colGreen);
    } else if (flatTable) {
      snprintf(buf, sizeof(buf), "flat=0x%llX", (uint64_t)flatTable);
      line("GC Table:", buf, colGreen);
    } else {
      line("GC Table:", "NOT FOUND - STEP 4 WILL FAIL", colRed);
    }
  }

  // 6. Entity chain step-by-step
  {
    const auto &d = g_SDK->entDbg;
    const char *stepNames[] = {"not run",
                               "1: TypeInfo (GA+baseptr)",
                               "2: staticFields (TI+0xB8)",
                               "3: wrapper1 (SF+0x18)",
                               "4: decrypt client_entities",
                               "5: wrapper2 (CE+0x10)",
                               "6: decrypt entity_list",
                               "7: bufferList (EL+0x18)",
                               "8: count/array from buffer"};
    int step = d.lastFailStep;
    if (step == 99) {
      line("Entity Chain:", "ALL STEPS OK", colGreen);
    } else if (step >= 1 && step <= 8) {
      snprintf(buf, sizeof(buf), "FAILED at step %s", stepNames[step]);
      line("Entity Chain:", buf, colRed);
    } else {
      line("Entity Chain:", "Not yet run", colYellow);
    }

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.typeInfo);
    line("  1.TypeInfo:", buf,
         d.typeInfo ? colGreen : (step >= 1 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.staticFields);
    line("  2.staticFields:", buf,
         d.staticFields ? colGreen : (step >= 2 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.wrapper1);
    line("  3.wrapper1:", buf,
         IsValidPtr(d.wrapper1) ? colGreen : (step >= 3 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.clientEntities);
    line("  4.clientEntities:", buf,
         IsValidPtr(d.clientEntities) ? colGreen
                                      : (step >= 4 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.wrapper2);
    line("  5.wrapper2:", buf,
         IsValidPtr(d.wrapper2) ? colGreen : (step >= 5 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.entityList);
    line("  6.entityList:", buf,
         IsValidPtr(d.entityList) ? colGreen : (step >= 6 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)d.bufferList);
    line("  7.bufferList:", buf,
         IsValidPtr(d.bufferList) ? colGreen : (step >= 7 ? colRed : colGray));

    snprintf(buf, sizeof(buf), "arr=0x%llX count=%d", (uint64_t)d.entityArray,
             d.rawCount);
    line("  8.array/count:", buf,
         (IsValidPtr(d.entityArray) && d.rawCount > 0)
             ? colGreen
             : (step >= 8 ? colRed : colGray));
  }

  // 7. Player cache + sample player (single lock)
  int cacheSize = 0;
  PlayerData samplePlayer = {};
  bool haveSample = false;
  {
    std::lock_guard<std::mutex> lock(g_DataMutex);
    cacheSize = (int)g_cachedPlayers.size();
    if (cacheSize > 0) {
      samplePlayer = g_cachedPlayers[0];
      haveSample = true;
    }
  }
  snprintf(buf, sizeof(buf), "%d", cacheSize);
  line("Cached Players:", buf,
       cacheSize > 0 ? colGreen : (entCount > 0 ? colYellow : colRed));

  // 8. View matrix
  ViewMatrix vm = {};
  bool vmOk = false;
  if (att)
    vmOk = g_SDK->GetViewMatrix(vm);
  bool vmNonZero = false;
  for (int i = 0; i < 4 && !vmNonZero; i++)
    for (int j = 0; j < 4 && !vmNonZero; j++)
      if (vm.m[i][j] != 0.f)
        vmNonZero = true;
  snprintf(buf, sizeof(buf), "%s (nonzero: %s)", vmOk ? "READ OK" : "READ FAIL",
           vmNonZero ? "YES" : "NO");
  line("View Matrix:", buf, (vmOk && vmNonZero) ? colGreen : colRed);

  // Show first row of view matrix for sanity
  snprintf(buf, sizeof(buf), "[%.2f, %.2f, %.2f, %.2f]", vm.m[0][0], vm.m[0][1],
           vm.m[0][2], vm.m[0][3]);
  line("  VM Row 0:", buf, colGray);

  // 9. Camera position
  Vec3 camPos = {};
  if (att)
    camPos = g_SDK->GetCameraPosition();
  snprintf(buf, sizeof(buf), "(%.1f, %.1f, %.1f)", camPos.x, camPos.y,
           camPos.z);
  bool camOk = (camPos.x != 0.f || camPos.y != 0.f || camPos.z != 0.f);
  line("Camera Pos:", buf, camOk ? colGreen : colRed);

  // 10. Local player
  uintptr_t localP = att ? g_SDK->GetLocalPlayer() : 0;
  snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)localP);
  line("Local Player:", buf, localP ? colGreen : colYellow);

  // 11. ESP enabled flags
  snprintf(buf, sizeof(buf), "esp=%d boxes=%d names=%d dist=%d skel=%d",
           g_espEnabled, g_espBoxes, g_espNames, g_espDistance, g_espSkeleton);
  line("ESP Flags:", buf, g_espEnabled ? colGreen : colRed);

  // 11b. Skeleton debug
  if (g_espSkeleton && g_SDK) {
    int skelPlayers = 0;
    {
      std::lock_guard<std::mutex> lk(g_DataMutex);
      for (const auto &p : g_cachedPlayers)
        if (!p.bones.empty())
          skelPlayers++;
    }
    snprintf(buf, sizeof(buf), "withBones=%d | %s", skelPlayers,
             g_SDK->boneDebug.c_str());
    line("Skeleton:", buf, skelPlayers > 0 ? colGreen : colRed);
  }

  // 12. Screen size
  snprintf(buf, sizeof(buf), "%dx%d", g_ScreenW, g_ScreenH);
  line("Screen:", buf, (g_ScreenW > 0 && g_ScreenH > 0) ? colGreen : colRed);

  // 13. Sample W2S test with first cached player
  if (haveSample) {
    Vec2 screenPt;
    bool w2s = RustSDK::WorldToScreen(samplePlayer.position, g_ViewMatrix,
                                      g_ScreenW, g_ScreenH, screenPt);

    char nameBuf[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, samplePlayer.name.c_str(), -1, nameBuf,
                        sizeof(nameBuf), nullptr, nullptr);

    snprintf(buf, sizeof(buf), "'%s' pos(%.0f,%.0f,%.0f) dist=%.0f", nameBuf,
             samplePlayer.position.x, samplePlayer.position.y,
             samplePlayer.position.z, samplePlayer.distance);
    line("Player[0]:", buf, colWhite);

    snprintf(
        buf, sizeof(buf), "W2S=%s screen(%.0f,%.0f) sleep=%d wound=%d vis=%d",
        w2s ? "OK" : "FAIL", screenPt.x, screenPt.y, samplePlayer.isSleeping,
        samplePlayer.isWounded, samplePlayer.isVisible);
    line("  W2S Test:", buf, w2s ? colGreen : colYellow);
  }

  // 14. Aimbot diagnostics
  snprintf(buf, sizeof(buf), "on=%d key=%s chk=%d w2s=%d tgt=0x%llX",
           Vars::Aim::enabled, g_aimDbg.keyHeld ? "HELD" : "no",
           g_aimDbg.playersChecked, g_aimDbg.playersPassedW2S,
           (unsigned long long)g_aimDbg.bestTarget);
  line("Aimbot:", buf,
       g_aimDbg.bestTarget ? colGreen
                           : (g_aimDbg.keyHeld ? colYellow : colGray));

  if (g_aimDbg.keyHeld) {
    snprintf(buf, sizeof(buf), "bone=(%.0f,%.0f,%.0f) write=%s",
             g_aimDbg.bonePos.x, g_aimDbg.bonePos.y, g_aimDbg.bonePos.z,
             g_aimDbg.writeAttempted ? "YES" : "NO");
    line("  aim state:", buf, g_aimDbg.writeAttempted ? colGreen : colRed);
  }

  if (att && localP) {
    uintptr_t pInput =
        g_SDK->ReadVal<uintptr_t>(localP + Offsets::BasePlayer::playerInput);
    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)pInput);
    line("  playerInput:", buf, IsValidPtr(pInput) ? colGreen : colRed);

    if (IsValidPtr(pInput)) {
      Vec3 ba = g_SDK->ReadVal<Vec3>(pInput + Offsets::PlayerInput::bodyAngles);
      snprintf(buf, sizeof(buf), "(%.1f, %.1f, %.1f)", ba.x, ba.y, ba.z);
      line("  bodyAngles:", buf,
           (ba.x != 0.f || ba.y != 0.f) ? colGreen : colYellow);
    }

    uintptr_t weapon = g_SDK->GetActiveWeaponBaseProjectile(localP);
    snprintf(buf, sizeof(buf), "0x%llX", (uint64_t)weapon);
    line("  heldWeapon:", buf, weapon ? colGreen : colGray);

    // Show decrypted active item UID
    uintptr_t encAI =
        g_SDK->ReadVal<uintptr_t>(localP + Offsets::BasePlayer::clactiveitem);
    uint32_t decUID = 0;
    if (encAI) {
      uintptr_t dec = RustDecrypt::DecryptClActiveItem(encAI);
      decUID = (uint32_t)(dec & 0xFFFFFFFF);
    }
    snprintf(buf, sizeof(buf), "UID=%u (enc=0x%llX)", decUID, (uint64_t)encAI);
    line("  activeItem:", buf, decUID ? colGreen : colRed);

    // Show raw inventory/activeitem offsets for debugging
    uintptr_t rawInv = g_SDK->ReadVal<uintptr_t>(
        localP + Offsets::BasePlayer::inventory);
    uintptr_t rawHeld2 =
        g_SDK->ReadVal<uintptr_t>(localP + Offsets::BasePlayer::clactiveitem);
    snprintf(buf, sizeof(buf), "inv=0x%llX  clact=0x%llX", (uint64_t)rawInv,
             (uint64_t)rawHeld2);
    line("  rawHeld:", buf, (rawInv || rawHeld2) ? colYellow : colRed);
    if (weapon) {
      std::string wcn = g_SDK->ReadClassName(weapon);
      float bSpeed = g_SDK->GetWeaponBulletSpeed(weapon);
      snprintf(buf, sizeof(buf), "%s  vel=%.0f m/s", wcn.c_str(), bSpeed);
      line("  weaponClass:", buf, colGreen);
    }
  }

  // 15. No-Recoil diagnostics (angle-correction mode)
  {
    bool firing = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    snprintf(buf, sizeof(buf), "enabled=%d local=%d correcting=%d firing=%d",
             g_noRecoilEnabled, g_noRecoilHasLocal, g_noRecoilHasWeapon,
             firing ? 1 : 0);
    ImU32 nrCol =
        !g_noRecoilEnabled
            ? colGray
            : (g_noRecoilHasWeapon ? colGreen
                                   : (g_noRecoilHasLocal ? colYellow : colRed));
    line("No-Recoil:", buf, nrCol);
  }

  // 17. Hotbar download progress
  if (!g_HotbarDownloader.IsDownloadComplete()) {
    int progress = g_HotbarDownloader.GetProgress();
    snprintf(buf, sizeof(buf), "Downloading %d%%", progress);
    line("Hotbar Images:", buf, colYellow);
  } else {
    line("Hotbar Images:", "Download Complete", colGreen);
  }

  // 18. Recent logs (probe output from SDK + global)
  {
    // SDK aiProbeLog (decrypt probe results)
    if (g_SDK) {
      int n = (int)g_SDK->aiProbeLog.size();
      int start = n > 8 ? (n - 8) : 0;
      snprintf(buf, sizeof(buf), "%d lines", n);
      line("AIProbe:", buf, n ? colYellow : colGray);
      for (int i = start; i < n; i++) {
        dl->AddText(ImVec2(x + 10, y), colYellow, g_SDK->aiProbeLog[i].c_str());
        y += lineH;
      }
    }

    // Global overlay log (ore probe etc.)
    std::lock_guard<std::mutex> lock(g_DebugLogMutex);
    int n = (int)g_DebugLogLines.size();
    int start = n > 6 ? (n - 6) : 0;
    snprintf(buf, sizeof(buf), "%d lines", n);
    line("Logs:", buf, n ? colYellow : colGray);
    for (int i = start; i < n; i++) {
      dl->AddText(ImVec2(x + 10, y), colGray, g_DebugLogLines[i].c_str());
      y += lineH;
    }
  }

  // 17. LocalTeam
  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)g_LocalTeam);
  line("Local Team:", buf, colGray);

  y += 4;
  dl->AddText(ImVec2(x, y), colGray, "Press F2 to hide this panel");
}

// ── Main ESP Render ────────────────────────────────────────────────

static bool IsGameInFocus() {
  HWND fg = GetForegroundWindow();
  if (!fg)
    return false;
  DWORD fgPid = 0;
  GetWindowThreadProcessId(fg, &fgPid);
  return (g_SDK && fgPid == g_SDK->GetPID());
}

void RenderESP() {
  if (!g_SDK || !g_SDK->IsAttached())
    return;
  if (!g_espEnabled)
    return;
  if (!IsGameInFocus())
    return; // only draw when game is in focus

  WorldEsp();

  ImDrawList *draw = ImGui::GetForegroundDrawList();

  // Watermark
  if (g_FontDefault)
    ImGui::PushFont(g_FontDefault);
  {
    float fps = ImGui::GetIO().Framerate;
    char fpsBuf[64];
    snprintf(fpsBuf, sizeof(fpsBuf), "|   FPS: %.0f", fps);

    ImVec2 textSize = ImGui::CalcTextSize("Jew Ware");
    ImVec2 fpsSize = ImGui::CalcTextSize(fpsBuf);
    float totalW = textSize.x + fpsSize.x + 16.f;
    draw->AddRectFilled(ImVec2(5, 5),
                        ImVec2(5 + totalW + 8, 5 + textSize.y + 6),
                        IM_COL32(0, 0, 0, 220), 4.0f);

    float tx = 9.f;
    draw->AddText(ImVec2(tx, 8), IM_COL32(255, 255, 255, 255), "Jew ");
    tx += ImGui::CalcTextSize("Jew ").x;
    draw->AddText(ImVec2(tx, 8), IM_COL32(251, 160, 227, 255), "Ware");
    tx += ImGui::CalcTextSize("Ware").x;
    draw->AddText(ImVec2(tx, 8), IM_COL32(255, 255, 255, 255), fpsBuf);
  }
  if (g_FontDefault)
    ImGui::PopFont();

  // View matrix (1 read per frame)
  if (!g_SDK->GetViewMatrix(g_ViewMatrix))
    return;

  // ── Bullet tracers (real projectile trails, red → black) ──
  if (g_bulletTracers) {
    std::lock_guard<std::mutex> tLock(g_tracerMutex);
    ULONGLONG now = GetTickCount64();

    for (const auto &t : g_tracers) {
      int nPts = t.numPoints;
      if (nPts < 2) continue;

      ULONGLONG age = now - t.spawnTick;
      // Fade factor: full brightness while alive, fade after projectile gone
      float fadeFactor = (age < 200) ? 1.0f : (1.0f - (float)(age - 200) / 1300.0f);
      if (fadeFactor <= 0.0f) continue;

      // Project all accumulated trail points
      Vec2 screenPts[TracerLine::MAX_PTS];
      bool visible[TracerLine::MAX_PTS];
      for (int i = 0; i < nPts; i++) {
        visible[i] = RustSDK::WorldToScreen(t.points[i], g_ViewMatrix,
                                            g_ScreenW, g_ScreenH, screenPts[i]);
      }

      // Draw all trail segments: oldest = black/faded, newest = bright red
      for (int i = 0; i < nPts - 1; i++) {
        if (!visible[i] || !visible[i + 1]) continue;

        // 0.0 = oldest point (tail), 1.0 = newest point (head)
        float frac = (float)i / (float)(nPts - 1);

        int a = (int)(frac * fadeFactor * 240.0f);
        if (a < 1) continue;

        // Red at head → black at tail
        int rr = (int)(255.0f * frac);

        ImVec2 p1(screenPts[i].x, screenPts[i].y);
        ImVec2 p2(screenPts[i + 1].x, screenPts[i + 1].y);

        draw->AddLine(p1, p2, IM_COL32(rr, 0, 0, a), 1.5f);
        draw->AddLine(p1, p2, IM_COL32(rr, 0, 0, a / 4), 3.0f);
      }
    }
  }

  int players = 0;

  std::lock_guard<std::mutex> lock(g_DataMutex);
  for (const auto &player : g_cachedPlayers) {
    if (player.isSleeping && !g_espShowSleepers)
      continue;
    if (player.isWounded && !g_espShowWounded)
      continue;
    // When vischeck is on, don't hide players — instead color bones per visibility

    // World -> screen
    Vec2 screenFeet, screenHead;
    bool feetOK = RustSDK::WorldToScreen(player.position, g_ViewMatrix,
                                         g_ScreenW, g_ScreenH, screenFeet);
    bool headOK = RustSDK::WorldToScreen(player.headPos, g_ViewMatrix,
                                         g_ScreenW, g_ScreenH, screenHead);
    if (!feetOK && !headOK)
      continue;

    float boxH = fabsf(screenFeet.y - screenHead.y);
    float boxW = boxH * 0.45f;
    if (boxH < 2.f)
      continue;

    float cx = (screenFeet.x + screenHead.x) * 0.5f;

    // Color by state
    ImU32 color = COL_ENEMY;
    if (player.isSleeping)
      color = COL_SLEEPER;
    else if (player.isWounded)
      color = COL_WOUNDED;
    else if (player.teamID != 0 && player.teamID == g_LocalTeam)
      color = COL_TEAM;

    players++;

    // Calculate dynamic bounding box from bones
    float x1 = 0, y1 = 0, x2 = 0, y2 = 0;
    bool hasBox = false;

    if (!player.bones.empty()) {
      float minX = 10000.f, minY = 10000.f, maxX = -10000.f, maxY = -10000.f;
      int projected = 0;
      for (const auto &bone : player.bones) {
        if (bone.x == 0.f && bone.y == 0.f && bone.z == 0.f)
          continue;
        Vec2 s;
        if (RustSDK::WorldToScreen(bone, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                   s)) {
          if (s.x < minX)
            minX = s.x;
          if (s.x > maxX)
            maxX = s.x;
          if (s.y < minY)
            minY = s.y;
          if (s.y > maxY)
            maxY = s.y;
          projected++;
        }
      }
      if (projected > 0) {
        // Add some padding
        float padX = (maxX - minX) * 0.05f + 2.f;
        float padY = (maxY - minY) * 0.05f + 2.f;
        x1 = minX - padX;
        x2 = maxX + padX;
        y1 = minY - padY;
        y2 = maxY + padY;
        hasBox = true;
      }
    }

    // Fallback to height-based box if bones failed
    if (!hasBox) {
      float boxH = fabsf(screenFeet.y - screenHead.y);
      float boxW = boxH * 0.45f;
      float cx = (screenFeet.x + screenHead.x) * 0.5f;
      x1 = cx - boxW * 0.5f;
      x2 = cx + boxW * 0.5f;
      y1 = screenHead.y;
      y2 = screenFeet.y;
    }

    // Box & Fill (dark transparent fill, subtle edge)
    if (g_espBoxes) {
      // Semi-transparent dark fill
      draw->AddRectFilled(ImVec2(x1, y1), ImVec2(x2, y2),
                          IM_COL32(0, 0, 0, 60));
      // Thin subtle dark border
      draw->AddRect(ImVec2(x1, y1), ImVec2(x2, y2),
                    IM_COL32(0, 0, 0, 120), 0.f, 0, 1.0f);
    }

    // Name
    if (g_FontESP)
      ImGui::PushFont(g_FontESP);
    float textY = screenHead.y - 12.f;
    if (g_espNames && !player.name.empty()) {
      char nameBuf[128] = {};
      WideCharToMultiByte(CP_UTF8, 0, player.name.c_str(), -1, nameBuf,
                          sizeof(nameBuf), nullptr, nullptr);
      ImVec2 ts = ImGui::CalcTextSize(nameBuf);
      float tx = cx - ts.x * 0.5f;
      ImU32 nameColor;
      if (g_espVisCheck)
        nameColor = player.isVisible ? IM_COL32(0, 255, 0, 255) : IM_COL32(255, 0, 0, 255);
      else
        nameColor = color;
      draw->AddText(ImVec2(tx + 1, textY + 1), IM_COL32(0, 0, 0, 200), nameBuf);
      draw->AddText(ImVec2(tx, textY), nameColor, nameBuf);
      textY -= 11.f;
    }

    // Distance
    if (g_espDistance) {
      char buf[32];
      snprintf(buf, sizeof(buf), "[%.0fm]", player.distance);
      ImVec2 ts = ImGui::CalcTextSize(buf);
      float tx = cx - ts.x * 0.5f;
      draw->AddText(ImVec2(tx + 1, screenFeet.y + 3), IM_COL32(0, 0, 0, 200),
                    buf);
      draw->AddText(ImVec2(tx, screenFeet.y + 2), IM_COL32(255, 255, 255, 255),
                    buf);
    }
    if (g_FontESP)
      ImGui::PopFont();

    // Snaplines
    if (g_espSnaplines) {
      draw->AddLine(ImVec2((float)(g_ScreenW / 2), (float)g_ScreenH),
                    ImVec2(screenFeet.x, screenFeet.y), COL_SNAP, 1.0f);
    }

    // Skeleton (using g_skeletonPairs from rust_sdk.h with correct bone
    // indices)
    if (g_espSkeleton && !player.bones.empty()) {
      int numBones = (int)player.bones.size();
      for (int p = 0; p < g_skeletonPairCount; p++) {
        int from = g_skeletonPairs[p].from;
        int to = g_skeletonPairs[p].to;
        if (from >= numBones || to >= numBones)
          continue;

        const Vec3 &b1 = player.bones[from];
        const Vec3 &b2 = player.bones[to];
        if (b1.x == 0.f && b1.y == 0.f && b1.z == 0.f)
          continue;
        if (b2.x == 0.f && b2.y == 0.f && b2.z == 0.f)
          continue;

        Vec2 s1, s2;
        if (RustSDK::WorldToScreen(b1, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                   s1) &&
            RustSDK::WorldToScreen(b2, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                   s2)) {
          ImU32 skelColor;
          if (g_espVisCheck) {
            // Per-bone visibility coloring: green = visible, red = not visible
            skelColor = player.isVisible ? IM_COL32(0, 255, 0, 255) : IM_COL32(255, 0, 0, 255);
          } else {
            skelColor = color; // use player state color (enemy/team/sleeper/wounded)
          }
          draw->AddLine(ImVec2(s1.x, s1.y), ImVec2(s2.x, s2.y), skelColor,
                        g_espSkeletonThickness);
        }
      }
    }

    // Health bar (placed on RIGHT side of bounding box, thick green bar)
    if (g_espHealthBar && g_espBoxes && player.maxHealth > 0.f) {
      float hpFrac = player.health / player.maxHealth;
      if (!(hpFrac >= 0.0f)) hpFrac = 0.0f; // catches NaN
      if (hpFrac > 1.0f) hpFrac = 1.0f;

      float barX = x2 + 3.f; // 3px gap from right of box
      float barW_ui = 4.0f;  // thicker bar to match reference
      float barH_ui = y2 - y1;
      float filled = barH_ui * hpFrac;

      // Background (dark)
      draw->AddRectFilled(ImVec2(barX, y1), ImVec2(barX + barW_ui, y2),
                          IM_COL32(0, 0, 0, 160));
      // Fill (solid bright green)
      draw->AddRectFilled(ImVec2(barX, y2 - filled), ImVec2(barX + barW_ui, y2),
                          IM_COL32(0, 255, 0, 255));
    }
  }

  // ── Hotbar ESP: show closest player's hotbar + clothing (reference-style) ──
  if (g_espHotbar) {
    float scrCX = (float)(g_ScreenW / 2);
    float scrCY = (float)(g_ScreenH / 2);
    float bestDist = Vars::Aim::fov;
    const PlayerData *hotbarTarget = nullptr;

    for (const auto &p : g_cachedPlayers) {
      if (p.hotbarItems.empty() && p.wearItems.empty())
        continue;
      if (p.address == g_SDK->GetLocalPlayer())
        continue;
      Vec2 hs;
      if (!RustSDK::WorldToScreen(p.headPos, g_ViewMatrix, g_ScreenW, g_ScreenH,
                                  hs))
        continue;
      float d = sqrtf((hs.x - scrCX) * (hs.x - scrCX) +
                      (hs.y - scrCY) * (hs.y - scrCY));
      if (d < bestDist) {
        bestDist = d;
        hotbarTarget = &p;
      }
    }

    if (hotbarTarget) {
      // Log shortnames once for debugging
      static uintptr_t lastLoggedTarget = 0;
      if (hotbarTarget->address != lastLoggedTarget) {
        lastLoggedTarget = hotbarTarget->address;
        auto &hi = hotbarTarget->hotbarItems;
        auto &wi = hotbarTarget->wearItems;
        if (!hi.empty() || !wi.empty()) {
          printf("[Hotbar] Belt: ");
          for (int i = 0; i < (int)hi.size(); i++)
            printf("'%s' ", hi[i].c_str());
          printf("| Wear: ");
          for (int i = 0; i < (int)wi.size(); i++)
            printf("'%s' ", wi[i].c_str());
          printf("| Icons loaded: %d\n", (int)g_ItemIcons.size());
        }
      }

      if (g_FontESP)
        ImGui::PushFont(g_FontESP);

      // ── Helper lambda to draw a row of item slots ──
      auto drawItemRow = [&](const std::vector<std::string> &items,
                             int maxSlots, float slotSize, float slotPad,
                             float panelX, float panelY, float panelW,
                             float panelH, float rounding) {
        // Panel background
        draw->AddRectFilled(ImVec2(panelX, panelY),
                            ImVec2(panelX + panelW, panelY + panelH),
                            IM_COL32(30, 30, 30, 160), rounding);
        draw->AddRect(ImVec2(panelX, panelY),
                      ImVec2(panelX + panelW, panelY + panelH),
                      IM_COL32(80, 80, 80, 100), rounding);

        int count = (int)items.size();
        if (count > maxSlots)
          count = maxSlots;
        float innerPad = 6.f;
        float slotsStartX = panelX + innerPad;
        float slotsStartY = panelY + innerPad;

        for (int s = 0; s < count; s++) {
          float sx = slotsStartX + s * (slotSize + slotPad);
          float sy = slotsStartY;

          // Slot background
          draw->AddRectFilled(ImVec2(sx, sy),
                              ImVec2(sx + slotSize, sy + slotSize),
                              IM_COL32(40, 40, 40, 180), 4.f);
          draw->AddRect(ImVec2(sx, sy), ImVec2(sx + slotSize, sy + slotSize),
                        IM_COL32(90, 90, 90, 120), 4.f);

          if (!items[s].empty()) {
            const std::string &sn = items[s];

            // Try icon texture first
            auto iconIt = g_ItemIcons.find(sn);
            if (iconIt != g_ItemIcons.end() && iconIt->second) {
              float ip = 3.f;
              draw->AddImage((ImTextureID)iconIt->second,
                             ImVec2(sx + ip, sy + ip),
                             ImVec2(sx + slotSize - ip, sy + slotSize - ip));
            } else {
              // Fallback: truncated shortname
              std::string abbr = sn;
              size_t dot = abbr.find('.');
              if (dot != std::string::npos)
                abbr = abbr.substr(dot + 1);
              if (abbr.length() > 6)
                abbr = abbr.substr(0, 6);
              ImVec2 ts = ImGui::CalcTextSize(abbr.c_str());
              draw->AddText(ImVec2(sx + (slotSize - ts.x) * 0.5f,
                                   sy + (slotSize - ts.y) * 0.5f),
                            IM_COL32(200, 200, 200, 220), abbr.c_str());
            }

            // "x1" count label below icon
            const char *countLabel = "x1";
            ImVec2 cs = ImGui::CalcTextSize(countLabel);
            float cx = sx + (slotSize - cs.x) * 0.5f;
            float cy = sy + slotSize - cs.y - 1.f;
            draw->AddText(ImVec2(cx + 1, cy + 1), IM_COL32(0, 0, 0, 180),
                          countLabel);
            draw->AddText(ImVec2(cx, cy), IM_COL32(255, 255, 255, 220),
                          countLabel);
          }
        }
      };

      // ── Layout calculations ──
      const auto &beltItems = hotbarTarget->hotbarItems;
      const auto &wearItems = hotbarTarget->wearItems;

      const float hotbarSlotSize = 48.f;
      const float hotbarSlotPad = 4.f;
      const float wearSlotSize = 52.f;
      const float wearSlotPad = 4.f;
      const float panelPad = 12.f; // inner padding on each side
      const float panelRound = 8.f;
      const float rowGap = 6.f;

      int beltCount = (int)beltItems.size();
      if (beltCount > 6)
        beltCount = 6;
      int wearCount = (int)wearItems.size();
      if (wearCount > 7)
        wearCount = 7;

      float hotbarPanelW = beltCount > 0
                               ? (beltCount * hotbarSlotSize +
                                  (beltCount - 1) * hotbarSlotPad + panelPad)
                               : 0;
      float hotbarPanelH = beltCount > 0 ? (hotbarSlotSize + panelPad) : 0;
      float wearPanelW = wearCount > 0
                             ? (wearCount * wearSlotSize +
                                (wearCount - 1) * wearSlotPad + panelPad)
                             : 0;
      float wearPanelH = wearCount > 0 ? (wearSlotSize + panelPad) : 0;

      float maxPanelW = (hotbarPanelW > wearPanelW) ? hotbarPanelW : wearPanelW;

      // Position: centered at top of screen
      float baseY = 32.f;

      // Player name label
      char nameBuf[128] = {};
      WideCharToMultiByte(CP_UTF8, 0, hotbarTarget->name.c_str(), -1, nameBuf,
                          sizeof(nameBuf), nullptr, nullptr);

      // Name background pill
      ImVec2 nameSize = ImGui::CalcTextSize(nameBuf);
      float namePillW = nameSize.x + 16.f;
      float namePillH = nameSize.y + 8.f;
      float namePillX = scrCX - namePillW * 0.5f;
      float namePillY = baseY;

      draw->AddRectFilled(ImVec2(namePillX, namePillY),
                          ImVec2(namePillX + namePillW, namePillY + namePillH),
                          IM_COL32(30, 30, 30, 180), namePillH * 0.5f);
      draw->AddRect(ImVec2(namePillX, namePillY),
                    ImVec2(namePillX + namePillW, namePillY + namePillH),
                    IM_COL32(100, 100, 100, 100), namePillH * 0.5f);
      draw->AddText(ImVec2(scrCX - nameSize.x * 0.5f, namePillY + 4.f),
                    IM_COL32(255, 255, 255, 255), nameBuf);

      float currentY = namePillY + namePillH + rowGap;

      // Hotbar row (belt items)
      if (beltCount > 0) {
        float px = scrCX - hotbarPanelW * 0.5f;
        drawItemRow(beltItems, 6, hotbarSlotSize, hotbarSlotPad, px, currentY,
                    hotbarPanelW, hotbarPanelH, panelRound);
        currentY += hotbarPanelH + rowGap;
      }

      // Clothing row (wear items)
      if (wearCount > 0) {
        float px = scrCX - wearPanelW * 0.5f;
        drawItemRow(wearItems, 7, wearSlotSize, wearSlotPad, px, currentY,
                    wearPanelW, wearPanelH, panelRound);
      }

      if (g_FontESP)
        ImGui::PopFont();
    }
  }

  g_PlayerCount = players;
}
