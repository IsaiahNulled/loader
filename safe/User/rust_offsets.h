#pragma once

namespace offsets {
    inline int basenetworkable_pointer = 0xD7F41D0;  // BaseNetworkable static inner class TypeInfo (UPDATED from 0xD735490)
    inline uint64_t camera_pointer = 0xD7E7AF0;  // MainCamera TypeInfo (UPDATED from 0xD73AE70)
    inline uint64_t tod_sky_pointer = 0xD827370;  // TOD_Sky TypeInfo (chain: +0xB8 +0x28 +0x10 +0x20)
    inline uint64_t console_pointer = 0xBDA4B28;  // TODO: find new offset
    inline uint64_t convar_graphics_pointer = 0xd793b80;  // ConVar.Graphics TypeInfo (for FOV) - UPDATED
    inline uint64_t Il2cppHandle = 0xDAD33E0;     // Il2cpp GC handle table (UPDATED - get_handle function)
    inline uint64_t WorldOffset = 0xD67F510;      // World TypeInfo - TODO: needs update
    inline uint64_t PhysxOffset = 0x1C3B3D0;      // Physx offset
    inline uint64_t ListComponent_Projectile_c = 0xD794B68;  // UPDATED from 0xD6F1350
    inline uint64_t PlayerEyes_c = 0xD78E9D0;  // UPDATED from 0xD72A6E8
    inline uint64_t HeldEntityClass = 0xD78C278;  // UPDATED from 0xD6373E0


    inline uint64_t convar_terrain_pointer = 0;  // ConVar.Terrain TypeInfo (TODO: dump offset)

    namespace Graphic
    {
        inline int  fov = 0x518;  // Convar.Graphics._fov static field offset - UPDATED
        inline uint64_t Base = 0xD793B80;  // Convar.Graphics TypeInfo (for FOV) - UPDATED
        inline int StaticFields = 0xB8;   // Static fields offset
    }

    namespace Terrain
    {
        inline int StaticFields = 0xB8;
        inline int drawTreeDistance = 0;    // ConVar.Terrain._drawTreeDistance (TODO: dump offset)
        inline int drawGrassDistance = 0;   // ConVar.Terrain._drawGrassDistance (TODO: dump offset)
    }

    namespace ConsoleSystem
    {
        inline int  static_fields = 0xB8;
        inline int  wrapper_class = 0x78;
        inline int  name = 0x30;
        inline int  allowrunfromserver = 0x99; // 0x3A


    }

    namespace BaseNetworkable
    {
        inline int  static_fields = 0xB8;
        inline int  client_entities = 0x20;        // UPDATED: client_entities at +0x20 (from new code)
        inline int  entity_list = 0x10;           // entity_list encrypted wrapper (in clientEntities)
        inline int  object_dictionary = 0x20;     // plain read from entityList
        inline int  entity_content = 0x10;        // entity array in objectDictionary
        inline int  entity_size = 0x18;           // entity count in objectDictionary (probe confirmed 1269 at +0x18)
        inline int  buffer_list = 0x10;           // buffer pointer from entityList (final 0x10 in chain)
        inline int  prefabID = 0x30;
        inline int  children = 0x40;
        inline int  parent_entity = 0x70;
    }
    namespace BaseCamera
    {
        inline uint64_t  static_fields = 0xB8;
        inline uint64_t  wrapper_class = 0x60;  // UPDATED: MainCamera.instance offset (from new code)
        inline uint64_t  parent_static_fields = 0x10;
        inline int matrix = 0x30c;       // OLD: was reading garbage far into object
        inline int viewMatrix = 0x80;   // View matrix (world-to-camera)
        inline int projMatrix = 0xC0;   // Projection matrix
        inline int position = 0x454;
        inline int cullingMask = 0x43C;
    }

    namespace TodSky
    {
        inline uint64_t  Class = 0xD827370;  // FIXED from working cheat
        inline uint64_t  static_fields = 0xB8;
        inline uint64_t  wrapper_class = 0x90;  // UPDATED: Step2 (was 0x20)
        inline uint64_t  parent_static_fields = 0x10;
        inline uint64_t  unk = 0x20;
        inline uint64_t  instance = 0x28;           // Static field holding instance/handle

        inline int  TOD_CycleParameters = 0x40;
        inline int TOD_AtmosphereParameters = 0x50;
        inline int TOD_DayParameters = 0x58;
        inline int TOD_NightParameters = 0x60;
        inline int TOD_StarParameters = 0x78;
        inline int TOD_FogParameters = 0x90;
        inline int TOD_AmbientParameters = 0x98;

        // TOD_Components (assigned in TOD_Sky.Initialize)
        inline int TOD_Components = 0x230; // UPDATED from dump.cs (was 0xA0)

        // TOD_Time offsets (on the TOD_Time component)
        namespace Time {
            inline int ProgressTime = 0x24;   // bool — controls whether time advances
            inline int UseTimeCurve = 0x25;    // bool
        }

        // TOD_Components field offsets
        namespace Components {
            inline int Time = 0xC8;            // UPDATED from dump.cs (TOD_Time at 0xC8, was 0x78)
        }

        namespace Cycle {
            inline int hour = 0x10;
        }
        namespace Night {
            inline int lightIntensity = 0x50;
            inline int ambientMultiplier = 0x5C;
            inline int reflectionMultiplier = 0x64;
        }
    }

    namespace BaseCombatEntity {
        inline int lifestate = 0x258;
        inline int model = 0xE8;
        inline int _health = 0x264;
        inline int _maxHealth = 0x268;
    };

    namespace BasePlayer {
        inline int playerFlags = 0x5E8;       // VERIFIED
        inline int clothingBlocksAiming = 0x6C4;
        inline int clothingMoveSpeedReduction = 0x6C8;
        inline int CameraMode = 0x3B8;
        inline int BaseMovement = 0x4E0;      // UPDATED from 0x5B8
        inline int ModelState = 0x628;        // UPDATED from RE (was 0x2A8)
        inline int displayName_ = 0x658;     // UPDATED from RE (was 0x2F0)
        inline int playername = 0x3e8;        // NEW: PlayerName offset
        inline int playerModel = 0x4F8;      // UPDATED from 0x2E8
        inline int clactiveitem = 0x4D0;     // UPDATED: matches new code - encrypted, needs decryption
        inline int inventory = 0x4E8;        // UPDATED: matches new code - encrypted<PlayerInventory>
        inline int playerInput = 0x338;       // UPDATED from 0x6E0
        inline int eyes = 0x2B0;             // UPDATED from 0x2B8 - matches new code
        // cachedHeldEntity REMOVED — 0xD8 is Unity internal, not a game field (caused BSOD)
        inline int Visible = 0x170;
        inline int Visible1 = 0x172;
        inline int currentTeam = 0x4A0;      // NEW - matches user provided
        inline int userId = 0x600;           // NEW - obfuscated field
        inline int lifestate = 0x258;        // NEW - BaseEntity lifestate
        inline int metabolism = 0x380;       // NEW - PlayerMetabolism UPDATED from 0x378
        inline int blueprints = 0x480;       // NEW - PlayerBlueprints UPDATED from 0x2D0
    }

    namespace BaseProjectile {
        inline int recoil = 0x380;
        inline int recoilProperties = 0x380;  // alias for aimbot_wrapper.h // UPDATED: confirmed at BP+0x380 (was 0x318)
        inline int automatic = 0x310;
        inline int isBurstWeapon = 0x3B7;
        inline int internalBurstFireRateScale = 0x3C0;

        inline int viewModel = 0x250; // HeldEntity::ViewModel
        inline int is_reloading = 0x3B8; // UPDATED from RE (was 0x3FC)
        inline int reloadDuration = 0x350;
        inline int primaryMagazine = 0x358;
        inline int sightAimConeScale = 0x390; // UPDATED from RE
        inline int hipAimConeScale = 0x3F4;   // UPDATED from RE

        // NEW offsets from update
        inline int projectileVelocityScale = 0x30C;
        inline int NoiseRadius = 0x300;
        inline int damageScale = 0x304;
        inline int distanceScale = 0x308;
        inline int usableByTurret = 0x311;
        inline int turretDamageScale = 0x314;
        inline int reloadTime = 0x350;
        inline int canUnloadAmmo = 0x354;
        inline int fractionalReload = 0x360;
        inline int aimSway = 0x378;
        inline int aimSwaySpeed = 0x37C;
        inline int aimconeCurve = 0x388;
        inline int aimCone = 0x390;
        inline int hipAimCone = 0x394;
        inline int aimconePenaltyPerShot = 0x398;
        inline int aimConePenaltyMax = 0x39C;
        inline int stancePenaltyScale = 0x3A8;
        inline int hasADS = 0x3AC;
        inline int noAimingWhileCycling = 0x3AD;
        inline int manualCycle = 0x3AE;
        inline int aiming = 0x3B6;
        inline int internalBurstRecoilScale = 0x3BC;
        inline int internalBurstAimConeScale = 0x3C4;
        inline int numShotsFired = 0x3CC;
        inline int repeatDelay = 0x26C;
        inline int deployDelay = 0x268;
        inline int noHeadshots = 0x2BE;
        inline int canChangeFireModes = 0x3B8;

        namespace viewModels {
            inline int baseviewModel = 0x28;
            namespace baseViewModel {
                inline int Animator = 0xC8;

                inline int ViewmodelBob = 0x90;
                inline int viewmodelSway = 0xB0;
                inline int viewmodelLower = 0x78;

                namespace ViewmodelLower {
                    inline int lowerOnSprint = 0x20;
                    inline int lowerWhenCantAttack = 0x21;
                    inline int shouldLower = 0x28;
                }
                namespace ViewmodelSway {
                    inline int positionalSwaySpeed = 0x20;
                    inline int rotationSwayAmount = 0x2C;
                }
                namespace viewmodelBob {
                    inline int bobAmountRun = 0x24;
                    inline int bobAmountWalk = 0x20;
                    inline int bobSpeedRun = 0x24;
                    inline int bobSpeedWalk = 0x20;
                }
            }
        }
    }

    // %f237393b98bdd18d789504eb4a40a794a1c731eb : 
    namespace RecoilProperties {
        inline int new_recoil = 0x80;
        inline int recoilYawMin = 0x18;
        inline int recoilYawMax = 0x1C;
        inline int recoilPitchMin = 0x20;
        inline int recoilPitchMax = 0x24;
        inline int aimconeCurveScale = 0x60;  // NEW
    }
    namespace PlayerInput {
        inline int bodyAngles = 0x44;       // PlayerInput.bodyAngles (Vec3 euler)
    }
    namespace PlayerEyes {
        inline int body_rotation = 0x50;     // Quaternion (Vec4) - controls bullet direction (UPDATED from ref project)
        inline int view_offset = 0x40;
        inline int eye_offset = 0x38;        // UPDATED from ref project (was 0x50, conflicts with body_rotation)
        inline int eye_rotation = 0x6C;
    }
    namespace ItemContainer {
        inline int itemlist = 0x68;           // UPDATED from RE (was 0x28)
        inline int capacity = 0x10;
    }
    namespace PlayerInventory {
        inline int belt = 0x60;            // containerBelt UPDATED from user RE
        inline int containerMain = 0x38;   // containerMain
        inline int clothingbelt = 0x78;    // containerWear UPDATED from RE
    }
    namespace item {
        inline int item_definition = 0x30;  // UPDATED from 0xC8 to match user provided
        inline int item_uid = 0x70;         // ItemId (uid) - UPDATED from user RE (was 0x40)
        inline int held_entity = 0x40;      // HeldEntity (primary) - from user RE
        inline int held_entity_2 = 0xb0;    // HeldEntity (secondary/resolved) - from user RE
        inline int max_health = 0x48;       // PROBE: float 150.0 at +0x48 for weapon
        inline int health = 0x4C;           // next to max_health
        inline int amount = 0xB8;           // PROBE confirmed: 1 for weapon, 999 for stack
        inline int parent_container = 0x18;
    }

    namespace BaseProjectileExploits
    {
        // Automatic
        inline bool automatic = 0x310;

        // Instant Eoka
        inline int FlintStrikeWeapon = 0x438;
        inline int DidShitTick = 0x448; // encrypted value 
    }

    namespace ItemDefinition
    {
        inline int ItemDisplayName = 0x40;
        inline int ShortName = 0x28;
        inline int ItemDisplayEnglish = 0x20;  // UPDATED from RE
        inline int category = 0x58;              // NEW
        inline int itemid = 0x70;                // NEW
        inline int itemMods = 0x170;             // ItemMod[] array (components like ItemModProjectile)
    }

    namespace PlayerModel {
        inline int BoneTransforms = 0x50; // Model::boneTransforms (used via BaseCombatEntity::model at 0xE8)
        inline int position = 0x1F8;      // VERIFIED
        inline int SkinnedMultiMesh = 0x1F0; // UPDATED from dump.cs (was 0x4B0)
        inline int SkinnedRenderersList = 0x50; // UPDATED from dump.cs (List<Renderer> at 0x50)
        inline int new_velocity = 0x21C;  // VERIFIED
        inline int velocity = 0x204;      // NEW
        inline int rotation = 0x228;      // NEW (Quaternion)
        inline int isVisible = 0x26C;     // NEW (bool)
        inline int InGesture = 0x270;     // bool - stops SpineIK bone flickering
        inline int CurrentGestureConfig = 0x268; // GestureConfig reference
    }

    namespace GestureConfig {
        inline int PlayerModelLayer = 0x68; // int (mode) - set to 0 to stop bone rotation flicker
    }


    // NEW: Projectile offsets
    namespace Projectile {
        inline int drag = 0x34;
        inline int gravityModifier = 0x38;
        inline int mod = 0x1D0;
        inline int thickness = 0x3C;
        inline int currentVelocity = 0x154;
        inline int currentPosition = 0x160;
        inline int sentPosition = 0x178;
        inline int owner = 0x1E0;
        inline int itemModProjectile = 0x110;
    }

    // NEW: ItemModProjectile offsets
    namespace ItemModProjectile {
        inline int projectileVelocity = 0x40;
        inline int projectileSpread = 0x3C;
    }

    // NEW: Magazine offsets
    namespace Magazine {
        inline int definition = 0x10;
        inline int capacity = 0x18;
        inline int contents = 0x1C;       // Ammo count
        inline int ammoType = 0x20;
    }

    // NEW: CompoundBowWeapon offsets
    namespace CompoundBowWeapon {
        inline int stringHoldDurationMax = 0x450;
        inline int stringBonusVelocity = 0x45C;
        inline int currentHoldProgress = 0x4A0;
    }

    // ModelState offsets (ProtoBuf message)
    namespace ModelState {
        inline int flags = 0x18;           // ModelState.flags_ (int) - ProtoBuf layout: ShouldPool=0x10, _disposed=0x11, flags=0x18
    }

    // PlayerWalkMovement offsets (BaseMovement at BasePlayer+0x5B8)
    namespace PlayerWalkMovement {
        inline int spiderman = 0x108;          // slope override set 0 = climb anything (encrypted)
    }

    // NEW: BaseMelee offsets
    namespace BaseMelee {
        inline int maxDistance = 0x318;
        inline int attackRadius = 0x31C;
        inline int blockSprintOnAttack = 0x321;
    }

    // NEW: HeldEntity offsets
    namespace HeldEntity {
        inline int ownerItemUID = 0x220;
        inline int viewModel = 0x250;
        inline int list = 0x218;
        inline int items = 0x90;
    }

    // NEW: ViewModel offsets
    namespace ViewModel {
        inline int instance = 0x28;
    }

    // NEW: BaseViewModel offsets
    namespace BaseViewModel {
        inline int useViewModelCamera = 0x40;
        inline int model = 0x80;
        inline int ironSights = 0xC0;
        inline int lower = 0xA0;
        inline int viewmodelBob = 0x80;
        inline int viewmodelSway = 0xA8;
        inline int animationEvents = 0xD0;
        inline int ViewmodelPunch = 0xE8;
        inline uint64_t Class = 0xD6373E0;
        inline int instanse = 0x218;
        inline int targetEntity = 0x28;
    }

    // NEW: HackableLockedCrate offsets
    namespace HackableLockedCrate {
        inline int timerText = 0x3C0;
    }

    // NEW: Text offsets
    namespace Text {
        inline int m_Text = 0xD8;
    }

    // NEW: Renderer offsets
    namespace Renderer {
        inline int materialList = 0x148;
    }

    // NEW: BuildingBlock offsets
    namespace BuildingBlock {
        inline int grade = 0x318;
    }

    // NEW: BaseEntity offsets
    namespace BaseEntity {
        inline int baseModel = 0xE8;
        inline int SkinnedMultiMesh = 0x168;
    }

    // NEW: Entity offsets (for entity traversal)
    namespace Entity {
        inline int baseObject = 0x10;
        inline int entityObject = 0x30;
        inline int transform = 0x8;
        inline int visualState = 0x38;
        inline int position = 0x90;
        inline int rotation = 0xA0;
        inline int prefabId = 0x30;
    }

    // NEW: Model offsets
    namespace Model {
        inline int boneTransforms = 0x50;
        inline int rootBone = 0x28;
        inline int headBone = 0x30;
        inline int eyeBone = 0x38;
        inline int skeleton = 0x48;
    }

    // NEW: TranslatePhrase offsets
    namespace TranslatePhrase {
        inline int legacyEnglish = 0x20;
        inline int english = 0x20;
        inline int legacyEnglish2 = 0x18;
    }

    // NEW: FlintStrikeWeapon offsets
    namespace FlintStrikeWeapon {
        inline int successFraction = 0x438;
        inline int didSparkThisFrame = 0x448;
    }

    // NEW: World offsets
    namespace World {
        inline int seed = 0x60;
        inline int size = 0x60;
    }

    // NEW: GameManager offsets
    namespace GameManager {
        inline uint64_t Class = 0xD702144;
        inline int instance = 0x18;
        inline int prefab_pool_collection = 0x28;
    }
};

/* Uppercase alias so aimbot_wrapper.h / esp_renderer.cpp can use Offsets:: */
namespace Offsets {
    namespace BaseCombatEntity = offsets::BaseCombatEntity;
    namespace BasePlayer       = offsets::BasePlayer;
    namespace BaseProjectile   = offsets::BaseProjectile;
    namespace RecoilProperties = offsets::RecoilProperties;
    namespace PlayerModel      = offsets::PlayerModel;
    namespace PlayerInput      = offsets::PlayerInput;
    namespace PlayerEyes       = offsets::PlayerEyes;
    namespace ItemDefinition   = offsets::ItemDefinition;
    namespace Item {
        inline int itemDefinition = offsets::item::item_definition;
    }
}
