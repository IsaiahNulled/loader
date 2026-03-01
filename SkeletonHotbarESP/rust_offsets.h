#pragma once
// go ham little boys. I left comments so its really really easy for you guys to paste - isaiah :)

namespace offsets {
inline int basenetworkable_pointer = 0xD7F41D0;
inline uint64_t camera_pointer = 0xD7E7AF0;
inline uint64_t Il2cppHandle = 0xDAD33E0;

namespace BaseNetworkable {
inline int static_fields = 0xB8;
inline int client_entities = 0x20;
inline int entity_list = 0x10;
inline int object_dictionary = 0x20;
inline int entity_content = 0x10;
inline int entity_size = 0x18;
inline int buffer_list = 0x10;
inline int prefabID = 0x30;
} // namespace BaseNetworkable

namespace BaseCamera {
inline uint64_t static_fields = 0xB8;
inline uint64_t wrapper_class = 0x60;
inline uint64_t parent_static_fields = 0x10;
inline int viewMatrix = 0x80;
inline int projMatrix = 0xC0;
inline int position = 0x454;
} // namespace BaseCamera

namespace BaseCombatEntity {
inline int lifestate = 0x258;
inline int _health = 0x264;
inline int _maxHealth = 0x268;
}; // namespace BaseCombatEntity

namespace BasePlayer {
inline int playerFlags = 0x5E8;
inline int ModelState = 0x628;
inline int playerModel = 0x4F8;
inline int clactiveitem = 0x4D0;
inline int inventory = 0x4E8;
inline int playerInput = 0x338;
inline int eyes = 0x2B0;
inline int currentTeam = 0x4A0;
} // namespace BasePlayer

namespace PlayerInput {
inline int bodyAngles = 0x44;
}

namespace ItemContainer {
inline int itemlist = 0x68;
}

namespace PlayerInventory {
inline int belt = 0x60;
inline int clothingbelt = 0x78;
} // namespace PlayerInventory

namespace item {
inline int item_definition = 0x30;
inline int item_uid = 0x70;
inline int held_entity = 0x40;
inline int held_entity_2 = 0xb0;
} // namespace item

namespace ItemDefinition {
inline int ShortName = 0x28;
}

namespace PlayerModel {
inline int position = 0x1F8;
inline int isVisible = 0x26C;
} // namespace PlayerModel

namespace ModelState {
inline int flags = 0x18;
}

namespace Entity {
inline int baseObject = 0x10;
inline int entityObject = 0x30;
inline int transform = 0x8;
inline int visualState = 0x38;
inline int position = 0x90;
} // namespace Entity
}; // namespace offsets

/* Uppercase alias */
namespace Offsets {
namespace BaseCombatEntity = offsets::BaseCombatEntity;
namespace BasePlayer = offsets::BasePlayer;
namespace PlayerModel = offsets::PlayerModel;
namespace PlayerInput = offsets::PlayerInput;
namespace ItemDefinition = offsets::ItemDefinition;
} // namespace Offsets
