import os, hashlib

main_dir = r"c:\Users\Isaiah\Desktop\external\User"
full_dir = r"c:\Users\Isaiah\Desktop\external\full\User"

files = [
    "rust_sdk.h", "rust_offsets.h", "driver_comm.h", "physx.hpp",
    "globals.h", "esp_renderer.cpp", "main.cpp", "config_manager.cpp",
    "aimbot.cpp", "aimbot_wrapper.h", "shared.h", "crash_log.h",
    "il2cpp_resolver.h"
]

def file_hash(path):
    if not os.path.exists(path):
        return "MISSING"
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

for fn in files:
    m = os.path.join(main_dir, fn)
    f = os.path.join(full_dir, fn)
    mh = file_hash(m)
    fh = file_hash(f)
    ms = os.path.getsize(m) if os.path.exists(m) else 0
    fs = os.path.getsize(f) if os.path.exists(f) else 0
    match = "SAME" if mh == fh else "DIFFERENT"
    print(f"{fn:30s}  Main={ms:>10,}  Full={fs:>10,}  {match}")
