#pragma once
/*
 * il2cpp_resolver.h - Runtime IL2CPP metadata resolver
 * Resolves field offsets and static pointers at runtime by parsing
 * global-metadata.dat and scanning GameAssembly.dll memory.
 */

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <algorithm>
#include <intrin.h>

// ── IL2CPP metadata structures (on-disk format) ──

#pragma pack(push, 4)

struct MetaHeader {
    uint32_t sanity;
    int32_t  version;
    int32_t  stringLiteralOff, stringLiteralSz;
    int32_t  stringLiteralDataOff, stringLiteralDataSz;
    int32_t  stringOff, stringSz;
    int32_t  eventsOff, eventsSz;
    int32_t  propertiesOff, propertiesSz;
    int32_t  methodsOff, methodsSz;
    int32_t  paramDefValOff, paramDefValSz;
    int32_t  fieldDefValOff, fieldDefValSz;
    int32_t  fieldParamDataOff, fieldParamDataSz;
    int32_t  fieldMarshaledOff, fieldMarshaledSz;
    int32_t  parametersOff, parametersSz;
    int32_t  fieldsOff, fieldsSz;
    int32_t  genParamsOff, genParamsSz;
    int32_t  genConstraintsOff, genConstraintsSz;
    int32_t  genContainersOff, genContainersSz;
    int32_t  nestedTypesOff, nestedTypesSz;
    int32_t  interfacesOff, interfacesSz;
    int32_t  vtableMethodsOff, vtableMethodsSz;
    int32_t  ifaceOffsetsOff, ifaceOffsetsSz;
    int32_t  typeDefsOff, typeDefsSz;
    int32_t  imagesOff, imagesSz;
    int32_t  assembliesOff, assembliesSz;
};

struct TypeDef29 {
    int32_t nameIdx, nsIdx;
    int32_t byvalTypeIdx, byrefTypeIdx;
    int32_t declaringTypeIdx, parentIdx, elementTypeIdx;
    int32_t genericContainerIdx;
    uint32_t flags;
    int32_t fieldStart, methodStart, eventStart, propertyStart;
    int32_t nestedStart, ifaceStart, vtableStart, ifaceOffStart;
    uint16_t method_count, property_count, field_count, event_count;
    uint16_t nested_count, vtable_count, iface_count, ifaceOff_count;
    uint32_t bitfield, token;
};

struct FieldDef {
    int32_t nameIdx, typeIdx;
    uint32_t token;
};

#pragma pack(pop)

// ── Decrypt operation types ──

enum class DcrOp : uint8_t { ADD, SUB, XOR, ROL, ROR };
struct DcrStep { DcrOp op; uint32_t val; };

struct DcrFunc {
    std::string name;
    std::vector<DcrStep> steps;
    bool needsGC = false;
};

// ── Il2CppClass layout constants (calibrated at runtime) ──

struct ClassLayout {
    int nameOff   = 0x10;
    int nsOff     = 0x18;
    int parentOff = 0x58;
    int sfOff     = 0xB8;
    int fcOff     = -1;     // field_count (calibrated)
    int fldsOff   = -1;     // FieldInfo* fields (calibrated)
    int fiSize    = 0x20;   // sizeof(FieldInfo)
    int fiNameOff = 0x00;   // FieldInfo::name
    int fiOffOff  = 0x18;   // FieldInfo::offset
    int mcOff     = -1;     // method_count (calibrated)
    int mtdsOff   = -1;     // MethodInfo** methods (calibrated)
};

// ═══════════════════════════════════════════════════════════════════
//  Il2CppResolver
// ═══════════════════════════════════════════════════════════════════

class Il2CppResolver {
public:
    bool Initialize(DriverComm* driver, DWORD gamePid, uintptr_t gameAssemblyBase) {
        drv    = driver;
        pid    = gamePid;
        gaBase = gameAssemblyBase;

        printf("\n[IL2CPP] === Runtime Resolver Initializing ===\n");
        if (!FindRustDir())       return fail("Rust directory");
        if (!LoadMetadata())      return fail("global-metadata.dat");
        ReadModuleSize();
        if (!FindTypeInfoTable()) return fail("TypeInfoTable");
        CalibrateLayout();

        ready = true;
        printf("[IL2CPP] Ready! types=%d fields=%d\n", nTypes, nFields);
        printf("[IL2CPP] ==========================================\n\n");
        return true;
    }

    bool Good() const { return ready; }

    /* Resolve field offset (-1 on fail) */
    int Field(const char* cls, const char* fld, const char* ns = "") {
        std::string key = std::string(cls) + "::" + fld;
        auto it = cache.find(key);
        if (it != cache.end()) return it->second;
        int v = ResolveField(cls, fld, ns);
        if (v >= 0) cache[key] = v;
        return v;
    }

    /* Get Il2CppClass* in game memory */
    uintptr_t Class(const char* cls, const char* ns = "") {
        return FindClassPtr(cls, ns);
    }

    /* Get static_fields pointer for a class */
    uintptr_t StaticFields(const char* cls, const char* ns = "") {
        uintptr_t k = FindClassPtr(cls, ns);
        return k ? Rd<uintptr_t>(k + lay.sfOff) : 0;
    }

    /* Find TypeInfo RVA (GA-relative offset where Il2CppClass* is stored) */
    uint64_t FindTypeInfoRVA(const char* cls, const char* ns = "") {
        uintptr_t klass = FindClassPtr(cls, ns);
        if (!klass) return 0;
        return ScanDataForPtr(klass);
    }

    /* Extract decrypt ops from function at RVA */
    DcrFunc ExtractDecrypt(const char* label, uintptr_t rva) {
        DcrFunc fn; fn.name = label;
        uint8_t code[128] = {};
        if (RdRaw(gaBase + rva, code, sizeof(code)))
            ParseDcrOps(code, sizeof(code), fn.steps);
        return fn;
    }

    /* Apply decrypt to encrypted qword */
    static uintptr_t Decrypt(uintptr_t enc, const DcrFunc& fn) {
        uint32_t* p = (uint32_t*)&enc;
        for (int i = 0; i < 2; i++)
            for (auto& s : fn.steps)
                switch (s.op) {
                case DcrOp::ADD: p[i] += s.val; break;
                case DcrOp::SUB: p[i] -= s.val; break;
                case DcrOp::XOR: p[i] ^= s.val; break;
                case DcrOp::ROL: p[i] = _rotl(p[i], s.val); break;
                case DcrOp::ROR: p[i] = _rotr(p[i], s.val); break;
                }
        return enc;
    }

    /* Find native code pointer for a method by class + method name */
    uintptr_t MethodNative(const char* cls, const char* methodName, const char* ns = "") {
        uintptr_t cp = FindClassPtr(cls, ns);
        if (!cp) return 0;
        if (lay.mcOff < 0 || lay.mtdsOff < 0) {
            if (!CalibrateMethods()) return 0;
        }
        uint16_t mc = Rd<uint16_t>(cp + lay.mcOff);
        uintptr_t mtds = Rd<uintptr_t>(cp + lay.mtdsOff);
        if (!mtds || mc == 0 || mc > 1000) return 0;
        for (int i = 0; i < mc; i++) {
            uintptr_t mi = Rd<uintptr_t>(mtds + (uintptr_t)i * 8);
            if (!mi) continue;
            uintptr_t np = Rd<uintptr_t>(mi + 0x10);
            if (!np) continue;
            std::string nm = RdStr(np, 64);
            if (nm == methodName) {
                uintptr_t code = Rd<uintptr_t>(mi);
                if (code && code > 0x10000)
                    return code;
            }
        }
        return 0;
    }

    /* Extract encrypt/decrypt ops from a native method's code (absolute address) */
    bool ExtractOpsFromNative(uintptr_t nativeAddr, std::vector<DcrStep>& out) {
        if (!nativeAddr) return false;
        uint8_t code[256] = {};
        if (!RdRaw(nativeAddr, code, sizeof(code))) return false;
        ParseEncryptOps(code, sizeof(code), out);
        return !out.empty();
    }

    /* Dump all fields of a class (for debugging) */
    void DumpClass(const char* cls, const char* ns = "") {
        uintptr_t k = FindClassPtr(cls, ns);
        if (!k) { printf("[IL2CPP] Class '%s' not found\n", cls); return; }
        if (lay.fcOff < 0 || lay.fldsOff < 0) return;
        uint16_t fc = Rd<uint16_t>(k + lay.fcOff);
        uintptr_t fl = Rd<uintptr_t>(k + lay.fldsOff);
        printf("[IL2CPP] %s: %d fields (FieldInfo* = 0x%llX)\n", cls, fc, (uint64_t)fl);
        for (int i = 0; i < fc && i < 200; i++) {
            uintptr_t fi = fl + (uintptr_t)i * lay.fiSize;
            uintptr_t np = Rd<uintptr_t>(fi + lay.fiNameOff);
            int32_t off  = Rd<int32_t>(fi + lay.fiOffOff);
            char buf[128] = {};
            if (np) RdRaw(np, buf, 127);
            printf("  [%3d] +0x%04X  %s\n", i, off, buf);
        }
    }

private:
    DriverComm* drv = nullptr;
    DWORD pid = 0;
    uintptr_t gaBase = 0, gaSize = 0;
    bool ready = false;
    std::wstring rustDir;

    // metadata
    std::vector<uint8_t> blob;
    const MetaHeader* hdr = nullptr;
    const char* strs = nullptr;
    int nTypes = 0, nFields = 0, metaVer = 0, tdStride = 0;

    // type info table
    uintptr_t ttBase = 0;

    // layout
    ClassLayout lay;

    // caches
    std::unordered_map<std::string, int> tdxCache;       // name → typeDefIndex
    std::unordered_map<std::string, uintptr_t> clsCache; // name → Il2CppClass*
    std::unordered_map<std::string, int> cache;           // cls::fld → offset

    // ── helpers ──
    template<typename T> T Rd(uintptr_t a) { return drv->Read<T>(pid, a); }
    bool RdRaw(uintptr_t a, void* b, size_t n) { return drv->ReadMemory(pid, a, b, n); }

    std::string RdStr(uintptr_t a, int mx = 128) {
        char b[256] = {};
        if (mx > 255) mx = 255;
        if (!RdRaw(a, b, mx)) return "";
        b[mx] = 0;
        return std::string(b);
    }

    bool fail(const char* what) {
        printf("[IL2CPP] FAIL: %s\n", what);
        return false;
    }

    const char* MetaStr(int32_t idx) const {
        if (idx < 0 || idx >= hdr->stringSz) return "";
        return strs + idx;
    }

    const TypeDef29* TypeAt(int i) const {
        if (i < 0 || i >= nTypes) return nullptr;
        return (const TypeDef29*)((const uint8_t*)blob.data()
               + hdr->typeDefsOff + (size_t)i * tdStride);
    }

    // ── Step 1: Find Rust install directory ──
    bool FindRustDir() {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return false;
        wchar_t p[MAX_PATH] = {};
        DWORD len = MAX_PATH;
        BOOL ok = QueryFullProcessImageNameW(h, 0, p, &len);
        CloseHandle(h);
        if (!ok) return false;
        wchar_t* sl = wcsrchr(p, L'\\');
        if (!sl) return false;
        *sl = 0;
        rustDir = p;
        wprintf(L"[IL2CPP] Rust dir: %s\n", rustDir.c_str());
        return true;
    }

    // ── Step 2: Parse global-metadata.dat ──
    bool LoadMetadata() {
        std::wstring path = rustDir +
            L"\\RustClient_Data\\il2cpp_data\\Metadata\\global-metadata.dat";

        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) {
            wprintf(L"[IL2CPP] Can't open: %s\n", path.c_str());
            return false;
        }
        size_t sz = (size_t)f.tellg(); f.seekg(0);
        blob.resize(sz);
        f.read((char*)blob.data(), sz); f.close();

        hdr = (const MetaHeader*)blob.data();
        if (hdr->sanity != 0xFAB11BAF) {
            printf("[IL2CPP] Bad magic: 0x%08X\n", hdr->sanity);
            return false;
        }
        metaVer = hdr->version;
        printf("[IL2CPP] Metadata v%d  (%zu bytes)\n", metaVer, sz);

        strs = (const char*)(blob.data() + hdr->stringOff);

        // TypeDef stride: v29 = sizeof(TypeDef29) = 92
        // v31+ removed byrefTypeIndex (-4 bytes)
        tdStride = (metaVer >= 31) ? (int)sizeof(TypeDef29) - 4
                                   : (int)sizeof(TypeDef29);
        nTypes  = hdr->typeDefsSz / tdStride;
        nFields = hdr->fieldsSz / (int)sizeof(FieldDef);

        // Index type names
        for (int i = 0; i < nTypes; i++) {
            auto* td = TypeAt(i);
            if (!td) continue;
            const char* n = MetaStr(td->nameIdx);
            const char* ns = MetaStr(td->nsIdx);
            if (!n || !n[0]) continue;
            // store both "Namespace.Name" and just "Name"
            if (ns && ns[0]) {
                tdxCache[std::string(ns) + "." + n] = i;
            }
            tdxCache[n] = i;  // short name (may collide, last wins)
        }
        printf("[IL2CPP] Indexed %d type names\n", (int)tdxCache.size());
        return true;
    }

    // ── Step 3: Module size ──
    void ReadModuleSize() {
        uint8_t dh[64] = {};
        if (!RdRaw(gaBase, dh, sizeof(dh))) return;
        auto* dos = (IMAGE_DOS_HEADER*)dh;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        uint8_t nh[264] = {};
        if (!RdRaw(gaBase + dos->e_lfanew, nh, sizeof(nh))) return;
        auto* nt = (IMAGE_NT_HEADERS64*)nh;
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        gaSize = nt->OptionalHeader.SizeOfImage;
        printf("[IL2CPP] GA size: 0x%llX\n", (uint64_t)gaSize);
    }

    // ── Helper: validate a candidate TypeInfoTable ──
    bool ValidateTable(uintptr_t tbl) {
        if (!tbl || tbl < 0x10000) return false;
        int good = 0;
        for (int t = 0; t < 50 && t < nTypes; t++) {
            uintptr_t cp = Rd<uintptr_t>(tbl + (uintptr_t)t * 8);
            if (!cp) continue;
            uintptr_t np = Rd<uintptr_t>(cp + 0x10);
            if (!np) continue;
            std::string nm = RdStr(np, 64);
            if (nm.size() > 1 && nm.size() < 100) good++;
        }
        if (good >= 10) {
            ttBase = tbl;
            printf("[IL2CPP] TypeInfoTable @ 0x%llX  (%d classes ok)\n",
                   (uint64_t)tbl, good);
            return true;
        }
        return false;
    }

    // ── Step 4: Find s_TypeInfoTable via pattern scan ──
    bool FindTypeInfoTable() {
        printf("[IL2CPP] Scanning for TypeInfoTable...\n");
        if (gaSize < 0x1000) gaSize = 0x4000000; // fallback 64MB

        const size_t CHUNK = 0x100000;
        std::vector<uint8_t> buf(CHUNK);

        for (uintptr_t off = 0x1000; off < gaSize; off += CHUNK - 32) {
            size_t rd = (std::min)((size_t)(gaSize - off), CHUNK);
            if (!RdRaw(gaBase + off, buf.data(), rd)) continue;

            for (size_t i = 0; i + 20 < rd; i++) {
                // Must start with movsxd (sign-extend 32→64)
                if (buf[i] != 0x48 || buf[i+1] != 0x63) continue;
                // Accept ecx, edx, r8d, r9d as source
                uint8_t srcReg = buf[i+2];
                if (srcReg != 0xC1 && srcReg != 0xC2 && srcReg != 0xC8 && srcReg != 0xD1) continue;
                // Determine which register holds the index (rax or rdx)
                // 0xC1=movsxd rax,ecx  0xC2=movsxd rax,edx  0xC8=movsxd rcx,eax  0xD1=movsxd rdx,ecx

                /*
                 * Pattern A: lea rcx,[rip+X]; mov rcx,[rcx]; mov rax,[rcx+rax*8]; ret
                 * 48 8D 0D XX XX XX XX  48 8B 09  48 8B 04 C1  C3
                 */
                if (i + 17 < rd &&
                    buf[i+3] == 0x48 && buf[i+4] == 0x8D && buf[i+5] == 0x0D &&
                    buf[i+10] == 0x48 && buf[i+11] == 0x8B && buf[i+12] == 0x09 &&
                    buf[i+13] == 0x48 && buf[i+14] == 0x8B && buf[i+15] == 0x04 && buf[i+16] == 0xC1 &&
                    buf[i+17] == 0xC3) {
                    int32_t disp = *(int32_t*)&buf[i+6];
                    uintptr_t varAddr = gaBase + off + i + 10 + disp;
                    uintptr_t tbl = Rd<uintptr_t>(varAddr);
                    if (ValidateTable(tbl)) return true;
                }

                /*
                 * Pattern B: mov rcx,[rip+X]; mov rax,[rcx+rax*8]; ret
                 * (no lea+deref — direct RIP-relative load of table pointer)
                 * 48 8B 0D XX XX XX XX  48 8B 04 C1  C3
                 */
                if (i + 14 < rd &&
                    buf[i+3] == 0x48 && buf[i+4] == 0x8B && buf[i+5] == 0x0D &&
                    buf[i+10] == 0x48 && buf[i+11] == 0x8B && buf[i+12] == 0x04 && buf[i+13] == 0xC1 &&
                    buf[i+14] == 0xC3) {
                    int32_t disp = *(int32_t*)&buf[i+6];
                    uintptr_t tbl = Rd<uintptr_t>(gaBase + off + i + 10 + disp);
                    if (ValidateTable(tbl)) return true;
                }

                /*
                 * Pattern C: mov rdx,[rip+X]; mov rax,[rdx+rax*8]; ret
                 * 48 8B 15 XX XX XX XX  48 8B 04 C2  C3
                 */
                if (i + 14 < rd &&
                    buf[i+3] == 0x48 && buf[i+4] == 0x8B && buf[i+5] == 0x15 &&
                    buf[i+10] == 0x48 && buf[i+11] == 0x8B && buf[i+12] == 0x04 && buf[i+13] == 0xC2 &&
                    buf[i+14] == 0xC3) {
                    int32_t disp = *(int32_t*)&buf[i+6];
                    uintptr_t tbl = Rd<uintptr_t>(gaBase + off + i + 10 + disp);
                    if (ValidateTable(tbl)) return true;
                }

                /*
                 * Pattern D: lea rcx,[rip+X]; mov rcx,[rcx]; mov rax,[rcx+rdx*8]; ret
                 * Same as A but uses rdx as index
                 */
                if (i + 17 < rd &&
                    buf[i+3] == 0x48 && buf[i+4] == 0x8D && buf[i+5] == 0x0D &&
                    buf[i+10] == 0x48 && buf[i+11] == 0x8B && buf[i+12] == 0x09 &&
                    buf[i+13] == 0x48 && buf[i+14] == 0x8B && buf[i+15] == 0x04 && buf[i+16] == 0xD1 &&
                    buf[i+17] == 0xC3) {
                    int32_t disp = *(int32_t*)&buf[i+6];
                    uintptr_t varAddr = gaBase + off + i + 10 + disp;
                    uintptr_t tbl = Rd<uintptr_t>(varAddr);
                    if (ValidateTable(tbl)) return true;
                }

                /*
                 * Pattern E: mov rax,[rip+X]; mov rax,[rax+rcx*8]; ret
                 * 48 8B 05 XX XX XX XX  48 8B 04 C8  C3
                 */
                if (i + 14 < rd &&
                    buf[i+3] == 0x48 && buf[i+4] == 0x8B && buf[i+5] == 0x05 &&
                    buf[i+10] == 0x48 && buf[i+11] == 0x8B && buf[i+12] == 0x04 && buf[i+13] == 0xC8 &&
                    buf[i+14] == 0xC3) {
                    int32_t disp = *(int32_t*)&buf[i+6];
                    uintptr_t tbl = Rd<uintptr_t>(gaBase + off + i + 10 + disp);
                    if (ValidateTable(tbl)) return true;
                }
            }
        }

        // ── Fallback: scan .text for any [rip+disp] near *8 scale-indexed load ──
        printf("[IL2CPP] Strict patterns failed, trying relaxed scan...\n");
        for (uintptr_t off = 0x1000; off < gaSize; off += CHUNK - 32) {
            size_t rd = (std::min)((size_t)(gaSize - off), CHUNK);
            if (!RdRaw(gaBase + off, buf.data(), rd)) continue;

            for (size_t i = 0; i + 15 < rd; i++) {
                // Look for: 48 8B XX [rip+disp] (7 bytes) anywhere before 48 8B 04 C1/C2/C8/D1 ... C3
                if (buf[i] != 0x48 || buf[i+1] != 0x8B) continue;
                // Must be [rip+disp32]: ModRM byte 0x0D/0x15/0x05/0x1D/0x25/0x2D/0x35/0x3D
                uint8_t modrm = buf[i+2];
                if ((modrm & 0xC7) != 0x05) continue; // [rip+disp32] encoding
                // Check if within next 10 bytes there's a scale*8 indexed load and ret
                int32_t disp = *(int32_t*)&buf[i+3];
                for (int ahead = 7; ahead < 14 && i + ahead + 4 < rd; ahead++) {
                    if (buf[i+ahead] == 0x48 && buf[i+ahead+1] == 0x8B) {
                        uint8_t m2 = buf[i+ahead+2];
                        // 0x04 = SIB follows with [base+idx*8]
                        if (m2 == 0x04) {
                            uint8_t sib = buf[i+ahead+3];
                            if ((sib & 0xC0) == 0xC0) { // scale = 8 (11 in top 2 bits)
                                // Check for ret within next 3 bytes
                                for (int r = ahead+4; r < ahead+8 && i+r < rd; r++) {
                                    if (buf[i+r] == 0xC3) {
                                        uintptr_t tbl = Rd<uintptr_t>(gaBase + off + i + 7 + disp);
                                        if (ValidateTable(tbl)) return true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    // ── Step 5: Calibrate Il2CppClass layout ──
    bool CalibrateLayout() {
        const char* probes[] = { "BasePlayer", "BaseCombatEntity", "BaseEntity" };
        for (auto* pname : probes) {
            auto it = tdxCache.find(pname);
            if (it == tdxCache.end()) continue;
            int idx = it->second;
            auto* td = TypeAt(idx);
            if (!td || td->field_count == 0) continue;

            uintptr_t cp = Rd<uintptr_t>(ttBase + (uintptr_t)idx * 8);
            if (!cp) continue;

            // verify name
            uintptr_t np = Rd<uintptr_t>(cp + 0x10);
            std::string nm = RdStr(np, 64);
            if (nm != pname) continue;

            uint16_t expect = td->field_count;
            printf("[IL2CPP] Calibrating on '%s' (expect %d fields)...\n", pname, expect);

            // read class struct
            uint8_t raw[0x200] = {};
            if (!RdRaw(cp, raw, sizeof(raw))) continue;

            // scan for field_count match
            for (int probe = 0xC0; probe < 0x180; probe += 2) {
                uint16_t fc = *(uint16_t*)(raw + probe);
                if (fc != expect || fc == 0) continue;

                // now find FieldInfo* fields nearby
                for (int fp = probe + 8; fp < probe + 80 && fp + 8 <= 0x200; fp += 8) {
                    uintptr_t fptr = *(uintptr_t*)(raw + fp);
                    if (!fptr || fptr < 0x10000) continue;

                    // validate first FieldInfo
                    uintptr_t fn0 = Rd<uintptr_t>(fptr);
                    if (!fn0) continue;
                    std::string f0name = RdStr(fn0, 64);
                    if (f0name.empty() || f0name.size() > 100) continue;

                    int32_t f0off = Rd<int32_t>(fptr + 0x18);
                    if (f0off < 0 || f0off > 0x10000) continue;

                    lay.fcOff   = probe;
                    lay.fldsOff = fp;
                    printf("[IL2CPP] Calibrated: field_count=+0x%X  fields=+0x%X\n",
                           probe, fp);
                    printf("[IL2CPP]   First field: '%s' at 0x%X\n",
                           f0name.c_str(), f0off);
                    return true;
                }
            }
        }
        printf("[IL2CPP] Calibration failed, field resolution won't work\n");
        return false;
    }

    // ── Find Il2CppClass* by name ──
    uintptr_t FindClassPtr(const char* cls, const char* ns = "") {
        std::string key = (ns && ns[0]) ? std::string(ns) + "." + cls
                                        : std::string(cls);
        auto it = clsCache.find(key);
        if (it != clsCache.end()) return it->second;

        // look up type def index
        auto ti = tdxCache.find(key);
        if (ti == tdxCache.end()) {
            ti = tdxCache.find(cls); // try without namespace
            if (ti == tdxCache.end()) return 0;
        }
        uintptr_t cp = Rd<uintptr_t>(ttBase + (uintptr_t)ti->second * 8);
        if (cp) clsCache[key] = cp;
        return cp;
    }

    // ── Resolve field offset from memory ──
    int ResolveField(const char* cls, const char* fld, const char* ns) {
        if (lay.fcOff < 0 || lay.fldsOff < 0) return -1;

        uintptr_t cp = FindClassPtr(cls, ns);
        if (!cp) return -1;

        // check this class and parent chain (up to 5 levels)
        for (int depth = 0; depth < 5 && cp; depth++) {
            uint16_t fc = Rd<uint16_t>(cp + lay.fcOff);
            uintptr_t fl = Rd<uintptr_t>(cp + lay.fldsOff);
            if (fl && fc > 0 && fc < 500) {
                for (int i = 0; i < fc; i++) {
                    uintptr_t fi = fl + (uintptr_t)i * lay.fiSize;
                    uintptr_t np = Rd<uintptr_t>(fi + lay.fiNameOff);
                    if (!np) continue;
                    std::string nm = RdStr(np, 128);
                    if (nm == fld) return Rd<int32_t>(fi + lay.fiOffOff);
                }
            }
            cp = Rd<uintptr_t>(cp + lay.parentOff); // traverse parent
        }
        return -1;
    }

    // ── Scan .data section for a pointer value ──
    uint64_t ScanDataForPtr(uintptr_t needle) {
        const size_t CHUNK = 0x100000;
        std::vector<uint8_t> buf(CHUNK);
        for (uintptr_t off = 0; off < gaSize; off += CHUNK - 8) {
            size_t rd = (std::min)((size_t)(gaSize - off), CHUNK);
            if (!RdRaw(gaBase + off, buf.data(), rd)) continue;
            for (size_t j = 0; j + 8 <= rd; j += 8) {
                if (*(uintptr_t*)(buf.data() + j) == needle)
                    return off + j;
            }
        }
        return 0;
    }

    // ── Calibrate methods array offset in Il2CppClass ──
    bool CalibrateMethods() {
        if (lay.fcOff < 0) return false;
        const char* probes[] = { "BasePlayer", "BaseCombatEntity", "BaseEntity" };
        for (auto* pname : probes) {
            auto it = tdxCache.find(pname);
            if (it == tdxCache.end()) continue;
            int idx = it->second;
            auto* td = TypeAt(idx);
            if (!td || td->method_count == 0) continue;

            uintptr_t cp = Rd<uintptr_t>(ttBase + (uintptr_t)idx * 8);
            if (!cp) continue;

            uint8_t raw[0x200] = {};
            if (!RdRaw(cp, raw, sizeof(raw))) continue;

            uint16_t expectMC = td->method_count;
            // method_count is typically at fcOff-4 (TypeDef order: mc, pc, fc, ec)
            int mcCandidates[] = { lay.fcOff - 4, lay.fcOff - 2, lay.fcOff + 2, lay.fcOff + 4 };
            for (int mcOff : mcCandidates) {
                if (mcOff < 0 || mcOff + 2 > 0x200) continue;
                uint16_t mc = *(uint16_t*)(raw + mcOff);
                if (mc != expectMC) continue;

                // Now find MethodInfo** methods pointer (scan pointer-sized fields before sfOff)
                for (int mp = 0x70; mp < lay.sfOff && mp + 8 <= 0x200; mp += 8) {
                    if (mp == lay.fldsOff) continue;
                    uintptr_t arr = *(uintptr_t*)(raw + mp);
                    if (!arr || arr < 0x10000 || arr > 0x7FFFFFFFFFFF) continue;
                    uintptr_t mi0 = Rd<uintptr_t>(arr);
                    if (!mi0 || mi0 < 0x10000) continue;
                    uintptr_t np = Rd<uintptr_t>(mi0 + 0x10);
                    if (!np || np < 0x10000) continue;
                    std::string nm = RdStr(np, 64);
                    if (nm.empty() || nm[0] < 0x20 || nm[0] > 0x7E) continue;
                    // Validate second method too
                    if (mc > 1) {
                        uintptr_t mi1 = Rd<uintptr_t>(arr + 8);
                        if (!mi1) continue;
                        np = Rd<uintptr_t>(mi1 + 0x10);
                        if (!np) continue;
                        std::string nm1 = RdStr(np, 64);
                        if (nm1.empty()) continue;
                    }
                    lay.mcOff = mcOff;
                    lay.mtdsOff = mp;
                    printf("[IL2CPP] Methods calibrated: method_count=+0x%X methods=+0x%X (expect %d)\n",
                           mcOff, mp, expectMC);
                    return true;
                }
            }
        }
        printf("[IL2CPP] Methods calibration failed\n");
        return false;
    }

    // ── Parse decrypt operations from x86 code ──
    void ParseDcrOps(const uint8_t* c, int len, std::vector<DcrStep>& out) {
        out.clear();
        int pos = 0;
        // skip initial mov eax, [rcx] if present (8B 01)
        if (pos + 2 <= len && c[0] == 0x8B && c[1] == 0x01) pos = 2;

        while (pos < len - 2 && out.size() < 8) {
            if (c[pos] == 0x05 && pos+5 <= len) {                         // ADD eax, imm32
                out.push_back({DcrOp::ADD, *(uint32_t*)(c+pos+1)});
                pos += 5; continue;
            }
            if (c[pos] == 0x2D && pos+5 <= len) {                         // SUB eax, imm32
                out.push_back({DcrOp::SUB, *(uint32_t*)(c+pos+1)});
                pos += 5; continue;
            }
            if (c[pos] == 0x35 && pos+5 <= len) {                         // XOR eax, imm32
                out.push_back({DcrOp::XOR, *(uint32_t*)(c+pos+1)});
                pos += 5; continue;
            }
            if (c[pos] == 0xC1 && pos+3 <= len) {
                if (c[pos+1] == 0xC0) {                                   // ROL eax, imm8
                    out.push_back({DcrOp::ROL, c[pos+2]});
                    pos += 3; continue;
                }
                if (c[pos+1] == 0xC8) {                                   // ROR eax, imm8
                    out.push_back({DcrOp::ROR, c[pos+2]});
                    pos += 3; continue;
                }
            }
            if (c[pos] == 0x89 && pos+2 <= len && c[pos+1] == 0x01) break; // mov [rcx], eax
            pos++;
        }
    }

    // ── Parse ENCRYPT operations from setter method code ──
    // Setter pattern: movss [rcx+off], xmm1 or mov [rcx+off], edx
    // Then arithmetic ops on eax, ending with sub eax, edi
    void ParseEncryptOps(const uint8_t* c, int len, std::vector<DcrStep>& out) {
        out.clear();
        int pos = 0;
        bool foundArith = false;

        while (pos < len - 2 && out.size() < 12) {
            // REX prefix handling
            bool hasREX = (c[pos] == 0x41);
            int base = hasREX ? pos + 1 : pos;
            if (base >= len - 2) break;

            // ADD eax, imm32 (05 xx xx xx xx)
            if (!hasREX && c[base] == 0x05 && base+5 <= len) {
                out.push_back({DcrOp::ADD, *(uint32_t*)(c+base+1)});
                pos = base + 5; foundArith = true; continue;
            }
            // SUB eax, imm32 (2D xx xx xx xx)
            if (!hasREX && c[base] == 0x2D && base+5 <= len) {
                out.push_back({DcrOp::SUB, *(uint32_t*)(c+base+1)});
                pos = base + 5; foundArith = true; continue;
            }
            // XOR eax, imm32 (35 xx xx xx xx)
            if (!hasREX && c[base] == 0x35 && base+5 <= len) {
                out.push_back({DcrOp::XOR, *(uint32_t*)(c+base+1)});
                pos = base + 5; foundArith = true; continue;
            }
            // Group1 /r rm32,imm32 (81 /reg modrm imm32)
            if (c[base] == 0x81 && base+6 <= len) {
                uint8_t modrm = c[base+1];
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t reg = (modrm >> 3) & 7;
                if (mod == 3) {
                    uint32_t imm = *(uint32_t*)(c+base+2);
                    if (reg == 0) out.push_back({DcrOp::ADD, imm});
                    else if (reg == 5) out.push_back({DcrOp::SUB, imm});
                    else if (reg == 6) out.push_back({DcrOp::XOR, imm});
                    pos = base + 6; foundArith = true; continue;
                }
            }
            // ROL/ROR rm32, imm8 (C1 /0=ROL /1=ROR modrm imm8)
            if (c[base] == 0xC1 && base+3 <= len) {
                uint8_t modrm = c[base+1];
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t reg = (modrm >> 3) & 7;
                if (mod == 3) {
                    uint8_t imm = c[base+2];
                    if (reg == 0) { out.push_back({DcrOp::ROL, imm}); pos = base+3; foundArith = true; continue; }
                    if (reg == 1) { out.push_back({DcrOp::ROR, imm}); pos = base+3; foundArith = true; continue; }
                }
            }
            // SUB eax, edi (29 F8 or 2B C7) = end of encrypt chain
            if (foundArith && c[pos] == 0x29 && pos+2 <= len && c[pos+1] == 0xF8) break;
            if (foundArith && c[pos] == 0x2B && pos+2 <= len && c[pos+1] == 0xC7) break;
            // RET = end of function
            if (foundArith && c[pos] == 0xC3) break;
            pos++;
        }
    }
};
