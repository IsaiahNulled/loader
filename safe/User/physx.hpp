#pragma once
/*
 * physx.hpp - PhysX scene reader + BVH raycast for visibility checks
 *
 * Reads the PhysX scene from Rust (Unity) memory via the kernel driver,
 * caches rigid actor triangle meshes into a BVH, and provides fast
 * ray/linecast for per-bone visibility checking.
 *
 * Supported geometry types:
 *   - TriangleMesh  (terrain, buildings, rocks)
 *   - Box           (deployables, barricades)
 *   - Capsule       (player colliders, barrels)
 *   - Sphere        (dome shields, small props)
 *   - ConvexMesh    (complex props)
 *   - HeightField   (terrain patches)
 */

#include "rust_sdk.h"
#include <array>
#include <atomic>
#include <cfloat>
#include <cmath>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <vector>

#pragma push_macro("min")
#pragma push_macro("max")
#undef min
#undef max
#include <algorithm>

class PhysXScene {
public:
    /* ── Basic types ─────────────────────────────────────────── */

    struct Triangle {
        Vec3 v0, v1, v2;
        Vec3 center() const { return (v0 + v1 + v2) / 3.0f; }
    };

    /* ── PhysX enums ─────────────────────────────────────────── */

    enum class PxConcreteType : uint16_t {
        eUndefined = 0,
        eHeightfield = 1,
        eConvexMesh = 2,
        eTriangleMeshBVH33 = 3,
        eTriangleMeshBVH34 = 4,
        eRigidDynamic = 6,
        eRigidStatic = 7,
        eShape = 8,
    };

    enum class PxGeometryType : int32_t {
        eSphere = 0,
        ePlane = 1,
        eCapsule = 2,
        eBox = 3,
        eConvexMesh = 4,
        eTriangleMesh = 5,
        eHeightfield = 6,
        eCount = 7,
        eInvalid = -1
    };

    /* ── PhysX math types ────────────────────────────────────── */

    struct PxMat33 {
        Vec3 col0{}, col1{}, col2{};

        PxMat33() = default;
        PxMat33(const Vec3 &c0, const Vec3 &c1, const Vec3 &c2) : col0(c0), col1(c1), col2(c2) {}

        PxMat33(const Vec4 &q) {
            float x2 = q.x + q.x, y2 = q.y + q.y, z2 = q.z + q.z;
            float xx = x2 * q.x, yy = y2 * q.y, zz = z2 * q.z;
            float xy = x2 * q.y, xz = x2 * q.z, xw = x2 * q.w;
            float yz = y2 * q.z, yw = y2 * q.w, zw = z2 * q.w;
            col0 = Vec3(1.0f - yy - zz, xy + zw, xz - yw);
            col1 = Vec3(xy - zw, 1.0f - xx - zz, yz + xw);
            col2 = Vec3(xz + yw, yz - xw, 1.0f - xx - yy);
        }

        PxMat33 transpose() const {
            return PxMat33(Vec3(col0.x, col1.x, col2.x),
                           Vec3(col0.y, col1.y, col2.y),
                           Vec3(col0.z, col1.z, col2.z));
        }

        Vec3 transform(const Vec3 &v) const {
            return col0 * v.x + col1 * v.y + col2 * v.z;
        }

        PxMat33 operator*(const PxMat33 &o) const {
            return PxMat33(transform(o.col0), transform(o.col1), transform(o.col2));
        }
    };

    struct PxTransform {
        Vec4 q{};
        Vec3 p{};

        PxTransform() = default;
        PxTransform(const Vec4 &rot, const Vec3 &pos) : q(rot), p(pos) {}

        Vec3 transformPoint(const Vec3 &v) const { return q.rotate(v) + p; }
        Vec3 inverseTransformPoint(const Vec3 &v) const { return q.rotate_inv(v - p); }

        PxTransform getInverse() const {
            Vec4 qi = q.conjugate();
            return PxTransform(qi, qi.rotate(Vec3(-p.x, -p.y, -p.z)));
        }
    };

    struct PxMeshScale {
        Vec3 scale{1, 1, 1};
        Vec4 rotation{};

        PxMat33 toMat33() const {
            PxMat33 rot(rotation);
            PxMat33 trans = rot.transpose();
            trans.col0 *= scale.x;
            trans.col1 *= scale.y;
            trans.col2 *= scale.z;
            return trans * rot;
        }
    };

    /* ── AABB + BVH ──────────────────────────────────────────── */

    struct AABB {
        Vec3 mn{FLT_MAX, FLT_MAX, FLT_MAX};
        Vec3 mx{-FLT_MAX, -FLT_MAX, -FLT_MAX};

        void expand(const Vec3 &p) {
            mn.x = std::min(mn.x, p.x); mn.y = std::min(mn.y, p.y); mn.z = std::min(mn.z, p.z);
            mx.x = std::max(mx.x, p.x); mx.y = std::max(mx.y, p.y); mx.z = std::max(mx.z, p.z);
        }

        bool intersects(const Vec3 &origin, const Vec3 &dir, float &tmin, float &tmax) const {
            tmin = 0.0f; tmax = FLT_MAX;
            for (int i = 0; i < 3; ++i) {
                float invD = 1.0f / dir[i];
                float t0 = (mn[i] - origin[i]) * invD;
                float t1 = (mx[i] - origin[i]) * invD;
                if (invD < 0.0f) std::swap(t0, t1);
                tmin = t0 > tmin ? t0 : tmin;
                tmax = t1 < tmax ? t1 : tmax;
                if (tmax <= tmin) return false;
            }
            return true;
        }

        int longestAxis() const {
            Vec3 ext = mx - mn;
            if (ext.x > ext.y && ext.x > ext.z) return 0;
            if (ext.y > ext.z) return 1;
            return 2;
        }
    };

    struct BVHNode {
        AABB bounds;
        std::vector<size_t> triIndices;
        std::unique_ptr<BVHNode> left, right;
    };

    /* ── Actor info (cached per scene refresh) ───────────────── */

    struct ActorInfo {
        std::vector<Triangle> triangles;
        PxTransform transform;
        PxGeometryType type = PxGeometryType::eInvalid;
        AABB bounds;
        std::unique_ptr<BVHNode> bvhRoot;
    };

    /* ── Hit result ──────────────────────────────────────────── */

    struct HitResult {
        Vec3 point{};
        Vec3 normal{};
        float distance = FLT_MAX;
        bool didHit = false;
    };

    /* ── In-memory PhysX structures (read from game) ─────────── */

#pragma pack(push, 1)

    struct PxActor_Mem {
        uint8_t _pad[0x8];
        uint16_t type;
        uint16_t baseFlags;
        uint64_t userData;
    };

    struct PtrTable_Mem {
        uint64_t single;
        uint16_t count;
        uint8_t ownsMemory;
        uint8_t bufferUsed;
    };

    struct NpShapeManager_Mem {
        PtrTable_Mem shapes;
        PtrTable_Mem sceneQueryData;
        uint64_t pruningStructure;
    };

    struct PxRigidActor_Mem : PxActor_Mem {
        uint64_t name;
        uint64_t connectorArray;
        NpShapeManager_Mem shapeManager;
        uint32_t index;
    };

    struct PxRigidCore_Mem {
        alignas(16) Vec4 bodyQ;
        Vec3 bodyP;
        uint8_t flags;
        uint8_t idtBodyToActor;
        uint16_t solverIterations;
    };

    struct BodyCore_Mem {
        uint8_t _pad[0x10];
        PxRigidCore_Mem core;
    };

    struct Body_Mem {
        uint64_t scene;
        uint64_t controlState;
        uint64_t streamPtr;
        BodyCore_Mem bodyCore;
    };

    struct NpRigidStatic_Mem : PxRigidActor_Mem {
        Body_Mem body;
    };

    struct PxGeometry_Mem {
        int32_t type;
    };

    struct GeometryUnion_Mem {
        uint8_t data[80];

        PxGeometryType getType() const {
            auto t = reinterpret_cast<const PxGeometry_Mem *>(data)->type;
            if (t < 0 || t > 6) return PxGeometryType::eInvalid;
            return static_cast<PxGeometryType>(t);
        }
    };

    struct PxShapeCore_Mem {
        alignas(16) Vec4 transformQ;
        Vec3 transformP;
        float contactOffset;
        uint8_t shapeFlags;
        uint8_t ownsMaterialIdxMem;
        uint16_t materialIndex;
        GeometryUnion_Mem geometry;
    };

    struct ShapeCore_Mem {
        uint8_t queryFilter[16];
        uint8_t simFilter[16];
        alignas(16) PxShapeCore_Mem core;
        float restOffset;
    };

    struct Shape_Mem {
        uint64_t scene;
        uint32_t controlState;
        uint32_t _pad;
        uint64_t streamPtr;
        ShapeCore_Mem shapeCore;
    };

    struct NpShape_Mem : PxActor_Mem {
        uint64_t refCountable;
        int32_t refCount;
        uint32_t _pad;
        uint64_t actor;
        Shape_Mem shape;
        uint64_t name;
        int32_t exclusiveAndActorCount;
    };

    /* Geometry sub-structs (overlaid in GeometryUnion_Mem::data) */

    struct PxBoxGeom_Mem {
        int32_t type;
        Vec3 halfExtents;
    };

    struct PxCapsuleGeom_Mem {
        int32_t type;
        float radius;
        float halfHeight;
    };

    struct PxSphereGeom_Mem {
        int32_t type;
        float radius;
    };

    struct PxTriMeshGeom_Mem {
        int32_t type;
        Vec3 scale;
        Vec4 scaleRot;
        uint8_t meshFlags;
        uint8_t _pad[3];
        uint64_t meshPtr;
    };

    struct PxConvexMeshGeom_Mem {
        int32_t type;
        Vec3 scale;
        Vec4 scaleRot;
        uint8_t meshFlags;
        uint8_t _pad[3];
        uint64_t meshPtr;
    };

    struct PxHeightFieldGeom_Mem {
        int32_t type;
        uint64_t heightFieldPtr;
        float heightScale;
        float rowScale;
        float columnScale;
        uint8_t heightFieldFlags;
    };

    struct TriangleMesh_Mem {
        uint8_t _pad0[0x8];
        uint16_t type;
        uint16_t baseFlags;
        uint64_t refCountVfptr;
        int64_t refCount;
        uint32_t nbVertices;
        uint32_t nbTriangles;
        uint64_t verticesPtr;
        uint64_t trianglesPtr;
        uint8_t aabb[24];
        uint64_t extraTrigData;
        float geomEpsilon;
        uint8_t flags;
    };

    struct ConvexMesh_Mem {
        uint8_t _pad0[0x8];
        uint16_t type;
        uint16_t baseFlags;
        uint64_t refCountVfptr;
        int64_t refCount;
        uint32_t nbVertices;
        uint32_t nbPolygons;
        uint64_t verticesPtr;
        uint64_t indicesPtr;
        uint64_t polygonsPtr;
    };

    struct HeightFieldData_Mem {
        uint8_t aabb[24];
        uint32_t rows;
        uint32_t columns;
        float rowLimit;
        float columnLimit;
        float nbColumns;
        uint64_t samplesPtr;
        float thickness;
    };

    struct PxHeightFieldSample_Mem {
        int16_t height;
        uint8_t matIdx0;
        uint8_t matIdx1;
    };

    struct NpScene_Mem {
        uint8_t _pad[0x23C8];
        uint64_t rigidActorsData;
        uint32_t rigidActorsCapacity;
        uint32_t rigidActorsSize;
    };

    struct NpPhysics_Mem {
        uint8_t _pad[0x8];
        uint64_t sceneArrayData;
        uint32_t sceneArrayCapacity;
        uint32_t sceneArraySize;
    };

#pragma pack(pop)

    /* ═══════════════════════════════════════════════════════════
     *              SHAPE GENERATORS
     * ═══════════════════════════════════════════════════════════ */

    /* ── Box ──────────────────────────────────────────────────── */

    static std::vector<Triangle> generateBoxTriangles(
        const PxTransform &xform, const Vec3 &halfExtents)
    {
        std::array<Vec3, 8> corners;
        int idx = 0;
        for (int x : {-1, 1})
            for (int y : {-1, 1})
                for (int z : {-1, 1})
                    corners[idx++] = xform.transformPoint(
                        Vec3(x * halfExtents.x, y * halfExtents.y, z * halfExtents.z));

        constexpr std::array<std::array<int, 3>, 12> faces = {{
            {0,1,2},{1,3,2}, {4,6,5},{5,6,7},
            {0,2,4},{2,6,4}, {1,5,3},{3,5,7},
            {0,4,1},{1,4,5}, {2,3,6},{3,7,6}
        }};

        std::vector<Triangle> tris;
        tris.reserve(12);
        for (const auto &f : faces) {
            const auto &a = corners[f[0]], &b = corners[f[1]], &c = corners[f[2]];
            if ((b - a).cross(c - a).length_squared() < 1e-6f) continue;
            tris.push_back({a, b, c});
        }
        return tris;
    }

    /* ── Capsule ─────────────────────────────────────────────── */

    static std::vector<Triangle> generateCapsuleTriangles(
        const PxTransform &xform, float radius, float halfHeight,
        int rings = 6, int segments = 8)
    {
        std::vector<Triangle> tris;
        std::vector<Vec3> verts;

        /* Generate vertices for a capsule aligned along X axis (PhysX convention) */
        const float PI = 3.14159265f;

        /* Top hemisphere */
        for (int r = 0; r <= rings / 2; r++) {
            float phi = PI * 0.5f * r / (rings / 2);
            float y = radius * cosf(phi);
            float ringR = radius * sinf(phi);
            for (int s = 0; s < segments; s++) {
                float theta = 2.0f * PI * s / segments;
                Vec3 local(halfHeight + y, ringR * cosf(theta), ringR * sinf(theta));
                verts.push_back(xform.transformPoint(local));
            }
        }

        /* Cylinder body */
        for (int r = 0; r <= 1; r++) {
            float x = halfHeight - 2.0f * halfHeight * r;
            for (int s = 0; s < segments; s++) {
                float theta = 2.0f * PI * s / segments;
                Vec3 local(x, radius * cosf(theta), radius * sinf(theta));
                verts.push_back(xform.transformPoint(local));
            }
        }

        /* Bottom hemisphere */
        for (int r = 0; r <= rings / 2; r++) {
            float phi = PI * 0.5f + PI * 0.5f * r / (rings / 2);
            float y = radius * cosf(phi);
            float ringR = fabsf(radius * sinf(phi));
            for (int s = 0; s < segments; s++) {
                float theta = 2.0f * PI * s / segments;
                Vec3 local(-halfHeight + y, ringR * cosf(theta), ringR * sinf(theta));
                verts.push_back(xform.transformPoint(local));
            }
        }

        /* Generate triangles between rings */
        int totalRings = (rings / 2 + 1) + 2 + (rings / 2 + 1);
        for (int r = 0; r < totalRings - 1; r++) {
            for (int s = 0; s < segments; s++) {
                int s1 = (s + 1) % segments;
                int i0 = r * segments + s;
                int i1 = r * segments + s1;
                int i2 = (r + 1) * segments + s;
                int i3 = (r + 1) * segments + s1;
                if (i0 < (int)verts.size() && i1 < (int)verts.size() &&
                    i2 < (int)verts.size() && i3 < (int)verts.size())
                {
                    tris.push_back({verts[i0], verts[i1], verts[i2]});
                    tris.push_back({verts[i1], verts[i3], verts[i2]});
                }
            }
        }

        return tris;
    }

    /* ── Sphere ──────────────────────────────────────────────── */

    static std::vector<Triangle> generateSphereTriangles(
        const PxTransform &xform, float radius,
        int stacks = 6, int slices = 8)
    {
        std::vector<Triangle> tris;
        const float PI = 3.14159265f;

        std::vector<Vec3> verts;
        for (int i = 0; i <= stacks; i++) {
            float phi = PI * i / stacks;
            float y = radius * cosf(phi);
            float r = radius * sinf(phi);
            for (int j = 0; j <= slices; j++) {
                float theta = 2.0f * PI * j / slices;
                Vec3 local(r * cosf(theta), y, r * sinf(theta));
                verts.push_back(xform.transformPoint(local));
            }
        }

        int cols = slices + 1;
        for (int i = 0; i < stacks; i++) {
            for (int j = 0; j < slices; j++) {
                int a = i * cols + j;
                int b = a + 1;
                int c = (i + 1) * cols + j;
                int d = c + 1;
                if (a < (int)verts.size() && b < (int)verts.size() && 
                    c < (int)verts.size() && d < (int)verts.size()) {
                    tris.push_back({verts[a], verts[b], verts[c]});
                    tris.push_back({verts[b], verts[d], verts[c]});
                }
            }
        }

        return tris;
    }

    /* ── Triangle mesh (read from game memory) ───────────────── */

    std::vector<Triangle> generateTriangleMeshTriangles(
        const PxTransform &xform, const uint8_t *geomData)
    {
        std::vector<Triangle> tris;
        auto *g = reinterpret_cast<const PxTriMeshGeom_Mem *>(geomData);
        if (!g->meshPtr) return tris;

        auto mesh = sdk->ReadVal<TriangleMesh_Mem>((uintptr_t)g->meshPtr);
        if (mesh.nbVertices == 0 || mesh.nbTriangles == 0 ||
            !mesh.verticesPtr || !mesh.trianglesPtr)
            return tris;

        if (mesh.nbVertices > 100000 || mesh.nbTriangles > 200000)
            return tris;

        std::vector<Vec3> vertices(mesh.nbVertices);
        if (!sdk->ReadRawPublic(mesh.verticesPtr, vertices.data(), mesh.nbVertices * sizeof(Vec3)))
            return tris;

        bool has16bit = mesh.flags & 2u;
        std::vector<uint32_t> indices;

        if (has16bit) {
            std::vector<uint16_t> smallIdx(mesh.nbTriangles * 3);
            if (!sdk->ReadRawPublic(mesh.trianglesPtr, smallIdx.data(), smallIdx.size() * sizeof(uint16_t)))
                return tris;
            indices.reserve(smallIdx.size());
            for (auto i : smallIdx) indices.push_back((uint32_t)i);
        } else {
            indices.resize(mesh.nbTriangles * 3);
            if (!sdk->ReadRawPublic(mesh.trianglesPtr, indices.data(), indices.size() * sizeof(uint32_t)))
                return tris;
        }

        PxMeshScale sc;
        sc.scale = g->scale;
        sc.rotation = g->scaleRot;
        PxMat33 scaleMat = sc.toMat33();

        tris.reserve(mesh.nbTriangles);
        for (size_t i = 0; i + 2 < indices.size(); i += 3) {
            uint32_t i0 = indices[i], i1 = indices[i + 1], i2 = indices[i + 2];
            if (i0 >= vertices.size() || i1 >= vertices.size() || i2 >= vertices.size()) continue;

            Vec3 s0 = scaleMat.transform(vertices[i0]);
            Vec3 s1 = scaleMat.transform(vertices[i1]);
            Vec3 s2 = scaleMat.transform(vertices[i2]);

            if (s0.is_empty() || s1.is_empty() || s2.is_empty()) continue;

            Vec3 w0 = xform.transformPoint(s0);
            Vec3 w1 = xform.transformPoint(s1);
            Vec3 w2 = xform.transformPoint(s2);

            if ((w1 - w0).cross(w2 - w0).length_squared() < 1e-6f) continue;
            tris.push_back({w0, w1, w2});
        }
        return tris;
    }

    /* ── Convex mesh (read from game memory) ─────────────────── */

    std::vector<Triangle> generateConvexMeshTriangles(
        const PxTransform &xform, const uint8_t *geomData)
    {
        std::vector<Triangle> tris;
        auto *g = reinterpret_cast<const PxConvexMeshGeom_Mem *>(geomData);
        if (!g->meshPtr) return tris;

        auto mesh = sdk->ReadVal<ConvexMesh_Mem>((uintptr_t)g->meshPtr);
        if (mesh.nbVertices == 0 || !mesh.verticesPtr || mesh.nbVertices > 50000)
            return tris;

        std::vector<Vec3> vertices(mesh.nbVertices);
        if (!sdk->ReadRawPublic(mesh.verticesPtr, vertices.data(), mesh.nbVertices * sizeof(Vec3)))
            return tris;

        PxMeshScale sc;
        sc.scale = g->scale;
        sc.rotation = g->scaleRot;
        PxMat33 scaleMat = sc.toMat33();

        /* Transform all vertices to world space */
        std::vector<Vec3> worldVerts(mesh.nbVertices);
        for (uint32_t i = 0; i < mesh.nbVertices; i++) {
            worldVerts[i] = xform.transformPoint(scaleMat.transform(vertices[i]));
        }

        /* Fan triangulation from vertex 0 (convex hull) */
        if (mesh.nbVertices >= 3) {
            tris.reserve(mesh.nbVertices - 2);
            for (uint32_t i = 1; i + 1 < mesh.nbVertices; i++) {
                const auto &a = worldVerts[0], &b = worldVerts[i], &c = worldVerts[i + 1];
                if ((b - a).cross(c - a).length_squared() >= 1e-6f)
                    tris.push_back({a, b, c});
            }
        }

        return tris;
    }

    /* ── Height field (read from game memory) ────────────────── */

    std::vector<Triangle> generateHeightFieldTriangles(
        const PxTransform &xform, const uint8_t *geomData,
        int maxSamples = 5000)
    {
        std::vector<Triangle> tris;
        auto *g = reinterpret_cast<const PxHeightFieldGeom_Mem *>(geomData);
        if (!g->heightFieldPtr) return tris;

        auto hf = sdk->ReadVal<HeightFieldData_Mem>((uintptr_t)g->heightFieldPtr);
        if (hf.rows == 0 || hf.columns == 0 || !hf.samplesPtr) return tris;
        if (hf.rows * hf.columns > (uint32_t)maxSamples) return tris;

        uint32_t total = hf.rows * hf.columns;
        std::vector<PxHeightFieldSample_Mem> samples(total);
        if (!sdk->ReadRawPublic(hf.samplesPtr, samples.data(), total * sizeof(PxHeightFieldSample_Mem)))
            return tris;

        tris.reserve((hf.rows - 1) * (hf.columns - 1) * 2);

        for (uint32_t r = 0; r + 1 < hf.rows; r++) {
            for (uint32_t c = 0; c + 1 < hf.columns; c++) {
                auto sample = [&](uint32_t row, uint32_t col) -> Vec3 {
                    auto &s = samples[row * hf.columns + col];
                    return xform.transformPoint(Vec3(
                        row * g->rowScale,
                        s.height * g->heightScale,
                        col * g->columnScale));
                };

                Vec3 v00 = sample(r, c);
                Vec3 v10 = sample(r + 1, c);
                Vec3 v01 = sample(r, c + 1);
                Vec3 v11 = sample(r + 1, c + 1);

                tris.push_back({v00, v10, v01});
                tris.push_back({v10, v11, v01});
            }
        }

        return tris;
    }

    /* ═══════════════════════════════════════════════════════════
     *              BVH CONSTRUCTION
     * ═══════════════════════════════════════════════════════════ */

    static AABB computeAABB(const std::vector<Triangle> &tris, const std::vector<size_t> &indices) {
        AABB b;
        for (size_t idx : indices) {
            b.expand(tris[idx].v0); b.expand(tris[idx].v1); b.expand(tris[idx].v2);
        }
        return b;
    }

    static AABB computeAABB(const std::vector<Triangle> &tris) {
        AABB b;
        for (const auto &t : tris) { b.expand(t.v0); b.expand(t.v1); b.expand(t.v2); }
        return b;
    }

    static BVHNode *buildBVH(const std::vector<Triangle> &tris,
                              std::vector<size_t> &indices, int depth = 0)
    {
        auto *node = new BVHNode();
        node->bounds = computeAABB(tris, indices);

        if (indices.size() <= 16 || depth > 12) {
            node->triIndices = indices;
            return node;
        }

        int axis = node->bounds.longestAxis();
        auto mid = indices.begin() + indices.size() / 2;
        std::nth_element(indices.begin(), mid, indices.end(),
            [&](size_t a, size_t b) {
                return tris[a].center()[axis] < tris[b].center()[axis];
            });

        std::vector<size_t> leftIdx(indices.begin(), mid);
        std::vector<size_t> rightIdx(mid, indices.end());

        node->left.reset(buildBVH(tris, leftIdx, depth + 1));
        node->right.reset(buildBVH(tris, rightIdx, depth + 1));
        return node;
    }

    static void buildActorBVH(ActorInfo &actor) {
        if (actor.triangles.empty()) return;
        std::vector<size_t> indices(actor.triangles.size());
        std::iota(indices.begin(), indices.end(), 0);
        actor.bounds = computeAABB(actor.triangles);
        actor.bvhRoot.reset(buildBVH(actor.triangles, indices));
    }

    /* ═══════════════════════════════════════════════════════════
     *              RAYCASTING
     * ═══════════════════════════════════════════════════════════ */

    static bool rayTriangle(const Vec3 &origin, const Vec3 &dir,
                             const Triangle &tri, float &outT, Vec3 &outNormal)
    {
        const float EPS = 1e-6f;
        Vec3 e1 = tri.v1 - tri.v0;
        Vec3 e2 = tri.v2 - tri.v0;
        Vec3 pvec = dir.cross(e2);
        float det = e1.dot(pvec);
        if (fabsf(det) < EPS) return false;
        float invDet = 1.0f / det;
        Vec3 tvec = origin - tri.v0;
        float u = tvec.dot(pvec) * invDet;
        if (u < 0.0f || u > 1.0f) return false;
        Vec3 qvec = tvec.cross(e1);
        float v = dir.dot(qvec) * invDet;
        if (v < 0.0f || u + v > 1.0f) return false;
        float t = e2.dot(qvec) * invDet;
        if (t <= 0.0f) return false;
        outT = t;
        outNormal = e1.cross(e2).normalize();
        return true;
    }

    static bool raycastBVH(const BVHNode *node, const Vec3 &origin, const Vec3 &dir,
                            float &closestT, HitResult &best,
                            const std::vector<Triangle> &tris)
    {
        float tmin, tmax;
        if (!node->bounds.intersects(origin, dir, tmin, tmax)) return false;

        bool hitAny = false;

        if (!node->left && !node->right) {
            for (size_t idx : node->triIndices) {
                float t; Vec3 normal;
                if (rayTriangle(origin, dir, tris[idx], t, normal) && t < closestT) {
                    closestT = t;
                    best.point = origin + dir * t;
                    best.normal = normal;
                    best.distance = t;
                    best.didHit = true;
                    hitAny = true;
                }
            }
            return hitAny;
        }

        if (node->left)  hitAny |= raycastBVH(node->left.get(), origin, dir, closestT, best, tris);
        if (node->right) hitAny |= raycastBVH(node->right.get(), origin, dir, closestT, best, tris);
        return hitAny;
    }

    /* ═══════════════════════════════════════════════════════════
     *              PUBLIC API
     * ═══════════════════════════════════════════════════════════ */

private:
    RustSDK *sdk = nullptr;
    uintptr_t unityPlayer = 0;
    uintptr_t physxSdkOffset = 0x1C3B3D0;
    mutable std::mutex m_actorsMutex;
    std::shared_ptr<std::vector<ActorInfo>> m_actors;

public:
    PhysXScene() = default;

    bool Init(RustSDK *sdkPtr, DriverComm *drv, DWORD pid) {
        sdk = sdkPtr;
        /* Resolve UnityPlayer.dll base */
        unityPlayer = drv->GetModuleBase(pid, L"UnityPlayer.dll");
        if (!unityPlayer) {
            printf("[PhysX] Failed to get UnityPlayer.dll base\n");
            return false;
        }
        printf("[PhysX] UnityPlayer.dll base: 0x%llX\n", (uint64_t)unityPlayer);

        /* Verify the PhysX SDK offset - try fallback scanning if it fails */
        uintptr_t testPtr = sdk->ReadVal<uint64_t>(unityPlayer + physxSdkOffset);
        if (!testPtr || (testPtr & 0xFFFF000000000000ULL) != 0) {
            printf("[PhysX] Hardcoded offset 0x%llX invalid, scanning for SDK pointer...\n", (uint64_t)physxSdkOffset);
            if (!ScanForPhysXSDK()) {
                printf("[PhysX] Failed to locate PhysX SDK pointer\n");
                return false;
            }
        } else {
            printf("[PhysX] Using hardcoded PhysX SDK offset: 0x%llX\n", (uint64_t)physxSdkOffset);
        }
        return true;
    }

    /* Scan UnityPlayer.dll for PhysX SDK singleton pointer pattern */
    bool ScanForPhysXSDK() {
        /* Read PE headers to get module size */
        IMAGE_DOS_HEADER dos = sdk->ReadVal<IMAGE_DOS_HEADER>(unityPlayer);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        IMAGE_NT_HEADERS64 nt = sdk->ReadVal<IMAGE_NT_HEADERS64>(unityPlayer + dos.e_lfanew);
        if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
        
        uintptr_t moduleEnd = unityPlayer + nt.OptionalHeader.SizeOfImage;
        const size_t SCAN_CHUNK = 0x10000; // 64KB chunks
        std::vector<uint8_t> chunk(SCAN_CHUNK);
        
        /* Scan for pattern: mov rax, [rel32]; test rax, rax; jz ... */
        for (uintptr_t addr = unityPlayer; addr < moduleEnd - SCAN_CHUNK; addr += SCAN_CHUNK) {
            if (!sdk->ReadRawPublic(addr, chunk.data(), SCAN_CHUNK)) continue;
            
            for (size_t i = 0; i < SCAN_CHUNK - 8; i++) {
                /* Look for: 48 8B 05 XX XX XX XX (mov rax, [rip+offset]) */
                if (chunk[i] == 0x48 && chunk[i+1] == 0x8B && chunk[i+2] == 0x05) {
                    int32_t relOffset = *(int32_t*)&chunk[i+3];
                    uintptr_t sdkPtr = addr + i + 7 + relOffset;
                    
                    /* Verify this looks like a valid SDK pointer */
                    if (sdkPtr > unityPlayer && sdkPtr < moduleEnd) {
                        uint64_t testVal = sdk->ReadVal<uint64_t>(sdkPtr);
                        if (testVal && testVal < 0x7FFFFFFFFFFF) {
                            /* Test scene array */
                            uint64_t sceneArray = sdk->ReadVal<uint64_t>(testVal + offsetof(NpPhysics_Mem, sceneArrayData));
                            uint32_t sceneCount = sdk->ReadVal<uint32_t>(testVal + offsetof(NpPhysics_Mem, sceneArraySize));
                            if (sceneArray && sceneCount > 0 && sceneCount < 1000) {
                                physxSdkOffset = sdkPtr - unityPlayer;
                                printf("[PhysX] Found SDK pointer at offset 0x%llX\n", (uint64_t)physxSdkOffset);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    void SetPhysXOffset(uintptr_t offset) { physxSdkOffset = offset; }

    /* ── Cache all scene actors (call from background thread) ── */

    void CacheActors() {
        if (!sdk || !unityPlayer) return;

        auto newActors = std::make_shared<std::vector<ActorInfo>>();

        uintptr_t sdkPtr = sdk->ReadVal<uint64_t>(unityPlayer + physxSdkOffset);
        if (!sdkPtr) return;

        auto physxSdk = sdk->ReadVal<NpPhysics_Mem>(sdkPtr);
        if (!physxSdk.sceneArraySize || !physxSdk.sceneArrayData) return;

        std::vector<uint64_t> scenePtrs(physxSdk.sceneArraySize);
        if (!sdk->ReadRawPublic(physxSdk.sceneArrayData, scenePtrs.data(),
                          physxSdk.sceneArraySize * sizeof(uint64_t)))
            return;

        for (auto scenePtr : scenePtrs) {
            if (!scenePtr) continue;

            NpScene_Mem sceneMem{};
            /* Read only the rigid actors array info */
            uint64_t actorsData = sdk->ReadVal<uint64_t>(
                scenePtr + offsetof(NpScene_Mem, rigidActorsData));
            uint32_t actorsSize = sdk->ReadVal<uint32_t>(
                scenePtr + offsetof(NpScene_Mem, rigidActorsSize));
            if (!actorsData || actorsSize == 0 || actorsSize > 100000) continue;

            std::vector<uint64_t> actorPtrs(actorsSize);
            if (!sdk->ReadRawPublic(actorsData, actorPtrs.data(), actorsSize * sizeof(uint64_t)))
                continue;

            for (auto actorPtr : actorPtrs) {
                if (!actorPtr) continue;

                auto actor = sdk->ReadVal<PxActor_Mem>(actorPtr);
                /* Only cache rigid statics (terrain, buildings, deployables) */
                if (actor.type != (uint16_t)PxConcreteType::eRigidStatic) continue;

                auto rigidStatic = sdk->ReadVal<NpRigidStatic_Mem>(actorPtr);
                if (!rigidStatic.shapeManager.shapes.single) continue;

                uint64_t shapeAddr = rigidStatic.shapeManager.shapes.single;
                auto shape = sdk->ReadVal<NpShape_Mem>(shapeAddr);
                if (!shape.shape.scene) continue;

                PxGeometryType geoType = shape.shape.shapeCore.core.geometry.getType();

                /* Get global pose */
                PxTransform pose;
                uint64_t state = rigidStatic.body.controlState;
                if ((state & 40) != 0) {
                    /* Buffered — read from stream */
                    auto streamBody = sdk->ReadVal<PxRigidCore_Mem>(
                        sdk->ReadVal<uint64_t>(rigidStatic.body.streamPtr + 0xB0));
                    pose.q = streamBody.bodyQ;
                    pose.p = streamBody.bodyP;
                } else {
                    pose.q = rigidStatic.body.bodyCore.core.bodyQ;
                    pose.p = rigidStatic.body.bodyCore.core.bodyP;
                }

                ActorInfo info;
                info.type = geoType;
                info.transform = pose;
                const uint8_t *gd = shape.shape.shapeCore.core.geometry.data;

                switch (geoType) {
                case PxGeometryType::eTriangleMesh:
                    info.triangles = generateTriangleMeshTriangles(pose, gd);
                    break;
                case PxGeometryType::eBox: {
                    auto *b = reinterpret_cast<const PxBoxGeom_Mem *>(gd);
                    info.triangles = generateBoxTriangles(pose, b->halfExtents);
                    break;
                }
                case PxGeometryType::eCapsule: {
                    auto *c = reinterpret_cast<const PxCapsuleGeom_Mem *>(gd);
                    info.triangles = generateCapsuleTriangles(pose, c->radius, c->halfHeight);
                    break;
                }
                case PxGeometryType::eSphere: {
                    auto *s = reinterpret_cast<const PxSphereGeom_Mem *>(gd);
                    info.triangles = generateSphereTriangles(pose, s->radius);
                    break;
                }
                case PxGeometryType::eConvexMesh:
                    info.triangles = generateConvexMeshTriangles(pose, gd);
                    break;
                case PxGeometryType::eHeightfield:
                    info.triangles = generateHeightFieldTriangles(pose, gd);
                    break;
                default:
                    break;
                }

                if (!info.triangles.empty()) {
                    buildActorBVH(info);
                    newActors->push_back(std::move(info));
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_actorsMutex);
            m_actors = newActors;
        }
        
        /* Debug: count by geometry type */
        std::map<PxGeometryType, int> typeCounts;
        for (const auto &actor : *newActors) {
            typeCounts[actor.type]++;
        }
        printf("[PhysX] Cached %d actors: ", (int)newActors->size());
        for (auto &[type, count] : typeCounts) {
            const char *typeName = "unknown";
            switch (type) {
                case PxGeometryType::eTriangleMesh: typeName = "triMesh"; break;
                case PxGeometryType::eBox: typeName = "box"; break;
                case PxGeometryType::eCapsule: typeName = "capsule"; break;
                case PxGeometryType::eSphere: typeName = "sphere"; break;
                case PxGeometryType::eConvexMesh: typeName = "convex"; break;
                case PxGeometryType::eHeightfield: typeName = "heightfield"; break;
                default: break;
            }
            printf("%s:%d ", typeName, count);
        }
        printf("\n");
    }

    /* ── Raycast ─────────────────────────────────────────────── */

    HitResult Raycast(Vec3 origin, Vec3 direction, float maxDist) {
        HitResult hit;
        if (origin.is_empty() || direction.is_empty() || maxDist <= 0) return hit;

        std::shared_ptr<std::vector<ActorInfo>> actors;
        {
            std::lock_guard<std::mutex> lock(m_actorsMutex);
            actors = m_actors;
        }
        if (!actors) return hit;

        float closestT = maxDist;
        for (const auto &actor : *actors) {
            if (!actor.bvhRoot) continue;
            float tmin, tmax;
            if (!actor.bounds.intersects(origin, direction, tmin, tmax)) continue;
            raycastBVH(actor.bvhRoot.get(), origin, direction, closestT, hit, actor.triangles);
        }
        return hit;
    }

    /* ── Linecast (from → to) ────────────────────────────────── */

    HitResult Linecast(Vec3 from, Vec3 to) {
        if (from.is_empty() || to.is_empty()) return {};
        Vec3 dir = (to - from).normalize();
        float dist = (to - from).Length();
        return Raycast(from, dir, dist);
    }

    /* ── Visibility check: is 'target' visible from 'eye'? ──── */

    bool IsVisible(Vec3 eye, Vec3 target) {
        if (eye.is_empty() || target.is_empty()) return true;
        auto hit = Linecast(eye, target);
        if (!hit.didHit) return true;
        /* If the hit is very close to the target, it's still "visible"
         * (hit the target's own collider or close geometry) */
        float targetDist = (target - eye).Length();
        return hit.distance >= (targetDist - 0.5f);
    }

    /* ── Per-bone visibility check ───────────────────────────── */

    bool CheckBoneVisible(Vec3 eye, Vec3 bonePos) {
        return IsVisible(eye, bonePos);
    }

    /* ── Check if any bone on a player is visible ────────────── */

    bool AnyBoneVisible(Vec3 eye, const std::vector<Vec3> &bones,
                        const int *boneIndices, int numBones)
    {
        for (int i = 0; i < numBones; i++) {
            int idx = boneIndices[i];
            if (idx >= (int)bones.size()) continue;
            if (bones[idx].is_empty()) continue;
            if (IsVisible(eye, bones[idx])) return true;
        }
        return false;
    }

    bool HasActors() const {
        std::lock_guard<std::mutex> lock(m_actorsMutex);
        return m_actors && !m_actors->empty();
    }
};

#pragma pop_macro("min")
#pragma pop_macro("max")
