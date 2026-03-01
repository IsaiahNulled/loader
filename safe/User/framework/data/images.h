#pragma once
#include <d3d11.h>

namespace UI_Icons {
    extern ID3D11ShaderResourceView* SkullTexture;
    extern ID3D11ShaderResourceView* EyeTexture;
    extern ID3D11ShaderResourceView* SlidersTexture;
    extern ID3D11ShaderResourceView* GearTexture;
    extern ID3D11ShaderResourceView* CheckmarkTexture;
    extern ID3D11ShaderResourceView* FolderTexture;
    extern ID3D11ShaderResourceView* PlayerTexture;
    extern ID3D11ShaderResourceView* AnimalTexture;
    extern ID3D11ShaderResourceView* WorldTexture;
    extern ID3D11ShaderResourceView* CollectibleTexture;

    void GenerateSkullTexture();
    void GenerateEyeTexture();
    void GenerateSlidersTexture();
    void GenerateGearTexture();
    void GenerateCheckmarkTexture();
    void GenerateFolderTexture();
    void GeneratePlayerTexture();
    void GenerateAnimalTexture();
    void GenerateWorldTexture();
    void GenerateCollectibleTexture();
}
