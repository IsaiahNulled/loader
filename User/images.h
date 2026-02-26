#pragma once

#include <d3d11.h>

// Load a single item icon from file path
ID3D11ShaderResourceView* LoadItemIcon(const std::string& path);
