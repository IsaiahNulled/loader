# GitHub Repository Upload Guide

## Current Status ✅
Both SAFE and FULL builds have been successfully compiled:

### Safe Build (Read-Only)
- `c:\Users\Isaiah\Desktop\external\safe\User\x64\Release\User.exe`
- `c:\Users\Isaiah\Desktop\external\safe\driver\x64\Release\driver.sys`
- `c:\Users\Isaiah\Desktop\external\safe\Loader\x64\Release\Loader.exe`

### Full Build (Write-Enabled)
- `c:\Users\Isaiah\Desktop\external\full\User\x64\Release\User.exe`
- `c:\Users\Isaiah\Desktop\external\full\driver\x64\Release\driver.sys`
- `c:\Users\Isaiah\Desktop\external\full\Loader\x64\Release\Loader.exe`

## Required GitHub Structure

```
IsaiahNulled/Needed/
├── main/
│   ├── safe/
│   │   ├── User.exe
│   │   ├── Loader.exe
│   │   └── driver.sys
│   └── full/
│       ├── User.exe
│       ├── Loader.exe
│       └── driver.sys
└── (existing files)
```

## Upload Methods

### Method 1: GitHub CLI (Recommended)
```bash
# Clone your repo if not already done
git clone https://github.com/IsaiahNulled/Needed.git
cd Needed

# Create directories
mkdir -p main/safe main/full

# Copy files
cp "c:\Users\Isaiah\Desktop\external\safe\User\x64\Release\User.exe" main/safe/
cp "c:\Users\Isaiah\Desktop\external\safe\driver\x64\Release\driver.sys" main/safe/
cp "c:\Users\Isaiah\Desktop\external\safe\Loader\x64\Release\Loader.exe" main/safe/

cp "c:\Users\Isaiah\Desktop\external\full\User\x64\Release\User.exe" main/full/
cp "c:\Users\Isaiah\Desktop\external\full\driver\x64\Release\driver.sys" main/full/
cp "c:\Users\Isaiah\Desktop\external\full\Loader\x64\Release\Loader.exe" main/full/

# Add and push
git add main/safe/ main/full/
git commit -m "Add dual build architecture: safe (read-only) and full (write-enabled)"
git push origin main
```

### Method 2: GitHub Web Interface
1. Go to https://github.com/IsaiahNulled/Needed
2. Click "Add file" → "Create new file"
3. Create `main/safe/User.exe` (paste binary content or use "Upload files")
4. Repeat for all 6 files:
   - `main/safe/Loader.exe`
   - `main/safe/driver.sys`
   - `main/full/User.exe`
   - `main/full/Loader.exe`
   - `main/full/driver.sys`

### Method 3: GitHub Desktop
1. Open GitHub Desktop
2. Navigate to your Needed repo
3. Drag the `main/safe` and `main/full` folders into the repo
4. Commit changes with description
5. Push to GitHub

## File Verification

After upload, verify these URLs work:
```
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/User.exe
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/Loader.exe
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/safe/driver.sys

https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/User.exe
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/Loader.exe
https://github.com/IsaiahNulled/Needed/raw/refs/heads/main/full/driver.sys
```

## Testing the Complete Flow

Once uploaded, test the full user experience:

1. **Download any Loader.exe** (safe or full - both work)
2. **Run Loader.exe**
3. **Authenticate** with your license key
4. **Select build type** when prompted:
   - Choose "1" for Safe (read-only)
   - Choose "2" for Full (write-enabled)
5. **Verify automatic download** of correct components
6. **Confirm driver installation** and User.exe launch

## Expected Behavior

### Safe Build Selection
- Downloads from `/safe/` folder
- Installs read-only driver
- Launches ESP-only User.exe
- No cheats available

### Full Build Selection  
- Downloads from `/full/` folder
- Installs write-enabled driver
- Launches full-featured User.exe
- All cheats available

## Troubleshooting

### If Downloads Fail
1. Check GitHub URLs are accessible
2. Verify auth server `/api/select-build` endpoint works
3. Check loader console for error messages

### If Driver Fails to Load
1. Verify correct driver build matches selection
2. Check Windows driver signing status
3. Review loader logs for installation errors

### If User.exe Features Wrong
1. Confirm correct User.exe build was downloaded
2. Check if safe build has cheat tabs removed
3. Verify full build has all features enabled

## Maintenance

### Updating Builds
1. Make changes to source code
2. Run `build.bat` in both `safe/` and `full/` directories
3. Upload new binaries to corresponding GitHub folders
4. Changes are immediately available to users

### Version Management
- Consider adding version numbers to filenames
- Keep older versions in backup folders
- Update changelog with each release

## Security Notes

- **Safe build**: Read-only driver, minimal detection risk
- **Full build**: Write-enabled driver, higher detection risk
- **User choice**: Clear risk vs. functionality trade-off
- **Separation**: No risk of accidentally loading wrong components

The dual build architecture is now ready for production use!
