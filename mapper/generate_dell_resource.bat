@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  generate_dell_resource.bat
REM  Converts dbutil_2_3.sys into a XOR-encrypted C byte array header.
REM
REM  Usage:
REM    1. Place dbutil_2_3.sys in this directory (mapper/)
REM    2. Run this batch file
REM    3. Rebuild the Loader project
REM ═══════════════════════════════════════════════════════════════════

set DRIVER_FILE=dbutil_2_3.sys
set OUTPUT_FILE=include\dell_driver_resource.hpp

if not exist "%DRIVER_FILE%" (
    echo [!] ERROR: %DRIVER_FILE% not found in current directory.
    echo     Place the Dell BIOS utility driver here and re-run.
    pause
    exit /b 1
)

echo [*] Generating %OUTPUT_FILE% from %DRIVER_FILE% (XOR encrypted^)...

powershell -NoProfile -Command ^
  "$bytes = [System.IO.File]::ReadAllBytes('%DRIVER_FILE%');" ^
  "$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();" ^
  "$key = [byte[]]::new(32);" ^
  "$rng.GetBytes($key);" ^
  "$rng.Dispose();" ^
  "" ^
  "$encrypted = [byte[]]::new($bytes.Length);" ^
  "for ($i = 0; $i -lt $bytes.Length; $i++) {" ^
  "  $encrypted[$i] = $bytes[$i] -bxor $key[$i %% 32];" ^
  "}" ^
  "" ^
  "$sb = [System.Text.StringBuilder]::new();" ^
  "[void]$sb.AppendLine('#pragma once');" ^
  "[void]$sb.AppendLine('');" ^
  "[void]$sb.AppendLine('/*');" ^
  "[void]$sb.AppendLine(' * dell_driver_resource.hpp - Auto-generated from dbutil_2_3.sys');" ^
  "[void]$sb.AppendLine(' * XOR encrypted at rest. Decrypt with dell_driver_resource::xor_key before use.');" ^
  "[void]$sb.AppendLine(' * DO NOT EDIT MANUALLY. Re-run generate_dell_resource.bat to regenerate.');" ^
  "[void]$sb.AppendLine(' */');" ^
  "[void]$sb.AppendLine('');" ^
  "[void]$sb.AppendLine('namespace dell_driver_resource {');" ^
  "[void]$sb.AppendLine('');" ^
  "[void]$sb.AppendLine('constexpr unsigned int driver_size = ' + $bytes.Length.ToString() + ';');" ^
  "[void]$sb.AppendLine('');" ^
  "" ^
  "[void]$sb.Append('inline unsigned char xor_key[32] = {');" ^
  "$hexKey = ($key | ForEach-Object { '0x{0:X2}' -f $_ }) -join ', ';" ^
  "[void]$sb.AppendLine($hexKey + '};');" ^
  "[void]$sb.AppendLine('');" ^
  "[void]$sb.AppendLine('inline unsigned char driver[] = {');" ^
  "" ^
  "for ($i = 0; $i -lt $encrypted.Length; $i += 16) {" ^
  "  $end = [Math]::Min($i+15, $encrypted.Length-1);" ^
  "  $chunk = $encrypted[$i..$end];" ^
  "  $hex = ($chunk | ForEach-Object { '0x{0:X2}' -f $_ }) -join ', ';" ^
  "  if ($i + 16 -lt $encrypted.Length) { $hex += ',' };" ^
  "  [void]$sb.AppendLine('    ' + $hex);" ^
  "}" ^
  "" ^
  "[void]$sb.AppendLine('};');" ^
  "[void]$sb.AppendLine('');" ^
  "[void]$sb.AppendLine('} // namespace dell_driver_resource');" ^
  "[System.IO.File]::WriteAllText('%OUTPUT_FILE%', $sb.ToString());"

echo [+] Generated %OUTPUT_FILE% (XOR encrypted with random 32-byte key^)
echo [+] Now rebuild the Loader project.
pause
