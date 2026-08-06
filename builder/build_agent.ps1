# Miau agent build script.
# Usage: .\build_agent.ps1 -Token miau_XXX -AesKeyHex 64hex -Pin SHA256HEX [-CaPath path] [-Host 1.2.3.4] [-Port 9000] [-HbInterval 15]
param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$AesKeyHex,
    [Parameter(Mandatory=$true)][string]$Pin,
    [string]$Host = "127.0.0.1",
    [int]$Port = 9000,
    [string]$CaPath = "",
    [int]$HbInterval = 15
)

$nimDir = "C:\Users\Hooli\AppData\Local\Microsoft\WinGet\Packages\nim.nim_Microsoft.Winget.Source_8wekyb3d8bbwe\nim-2.0.8"
$gccDir = "C:\Users\Hooli\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.MCF.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$env:Path = "$nimDir\bin;$gccDir;" + $env:Path
$p = "C:\Users\Hooli\.nimble\pkgs2\nimcrypto-0.7.3-f72b90fe3f4da09efa482de4f8729e7ee4abea2f"

Push-Location "C:\Users\Hooli\Desktop\Miau\client\nim"
try {
    # NOTE: -d: defines MUST come BEFORE the source file (PowerShell/nim arg order).
    cmd /c "nim.exe c -d:ssl -d:useOpenssl3 -d:sslVersion=3 --path:""$p"" --hints:off -d:ServerAddr=$Host -d:ServerPort=$Port -d:AgentToken=$Token -d:AgentAesKey=$AesKeyHex -d:ServerPin=$Pin -d:CaPath=$CaPath -d:HbInterval=$HbInterval agent.nim 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Output "BUILD OK -> agent.exe"
    } else {
        Write-Output "BUILD FAILED"
    }
} finally {
    Pop-Location
}
