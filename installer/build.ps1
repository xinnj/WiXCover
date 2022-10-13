#Requires -Version 5.1

param (
    [Parameter(Mandatory)][string]$Version
)

New-Item -ItemType Directory -Force -Path .\build

$VersionNum = $Version -replace ".*?(\d.*)", "`${1}"
Write-Host "Version: ${Version}"
Write-Host "VersionNum: ${VersionNum}"

((Get-Content .\installer\config.yaml -Raw -Encoding utf8) -replace "(Version:) .*", "`${1} '${VersionNum}'") |
        Set-Content .\installer\config.yaml -Encoding utf8
.\source\wixc.ps1 -config .\installer\config.yaml -output .\build\WiXCover-${Version}.msi