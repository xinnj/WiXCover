#Requires -Version 5.1

<#
.SYNOPSIS
    Build MSI package based on yaml config.

.DESCRIPTION
    Build MSI package based on yaml config.

.PARAMETER Config
    The yaml config file.

.PARAMETER Output
    The output MSI package file.

.PARAMETER TemplateFile
    The template file used by WiX as source file. Will use the default one if not provided.

.PARAMETER WorkingDir
    The directory to store the temporary files.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$Output,
    [string]$TemplateFile = "$PSScriptRoot\template.wxs",
    [string]$WorkingDir = $(Join-Path $env:TEMP "~wixc")
)

$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
function ThrowOnNativeFailure
{
    if (-not$?)
    {
        throw 'Native Failure'
    }
}

function AddOrUpdateList ([Hashtable]$MyList, [String]$MyKey, [String]$MyValue) {
    if ($MyList.ContainsKey($MyKey)) {
        $MyList[$MyKey] = $MyValue
    } else {
        $MyList.Add($MyKey, $ValMyValueue)
    }
}

$Env:PATH = "$PSScriptRoot\WiX-v3.11\bin;" + $Env:PATH
Import-Module $PSScriptRoot\powershell-yaml

New-Item -ItemType Directory -Force -Path "$WorkingDir"

$ConfigYaml = (Get-Content $Config -Encoding UTF8 | ConvertFrom-Yaml)

$VarsList = @{ }
$VarsList.Add("ProductName", $ConfigYaml.Product.Name)
$VarsList.Add("ProductVersion", $ConfigYaml.Product.Version)
$VarsList.Add("UpgradeCode", $ConfigYaml.UpgradeCode)
$VarsList.Add("Manufacturer", $ConfigYaml.Manufacturer)
$VarsList.Add("MainExecutable", $ConfigYaml.Files.MainExecutable)


$VarsList.Add("IconFile", $ConfigYaml.Files.Icon.File)
$VarsList.Add("IconIndex",$ConfigYaml.Files.Icon.Index.ToString())
$IconExt = $ConfigYaml.Files.Icon.File.split('.')[-1]
$VarsList.Add("IconId", "icon." + $IconExt)

# Upgrade method
if ($ConfigYaml.Upgrade.AllowDowngrades)
{
    $VarsList.Add("AllowDowngrades", "yes")
}
else
{
    $VarsList.Add("AllowDowngrades", "no")
}
if ($ConfigYaml.Upgrade.AllowSameVersionUpgrades)
{
    $VarsList.Add("AllowSameVersionUpgrades", "yes")
}
else
{
    $VarsList.Add("AllowSameVersionUpgrades", "no")
}

# Install scope
switch ($ConfigYaml.InstallScope.Mode)
{
    'both' {
        $VarsList.Add("WixUISupportPerUser", "1")
        $VarsList.Add("WixUISupportPerMachine", "1")
        switch ($ConfigYaml.InstallScope.DefaultMode)
        {
            'user' {
                $VarsList.Add("WixAppFolder", "WixPerUserFolder")
                $VarsList.Add("ALLUSERS", "2")
                $VarsList.Add("Privileged", "0")
                $VarsList.Add("MSIINSTALLPERUSER", "1")
            }
            'machine' {
                $VarsList.Add("WixAppFolder", "WixPerMachineFolder")
                $VarsList.Add("ALLUSERS", "1")
                $VarsList.Add("Privileged", "1")
                $VarsList.Add("MSIINSTALLPERUSER", "0")
            }
            default {
                throw "InstallScope.DefaultMode can only be 'user' or 'machine' in config file!"
            }
        }
    }
    'user' {
        $VarsList.Add("WixUISupportPerUser", "1")
        $VarsList.Add("WixUISupportPerMachine", "0")
        $VarsList.Add("WixAppFolder", "WixPerUserFolder")
        $VarsList.Add("ALLUSERS", "2")
        $VarsList.Add("Privileged", "0")
        $VarsList.Add("MSIINSTALLPERUSER", "1")
    }
    'machine' {
        $VarsList.Add("WixUISupportPerUser", "0")
        $VarsList.Add("WixUISupportPerMachine", "1")
        $VarsList.Add("WixAppFolder", "WixPerMachineFolder")
        $VarsList.Add("ALLUSERS", "1")
        $VarsList.Add("Privileged", "1")
        $VarsList.Add("MSIINSTALLPERUSER", "0")
    }
    default {
        throw "InstallScope.Mode can only be 'both', 'user' or 'machine' in config file!"
    }
}

# Kill process
if ($ConfigYaml.KillProcess)
{
    $VarsList.Add("KillProcess", "<Custom Action='KillProcess' Before='InstallValidate'/>")
}
else
{
    $VarsList.Add("KillProcess", "<!-- <Custom Action='KillProcess' Before='InstallValidate'/> -->")
}

# Launch app
if ($ConfigYaml.LaunchApplication.Enable)
{
    $VarsList.Add("LaunchApplication", "<Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish>")
    if ($ConfigYaml.LaunchApplication.CheckedByDefault)
    {
        $VarsList.Add("LaunchApplicationChecked", "<Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' />")
    }
    else
    {
        $VarsList.Add("LaunchApplicationChecked", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' /> -->")
    }
}
else
{
    $VarsList.Add("LaunchApplication", "<!-- <Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish> -->")
    $VarsList.Add("LaunchApplicationChecked", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' /> -->")
}

# Generate file group
$FileRootfolder = @($ConfigYaml.Files.RootFolder -replace '\\$', '')
heat dir "$FileRootfolder" -cg FileGroup -dr APPLICATIONFOLDER -gg -srd -out "$WorkingDir\FileGroup.wxs"
ThrowOnNativeFailure

# Generate reg group
Write-Output "Windows Registry Editor Version 5.00" | Out-File "$WorkingDir\combined.reg"
$RegRootfolder = @($ConfigYaml.Regs.RootFolder -replace '\\$', '')
Get-ChildItem -Path "$RegRootfolder" -Include *.reg -Recurse | ForEach-Object { Get-Content $_ | Select-Object -Skip 1 } | Out-File -FilePath "$WorkingDir\combined.reg" -Append
heat reg "$WorkingDir\combined.reg" -cg RegGroup -gg -out "$WorkingDir\RegGroup.wxs"
ThrowOnNativeFailure
if ($ConfigYaml.Regs.ConvertToHkMU)
{
    (Get-Content "$WorkingDir\RegGroup.wxs").replace('Root="HKCU"', 'Root="HKMU"').replace('Root="HKLM"', 'Root="HKMU"').replace('SOFTWARE\WOW6432Node\', 'SOFTWARE\') | Out-File "$WorkingDir\RegGroup.wxs" -Encoding utf8
}

# Localiztion
$CultureLanguage = [ordered]@{}
$localizations = (Get-Content $PSScriptRoot\i18n\localizations.yaml -Encoding UTF8 | ConvertFrom-Yaml)
foreach ($OneLoc in $ConfigYaml.Localization)
{
    foreach ($k in $OneLoc.Keys) {
        if ($VarsList.ContainsKey($k)) {
            $VarsList.$k = $OneLoc.$k
        } else {
            $VarsList.Add($k, $OneLoc.$k)
        }
    }

    foreach ($k in $localizations[@($VarsList.Culture)].Keys) {
        if ($VarsList.ContainsKey($k)) {
            $VarsList.$k = $localizations[@($VarsList.Culture)].$k
        } else {
            $VarsList.Add($k, $localizations[@($VarsList.Culture)].$k)
        }
    }

    # make sure all vars are not empty
    foreach ($k in $VarsList.Keys) {
        if ($VarsList.$k -eq "")
        {
            throw "$k is empty!"
        }
        Remove-Variable -Name "$k" -ErrorAction SilentlyContinue
        New-Variable -Name "$k" -Value @($VarsList.$k)
    }

    $CultureLanguage.Add($VarsList.Culture, $VarsList.Language)

    # Substitude all variables in template file
    [string]$Template = Get-Content -Path "$TemplateFile" -Encoding UTF8
    foreach ($k in $VarsList.Keys) {
        $Template = $Template.Replace("`$`{$k`}", $VarsList.$k)
    }

    # Substitude all guid in template file
    $Count = ([regex]::Matches($Template, "Guid=''" )).count
    for($i = 1; $i -le $Count; $i++) {
        $Guid = [guid]::NewGuid().ToString()
        [regex]$Pattern = "Guid=''"
        $Template = $Pattern.replace($Template, "Guid='$Guid'", 1)
    }

    $MainFileName = [string]@($VarsList.Culture) + '.wsx'
    Out-File -InputObject $Template -FilePath "$WorkingDir\$MainFileName" -Encoding utf8 -Force

    Push-Location
    Set-Location "$WorkingDir"
    candle $MainFileName FileGroup.wxs RegGroup.wxs
    ThrowOnNativeFailure
    Pop-Location

    $ClutersParameter = '-cultures:' + [string]@($VarsList.Culture)
    $MsiName = [string]@($VarsList.Culture) + '.msi'
    $MainObjName = [string]@($VarsList.Culture) + '.wixobj'
    light -ext WixUIExtension -ext WiXUtilExtension $ClutersParameter -b "$FileRootfolder" -o "$WorkingDir\$MsiName" "$WorkingDir\$MainObjName" "$WorkingDir\FileGroup.wixobj" "$WorkingDir\RegGroup.wixobj"
    ThrowOnNativeFailure
}

$FirstCulture = ""
if (([Hashtable]$CultureLanguage).Count -gt 1) {
    foreach ($k in $CultureLanguage.Keys) {
        if ($FirstCulture -eq "") {
            $FirstCulture = $k
        } else {
            $CurrentCulture = $k
            torch -t language "$WorkingDir\${FirstCulture}`.msi" "$WorkingDir\${CurrentCulture}`.msi" -out "$WorkingDir\${CurrentCulture}`.mst"
            ThrowOnNativeFailure
            cscript $PSScriptRoot\i18n\WiSubStg.vbs "$WorkingDir\${FirstCulture}`.msi" "$WorkingDir\${CurrentCulture}`.mst" $CultureLanguage.$k
            ThrowOnNativeFailure
        }
    }

    $Languages = [Array]$CultureLanguage.Values -join ','
    cscript $PSScriptRoot\i18n\WiLangId.vbs "$WorkingDir\${FirstCulture}`.msi" Package $Languages
    ThrowOnNativeFailure
} else {
    $FirstCulture = $CultureLanguage[0]
}

Move-Item -Force "$WorkingDir\$FirstCulture`.msi" "$Output"

if (-not $PSBoundParameters['Debug']) {
    Remove-Item -Force -Recurse "$WorkingDir"
}