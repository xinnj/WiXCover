# todo: set working dir
# todo: check wix installed
# todo: config file congiguable

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

Import-Module powershell-yaml

$WorkingDir = @(Get-Location).Path
New-Item -ItemType Directory -Force -Path "$WorkingDir"

$config = (Get-Content .\config.yaml -Encoding UTF8 | ConvertFrom-Yaml)

$VarsList = @{ }
$VarsList.Add("ProductName", $config.Product.Name)
$VarsList.Add("ProductVersion", $config.Product.Version)
$VarsList.Add("UpgradeCode", $config.UpgradeCode)
$VarsList.Add("Manufacturer", $config.Manufacturer)
$VarsList.Add("MainExecutable", $config.Files.MainExecutable)


$VarsList.Add("IconFile", $config.Files.Icon.File)
$VarsList.Add("IconIndex",$config.Files.Icon.Index.ToString())
$IconExt = $config.Files.Icon.File.split('.')[-1]
$VarsList.Add("IconId", "icon." + $IconExt)

if ($config.Upgrade.AllowDowngrades)
{
    $VarsList.Add("AllowDowngrades", "yes")
}
else
{
    $VarsList.Add("AllowDowngrades", "no")
}
if ($config.Upgrade.AllowSameVersionUpgrades)
{
    $VarsList.Add("AllowSameVersionUpgrades", "yes")
}
else
{
    $VarsList.Add("AllowSameVersionUpgrades", "no")
}

switch ($config.InstallScope.Mode)
{
    'both' {
        $VarsList.Add("WixUISupportPerUser", "1")
        $VarsList.Add("WixUISupportPerMachine", "1")
        switch ($config.InstallScope.DefaultMode)
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

if ($config.KillProcess)
{
    $VarsList.Add("KillProcess", "<Custom Action='KillProcess' Before='InstallValidate'/>")
}
else
{
    $VarsList.Add("KillProcess", "<!-- <Custom Action='KillProcess' Before='InstallValidate'/> -->")
}

if ($config.LaunchApplication.Enable)
{
    $VarsList.Add("LaunchApplication", "<Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish>")
    if ($config.LaunchApplication.CheckedByDefault)
    {
        $VarsList.Add("LaunchApplicationChecked", "1")
    }
    else
    {
        $VarsList.Add("LaunchApplicationChecked", "0")
    }
}
else
{
    $VarsList.Add("LaunchApplication", "<!-- <Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish> -->")
    $VarsList.Add("LaunchApplicationChecked", "0")
}

$folder = @($config.Files.RootFolder -replace '\\$', '')
heat dir "$folder" -cg FileGroup -dr APPLICATIONFOLDER -gg -srd -out "$WorkingDir\FileGroup.wxs"
ThrowOnNativeFailure

Write-Output "Windows Registry Editor Version 5.00" | Out-File "$WorkingDir\combined.reg"
$folder = @($config.Regs.RootFolder -replace '\\$', '')
Get-ChildItem -Path "$folder" -Include *.reg -Recurse | ForEach-Object { Get-Content $_ | Select-Object -Skip 1 } | Out-File -FilePath "$WorkingDir\combined.reg" -Append
heat reg "$WorkingDir\combined.reg" -cg RegGroup -gg -out "$WorkingDir\RegGroup.wxs"
ThrowOnNativeFailure
if ($config.Regs.ConvertToHkMU)
{
    (Get-Content "$WorkingDir\RegGroup.wxs").replace('Root="HKCU"', 'Root="HKMU"').replace('Root="HKLM"', 'Root="HKMU"').replace('SOFTWARE\WOW6432Node\', 'SOFTWARE\') | Out-File "$WorkingDir\RegGroup.wxs" -Encoding utf8
}

foreach ($OneLoc in $config.Localization)
{
    foreach ($k in $OneLoc.Keys) {
        if ($VarsList.ContainsKey($k)) {
            $VarsList.$k = $OneLoc.$k
        } else {
            $VarsList.Add($k, $OneLoc.$k)
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

    [string]$Template = Get-Content -Path "$PSScriptRoot\template.wxs" -Encoding UTF8
    foreach ($k in $VarsList.Keys) {
        $Template = $Template.Replace("`$`{$k`}", $VarsList.$k)
    }

    $Template > 2.wxs

}