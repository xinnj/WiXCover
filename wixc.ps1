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

#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser
#Install-Module powershell-yaml -Scope CurrentUser
Import-Module powershell-yaml

$WorkingDir = @(Get-Location).Path
New-Item -ItemType Directory -Force -Path "$WorkingDir"

$FinalMsiFile = 'final.msi'

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

# Upgrade method
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

# Install scope
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

# Kill process
if ($config.KillProcess)
{
    $VarsList.Add("KillProcess", "<Custom Action='KillProcess' Before='InstallValidate'/>")
}
else
{
    $VarsList.Add("KillProcess", "<!-- <Custom Action='KillProcess' Before='InstallValidate'/> -->")
}

# Launch app
if ($config.LaunchApplication.Enable)
{
    $VarsList.Add("LaunchApplication", "<Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish>")
    if ($config.LaunchApplication.CheckedByDefault)
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
$FileRootfolder = @($config.Files.RootFolder -replace '\\$', '')
heat dir "$FileRootfolder" -cg FileGroup -dr APPLICATIONFOLDER -gg -srd -out "$WorkingDir\FileGroup.wxs"
ThrowOnNativeFailure

# Generate reg group
Write-Output "Windows Registry Editor Version 5.00" | Out-File "$WorkingDir\combined.reg"
$RegRootfolder = @($config.Regs.RootFolder -replace '\\$', '')
Get-ChildItem -Path "$RegRootfolder" -Include *.reg -Recurse | ForEach-Object { Get-Content $_ | Select-Object -Skip 1 } | Out-File -FilePath "$WorkingDir\combined.reg" -Append
heat reg "$WorkingDir\combined.reg" -cg RegGroup -gg -out "$WorkingDir\RegGroup.wxs"
ThrowOnNativeFailure
if ($config.Regs.ConvertToHkMU)
{
    (Get-Content "$WorkingDir\RegGroup.wxs").replace('Root="HKCU"', 'Root="HKMU"').replace('Root="HKLM"', 'Root="HKMU"').replace('SOFTWARE\WOW6432Node\', 'SOFTWARE\') | Out-File "$WorkingDir\RegGroup.wxs" -Encoding utf8
}

# Localiztion
$CultureLanguage = [ordered]@{}
$localizations = (Get-Content $PSScriptRoot\localizations.yaml -Encoding UTF8 | ConvertFrom-Yaml)
foreach ($OneLoc in $config.Localization)
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
    [string]$Template = Get-Content -Path "$PSScriptRoot\template.wxs" -Encoding UTF8
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
    Out-File -InputObject $Template -FilePath $WorkingDir\$MainFileName -Encoding utf8 -Force

    candle $WorkingDir\$MainFileName $WorkingDir\FileGroup.wxs $WorkingDir\RegGroup.wxs
    ThrowOnNativeFailure

    $ClutersParameter = '-cultures:' + [string]@($VarsList.Culture)
    $MsiName = [string]@($VarsList.Culture) + '.msi'
    $MainObjName = [string]@($VarsList.Culture) + '.wixobj'
    light -ext WixUIExtension -ext WiXUtilExtension $ClutersParameter -b $FileRootfolder -o $WorkingDir\$MsiName $WorkingDir\$MainObjName $WorkingDir\FileGroup.wixobj $WorkingDir\RegGroup.wixobj
    ThrowOnNativeFailure
}

$FirstCulture = ""
if (([Hashtable]$CultureLanguage).Count -gt 1) {
    foreach ($k in $CultureLanguage.Keys) {
        if ($FirstCulture -eq "") {
            $FirstCulture = $k
        } else {
            $CurrentCulture = $k
            torch -t language ${FirstCulture}`.msi ${CurrentCulture}`.msi -out ${CurrentCulture}`.mst
            cscript $PSScriptRoot\WiSubStg.vbs ${FirstCulture}`.msi ${CurrentCulture}`.mst $CultureLanguage.$k
        }
    }

    $Languages = [Array]$CultureLanguage.Values -join ','
    cscript $PSScriptRoot\WiLangId.vbs ${FirstCulture}`.msi Package $Languages
} else {
    $FirstCulture = $CultureLanguage[0]
}

Move-Item -Force $WorkingDir\$FirstCulture`.msi $WorkingDir\$FinalMsiFile