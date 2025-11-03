#Requires -Version 5.1

<#
.SYNOPSIS
    Build MSI package based on yaml config.

.DESCRIPTION
    Build MSI package based on yaml config.

.PARAMETER Config
    The yaml config file. (required)

.PARAMETER Output
    The output MSI package file. (required)

.PARAMETER TemplateFile
    The template file used by WiX as source file. Will use the default one if not provided. (optional)

.PARAMETER WorkingDir
    The directory to store the temporary files. (optional)
#>

    [CmdletBinding()]
param (
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$Output,
    [string]$TemplateFile = "$PSScriptRoot\template.wxs",
    [string]$WorkingDir = $( Join-Path $env:TEMP "~wixc" )
)

Set-PSDebug -Trace 0
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function SignCode
{
    param
    (
        [Parameter(Mandatory)][string[]]$File,
        [Parameter(Mandatory)][string]$CertFile,
        [Parameter(Mandatory)][string]$CertPassword,
        [bool]$Replace,
        [string]$Description
    )

    if (-not $Replace)
    {
        $cert = Get-AuthenticodeSignature -FilePath $File
        if ($cert.status -eq 'Valid')
        {
            return
        }
    }

    $timeStampServers = @(
        "http://time.certum.pl",
        "http://timestamp.digicert.com",
        "http://timestamp.comodoca.com/authenticode"
    )
    $retryTime = 2

    :finish foreach ($server in $timeStampServers)
    {
        for ($i = 0; $i -lt $retryTime; $i++)
        {
            if ($Description)
            {
                signtool sign /f "$CertFile" /p $CertPassword /t $server /d "$Description" "$File"
            }
            else
            {
                signtool sign /f "$CertFile" /p $CertPassword /t $server "$File"
            }

            if (-not$?)
            {
                throw "Sign file failed: $File"
            }
            else
            {
                break finish
            }
        }
    }
}

function AddOrUpdateList([Hashtable]$MyList, [String]$MyKey, [String]$MyValue)
{
    if ($MyList.ContainsKey($MyKey))
    {
        $MyList[$MyKey] = $MyValue
    }
    else
    {
        $MyList.Add($MyKey, $ValMyValueue)
    }
}

$Env:PATH = "$PSScriptRoot;$PSScriptRoot\WiX-v3.11\bin;" + $Env:PATH
Import-Module $PSScriptRoot\powershell-yaml

New-Item -ItemType Directory -Force -Path "$WorkingDir"

$ConfigYaml = (Get-Content $Config -Encoding UTF8 | ConvertFrom-Yaml)

$VarsList = @{ }
$VarsList.Add("ProductName", $ConfigYaml.Product.Name)
$VarsList.Add("ProductVersion", $ConfigYaml.Product.Version)
$VarsList.Add("UpgradeCode", $ConfigYaml.UpgradeCode)
$VarsList.Add("Manufacturer", $ConfigYaml.Manufacturer)
$VarsList.Add("MainExecutable", $ConfigYaml.Files.MainExecutable)

if ([string]::IsNullOrEmpty($ConfigYaml.Files.MainExecutableArguments))
{
    $VarsList.Add("MainExecutableArgumentsTxt", " ")
}
else
{
    $VarsList.Add("MainExecutableArgumentsTxt", "Arguments='" + $ConfigYaml.Files.MainExecutableArguments + "'")
}

$VarsList.Add("IconFile", $ConfigYaml.Files.Icon.File)
$VarsList.Add("IconIndex",$ConfigYaml.Files.Icon.Index.ToString())
$IconExt = $ConfigYaml.Files.Icon.File.split('.')[-1]
$VarsList.Add("IconId", "icon." + $IconExt)

if ($ConfigYaml.TemplateExtraConfig)
{
    $VarsList.Add("TemplateExtraConfig", $ConfigYaml.TemplateExtraConfig)
}
else
{
    $VarsList.Add("TemplateExtraConfig", "<!-- No extra config -->")
}

# check arch
if ($ConfigYaml.arch -eq 'x86')
{
    $VarsList.Add("ProgramFilesFolder", "ProgramFilesFolder")
    $VarsList.Add("SystemFolder", "SystemFolder")
}
else
{
    if ($ConfigYaml.arch -eq 'x64')
    {
        $VarsList.Add("ProgramFilesFolder", "ProgramFiles64Folder")
        $VarsList.Add("SystemFolder", "System64Folder")
    }
    else
    {
        throw "arch '$ConfigYaml.arch' is invalid!"
    }
}

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
$KillProcessParams = "/IM " + (Split-Path $VarsList.MainExecutable -leaf)
if ($ConfigYaml.KillAdditionalProcesses)
{
    foreach ($OneProcess in $ConfigYaml.KillAdditionalProcesses)
    {
        $KillProcessParams = $KillProcessParams + " /IM " + $OneProcess
    }
}
$VarsList.Add("KillProcessParams", $KillProcessParams)

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

    $VarsList.Add("LaunchApplicationText", "<Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT' Value='`${LocLaunch} `${ProductNameLoc}' />")

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
    $VarsList.Add("LaunchApplicationText", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT' Value='`${LocLaunch} `${ProductNameLoc}' /> -->")

}

# Auto start
if ($ConfigYaml.AutoStart)
{
    $VarsList.Add("AutoStart", "<RegistryValue Root='HKMU' Key='Software\Microsoft\Windows\CurrentVersion\Run' Name='`${ProductNameLoc}' Type='string' Value='[ProgramMenuDir]`${ProductNameLoc}.lnk' KeyPath='no' />")
}
else
{
    $VarsList.Add("AutoStart", "<!-- Auto start is disabled -->")
}

# Generate file group
if ($ConfigYaml.Files.RootFolder -and ($ConfigYaml.Files.RootFolder -ne ''))
{
    $FileRootfolder = Resolve-Path -LiteralPath "$($ConfigYaml.Files.RootFolder)"
    $FileRootfolder = $FileRootfolder -replace '\\$', ''

    # Sign code
    if ($ConfigYaml.CodeSign.CertFile -and $ConfigYaml.CodeSign.CertPassword -and $ConfigYaml.CodeSign.fileFilters)
    {
        echo "Start to sign code..."
        $files = @()
        foreach ($OneFilter in $ConfigYaml.CodeSign.fileFilters)
        {
            $files += Get-ChildItem -Path $FileRootfolder -Recurse -Filter $OneFilter | %{$_.FullName}
        }

        $Replace = $False
        if ($null -ne $ConfigYaml.CodeSign.Replace)
        {
            $Replace = $ConfigYaml.CodeSign.Replace
        }

        foreach ($file in $Files)
        {
            SignCode -File "$file" -CertFile $ConfigYaml.CodeSign.CertFile -CertPassword $ConfigYaml.CodeSign.CertPassword -Replace $Replace
        }
    }

    heat dir "$FileRootfolder" -cg FileGroup -dr APPLICATIONFOLDER -gg -srd -out "$WorkingDir\FileGroup.wxs"
    if (-not$?)
    {
        throw 'Native Failure'
    }

    $VarsList.Add("FileGroup", "<ComponentGroupRef Id='FileGroup' />")

    $FileGroupFileName = "FileGroup.wxs"
    $FileGroupObjFileName = "FileGroup.wixobj"
}
else
{
    $VarsList.Add("FileGroup", "<!-- <ComponentGroupRef Id='FileGroup' /> -->")
    $FileRootfolder= "."
    $FileGroupFileName = ""
    $FileGroupObjFileName = ""
}

# Generate reg group
if ($ConfigYaml.Regs.RootFolder -and ($ConfigYaml.Regs.RootFolder -ne ''))
{
    Write-Output "Windows Registry Editor Version 5.00" | Out-File "$WorkingDir\combined.reg"
    $RegRootfolder = $ConfigYaml.Regs.RootFolder -replace '\\$', ''
    Get-ChildItem -Path "$RegRootfolder" -Include *.reg -Recurse | ForEach-Object { Get-Content $_ | Select-Object -Skip 1 } | Out-File -FilePath "$WorkingDir\combined.reg" -Append
    heat reg "$WorkingDir\combined.reg" -cg RegGroup -gg -out "$WorkingDir\RegGroup.wxs"
    if (-not$?)
    {
        throw 'Native Failure'
    }

    if ($ConfigYaml.Regs.ConvertToHkMU)
    {
        (Get-Content "$WorkingDir\RegGroup.wxs").replace('Root="HKCU"', 'Root="HKMU"').replace('Root="HKLM"', 'Root="HKMU"').replace('SOFTWARE\WOW6432Node\', 'SOFTWARE\') | Out-File "$WorkingDir\RegGroup.wxs" -Encoding utf8
    }

    $VarsList.Add("RegGroup", "<ComponentGroupRef Id='RegGroup' />")

    $RegGroupFileName = "RegGroup.wxs"
    $RegGroupObjFileName = "RegGroup.wixobj"
}
else
{
    $VarsList.Add("RegGroup", "<!-- <ComponentGroupRef Id='RegGroup' /> -->")
    $RegGroupFileName = ""
    $RegGroupObjFileName = ""
}

# Generate env group
if ($ConfigYaml.Envs -and ($ConfigYaml.Envs.Count -gt 0))
{
    $c = @"
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Fragment>
    <ComponentGroup Id="EnvGroup">
"@
    $c | Out-File "$WorkingDir\EnvGroup.wxs" -Encoding utf8

    for ($i = 0; $i -lt $ConfigYaml.Envs.Count; $i++)
    {
        $Guid = [guid]::NewGuid().ToString()
        $c = @"
      <Component Id="Env_$i" Directory="TARGETDIR" Guid="$Guid" KeyPath="yes">
        <Environment Id="Env_$i" Name="$($ConfigYaml.Envs[$i].Name)" Action="$($ConfigYaml.Envs[$i].Action)"
        Permanent="$($ConfigYaml.Envs[$i].Permanent)" System="$($ConfigYaml.Envs[$i].System)"
        Part="$($ConfigYaml.Envs[$i].Part)" Value="$($ConfigYaml.Envs[$i].Value)" />
      </Component>
"@
        $c | Out-File "$WorkingDir\EnvGroup.wxs" -Append -Encoding utf8
    }

    $c = @"
    </ComponentGroup>
  </Fragment>
</Wix>
"@
    $c | Out-File "$WorkingDir\EnvGroup.wxs" -Append -Encoding utf8

    $VarsList.Add("EnvGroup", "<ComponentGroupRef Id='EnvGroup' />")

    $EnvGroupFileName = "EnvGroup.wxs"
    $EnvGroupObjFileName = "EnvGroup.wixobj"
}
else
{
    $VarsList.Add("EnvGroup", "<!-- <ComponentGroupRef Id='EnvGroup' /> -->")
    $EnvGroupFileName = ""
    $EnvGroupObjFileName = ""
}

# Generate extra groups
if ($ConfigYaml.ExtraSourceFiles)
{
    $ExtraGroups = ""
    $ExtraGroupFileNames = ""
    $ExtraGroupObjFileNames = ""
    foreach ($OneExtraFilePath in $ConfigYaml.ExtraSourceFiles)
    {
        [string]$ExtraFileContent = Get-Content -Path "$OneExtraFilePath" -Encoding UTF8
        if ($ExtraFileContent -match "<ComponentGroup Id=[`"'](.+?)[`"']>")
        {
            $ComponentGroupId = $matches[1]
        }
        else
        {
            throw "File $OneExtraFilePath doesn't have ComponentGroup!"
        }

        $ExtraGroups = $ExtraGroups + "<ComponentGroupRef Id='$ComponentGroupId'/>`n"

        $OneExtraFileName = [System.IO.Path]::GetFileName($OneExtraFilePath)
        $ExtraGroupFileNames = $ExtraGroupFileNames + "'" + $OneExtraFileName + "' "
        $ExtraGroupObjFileNames = $ExtraGroupObjFileNames + "'" + [System.IO.Path]::GetFileNameWithoutExtension($OneExtraFileName) + ".wixobj' "
    }
    $VarsList.Add("ExtraGroups", $ExtraGroups)
}
else
{
    $VarsList.Add("ExtraGroups", "<!-- No extra groups -->")
}

# Localiztion
$CultureLanguage = [ordered]@{ }
$localizations = (Get-Content $PSScriptRoot\i18n\localizations.yaml -Encoding UTF8 | ConvertFrom-Yaml)
foreach ($OneLoc in $ConfigYaml.Localization)
{
    foreach ($k in $OneLoc.Keys)
    {
        if ( $VarsList.ContainsKey($k))
        {
            $VarsList.$k = $OneLoc.$k
        }
        else
        {
            $VarsList.Add($k, $OneLoc.$k)
        }
    }

    foreach ($k in $localizations[$VarsList.Culture].Keys)
    {
        if ( $VarsList.ContainsKey($k))
        {
            $VarsList.$k = $localizations[$VarsList.Culture].$k
        }
        else
        {
            $VarsList.Add($k, $localizations[$VarsList.Culture].$k)
        }
    }

    # make sure all vars are not empty
    foreach ($k in $VarsList.Keys)
    {
        if ($VarsList.$k -eq "")
        {
            throw "$k is empty!"
        }
        Remove-Variable -Name "$k" -ErrorAction SilentlyContinue
        New-Variable -Name "$k" -Value $($VarsList.$k)
    }

    $CultureLanguage.Add($VarsList.Culture, $VarsList.Language)

    # Substitude all variables in template file
    [string]$Template = Get-Content -Path "$TemplateFile" -Encoding UTF8
    $maxIterations = 5  # Prevent infinite loops
    $iteration = 0
    while ($Template.Contains("`${") -and $iteration -lt $maxIterations) {
        $iteration++

        foreach ($k in $VarsList.Keys)
        {
            $Template = $Template.Replace("`$`{$k`}", $VarsList.$k)
        }
    }

    if ($iteration -ge $maxIterations) {
        # Detect unresolved variables
        $unresolvedVars = [regex]::Matches($Template, '\$\{(.+?)\}') | ForEach-Object { $_.Groups[1].Value }
        throw "The following variables were not resolved: $($unresolvedVars -join ', ')"
    }

    # Substitude all guid in template file
    $Count = ([regex]::Matches($Template, "Guid=''")).count
    for($i = 1; $i -le $Count; $i++) {
        $Guid = [guid]::NewGuid().ToString()
        [regex]$Pattern = "Guid=''"
        $Template = $Pattern.replace($Template, "Guid='$Guid'", 1)
    }

    # Remove AllowSameVersionUpgrades & DowngradeErrorMessage if AllowDowngrades
    if ($ConfigYaml.Upgrade.AllowDowngrades) {
        [regex]$Pattern = "AllowSameVersionUpgrades=['`"].*?['`"]"
        $Template = $Pattern.replace($Template, "", 1)

        [regex]$Pattern = "DowngradeErrorMessage=['`"].*?['`"]"
        $Template = $Pattern.replace($Template, "", 1)
    }

    $MainFileName = $VarsList.Culture + '.wsx'
    Out-File -InputObject $Template -FilePath "$WorkingDir\$MainFileName" -Encoding utf8 -Force

    foreach ($OneExtraFilePath in $ConfigYaml.ExtraSourceFiles)
    {
        # Substitude all variables in extra group file
        [string]$Extra = Get-Content -Path "$OneExtraFilePath" -Encoding UTF8
        while ($Extra.Contains("`${"))
        {
            foreach ($k in $VarsList.Keys)
            {
                $Extra = $Extra.Replace("`$`{$k`}", $VarsList.$k)
            }
        }

        # Substitude all guid in extra group file
        $Count = ([regex]::Matches($Extra, "Guid=''")).count
        for($i = 1; $i -le $Count; $i++) {
            $Guid = [guid]::NewGuid().ToString()
            [regex]$Pattern = "Guid=''"
            $Extra = $Pattern.replace($Extra, "Guid='$Guid'", 1)
        }

        $OneExtraFileName = [System.IO.Path]::GetFileName($OneExtraFilePath)
        Out-File -InputObject $Extra -FilePath "$WorkingDir\$OneExtraFileName" -Encoding utf8 -Force
    }

    Push-Location
    Set-Location "$WorkingDir"
    $arch = $ConfigYaml.arch
    $Command = "candle -arch $arch $MainFileName $FileGroupFileName $RegGroupFileName $EnvGroupFileName $ExtraGroupFileNames"
    Write-Host $Command
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0)
    {
        throw 'Invoke-Expression Failure'
    }

    $ClutersParameter = '-cultures:' + $VarsList.Culture
    $MsiName = $VarsList.Culture + '.msi'
    $MainObjName = $VarsList.Culture + '.wixobj'

    $LightParams = ''
    if ($ConfigYaml.LightParams)
    {
        $LightParams = $ConfigYaml.LightParams
    }

    $Command = "light -ext WixUIExtension -ext WiXUtilExtension $LightParams $ClutersParameter -b `"$FileRootfolder`" -o $MsiName $MainObjName $FileGroupObjFileName $RegGroupObjFileName $EnvGroupObjFileName $ExtraGroupObjFileNames"
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0)
    {
        throw 'Invoke-Expression Failure'
    }
    Pop-Location
}

$FirstCulture = ""
if (([Hashtable]$CultureLanguage).Count -gt 1)
{
    foreach ($k in $CultureLanguage.Keys)
    {
        if ($FirstCulture -eq "")
        {
            $FirstCulture = $k
        }
        else
        {
            $CurrentCulture = $k
            torch -t language "$WorkingDir\${FirstCulture}`.msi" "$WorkingDir\${CurrentCulture}`.msi" -out "$WorkingDir\${CurrentCulture}`.mst"
            if (-not$?)
            {
                throw 'Native Failure'
            }
            cscript $PSScriptRoot\i18n\WiSubStg.vbs "$WorkingDir\${FirstCulture}`.msi" "$WorkingDir\${CurrentCulture}`.mst" $CultureLanguage.$k
            if (-not$?)
            {
                throw 'Native Failure'
            }
        }
    }

    $Languages = [Array]$CultureLanguage.Values -join ','
    cscript $PSScriptRoot\i18n\WiLangId.vbs "$WorkingDir\${FirstCulture}`.msi" Package $Languages
    if (-not$?)
    {
        throw 'Native Failure'
    }
}
else
{
    $FirstCulture = $CultureLanguage.Keys[0]
}

if (-not $Output.Contains('\'))
{
    $Output = ".\" + $Output
}

if ($ConfigYaml.CodeSign.CertFile -and $ConfigYaml.CodeSign.CertPassword -and $ConfigYaml.CodeSign.fileFilters)
{
    Write-Host "Sign msi file..."
    SignCode -File "$WorkingDir\$FirstCulture`.msi" -CertFile $ConfigYaml.CodeSign.CertFile -CertPassword $ConfigYaml.CodeSign.CertPassword -Replace $True -Description $ConfigYaml.Product.Name
}

Move-Item -Force "$WorkingDir\$FirstCulture`.msi" "$Output"
Write-Output "MSI package generated at: $Output"

if (-not$PSBoundParameters['Debug'])
{
    Remove-Item -Force -Recurse "$WorkingDir"
}