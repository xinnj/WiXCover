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
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$CertFile,
        [string]$CertPassword,
        [string]$Csp,
        [string]$Kc,
        [bool]$Replace,
        [string]$Description
    )

    $File = [System.Environment]::ExpandEnvironmentVariables($File)
    $CertFile = [System.Environment]::ExpandEnvironmentVariables($CertFile)
    if ($CertPassword) { $CertPassword = [System.Environment]::ExpandEnvironmentVariables($CertPassword) }
    if ($Csp) { $Csp = [System.Environment]::ExpandEnvironmentVariables($Csp) }
    if ($Kc) { $Kc = [System.Environment]::ExpandEnvironmentVariables($Kc) }
    if ($Description) { $Description = [System.Environment]::ExpandEnvironmentVariables($Description) }

    $timeStampServers = @(
        "http://time.certum.pl",
        "http://timestamp.digicert.com"
    )
    
    $signtoolPath = "$PSScriptRoot\signtool.exe"

    $signArgs = @(
        "sign",
        "/f", $CertFile,
        "/td", "sha256",
        "/fd", "sha256"
    )
    
    if ($CertPassword) { $signArgs += @("/p", $CertPassword) }
    if ($Description) { $signArgs += @("/d", $Description) }
    if ($Csp) { $signArgs += @("/csp", $Csp) }
    if ($Kc) { $signArgs += @("/kc", $Kc) }

    if (-not $Replace)
    {
        try {
            $cert = Get-AuthenticodeSignature -FilePath $File
            if ($cert.Status -eq 'Valid')
            {
                Write-Host "File already signed, skipping: $File"
                return
            }
        }
        catch {
            Write-Warning "Failed to check signature status for: $File"
        }
    }

    $signSuccess = $false
    foreach ($server in $timeStampServers)
    {
        $currentArgs = $signArgs + @("/tr", $server, $File)
        for ($attempt = 0; $attempt -lt 2; $attempt++)
        {
            try
            {
                & $signtoolPath @currentArgs

                if ($LASTEXITCODE -eq 0)
                {
                    $signSuccess = $true
                    break
                }
                else
                {
                    Write-Warning "Signing failed (exit code: $LASTEXITCODE) for file: $File with server: $server"
                }
            }
            catch
            {
                Write-Warning "Signing attempt failed: $($_.Exception.Message)"
            }

            if ($attempt -lt 1) { Start-Sleep -Seconds 1 }
        }

        if ($signSuccess) { break }
    }

    if (-not $signSuccess)
    {
        throw "Failed to sign file after all attempts: $File"
    }
}

function AddOrUpdateList([Hashtable]$MyList, [String]$MyKey, [String]$MyValue)
{
    if ( $MyList.ContainsKey($MyKey))
    {
        $MyList[$MyKey] = $MyValue
    }
    else
    {
        $MyList.Add($MyKey, $MyValue)
    }
}

$Env:PATH = "$PSScriptRoot;$PSScriptRoot\WiX-v3.14.1\bin;" + $Env:PATH
Import-Module $PSScriptRoot\powershell-yaml

New-Item -ItemType Directory -Force -Path "$WorkingDir"

$ConfigYaml = (Get-Content $Config -Encoding UTF8 | ConvertFrom-Yaml)

$VarsList = @{ }
$VarsList.Add("ProductName", $ConfigYaml.Product.Name)
$VarsList.Add("ProductVersion", $ConfigYaml.Product.Version)
$VarsList.Add("UpgradeCode", $ConfigYaml.UpgradeCode)
$VarsList.Add("Manufacturer", $ConfigYaml.Manufacturer)
$VarsList.Add("MainExecutable", $ConfigYaml.Files.MainExecutable)

if ( [string]::IsNullOrEmpty($ConfigYaml.Files.MainExecutableArguments))
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

    $LaunchApplicationText = '${LocLaunch} ${ProductNameLoc}'
    if ($ConfigYaml.Localization[0].LaunchApplicationText -and ($ConfigYaml.Localization[0].LaunchApplicationText -ne ''))
    {
        $LaunchApplicationText = '${LaunchApplicationText}'
    }
    $VarsList.Add("LaunchApplicationTextProperty", "<Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT' Value='${LaunchApplicationText}' />")

    if ($ConfigYaml.LaunchApplication.CheckedByDefault)
    {
        $VarsList.Add("LaunchApplicationChecked", "<Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' />")
    }
    else
    {
        $VarsList.Add("LaunchApplicationChecked", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' /> -->")
    }

    $LaunchApplicationTarget = '[ProgramMenuFolder]${ProductNameLoc}\${ProductNameLoc}.lnk'
    if ($ConfigYaml.LaunchApplication.ExecTarget -and ($ConfigYaml.LaunchApplication.ExecTarget -ne ''))
    {
        $LaunchApplicationTarget = $ConfigYaml.LaunchApplication.ExecTarget
        if ($LaunchApplicationTarget -match '\s')
        {
            throw "LaunchApplication.ExecTarget can not contain whitespace (space, tab, etc.)"
        }
    }
    $VarsList.Add("LaunchApplicationTargetProperty", "<Property Id='WixShellExecTarget' Value='${LaunchApplicationTarget}' />")
    $VarsList.Add("LaunchApplicationCustomAction", "<CustomAction Id='LaunchApplication' BinaryKey='WixCA' DllEntry='WixShellExec' Impersonate='yes' />")
}
else
{
    $VarsList.Add("LaunchApplication", "<!-- <Publish Dialog='ExitDialog' Control='Finish' Event='DoAction' Value='LaunchApplication'>WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed</Publish> -->")
    $VarsList.Add("LaunchApplicationChecked", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOX' Value='1' /> -->")
    $VarsList.Add("LaunchApplicationTextProperty", "<!-- <Property Id='WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT' Value='' /> -->")
    $VarsList.Add("LaunchApplicationTargetProperty", "<!-- <Property Id='WixShellExecTarget' Value='' /> -->")
    $VarsList.Add("LaunchApplicationCustomAction", "<!-- <CustomAction Id='LaunchApplication' BinaryKey='WixCA' DllEntry='WixShellExec' Impersonate='yes' /> -->")

}

# Auto start
if ($ConfigYaml.AutoStart)
{
    $MainExecutable = $VarsList.MainExecutable
    if ( [string]::IsNullOrEmpty($ConfigYaml.Files.MainExecutableArguments))
    {
        $VarsList.Add("AutoStart", "<RegistryValue Root='HKMU' Key='Software\Microsoft\Windows\CurrentVersion\Run' Name='`${ProductNameLoc}' Type='string' Value='[APPLICATIONFOLDER]${MainExecutable}' KeyPath='no' />")
    }
    else
    {
        $MainExecutableArguments = $ConfigYaml.Files.MainExecutableArguments
        $VarsList.Add("AutoStart", "<RegistryValue Root='HKMU' Key='Software\Microsoft\Windows\CurrentVersion\Run' Name='`${ProductNameLoc}' Type='string' Value='`"[APPLICATIONFOLDER]${MainExecutable}`" ${MainExecutableArguments}' KeyPath='no' />")
    }
}
else
{
    $VarsList.Add("AutoStart", "<!-- Auto start is disabled -->")
}

# Generate file group
$FirewallExt = ""
if ($ConfigYaml.Files.RootFolder -and ($ConfigYaml.Files.RootFolder -ne ''))
{
    $FileRootfolder = Resolve-Path -LiteralPath "$( $ConfigYaml.Files.RootFolder )"
    $FileRootfolder = $FileRootfolder -replace '\\$', ''

        # Sign code
        if ($ConfigYaml.CodeSign.CertFile -and $ConfigYaml.CodeSign.fileFilters)
        {
            Write-Host "Start to sign code..."
            
            $files = @()
            foreach ($OneFilter in $ConfigYaml.CodeSign.fileFilters)
            {
                $files += Get-ChildItem -Path $FileRootfolder -Recurse -Filter $OneFilter | ForEach-Object { $_.FullName }
            }

            $Replace = $False
            if ($null -ne $ConfigYaml.CodeSign.Replace)
            {
                $Replace = $ConfigYaml.CodeSign.Replace
            }

            if ($files.Count -gt 0)
            {
                foreach ($file in $files)
                {
                    SignCode -File $file -CertFile $ConfigYaml.CodeSign.CertFile -CertPassword $ConfigYaml.CodeSign.CertPassword -Csp $ConfigYaml.CodeSign.Csp -Kc $ConfigYaml.CodeSign.Kc -Replace $Replace -Description $ConfigYaml.CodeSign.Description
                }
            }
            else
            {
                Write-Warning "No files found to sign with the specified filters"
            }
        }

    heat dir "$FileRootfolder" -cg FileGroup -dr APPLICATIONFOLDER -gg -srd -out "$WorkingDir\FileGroup.wxs"
    if (-not $?)
    {
        throw 'Native Failure'
    }

    $VarsList.Add("FileGroup", "<ComponentGroupRef Id='FileGroup' />")

    $FileGroupFileName = "FileGroup.wxs"
    $FileGroupObjFileName = "FileGroup.wixobj"

    if ($ConfigYaml.FirewallException)
    {
        # Read file as single string, build insertion with here-string to avoid quoting issues
        $content = Get-Content "$WorkingDir\FileGroup.wxs" -Raw

        foreach ($fe in $ConfigYaml.FirewallException)
        {
            if ($fe.File -and ($fe.File -ne ''))
            {
                $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($fe.File)
                $ID = "FirewallException_" + $nameWithoutExt

                $Profile = "Profile='all'"
                if ($fe.Profile -and ($fe.Profile -ne ''))
                {
                    $Profile = "Profile='$( $fe.Profile )'"
                }

                $Scope = "Scope='any'"
                if ($fe.Scope -and ($fe.Scope -ne ''))
                {
                    $Scope = "Scope='$( $fe.Scope )'"
                }

                $RemoteAddress = ''
                if ($fe.RemoteAddress)
                {
                    $Scope = ''
                    foreach ($addr in $fe.RemoteAddress)
                    {
                        $RemoteAddress = $RemoteAddress + " <fire:RemoteAddress>$addr</fire:RemoteAddress>"
                    }
                }

                $Port = ''
                if ($fe.Port -and ($fe.Port -ne ''))
                {
                    $Port = "Port='$( $fe.Port )'"
                }

                $Protocol = ''
                if ($fe.Protocol -and ($fe.Protocol -ne ''))
                {
                    $Protocol = "Protocol='$( $fe.Protocol )'"
                }

                $pattern = "(\s*)<File Id=`"(.+?)`" .* Source=`".*$( $fe.File )`" />"
                foreach ($line in $content -split "`r?`n")
                {
                    if ($line -match $pattern)
                    {
                        $leadingSpaces = $matches[1]
                        $fileId = $matches[2]
                        $insert = @"
$line
$leadingSpaces<fire:FirewallException Id="$ID" Name="$nameWithoutExt" Program="[#$fileId]" $Profile $Scope $Port $Protocol>
$leadingSpaces$RemoteAddress
$leadingSpaces</fire:FirewallException>
"@
                        $content = $content.Replace($line, $insert)
                    }
                }
            }
        }

        $content = $content.Replace('<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">', '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi" xmlns:fire="http://schemas.microsoft.com/wix/FirewallExtension">')
        Set-Content -Path "$WorkingDir\FileGroup.wxs" -Value $content -Encoding utf8

        $FirewallExt = "-ext WixFirewallExtension"
    }
}
else
{
    $VarsList.Add("FileGroup", "<!-- <ComponentGroupRef Id='FileGroup' /> -->")
    $FileRootfolder = "."
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
    if (-not $?)
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
        <Environment Id="Env_$i" Name="$( $ConfigYaml.Envs[$i].Name )" Action="$( $ConfigYaml.Envs[$i].Action )"
        Permanent="$( $ConfigYaml.Envs[$i].Permanent )" System="$( $ConfigYaml.Envs[$i].System )"
        Part="$( $ConfigYaml.Envs[$i].Part )" Value="$( $ConfigYaml.Envs[$i].Value )" />
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

# Handle extra wxs files. Generate extra groups or include fragments
$ExtraWxsFileNames = ""
$ExtraObjFileNames = ""
$ExtraGroups = ""
if ($ConfigYaml.ExtraSourceFiles)
{
    foreach ($OneFilePath in $ConfigYaml.ExtraSourceFiles)
    {
        [string]$ExtraFileContent = Get-Content -Path "$OneFilePath" -Encoding UTF8
        if ($ExtraFileContent -match "<ComponentGroup Id=[`"'](.+?)[`"']>")
        {
            $ComponentGroupId = $matches[1]
            $ExtraGroups = $ExtraGroups + "<ComponentGroupRef Id='$ComponentGroupId'/>`n"
        }

        $OneFileName = [System.IO.Path]::GetFileName($OneFilePath)
        $ExtraWxsFileNames = $ExtraWxsFileNames + "'" + $OneFileName + "' "
        $ExtraObjFileNames = $ExtraObjFileNames + "'" + [System.IO.Path]::GetFileNameWithoutExtension($OneFileName) + ".wixobj' "
    }
}
if ($ExtraGroups)
{
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
        New-Variable -Name "$k" -Value $( $VarsList.$k )
    }

    $CultureLanguage.Add($VarsList.Culture, $VarsList.Language)

    # Substitude all variables in template file
    [string]$Template = Get-Content -Path "$TemplateFile" -Encoding UTF8
    $maxIterations = 5  # Prevent infinite loops
    $iteration = 0
    while ($Template.Contains("`${") -and $iteration -lt $maxIterations)
    {
        $iteration++

        foreach ($k in $VarsList.Keys)
        {
            $Template = $Template.Replace("`$`{$k`}", $VarsList.$k)
        }
    }

    if ($iteration -ge $maxIterations)
    {
        # Detect unresolved variables
        $unresolvedVars = [regex]::Matches($Template, '\$\{(.+?)\}') | ForEach-Object { $_.Groups[1].Value }
        throw "The following variables were not resolved: $( $unresolvedVars -join ', ' )"
    }

    # Substitude all guid in template file
    $Count = ([regex]::Matches($Template, "Guid=''")).count
    for($i = 1; $i -le $Count; $i++) {
        $Guid = [guid]::NewGuid().ToString()
        [regex]$Pattern = "Guid=''"
        $Template = $Pattern.replace($Template, "Guid='$Guid'", 1)
    }

    # Remove AllowSameVersionUpgrades & DowngradeErrorMessage if AllowDowngrades
    if ($ConfigYaml.Upgrade.AllowDowngrades)
    {
        [regex]$Pattern = "AllowSameVersionUpgrades=['`"].*?['`"]"
        $Template = $Pattern.replace($Template, "", 1)

        [regex]$Pattern = "DowngradeErrorMessage=['`"].*?['`"]"
        $Template = $Pattern.replace($Template, "", 1)
    }

    $MainFileName = $VarsList.Culture + '.wsx'
    Out-File -InputObject $Template -FilePath "$WorkingDir\$MainFileName" -Encoding utf8 -Force

    foreach ($OneFilePath in $ConfigYaml.ExtraSourceFiles)
    {
        # Substitude all variables in extra group file
        [string]$Extra = Get-Content -Path "$OneFilePath" -Encoding UTF8
        while ( $Extra.Contains("`${"))
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

        $OneFileName = [System.IO.Path]::GetFileName($OneFilePath)
        Out-File -InputObject $Extra -FilePath "$WorkingDir\$OneFileName" -Encoding utf8 -Force
    }

    Push-Location
    Set-Location "$WorkingDir"
    $arch = $ConfigYaml.arch
    $Command = "candle -ext WiXUtilExtension $FirewallExt -arch $arch $MainFileName $FileGroupFileName $RegGroupFileName $EnvGroupFileName $ExtraWxsFileNames"
    Write-Host $Command
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0)
    {
        throw "Candle compilation failed with exit code: $LASTEXITCODE"
    }

    $Culture = $VarsList.Culture
    if ($Culture -ne 'en-us')
    {
        $Culture = $Culture + ';en-us'
    }
    $ClutersParameter = "-cultures:'" + $Culture + "'"

    $MsiName = $VarsList.Culture + '.msi'
    $MainObjName = $VarsList.Culture + '.wixobj'

    $LightParams = ''
    if ($ConfigYaml.LightParams)
    {
        $LightParams = $ConfigYaml.LightParams
    }

    $Command = "light -ext WixUIExtension -ext WiXUtilExtension $FirewallExt $LightParams $ClutersParameter -b `"$FileRootfolder`" -o $MsiName $MainObjName $FileGroupObjFileName $RegGroupObjFileName $EnvGroupObjFileName $ExtraObjFileNames"
    Write-Host $Command
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0)
    {
        throw "Light linking failed with exit code: $LASTEXITCODE"
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
            if (-not $?)
            {
                throw 'Native Failure'
            }
            cscript $PSScriptRoot\i18n\WiSubStg.vbs "$WorkingDir\${FirstCulture}`.msi" "$WorkingDir\${CurrentCulture}`.mst" $CultureLanguage.$k
            if (-not $?)
            {
                throw 'Native Failure'
            }
        }
    }

    $Languages = [Array]$CultureLanguage.Values -join ','
    cscript $PSScriptRoot\i18n\WiLangId.vbs "$WorkingDir\${FirstCulture}`.msi" Package $Languages
    if (-not $?)
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

if ($ConfigYaml.CodeSign.CertFile)
{
    Write-Host "Sign msi file..."
    SignCode -File "$WorkingDir\$FirstCulture`.msi" -CertFile $ConfigYaml.CodeSign.CertFile -CertPassword $ConfigYaml.CodeSign.CertPassword -Csp $ConfigYaml.CodeSign.Csp -Kc $ConfigYaml.CodeSign.Kc -Replace $True -Description $ConfigYaml.CodeSign.Description
}

Move-Item -Force "$WorkingDir\$FirstCulture`.msi" "$Output"
Write-Output "MSI package generated at: $Output"

if (-not $PSBoundParameters['Debug'])
{
    Remove-Item -Force -Recurse "$WorkingDir"
}