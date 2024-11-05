#requires -version 5.0

<#
.SYNOPSIS
    Sign files with the certification
.DESCRIPTION

.PARAMETER Files
    The files to digitally sign.
.PARAMETER CertFile
    The pfx file.
.PARAMETER CertPassword
    Password of the certificate.
.PARAMETER Replace
    Replace the existing signature. (optional)
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory)][string[]]$Files,
    [Parameter(Mandatory)][string]$CertFile,
    [Parameter(Mandatory)][string]$CertPassword,
    [switch]$Replace
)

Set-PSDebug -Trace 0
Set-StrictMode -version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Verify-Sign
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][String]$File
    )

    begin
    {
        $signature = @"
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptQueryObject(
            int dwObjectType,
            [MarshalAs(UnmanagedType.LPWStr)]string pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            ref int pdwMsgAndCertEncodingType,
            ref int pdwContentType,
            ref int pdwFormatType,
            ref IntPtr phCertStore,
            ref IntPtr phMsg,
            ref IntPtr ppvContext
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            byte[] pvData,
            ref int pcbData
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptMsgClose(
            IntPtr hCryptMsg
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertCloseStore(
            IntPtr hCertStore,
            int dwFlags
        );
"@
        Add-Type -AssemblyName System.Security
        Add-Type -MemberDefinition $signature -Namespace PKI -Name Crypt32
    }

    process
    {
        Get-AuthenticodeSignature $File | ForEach-Object {
            $Output = $_
            if ($null -ne $Output.SignerCertificate)
            {
                $pdwMsgAndCertEncodingType = 0
                $pdwContentType = 0
                $pdwFormatType = 0
                [IntPtr]$phCertStore = [IntPtr]::Zero
                [IntPtr]$phMsg = [IntPtr]::Zero
                [IntPtr]$ppvContext = [IntPtr]::Zero
                [PKI.Crypt32]::CryptQueryObject(
                        1,
                        $_.Path,
                        16382,
                        14,
                        $null,
                        [ref]$pdwMsgAndCertEncodingType,
                        [ref]$pdwContentType,
                        [ref]$pdwFormatType,
                        [ref]$phCertStore,
                        [ref]$phMsg,
                        [ref]$ppvContext
                )

                $pcbData = 0
                [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $null, [ref]$pcbData)
                $pvData = New-Object byte[] -ArgumentList $pcbData
                [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $pvData, [ref]$pcbData)
                $SignedCms = New-Object Security.Cryptography.Pkcs.SignedCms
                $SignedCms.Decode($pvData)
                $sTime = $null
                foreach ($Infos in $SignedCms.SignerInfos)
                {
                    foreach ($CounterSignerInfos in $Infos.CounterSignerInfos)
                    {
                        $sTime = ($CounterSignerInfos.SignedAttributes | Where-Object { $_.Oid.Value -eq "1.2.840.113549.1.9.5" }).Values | Where-Object { $null -ne $_.SigningTime }
                    }
                }
                [void][PKI.Crypt32]::CryptMsgClose($phMsg)
                [void][PKI.Crypt32]::CertCloseStore($phCertStore, 0)

                if (($null -ne $sTime) -and ($null -ne $sTime.SigningTime))
                {
                    return $true
                }
            }
            return $false
        }
    }
}

$timeStampServers = @(
    "http://time.certum.pl",
    "http://timestamp.digicert.com",
    "http://timestamp.comodoca.com/authenticode"
)
$retryTime = 2

$securePassword = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
$certificate = Get-PfxCertificate -FilePath "$CertFile" -Password $securePassword

:next foreach ($file in $Files)
{
    if (-not $Replace)
    {
        $cert = Get-AuthenticodeSignature -FilePath $file
        if ($cert.status -eq 'Valid')
        {
            break next
        }
    }

    foreach ($server in $timeStampServers)
    {
        for ($i = 0; $i -lt $retryTime; $i++)
        {
            Write-Host "Use: $server"
            Set-AuthenticodeSignature -FilePath $file -Certificate $certificate -TimestampServer $server -HashAlgorithm SHA256
            if (Verify-Sign($file))
            {
                echo "Signed: $file"
                break next
            }
        }
    }
    throw "Sign file failed: $file"
}

