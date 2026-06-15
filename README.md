# WiX Cover

A tool for creating Windows installer packages (MSI) from a YAML config file, built on [WiX Toolset](https://wixtoolset.org/) v3.

WiX Toolset is powerful but has a steep learning curve. For many Windows developers, a simpler tool with a focused feature set is a better fit. WiX Cover lets you describe your installer in a single YAML file — it handles the WiX XML generation, compilation, and linking for you.

*A guide in Chinese can be found [here](https://juejin.cn/post/7158712946065932295).*

## Quick Start

1. Create a `config.yaml` based on the [sample config](source/sample-config.yaml)
2. Run the build:

```powershell
.\source\wixc.ps1 -config .\my-config.yaml -output .\my-installer.msi
```

Add `-Debug` for verbose WiX toolchain output when troubleshooting.

## Features

- **YAML-driven** — one config file defines the entire installer: files, registry entries, environment variables, shortcuts, UI text, and code signing
- **Automatic file packaging** — scans a root folder recursively and packages all files and subdirectories into the installer
- **Registry import** — imports `.reg` export files into the installer; optionally converts `HKCU`/`HKLM` roots to `HKMU` for dual-scope installs
- **Environment variables** — set, create, or remove environment variables on the target machine
- **Dual-mode installation** — per-user or per-machine, configurable per installer
- **Upgrade-aware defaults** — detects the install scope and path of a previous version and uses them as the new installation's defaults
- **EULA confirmation** — displays a license agreement (RTF) during installation
- **Multi-language support** — multiple cultures in a single MSI
- **Launch on finish** — optional checkbox to launch the application after installation
- **Process termination** — optionally kills running processes from a previous version during install to avoid reboots
- **Code signing** — signs source binaries and the final MSI; supports multiple signing rules with Skip/Replace/Append modes
- **Firewall exceptions** — registers Windows Firewall rules for specified executables
- **Auto-start** — optionally registers the application to start on user logon
- **Extensible** — inject custom WiX XML via `ExtraSourceFiles` or `TemplateExtraConfig` for advanced scenarios (e.g., .NET Framework checks, VC++ redistributables)
- **Workarounds for known WiX bugs** — [\#2376](https://github.com/wixtoolset/issues/issues/2376), [\#2165](https://github.com/wixtoolset/issues/issues/2165)

## Examples

The [`examples/`](examples/) directory contains configs for common advanced scenarios:

| Example | What it demonstrates |
|---------|---------------------|
| [`check-dotnet_framework`](examples/check-dotnet_framework/config.yaml) | Detecting .NET Framework 4.0 before install using `TemplateExtraConfig` + `WixNetFxExtension` |
| [`install-vc_redist-by-customer_action`](examples/install-vc_redist-by-customer_action/) | Installing VC++ redistributable via a custom action (two methods) |
| [`install-vc_redist-merge-module`](examples/install-vc_redist-merge-module/config.yaml) | Installing VC++ runtime via merge module |

## Usage

```
wixc.ps1 -config <path> -output <path> [-TemplateFile <path>] [-WorkingDir <path>] [-Debug]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Config` | Yes | Path to the YAML config file |
| `-Output` | Yes | Path for the output `.msi` file |
| `-TemplateFile` | No | Custom WiX template file (defaults to bundled `template.wxs`) |
| `-WorkingDir` | No | Directory for intermediate files (defaults to `$env:TEMP\~wixc`) |
| `-Debug` | No | Enable PowerShell trace and WiX verbose output; keeps intermediate files |

### Prerequisites

- Windows PowerShell 5.1 or later
- The `source/` directory must be kept intact alongside `wixc.ps1` — it bundles WiX v3.14.1 binaries, the YAML parsing module, and the code-signing tool

## Configuration

The config file is YAML. See [`source/sample-config.yaml`](source/sample-config.yaml) for the full annotated reference. WiX Cover packages itself — its [own config](installer/config.yaml) is another useful reference.

Minimal config skeleton:

```yaml
arch: 'x64'
Product:
  Name: 'MyApp'
  Version: '1.0.0'
UpgradeCode: 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
Manufacturer: 'MyCompany'
Localization:
  - Culture: 'en-us'
    ProductNameLoc: 'My Application'
    ManufacturerLoc: 'MyCompany'
    LicenseFile: 'license.rtf'
Files:
  RootFolder: '.\my-app\bin'
  MainExecutable: 'MyApp.exe'
  Icon:
    File: 'MyApp.ico'
    Index: 0
InstallScope:
  Mode: 'both'
  DefaultMode: 'user'
```
