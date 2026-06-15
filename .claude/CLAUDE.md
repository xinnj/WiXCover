# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

WiX Cover is a PowerShell-based tool that generates Windows MSI installers from YAML config files, wrapping the WiX Toolset v3.14.1 toolchain. The core script is `source/wixc.ps1` — it reads a YAML config, generates intermediate `.wxs` files, compiles them with WiX's `candle`/`light`/`torch`, and produces the final `.msi`.

## Build & test

There is no traditional test suite. The build is the test — run `wixc.ps1` against a config to produce an MSI:

```powershell
source\wixc.ps1 -config installer\config.yaml -output build\WiXCover.msi
```

Add `-Debug` to enable PowerShell trace output and WiX verbose mode:

```powershell
source\wixc.ps1 -config installer\config.yaml -output build\WiXCover.msi -Debug
```

The CI release pipeline is at `.github/workflows/release.yml` — it runs `installer/build.ps1 -Version <tag>` which patches the version into `config.yaml` and invokes `wixc.ps1`.

## Architecture

### Data flow

```
config.yaml  ──►  wixc.ps1  ──►  intermediate .wxs files  ──►  WiX toolchain  ──►  .msi
                    │                    │
                    ▼                    ▼
             template.wxs          candle → .wixobj
             (variable             light  → .msi
              substitution)        torch  → .mst (multilingual transforms)
```

### Config → MSI pipeline in `wixc.ps1`

1. **Parse YAML config** using the bundled `powershell-yaml` module (v0.4.3) — `ConvertFrom-Yaml`
2. **Populate `$VarsList`** — a hashtable of WiX template variables derived from config values (arch, install scope, upgrade behavior, localization, etc.)
3. **Sign source files** (code signing) before packaging — iterates `CodeSign` rules, each with `fileFilters`, calls `signtool.exe`
4. **Generate intermediate `.wxs` files** in `$WorkingDir`:
   - `New-FileGroupWxs` — custom PowerShell function that scans `Files.RootFolder` recursively and emits a WiX fragment with `<Component>`/`<File>`/`<Directory>` elements. Replaced `heat.exe` to avoid `STATUS_STACK_BUFFER_OVERRUN` crashes on large file trees.
   - `heat reg` — still uses `heat.exe` to generate `RegGroup.wxs` from combined `.reg` exports
   - `EnvGroup.wxs` — hand-written XML string for environment variable components
   - Extra `.wxs` files from `ExtraSourceFiles` — compiled directly, their `<ComponentGroup>` IDs are auto-detected and referenced
5. **Variable substitution**: `${var}` placeholders in `template.wxs` and extra source files are replaced with values from `$VarsList`. Empty `Guid=''` gets auto-filled with new GUIDs. Iterates up to 5 passes to resolve nested variables.
6. **Compile & link** per culture (multi-language loop):
   - `candle` compiles `.wxs` → `.wixobj`
   - `light` links `.wixobj` → `.msi`
7. **Multilingual packaging**: If multiple cultures, `torch` creates `.mst` transforms between the first culture's MSI and each subsequent one, then `WiSubStg.vbs`/`WiLangId.vbs` (VBScript from WiX SDK) embed them into a single multi-language MSI
8. **MSI code signing**: Signs the final MSI using the first `CodeSign` rule
9. **Output**: Moves the final MSI to the `-Output` path; cleans up `$WorkingDir` unless `-Debug` was used

### Key files

- `source/wixc.ps1` — main build script (all logic in one file, ~950 lines)
- `source/template.wxs` — WiX template with `${variable}` placeholders. Defines the installer UI (WixUI_Advanced), directories, shortcuts, upgrade detection, install scope detection, kill-process custom action, and launch-application support.
- `source/sample-config.yaml` — documented config reference
- `installer/config.yaml` — the actual config used to build WiX Cover's own installer
- `source/i18n/localizations.yaml` — per-culture strings (Language LCID, Codepage, translated UI text)
- `source/i18n/WiSubStg.vbs`, `WiLangId.vbs` — WiX SDK VBScript tools for multilingual MSI transforms
- `source/signtool.exe` — bundled Windows SDK signtool for code signing
- `source/powershell-yaml/` — bundled PowerShell YAML parsing module (v0.4.3)
- `source/WiX-v3.14.1/` — bundled WiX Toolset binaries and SDK

### Template variable system

`template.wxs` uses `${VariableName}` placeholders. The script substitutes from `$VarsList`, which is built from:
- Direct config values (`ProductName`, `ProductVersion`, `UpgradeCode`, `Manufacturer`)
- Derived values (arch → `ProgramFilesFolder`/`SystemFolder`, install scope → `ALLUSERS`/`Privileged`/`MSIINSTALLPERUSER`)
- Localization values from `localizations.yaml` keyed by `Culture`
- Config overrides (localization entries can set additional template variables directly)
- Generated references (`FileGroup`, `RegGroup`, `EnvGroup`, `ExtraGroups` — either `<ComponentGroupRef>` or XML comments if disabled)

When a config key is optional and absent, its placeholder is replaced with an XML comment (`<!-- ... -->`) so the template still compiles.

### Install scope detection

During upgrade, `template.wxs` uses `RegistrySearch` to read the previous version's `InstallScope` and `InstallDir` from `HKCU\Software\{Manufacturer}\{ProductName}`. `SetProperty` custom actions then adjust `WixAppFolder`, `ALLUSERS`, `Privileged`, `MSIINSTALLPERUSER`, and `APPLICATIONFOLDER` to match the previous installation. The final scope is recorded in `FinalInstallScope` via execute-sequence `SetProperty` actions.

### Firewall exceptions

When `FirewallException` entries exist, `New-FileGroupWxs` output is post-processed: each matched `<File>` element gets an inline `<fire:FirewallException>` sibling, and the WiX namespace gains `xmlns:fire`. The `WixFirewallExtension` is passed to both `candle` and `light`.

### Code signing

Supports multiple signing rules with `Skip`/`Replace`/`Append` modes. `Append` (dual signing) requires an existing valid signature and PE files (.exe/.dll). Falls back to `Replace` otherwise. Each rule defines `fileFilters` (globs like `*.exe`) applied against `Files.RootFolder`. Timestamp servers are tried in order with retries.

## Git history conventions

Commit messages follow Angular-style: `type(scope): description`. Recent scopes include `wixc`, `wix`, and no-scope for cross-cutting changes.
