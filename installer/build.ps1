New-Item -ItemType Directory -Force -Path .\build
.\source\wixc.ps1 -config .\installer\config.yaml -output .\build\WiXCover-1.0.0.msi