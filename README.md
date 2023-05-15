# WiXCover 

*A guidline in Chinese can be found [here](https://juejin.cn/post/7158712946065932295).*

WiX Cover is a tool to create Windows installer package (MSI package), based on [WiX toolset](https://wixtoolset.org/) technologies.

WiX toolset is powerful but the learning curve is not so slight. For many Windows developers, an easy-to-use tool with limited functions maybe a better choice.

### What's New
V1.2.0 - During upgrade, set default installation scope (per user or per machine) according to previous version installed

### Features:
- A YAML format config file to include all the information to build the installer
- Scan and package all sub-folders / files from a root folder into installer
- Import registry data into installer by scanning exported registry files
- Environment variables added or removed on target machine
- EULA confirmation
- Dual-mode installation scope supported
  - Per user: the application installed is only available for current user
  - Per machine: the application installed is only available for all the users on the machine
- Auto detect install options (scope & install path) of previous installation, and set as the new installation's default options
- Configurable option to launch application when installation finished
- Configurable option to kill the running process from previous version during installation
- Multi-language in one installer
- Workaround the known bugs of WiX toolset, e.g.
  - https://github.com/wixtoolset/issues/issues/2376
  - https://github.com/wixtoolset/issues/issues/2165

### Usage:
1. Install WiX Cover
2. Create your own config file based on the sample file "sample-config.yaml" in the installation folder,
   or download from: https://github.com/xinnj/WiXCover/blob/main/source/sample-config.yaml.   
   The config file is quite self-explained. WiX Cover is packaged by itself, you may refer to its [config file](https://github.com/xinnj/WiXCover/blob/main/installer/config.yaml) for some tips.
3. Open a PowerShell window and get the help information by command:
   >get-help wixc.ps1 -Detailed
   
   For example:
   > wixc.ps1 -config some-path\my-config.yaml -output some-path\my-installer.msi
