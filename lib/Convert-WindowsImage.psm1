Import-Module "$PSScriptRoot\Copy-GPUDrivers.psm1"

function Convert-WindowsImage {
  <#
    .NOTES
        Version: 21H2-20211020 + GPU

        License: GPLv3 or later
                 MIT for Microsoft's commits

        Convert-WindowsImage - Creates a bootable VHD(X) based on Windows 7,8, 10, 11 or Windows Server 2012, 2012R2, 2016, 2019, 2022 installation media.

        Copyright (c) 2019 x0nn

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <https://www.gnu.org/licenses/>.

        MIT License

        Copyright (c) Microsoft Corporation.  All rights reserved.

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.

    .SYNOPSIS
        Creates a bootable VHD(X) based on Windows 7,8, 10, 11 or Windows Server 2012, 2012R2, 2016, 2019, 2022 installation media.

    .DESCRIPTION
        Creates a bootable VHD(X) based on Windows 7,8, 10, 11 or Windows Server 2012, 2012R2, 2016, 2019, 2022 installation media.

    .PARAMETER SourcePath
        The complete path to the WIM or ISO file that will be converted to a Virtual Hard Disk.
        The ISO file must be valid Windows installation media to be recognized successfully.

    .PARAMETER CacheSource
        If the source WIM/ISO was copied locally, we delete it by default.
        Pass $true to cache the source image from the temp directory.

    .PARAMETER VHDPath
        The name and path of the Virtual Hard Disk to create.
        Omitting this parameter will create the Virtual Hard Disk is the current directory, (or,
        if specified by the -WorkingDirectory parameter, the working directory) and will automatically
        name the file in the following format:

        <build>.<revision>.<architecture>.<branch>.<timestamp>_<skufamily>_<sku>_<language>.<extension>
        i.e.:
        9200.0.amd64fre.winmain_win8rtm.120725-1247_client_professional_en-us.vhd(x)

    .PARAMETER WorkingDirectory
        Specifies the directory where the VHD(X) file should be generated.
        If specified along with -VHDPath, the -WorkingDirectory value is ignored.
        The default value is the current directory ($pwd).

    .PARAMETER TempDirectory
        Specifies the directory where the logs and ISO files should be placed.
        The default value is the temp directory ($env:Temp).

    .PARAMETER SizeBytes
        The size of the Virtual Hard Disk to create.
        For fixed disks, the VHD(X) file will be allocated all of this space immediately.
        For dynamic disks, this will be the maximum size that the VHD(X) can grow to.
        The default value is 40GB.

    .PARAMETER VHDFormat
        Specifies whether to create a VHD or VHDX formatted Virtual Hard Disk.
        The default is AUTO, which will create a VHD if using the BIOS disk layout or
        VHDX if using UEFI or WindowsToGo layouts.

    .PARAMETER IsFixed
        Specifies to create a fixed (fully allocated) VHD(X) instead of dynamic (quick allocation of space) VHD(X).

    .PARAMETER DiskLayout
        Specifies whether to build the image for BIOS (MBR), UEFI (GPT), or WindowsToGo (MBR).
        Generation 1 VMs require BIOS (MBR) images.  Generation 2 VMs require UEFI (GPT) images.
        Windows To Go images will boot in UEFI or BIOS but are not technically supported (upgrade
        doesn't work)

    .PARAMETER UnattendPath
        The complete path to an unattend.xml file that can be injected into the VHD(X).

    .PARAMETER Edition
        The name or image index of the image to apply from the ESD/WIM. If omitted and more than one image is available, all images are listed.

    .PARAMETER Passthru
        Specifies that the full path to the VHD(X) that is created should be
        returned on the pipeline.

    .PARAMETER BCDBoot
        By default, the version of BCDBOOT.EXE that is present in \Windows\System32
        is used by Convert-WindowsImage.  If you need to specify an alternate version,
        use this parameter to do so.

    .PARAMETER MergeFolder
        Specifies additional MergeFolder path to be added to the root of the VHD(X)

    .PARAMETER BCDinVHD
        Specifies the purpose of the VHD(x). Use NativeBoot to skip cration of BCD store
        inside the VHD(x). Use VirtualMachine (or do not specify this option) to ensure
        the BCD store is created inside the VHD(x).

    .PARAMETER Driver
        Full path to driver(s) (.inf files) to inject to the OS inside the VHD(x).

    .PARAMETER ExpandOnNativeBoot
        Specifies whether to expand the VHD(x) to its maximum suze upon native boot.
        The default is True. Set to False to disable expansion.

    .PARAMETER RemoteDesktopEnable
        Enable Remote Desktop to connect to the OS inside the VHD(x) upon provisioning.
        Does not include Windows Firewall rules (firewall exceptions). The default is False.

    .PARAMETER Feature
        Enables specified Windows Feature(s). Note that you need to specify the Internal names
        understood by DISM and DISM CMDLets (e.g. NetFx3) instead of the "Friendly" names
        from Server Manager CMDLets (e.g. NET-Framework-Core).

    .PARAMETER Package
        Injects specified Windows Package(s). Accepts path to either a directory or individual
        CAB or MSU file.

    .PARAMETER ShowUI
        Specifies that the Graphical User Interface should be displayed.

    .PARAMETER EnableDebugger
        Configures kernel debugging for the VHD(X) being created.
        EnableDebugger takes a single argument which specifies the debugging transport to use.
        Valid transports are: None, Serial, 1394, USB, Network, Local.

        Depending on the type of transport selected, additional configuration parameters will become
        available.

        Serial:
            -ComPort   - The COM port number to use while communicating with the debugger.
                         The default value is 1 (indicating COM1).
            -BaudRate  - The baud rate (in bps) to use while communicating with the debugger.
                         The default value is 115200, valid values are:
                         9600, 19200, 38400, 56700, 115200

        1394:
            -Channel   - The 1394 channel used to communicate with the debugger.
                         The default value is 10.

        USB:
            -Target    - The target name used for USB debugging.
                         The default value is "debugging".

        Network:
            -IPAddress - The IP address of the debugging host computer.
            -Port      - The port on which to connect to the debugging host.
                         The default value is 50000, with a minimum value of 49152.
            -Key       - The key used to encrypt the connection.  Only [0-9] and [a-z] are allowed.
            -nodhcp    - Prevents the use of DHCP to obtain the target IP address.
            -newkey    - Specifies that a new encryption key should be generated for the connection.

    .PARAMETER DismPath
        Full Path to an alternative version of the Dism.exe tool. The default is the current OS version.

    .PARAMETER ApplyEA
        Specifies that any EAs captured in the WIM should be applied to the VHD.
        The default is False.

    .EXAMPLE
        Convert-WindowsImage -SourcePath D:\foo\install.wim -Edition Professional -WorkingDirectory D:\foo

        This command will create a 40GB dynamically expanding VHD in the D:\foo folder.
        The VHD will be based on the Professional edition from D:\foo\install.wim,
        and will be named automatically.

    .EXAMPLE
        Convert-WindowsImage -SourcePath D:\foo\Win7SP1.iso -Edition Ultimate -VHDPath D:\foo\Win7_Ultimate_SP1.vhd

        This command will parse the ISO file D:\foo\Win7SP1.iso and try to locate
        \sources\install.wim.  If that file is found, it will be used to create a
        dynamically-expanding 40GB VHD containing the Ultimate SKU, and will be
        named D:\foo\Win7_Ultimate_SP1.vhd

    .EXAMPLE
        Convert-WindowsImage -SourcePath "D:\foo\WindowsServer2019.iso" -VHDFormat "VHDX" -Edition "Windows Server 2019 Standard" -SizeBytes 30GB -isFixed -DiskLayout "UEFI" -VHDPath "D:\foo\WindowsServer2019.vhdx"

        This command will create a fixed size VHDX for Windows Server with the Edition set to Standard. It will use modern UEFI layout for the disk.

    .EXAMPLE
        Convert-WindowsImage -SourcePath D:\foo\install.wim -Edition Professional -EnableDebugger Serial -ComPort 2 -BaudRate 38400

        This command will create a VHD from D:\foo\install.wim of the Professional SKU.
        Serial debugging will be enabled in the VHD via COM2 at a baud rate of 38400bps.

    .OUTPUTS
        System.IO.FileInfo
    #>
  #Requires -Version 3.0
  [CmdletBinding(DefaultParameterSetName = "SRC",
    HelpURI = "https://github.com/x0nn/Convert-WindowsImage#readme")]

  param(
    [Parameter(ParameterSetName = "SRC", Mandatory = $true, ValueFromPipeline = $true)]
    [Alias("WIM")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $SourcePath,

    [Parameter(ParameterSetName = "SRC")]
    [switch]
    $CacheSource = $false,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("SKU")]
    [string[]]
    [ValidateNotNullOrEmpty()]
    $Edition,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("WorkDir")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_ })]
    $WorkingDirectory = $pwd,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("TempDir")]
    [string]
    [ValidateNotNullOrEmpty()]
    $TempDirectory = $env:Temp,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("VHD")]
    [string]
    [ValidateNotNullOrEmpty()]
    $VHDPath,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("Size")]
    [UInt64]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(512MB, 64TB)]
    $SizeBytes = 25GB,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("Format")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("VHD", "VHDX", "AUTO")]
    $VHDFormat = "AUTO",

    [Parameter(ParameterSetName = "SRC")]
    [Parameter(ParameterSetName = "UI")]
    [switch]
    $IsFixed = $false,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("MergeFolder")]
    [string]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $MergeFolderPath = $null,

    [Parameter(ParameterSetName = "SRC", Mandatory = $true)]
    [Alias("Layout")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("BIOS", "UEFI", "WindowsToGo")]
    $DiskLayout,

    [Parameter(ParameterSetName = "SRC")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("NativeBoot", "VirtualMachine")]
    $BCDinVHD = "VirtualMachine",

    [Parameter(ParameterSetName = "SRC")]
    [Parameter(ParameterSetName = "UI")]
    [string]
    $BCDBoot = "bcdboot.exe",

    [Parameter(ParameterSetName = "SRC")]
    [Parameter(ParameterSetName = "UI")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("None", "Serial", "1394", "USB", "Local", "Network")]
    $EnableDebugger = "None",

    [Parameter(ParameterSetName = "SRC")]
    [string[]]
    [ValidateNotNullOrEmpty()]
    $Feature,

    [Parameter(ParameterSetName = "SRC")]
    [string[]]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $Driver,

    [Parameter(ParameterSetName = "SRC")]
    [string[]]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $Package,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("GPU")]
    [string]
    [ValidateNotNullOrEmpty()]
    $GPUName,

    [Parameter(ParameterSetName = "SRC")]
    [switch]
    $ExpandOnNativeBoot = $true,

    [Parameter(ParameterSetName = "SRC")]
    [switch]
    $RemoteDesktopEnable = $false,

    [Parameter(ParameterSetName = "SRC")]
    [Alias("Unattend")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $UnattendPath = $null,

    [Parameter(ParameterSetName = "SRC")]
    [Parameter(ParameterSetName = "UI")]
    [switch]
    $Passthru,

    [Parameter(ParameterSetName = "SRC")]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $(Resolve-Path $_) })]
    $DismPath,

    [Parameter(ParameterSetName = "SRC")]
    [switch]
    $ApplyEA = $false,

    [Parameter(ParameterSetName = "UI")]
    [switch]
    $ShowUI
  )
  #region Code

  # Begin Dynamic Parameters
  # Create the parameters for the various types of debugging.
  DynamicParam {
    # Get rid of the Windows ShortName mess
    $SourcePath = (Get-Item -LiteralPath $SourcePath).FullName
        
    if (![String]::IsNullOrWhiteSpace($WorkingDirectory)) { $WorkingDirectory = (Get-Item -LiteralPath $WorkingDirectory).FullName }
    if (![String]::IsNullOrWhiteSpace($TempDirectory)) { $TempDirectory = (Get-Item -LiteralPath $TempDirectory).FullName }
    if (![String]::IsNullOrWhiteSpace($MergeFolderPath)) { $MergeFolderPath = (Get-Item -LiteralPath $MergeFolderPath).FullName }
    if (![String]::IsNullOrWhiteSpace($UnattendPath)) { $UnattendPath = (Get-Item -LiteralPath $UnattendPath).FullName }

    # Since we use the VHDFormat in output, make it uppercase.
    # We'll make it lowercase again when we use it as a file extension.
    if (![String]::IsNullOrWhiteSpace($VHDFormat)) { $VHDFormat = $VHDFormat.ToUpper() }

    Set-StrictMode -version 3

    # Set up the dynamic parameters.
    # Dynamic parameters are only available if certain conditions are met, so they'll only show up
    # as valid parameters when those conditions apply.  Here, the conditions are based on the value of
    # the EnableDebugger parameter.  Depending on which of a set of values is the specified argument
    # for EnableDebugger, different parameters will light up, as outlined below.

    $parameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    if (!(Test-Path Variable:Private:EnableDebugger)) {
      return $parameterDictionary
    }

    switch ($EnableDebugger) {
      "Serial" {
        #region ComPort

        $ComPortAttr = New-Object System.Management.Automation.ParameterAttribute
        $ComPortAttr.ParameterSetName = "__AllParameterSets"
        $ComPortAttr.Mandatory = $false

        $ComPortValidator = New-Object System.Management.Automation.ValidateRangeAttribute(
          1,
          10   # Is that a good maximum?
        )

        $ComPortNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $ComPortAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ComPortAttrCollection.Add($ComPortAttr)
        $ComPortAttrCollection.Add($ComPortValidator)
        $ComPortAttrCollection.Add($ComPortNotNull)

        $ComPort = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "ComPort",
          [UInt16],
          $ComPortAttrCollection
        )

        # By default, use COM1
        $ComPort.Value = 1
        $parameterDictionary.Add("ComPort", $ComPort)
        #endregion ComPort

        #region BaudRate
        $BaudRateAttr = New-Object System.Management.Automation.ParameterAttribute
        $BaudRateAttr.ParameterSetName = "__AllParameterSets"
        $BaudRateAttr.Mandatory = $false

        $BaudRateValidator = New-Object System.Management.Automation.ValidateSetAttribute(
          9600, 19200, 38400, 57600, 115200
        )

        $BaudRateNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $BaudRateAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $BaudRateAttrCollection.Add($BaudRateAttr)
        $BaudRateAttrCollection.Add($BaudRateValidator)
        $BaudRateAttrCollection.Add($BaudRateNotNull)

        $BaudRate = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "BaudRate",
          [UInt32],
          $BaudRateAttrCollection
        )

        # By default, use 115,200.
        $BaudRate.Value = 115200
        $parameterDictionary.Add("BaudRate", $BaudRate)
        #endregion BaudRate

        break
      }

      "1394" {
        $ChannelAttr = New-Object System.Management.Automation.ParameterAttribute
        $ChannelAttr.ParameterSetName = "__AllParameterSets"
        $ChannelAttr.Mandatory = $false

        $ChannelValidator = New-Object System.Management.Automation.ValidateRangeAttribute(
          0,
          62
        )

        $ChannelNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $ChannelAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ChannelAttrCollection.Add($ChannelAttr)
        $ChannelAttrCollection.Add($ChannelValidator)
        $ChannelAttrCollection.Add($ChannelNotNull)

        $Channel = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "Channel",
          [UInt16],
          $ChannelAttrCollection
        )

        # By default, use channel 10
        $Channel.Value = 10
        $parameterDictionary.Add("Channel", $Channel)
        break
      }

      "USB" {
        $TargetAttr = New-Object System.Management.Automation.ParameterAttribute
        $TargetAttr.ParameterSetName = "__AllParameterSets"
        $TargetAttr.Mandatory = $false

        $TargetNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $TargetAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $TargetAttrCollection.Add($TargetAttr)
        $TargetAttrCollection.Add($TargetNotNull)

        $Target = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "Target",
          [string],
          $TargetAttrCollection
        )

        # By default, use target = "debugging"
        $Target.Value = "Debugging"
        $parameterDictionary.Add("Target", $Target)
        break
      }

      "Network" {
        #region IP
        $IpAttr = New-Object System.Management.Automation.ParameterAttribute
        $IpAttr.ParameterSetName = "__AllParameterSets"
        $IpAttr.Mandatory = $true

        $IpValidator = New-Object System.Management.Automation.ValidatePatternAttribute(
          "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        $IpNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $IpAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $IpAttrCollection.Add($IpAttr)
        $IpAttrCollection.Add($IpValidator)
        $IpAttrCollection.Add($IpNotNull)

        $IP = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "IPAddress",
          [string],
          $IpAttrCollection
        )

        # There's no good way to set a default value for this.
        $parameterDictionary.Add("IPAddress", $IP)
        #endregion IP

        #region Port
        $PortAttr = New-Object System.Management.Automation.ParameterAttribute
        $PortAttr.ParameterSetName = "__AllParameterSets"
        $PortAttr.Mandatory = $false

        $PortValidator = New-Object System.Management.Automation.ValidateRangeAttribute(
          49152,
          50039
        )

        $PortNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $PortAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $PortAttrCollection.Add($PortAttr)
        $PortAttrCollection.Add($PortValidator)
        $PortAttrCollection.Add($PortNotNull)


        $Port = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "Port",
          [UInt16],
          $PortAttrCollection
        )

        # By default, use port 50000
        $Port.Value = 50000
        $parameterDictionary.Add("Port", $Port)
        #endregion Port

        #region Key
        $KeyAttr = New-Object System.Management.Automation.ParameterAttribute
        $KeyAttr.ParameterSetName = "__AllParameterSets"
        $KeyAttr.Mandatory = $true

        $KeyValidator = New-Object System.Management.Automation.ValidatePatternAttribute(
          "\b([A-Z0-9]+).([A-Z0-9]+).([A-Z0-9]+).([A-Z0-9]+)\b"
        )

        $KeyNotNull = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute

        $KeyAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $KeyAttrCollection.Add($KeyAttr)
        $KeyAttrCollection.Add($KeyValidator)
        $KeyAttrCollection.Add($KeyNotNull)

        $Key = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "Key",
          [string],
          $KeyAttrCollection
        )

        # Don't set a default key.
        $parameterDictionary.Add("Key", $Key)
        #endregion Key

        #region NoDHCP
        $NoDHCPAttr = New-Object System.Management.Automation.ParameterAttribute
        $NoDHCPAttr.ParameterSetName = "__AllParameterSets"
        $NoDHCPAttr.Mandatory = $false

        $NoDHCPAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $NoDHCPAttrCollection.Add($NoDHCPAttr)

        $NoDHCP = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "NoDHCP",
          [switch],
          $NoDHCPAttrCollection
        )

        $parameterDictionary.Add("NoDHCP", $NoDHCP)
        #endregion NoDHCP

        #region NewKey
        $NewKeyAttr = New-Object System.Management.Automation.ParameterAttribute
        $NewKeyAttr.ParameterSetName = "__AllParameterSets"
        $NewKeyAttr.Mandatory = $false

        $NewKeyAttrCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $NewKeyAttrCollection.Add($NewKeyAttr)

        $NewKey = New-Object System.Management.Automation.RuntimeDefinedParameter(
          "NewKey",
          [switch],
          $NewKeyAttrCollection
        )

        # Don't set a default key.
        $parameterDictionary.Add("NewKey", $NewKey)
        #endregion NewKey

        break
      }

      # There's nothing to do for local debugging.
      # Synthetic debugging is not yet implemented.

      default {
        break
      }
    }

    return $parameterDictionary
  }

  Begin {
    ##########################################################################################
    #                             Constants and Pseudo-Constants
    ##########################################################################################
    $PARTITION_STYLE_MBR = 0x00000000                                   # The default value
    $PARTITION_STYLE_GPT = 0x00000001                                   # Just in case...

    # Version information that can be populated by timebuild.
    $ScriptVersion = DATA {
      ConvertFrom-StringData -StringData @"
        Major     = 10
        Minor     = 0
        Build     = 14278
        Qfe       = 1000
        Branch    = rs1_es_media
        Timestamp = 160201-1707
        Flavor    = amd64fre
"@
    }

    $myVersion = "$($ScriptVersion.Major).$($ScriptVersion.Minor).$($ScriptVersion.Build).$($ScriptVersion.QFE).$($ScriptVersion.Flavor).$($ScriptVersion.Branch).$($ScriptVersion.Timestamp)"
    $scriptName = "Convert-WindowsImage"                       # Name of the script, obviously.
    $sessionKey = [Guid]::NewGuid().ToString()                 # Session key, used for keeping records unique between multiple runs.
    $logFolder = "$($TempDirectory)\$($scriptName)\$($sessionKey)" # Log folder path.
    $vhdMaxSize = 2040GB                                       # Maximum size for VHD is ~2040GB.
    $vhdxMaxSize = 64TB                                         # Maximum size for VHDX is ~64TB.
    $lowestSupportedVersion = New-Object Version "6.1"                     # The lowest supported *image* version; making sure we don't run against Vista/2k8.
    $lowestSupportedBuild = 9200                                         # The lowest supported *host* build.  Set to Win8 CP.
    $transcripting = $false

    ##########################################################################################
    #                                      Here Strings
    ##########################################################################################

    # Banner text displayed during each run.
    $header = @"

Windows(R) Image to Virtual Hard Disk Converter for Windows(R)
Copyright (C) Microsoft Corporation.  All rights reserved.
Copyright (C) 2019 x0nn
Version $myVersion

"@

    # Text used as the banner in the UI.
    $uiHeader = @"
You can use the fields below to configure the VHD or VHDX that you want to create!
"@

    #region Helper Functions

    ##########################################################################################
    #                                   Helper Functions
    ##########################################################################################

    <#
            Functions to mount and dismount registry hives.
            These hives will automatically be accessible via the HKLM:\ registry PSDrive.

            It should be noted that I have more confidence in using the RegLoadKey and
            RegUnloadKey Win32 APIs than I do using REG.EXE - it just seems like we should
            do things ourselves if we can, instead of using yet another binary.

            Consider this a TODO for future versions.
        #>
    Function Mount-RegistryHive {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.IO.FileInfo]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Exists })]
        $Hive
      )

      $mountKey = [System.Guid]::NewGuid().ToString()
      $regPath = "REG.EXE"

      if (Test-Path HKLM:\$mountKey) {
        throw "The registry path already exists.  I should just regenerate it, but I'm lazy."
      }

      $regArgs = (
        "LOAD",
        "HKLM\$mountKey",
        $Hive.Fullname
      )
      try {

        Run-Executable -Executable $regPath -Arguments $regArgs

      }
      catch {
        throw
      }

      # Set a global variable containing the name of the mounted registry key
      # so we can unmount it if there's an error.
      $global:mountedHive = $mountKey

      return $mountKey
    }

    ##########################################################################################

    Function Dismount-RegistryHive {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]
        [ValidateNotNullOrEmpty()]
        $HiveMountPoint
      )

      $regPath = "REG.EXE"

      $regArgs = (
        "UNLOAD",
        "HKLM\$($HiveMountPoint)"
      )

      Run-Executable -Executable $regPath -Arguments $regArgs

      $global:mountedHive = $null
    }

    function
    Test-Admin {
      <#
                .SYNOPSIS
                    Short function to determine whether the logged-on user is an administrator.

                .EXAMPLE
                    Do you honestly need one?  There are no parameters!

                .OUTPUTS
                    $true if user is admin.
                    $false if user is not an admin.
            #>
      [CmdletBinding()]
      param()

      $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
      $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
      Write-LogMessage "isUserAdmin? $isAdmin" -logType Debug

      return $isAdmin
    }

    function
    Get-WindowsBuildNumber {
      $os = Get-WmiObject -Class Win32_OperatingSystem
      return [int]($os.BuildNumber)
    }

    function
    Test-WindowsVersion {
      $isWin8 = ((Get-WindowsBuildNumber) -ge [int]$lowestSupportedBuild)

      Write-LogMessage "is Windows 8 or Higher? $isWin8" -logType Debug
      return $isWin8
    }


    function
    Run-Executable {
      <#
                .SYNOPSIS
                    Runs an external executable file, and validates the error level.

                .PARAMETER Executable
                    The path to the executable to run and monitor.

                .PARAMETER Arguments
                    An array of arguments to pass to the executable when it's executed.

                .PARAMETER SuccessfulErrorCode
                    The error code that means the executable ran successfully.
                    The default value is 0.
            #>

      [CmdletBinding()]
      param(
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Executable,

        [Parameter(Mandatory = $true)]
        [string[]]
        [ValidateNotNullOrEmpty()]
        $Arguments,

        [Parameter()]
        [int]
        [ValidateNotNullOrEmpty()]
        $SuccessfulErrorCode = 0

      )

      Write-LogMessage "Running $Executable $(($Arguments | Out-String).Replace("`r`n"," "))" -logType Debug
      $ret = Start-Process           `
        -FilePath $Executable      `
        -ArgumentList $Arguments   `
        -NoNewWindow               `
        -Wait                      `
        -RedirectStandardOutput "$($TempDirectory)\$($scriptName)\$($sessionKey)\$($Executable)-StandardOutput.txt" `
        -RedirectStandardError  "$($TempDirectory)\$($scriptName)\$($sessionKey)\$($Executable)-StandardError.txt"  `
        -Passthru

      Write-LogMessage "Return code was $($ret.ExitCode)." -logType Debug

      if ($ret.ExitCode -ne $SuccessfulErrorCode) {
        throw "$Executable failed with code $($ret.ExitCode)!"
      }
    }

    ##########################################################################################
    Function Test-IsNetworkLocation {
      <#
                .SYNOPSIS
                    Determines whether or not a given path is a network location or a local drive.

                .DESCRIPTION
                    Function to determine whether or not a specified path is a local path, a UNC path,
                    or a mapped network drive.

                .PARAMETER Path
                    The path that we need to figure stuff out about,
            #>

      [CmdletBinding()]
      param(
        [Parameter(ValueFromPipeLine = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Path
      )

      $result = $false

      if ([bool]([URI]$Path).IsUNC) {
        $result = $true
      }
      else {
        $driveInfo = [IO.DriveInfo]((Resolve-Path $Path).Path)

        if ($driveInfo.DriveType -eq "Network") {
          $result = $true
        }
      }

      return $result
    }
    ##########################################################################################

    #endregion Helper Functions
  }

  Process {
    Write-Host $header
        
    $disk = $null
    $openWim = $null
    $openIso = $null
    $vhdFinalName = $null
    $vhdFinalPath = $null
    $mountedHive = $null
    $isoPath = $null
    $tempSource = $null

    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
      try {
        $hyperVEnabled = $((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -eq "Enabled")
      }
      catch {
        # WinPE DISM does not support online queries.  This will throw on non-WinPE machines
        $winpeVersion = (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinPE').Version

        Write-LogMessage "Running WinPE version $winpeVersion" -logType Verbose

        $hyperVEnabled = $false
      }
    }
    else {
      $hyperVEnabled = $false
    }

    $vhd = @()

    try {
      # Create log folder
      if (Test-Path $logFolder) {
        $null = rd $logFolder -Force -Recurse
      }

      $null = md $logFolder -Force

      # Try to start transcripting.  If it's already running, we'll get an exception and swallow it.
      try {
        $null = Start-Transcript -Path (Join-Path $logFolder "Convert-WindowsImageTranscript.txt") -Force -ErrorAction SilentlyContinue
        $transcripting = $true
      }
      catch {
        Write-LogMessage "Transcription is already running.  No Convert-WindowsImage-specific transcript will be created." -logType Warning
        $transcripting = $false
      }

      #
      # Add types
      #
      Add-WindowsImageTypes

      # Check to make sure we're running as Admin.
      if (!(Test-Admin)) {
        throw "Images can only be applied by an administrator.  Please launch PowerShell elevated and run this script again."
      }

      # Check to make sure we're running on Win8.
      if (!(Test-WindowsVersion)) {
        throw "$scriptName requires Windows 8 Consumer Preview or higher.  Please use WIM2VHD.WSF (http://code.msdn.microsoft.com/wim2vhd) if you need to create VHDs from Windows 7."
      }

      # Resolve the path for the unattend file.
      if (![string]::IsNullOrEmpty($UnattendPath)) {
        $UnattendPath = (Resolve-Path $UnattendPath).Path
      }

      if ($ShowUI) {

        Write-LogMessage "Launching UI..." -logType Verbose
        Add-Type -AssemblyName System.Drawing, System.Windows.Forms

        #region Form Objects
        $frmMain = New-Object System.Windows.Forms.Form
        $groupBox4 = New-Object System.Windows.Forms.GroupBox
        $btnGo = New-Object System.Windows.Forms.Button
        $groupBox3 = New-Object System.Windows.Forms.GroupBox
        $txtVhdName = New-Object System.Windows.Forms.TextBox
        $label6 = New-Object System.Windows.Forms.Label
        $btnWrkBrowse = New-Object System.Windows.Forms.Button
        $cmbVhdSizeUnit = New-Object System.Windows.Forms.ComboBox
        $numVhdSize = New-Object System.Windows.Forms.NumericUpDown
        $cmbVhdFormat = New-Object System.Windows.Forms.ComboBox
        $label5 = New-Object System.Windows.Forms.Label
        $txtWorkingDirectory = New-Object System.Windows.Forms.TextBox
        $label4 = New-Object System.Windows.Forms.Label
        $label3 = New-Object System.Windows.Forms.Label
        $label2 = New-Object System.Windows.Forms.Label
        $label7 = New-Object System.Windows.Forms.Label
        $txtUnattendFile = New-Object System.Windows.Forms.TextBox
        $btnUnattendBrowse = New-Object System.Windows.Forms.Button
        $groupBox2 = New-Object System.Windows.Forms.GroupBox
        $cmbSkuList = New-Object System.Windows.Forms.ComboBox
        $label1 = New-Object System.Windows.Forms.Label
        $groupBox1 = New-Object System.Windows.Forms.GroupBox
        $txtSourcePath = New-Object System.Windows.Forms.TextBox
        $btnBrowseWim = New-Object System.Windows.Forms.Button
        $openFileDialog1 = New-Object System.Windows.Forms.OpenFileDialog
        $openFolderDialog1 = New-Object System.Windows.Forms.FolderBrowserDialog
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

        #endregion Form Objects

        #region Event scriptblocks.

        $btnGo_OnClick = {
          $frmMain.Close()
        }

        $btnWrkBrowse_OnClick = {
          $openFolderDialog1.RootFolder = "Desktop"
          $openFolderDialog1.Description = "Select the folder you'd like your VHD(X) to be created in."
          $openFolderDialog1.SelectedPath = $WorkingDirectory

          $ret = $openFolderDialog1.ShowDialog()

          if ($ret -ilike "ok") {
            $WorkingDirectory = $txtWorkingDirectory = $openFolderDialog1.SelectedPath
            Write-LogMessage "Selected Working Directory is $WorkingDirectory..." -logType Verbose
          }
        }

        $btnUnattendBrowse_OnClick = {
          $openFileDialog1.InitialDirectory = $pwd
          $openFileDialog1.Filter = "XML files (*.xml)|*.XML|All files (*.*)|*.*"
          $openFileDialog1.FilterIndex = 1
          $openFileDialog1.CheckFileExists = $true
          $openFileDialog1.CheckPathExists = $true
          $openFileDialog1.FileName = $null
          $openFileDialog1.ShowHelp = $false
          $openFileDialog1.Title = "Select an unattend file..."

          $ret = $openFileDialog1.ShowDialog()

          if ($ret -ilike "ok") {
            $UnattendPath = $txtUnattendFile.Text = $openFileDialog1.FileName
          }
        }

        $btnBrowseWim_OnClick = {
          $openFileDialog1.InitialDirectory = $pwd
          $openFileDialog1.Filter = "All compatible files (*.ISO, *.WIM)|*.ISO;*.WIM|All files (*.*)|*.*"
          $openFileDialog1.FilterIndex = 1
          $openFileDialog1.CheckFileExists = $true
          $openFileDialog1.CheckPathExists = $true
          $openFileDialog1.FileName = $null
          $openFileDialog1.ShowHelp = $false
          $openFileDialog1.Title = "Select a source file..."

          $ret = $openFileDialog1.ShowDialog()

          if ($ret -ilike "ok") {

            if (([IO.FileInfo]$openFileDialog1.FileName).Extension -ilike ".iso") {

              if (Test-IsNetworkLocation $openFileDialog1.FileName) {
                Write-LogMessage "Copying ISO $(Split-Path $openFileDialog1.FileName -Leaf) to temp folder..." -logType Verbose
                Write-LogMessage "The UI may become non-responsive while this copy takes place..." -logType Warning
                Copy-Item -Path $openFileDialog1.FileName -Destination $TempDirectory -Force
                $openFileDialog1.FileName = "$($TempDirectory)\$(Split-Path $openFileDialog1.FileName -Leaf)"
              }

              $txtSourcePath.Text = $isoPath = (Resolve-Path $openFileDialog1.FileName).Path
              Write-LogMessage "Opening ISO $(Split-Path $isoPath -Leaf)..." -logType Verbose

              Mount-DiskImage -ImagePath $isoPath -StorageType ISO
              Get-PSDrive -PSProvider FileSystem | Out-Null #Bugfix to refresh the Drive-List
              # Refresh the DiskImage object so we can get the real information about it.  I assume this is a bug.
              $openIso = Get-DiskImage -ImagePath $isoPath
              $driveLetter = (Get-Volume -DiskImage $openIso).DriveLetter

              # Check to see if there's a WIM file we can muck about with.
              Write-LogMessage "Looking for $($SourcePath)..." -logType Verbose

              if (Test-Path -Path "$($driveLetter):\sources\install.wim") {
                $SourcePath = "$($driveLetter):\sources\install.wim"
              }
              elseif (Test-Path -Path "$($driveLetter):\sources\install.esd") {
                $SourcePath = "$($driveLetter):\sources\install.esd"
              }
              else {
                throw "The specified ISO does not appear to be valid Windows installation media."
              }
                            
            }
            else {
              $txtSourcePath.Text = $SourcePath = $openFileDialog1.FileName
            }

            # Check to see if the WIM is local, or on a network location.  If the latter, copy it locally.
            if (Test-IsNetworkLocation $SourcePath) {
              Write-LogMessage "Copying WIM $(Split-Path $SourcePath -Leaf) to temp folder..." -logType Verbose
              Write-LogMessage "The UI may become non-responsive while this copy takes place..." -logType Warning
              Copy-Item -Path $SourcePath -Destination $TempDirectory -Force
              $txtSourcePath.Text = $SourcePath = "$($TempDirectory)\$(Split-Path $SourcePath -Leaf)"
            }

            $SourcePath = (Resolve-Path $SourcePath).Path

            Write-LogMessage "Scanning WIM metadata..." -logType Verbose

            $tempOpenWim = $null

            try {
              $tempOpenWim = New-Object WIM2VHD.WimFile $SourcePath

              # Let's see if we're running against an unstaged build.  If we are, we need to blow up.
              if ($tempOpenWim.ImageNames.Contains("Windows Longhorn Client") -or
                $tempOpenWim.ImageNames.Contains("Windows Longhorn Server") -or
                $tempOpenWim.ImageNames.Contains("Windows Longhorn Server Core")) {
                [Windows.Forms.MessageBox]::Show(
                  "Convert-WindowsImage cannot run against unstaged builds. Please try again with a staged build.",
                  "WIM is incompatible!",
                  "OK",
                  "Error"
                )

                return
              }
              else {
                $tempOpenWim.Images | % { $cmbSkuList.Items.Add($_.ImageFlags) }
                $cmbSkuList.SelectedIndex = 0
              }

            }
            catch {
              throw "Unable to load WIM metadata!"
            }
            finally {
              $tempOpenWim.Close()
              Write-LogMessage "Closing WIM metadata..." -logType Verbose
            }
          }
        }

        $OnLoadForm_StateCorrection = {

          # Correct the initial state of the form to prevent the .Net maximized form issue
          $frmMain.WindowState = $InitialFormWindowState
        }

        #endregion Event scriptblocks

        # Figure out VHD size and size unit.
        $unit = $null
        switch ([Math]::Round($SizeBytes.ToString().Length / 3)) {
          3 { $unit = "MB"; break }
          4 { $unit = "GB"; break }
          5 { $unit = "TB"; break }
          default { $unit = ""; break }
        }

        $quantity = Invoke-Expression -Command "$($SizeBytes) / 1$($unit)"

        #region Form Code
        #region frmMain
        $frmMain.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 579
        $System_Drawing_Size.Width = 512
        $frmMain.ClientSize = $System_Drawing_Size
        $frmMain.Font = New-Object System.Drawing.Font("Segoe UI", 10, 0, 3, 1)
        $frmMain.FormBorderStyle = 1
        $frmMain.MaximizeBox = $False
        $frmMain.MinimizeBox = $False
        $frmMain.Name = "frmMain"
        $frmMain.StartPosition = 1
        $frmMain.Text = "Convert-WindowsImage UI"
        #endregion frmMain

        #region groupBox4
        $groupBox4.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 10
        $System_Drawing_Point.Y = 498
        $groupBox4.Location = $System_Drawing_Point
        $groupBox4.Name = "groupBox4"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 69
        $System_Drawing_Size.Width = 489
        $groupBox4.Size = $System_Drawing_Size
        $groupBox4.TabIndex = 8
        $groupBox4.TabStop = $False
        $groupBox4.Text = "4. Make the VHD!"

        $frmMain.Controls.Add($groupBox4)
        #endregion groupBox4

        #region btnGo
        $btnGo.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 39
        $System_Drawing_Point.Y = 24
        $btnGo.Location = $System_Drawing_Point
        $btnGo.Name = "btnGo"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 33
        $System_Drawing_Size.Width = 415
        $btnGo.Size = $System_Drawing_Size
        $btnGo.TabIndex = 0
        $btnGo.Text = "&Make my VHD"
        $btnGo.UseVisualStyleBackColor = $True
        $btnGo.DialogResult = "OK"
        $btnGo.add_Click($btnGo_OnClick)

        $groupBox4.Controls.Add($btnGo)
        $frmMain.AcceptButton = $btnGo
        #endregion btnGo

        #region groupBox3
        $groupBox3.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 10
        $System_Drawing_Point.Y = 243
        $groupBox3.Location = $System_Drawing_Point
        $groupBox3.Name = "groupBox3"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 245
        $System_Drawing_Size.Width = 489
        $groupBox3.Size = $System_Drawing_Size
        $groupBox3.TabIndex = 7
        $groupBox3.TabStop = $False
        $groupBox3.Text = "3. Choose configuration options"

        $frmMain.Controls.Add($groupBox3)
        #endregion groupBox3

        #region txtVhdName
        $txtVhdName.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 150
        $txtVhdName.Location = $System_Drawing_Point
        $txtVhdName.Name = "txtVhdName"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 418
        $txtVhdName.Size = $System_Drawing_Size
        $txtVhdName.TabIndex = 10

        $groupBox3.Controls.Add($txtVhdName)
        #endregion txtVhdName

        #region txtUnattendFile
        $txtUnattendFile.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 198
        $txtUnattendFile.Location = $System_Drawing_Point
        $txtUnattendFile.Name = "txtUnattendFile"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 418
        $txtUnattendFile.Size = $System_Drawing_Size
        $txtUnattendFile.TabIndex = 11

        $groupBox3.Controls.Add($txtUnattendFile)
        #endregion txtUnattendFile

        #region label7
        $label7.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 23
        $System_Drawing_Point.Y = 180
        $label7.Location = $System_Drawing_Point
        $label7.Name = "label7"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 23
        $System_Drawing_Size.Width = 175
        $label7.Size = $System_Drawing_Size
        $label7.Text = "Unattend File (Optional)"

        $groupBox3.Controls.Add($label7)
        #endregion label7

        #region label6
        $label6.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 23
        $System_Drawing_Point.Y = 132
        $label6.Location = $System_Drawing_Point
        $label6.Name = "label6"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 23
        $System_Drawing_Size.Width = 175
        $label6.Size = $System_Drawing_Size
        $label6.Text = "VHD Name (Optional)"

        $groupBox3.Controls.Add($label6)
        #endregion label6

        #region btnUnattendBrowse
        $btnUnattendBrowse.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 449
        $System_Drawing_Point.Y = 199
        $btnUnattendBrowse.Location = $System_Drawing_Point
        $btnUnattendBrowse.Name = "btnUnattendBrowse"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 27
        $btnUnattendBrowse.Size = $System_Drawing_Size
        $btnUnattendBrowse.TabIndex = 9
        $btnUnattendBrowse.Text = "..."
        $btnUnattendBrowse.UseVisualStyleBackColor = $True
        $btnUnattendBrowse.add_Click($btnUnattendBrowse_OnClick)

        $groupBox3.Controls.Add($btnUnattendBrowse)
        #endregion btnUnattendBrowse

        #region btnWrkBrowse
        $btnWrkBrowse.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 449
        $System_Drawing_Point.Y = 98
        $btnWrkBrowse.Location = $System_Drawing_Point
        $btnWrkBrowse.Name = "btnWrkBrowse"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 27
        $btnWrkBrowse.Size = $System_Drawing_Size
        $btnWrkBrowse.TabIndex = 9
        $btnWrkBrowse.Text = "..."
        $btnWrkBrowse.UseVisualStyleBackColor = $True
        $btnWrkBrowse.add_Click($btnWrkBrowse_OnClick)

        $groupBox3.Controls.Add($btnWrkBrowse)
        #endregion btnWrkBrowse

        #region cmbVhdSizeUnit
        $cmbVhdSizeUnit.DataBindings.DefaultDataSourceUpdateMode = 0
        $cmbVhdSizeUnit.FormattingEnabled = $True
        $cmbVhdSizeUnit.Items.Add("MB") | Out-Null
        $cmbVhdSizeUnit.Items.Add("GB") | Out-Null
        $cmbVhdSizeUnit.Items.Add("TB") | Out-Null
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 409
        $System_Drawing_Point.Y = 42
        $cmbVhdSizeUnit.Location = $System_Drawing_Point
        $cmbVhdSizeUnit.Name = "cmbVhdSizeUnit"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 67
        $cmbVhdSizeUnit.Size = $System_Drawing_Size
        $cmbVhdSizeUnit.TabIndex = 5
        $cmbVhdSizeUnit.Text = $unit

        $groupBox3.Controls.Add($cmbVhdSizeUnit)
        #endregion cmbVhdSizeUnit

        #region numVhdSize
        $numVhdSize.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 340
        $System_Drawing_Point.Y = 42
        $numVhdSize.Location = $System_Drawing_Point
        $numVhdSize.Name = "numVhdSize"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 63
        $numVhdSize.Size = $System_Drawing_Size
        $numVhdSize.TabIndex = 4
        $numVhdSize.Value = $quantity

        $groupBox3.Controls.Add($numVhdSize)
        #endregion numVhdSize

        #region cmbVhdFormat
        $cmbVhdFormat.DataBindings.DefaultDataSourceUpdateMode = 0
        $cmbVhdFormat.FormattingEnabled = $True
        $cmbVhdFormat.Items.Add("VHD")  | Out-Null
        $cmbVhdFormat.Items.Add("VHDX") | Out-Null
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 42
        $cmbVhdFormat.Location = $System_Drawing_Point
        $cmbVhdFormat.Name = "cmbVhdFormat"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 136
        $cmbVhdFormat.Size = $System_Drawing_Size
        $cmbVhdFormat.TabIndex = 0
        $cmbVhdFormat.Text = $VHDFormat

        $groupBox3.Controls.Add($cmbVhdFormat)
        #endregion cmbVhdFormat

        #region label5
        $label5.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 23
        $System_Drawing_Point.Y = 76
        $label5.Location = $System_Drawing_Point
        $label5.Name = "label5"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 23
        $System_Drawing_Size.Width = 264
        $label5.Size = $System_Drawing_Size
        $label5.TabIndex = 8
        $label5.Text = "Working Directory"

        $groupBox3.Controls.Add($label5)
        #endregion label5

        #region txtWorkingDirectory
        $txtWorkingDirectory.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 99
        $txtWorkingDirectory.Location = $System_Drawing_Point
        $txtWorkingDirectory.Name = "txtWorkingDirectory"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 418
        $txtWorkingDirectory.Size = $System_Drawing_Size
        $txtWorkingDirectory.TabIndex = 7
        $txtWorkingDirectory.Text = $WorkingDirectory

        $groupBox3.Controls.Add($txtWorkingDirectory)
        #endregion txtWorkingDirectory

        #region label4
        $label4.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 340
        $System_Drawing_Point.Y = 21
        $label4.Location = $System_Drawing_Point
        $label4.Name = "label4"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 27
        $System_Drawing_Size.Width = 86
        $label4.Size = $System_Drawing_Size
        $label4.TabIndex = 6
        $label4.Text = "VHD Size"

        $groupBox3.Controls.Add($label4)
        #endregion label4

        #region label3
        $label3.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 176
        $System_Drawing_Point.Y = 21
        $label3.Location = $System_Drawing_Point
        $label3.Name = "label3"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 27
        $System_Drawing_Size.Width = 92
        $label3.Size = $System_Drawing_Size
        $label3.TabIndex = 3
        $label3.Text = "VHD Type"

        $groupBox3.Controls.Add($label3)
        #endregion label3

        #region label2
        $label2.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 21
        $label2.Location = $System_Drawing_Point
        $label2.Name = "label2"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 30
        $System_Drawing_Size.Width = 118
        $label2.Size = $System_Drawing_Size
        $label2.TabIndex = 1
        $label2.Text = "VHD Format"

        $groupBox3.Controls.Add($label2)
        #endregion label2

        #region groupBox2
        $groupBox2.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 10
        $System_Drawing_Point.Y = 169
        $groupBox2.Location = $System_Drawing_Point
        $groupBox2.Name = "groupBox2"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 68
        $System_Drawing_Size.Width = 490
        $groupBox2.Size = $System_Drawing_Size
        $groupBox2.TabIndex = 6
        $groupBox2.TabStop = $False
        $groupBox2.Text = "2. Choose a SKU from the list"

        $frmMain.Controls.Add($groupBox2)
        #endregion groupBox2

        #region cmbSkuList
        $cmbSkuList.DataBindings.DefaultDataSourceUpdateMode = 0
        $cmbSkuList.FormattingEnabled = $True
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 24
        $cmbSkuList.Location = $System_Drawing_Point
        $cmbSkuList.Name = "cmbSkuList"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 452
        $cmbSkuList.Size = $System_Drawing_Size
        $cmbSkuList.TabIndex = 2

        $groupBox2.Controls.Add($cmbSkuList)
        #endregion cmbSkuList

        #region label1
        $label1.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 23
        $System_Drawing_Point.Y = 21
        $label1.Location = $System_Drawing_Point
        $label1.Name = "label1"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 71
        $System_Drawing_Size.Width = 464
        $label1.Size = $System_Drawing_Size
        $label1.TabIndex = 5
        $label1.Text = $uiHeader

        $frmMain.Controls.Add($label1)
        #endregion label1

        #region groupBox1
        $groupBox1.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 10
        $System_Drawing_Point.Y = 95
        $groupBox1.Location = $System_Drawing_Point
        $groupBox1.Name = "groupBox1"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 68
        $System_Drawing_Size.Width = 490
        $groupBox1.Size = $System_Drawing_Size
        $groupBox1.TabIndex = 4
        $groupBox1.TabStop = $False
        $groupBox1.Text = "1. Choose a source"

        $frmMain.Controls.Add($groupBox1)
        #endregion groupBox1

        #region txtSourcePath
        $txtSourcePath.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 25
        $System_Drawing_Point.Y = 24
        $txtSourcePath.Location = $System_Drawing_Point
        $txtSourcePath.Name = "txtSourcePath"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 418
        $txtSourcePath.Size = $System_Drawing_Size
        $txtSourcePath.TabIndex = 0

        $groupBox1.Controls.Add($txtSourcePath)
        #endregion txtSourcePath

        #region btnBrowseWim
        $btnBrowseWim.DataBindings.DefaultDataSourceUpdateMode = 0
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 449
        $System_Drawing_Point.Y = 24
        $btnBrowseWim.Location = $System_Drawing_Point
        $btnBrowseWim.Name = "btnBrowseWim"
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 25
        $System_Drawing_Size.Width = 28
        $btnBrowseWim.Size = $System_Drawing_Size
        $btnBrowseWim.TabIndex = 1
        $btnBrowseWim.Text = "..."
        $btnBrowseWim.UseVisualStyleBackColor = $True
        $btnBrowseWim.add_Click($btnBrowseWim_OnClick)

        $groupBox1.Controls.Add($btnBrowseWim)
        #endregion btnBrowseWim

        $openFileDialog1.FileName = "openFileDialog1"
        $openFileDialog1.ShowHelp = $True

        #endregion Form Code

        # Save the initial state of the form
        $InitialFormWindowState = $frmMain.WindowState

        # Init the OnLoad event to correct the initial state of the form
        $frmMain.add_Load($OnLoadForm_StateCorrection)

        # Return the constructed form.
        $ret = $frmMain.ShowDialog()

        if (!($ret -ilike "OK")) {
          throw "Form session has been cancelled."
        }

        if ([string]::IsNullOrEmpty($SourcePath)) {
          throw "No source path specified."
        }

        # VHD Format
        $VHDFormat = $cmbVhdFormat.SelectedItem

        # VHD Size
        $SizeBytes = Invoke-Expression "$($numVhdSize.Value)$($cmbVhdSizeUnit.SelectedItem)"

        # Working Directory
        $WorkingDirectory = $txtWorkingDirectory.Text

        # VHDPath
        if (![string]::IsNullOrEmpty($txtVhdName.Text)) {
          $VHDPath = "$($WorkingDirectory)\$($txtVhdName.Text)"
        }

        # Edition
        if (![string]::IsNullOrEmpty($cmbSkuList.SelectedItem)) {
          $Edition = $cmbSkuList.SelectedItem
        }

        # Because we used ShowDialog, we need to manually dispose of the form.
        # This probably won't make much of a difference, but let's free up all of the resources we can
        # before we start the conversion process.

        $frmMain.Dispose()
      }

      if ($VHDFormat -ilike "AUTO") {
        switch (([IO.FileInfo]$VHDPath).Extension.ToUpper()) {
          ".VHD" { $VHDFormat = "VHD" }
          ".VHDX" { $VHDFormat = "VHDX" }
        }
      }

      #
      # Choose smallest supported block size for dynamic VHD(X)
      #
      $BlockSizeBytes = 1MB

      # There's a difference between the maximum sizes for VHDs and VHDXs.  Make sure we follow it.
      if ("VHD" -ilike $VHDFormat) {
        if ($SizeBytes -gt $vhdMaxSize) {
          Write-LogMessage "For the VHD file format, the maximum file size is ~2040GB.  We're automatically setting the size to 2040GB for you." -logType Warning
          $SizeBytes = 2040GB
        }

        $BlockSizeBytes = 512KB
      }

      # Check if -VHDPath and -WorkingDirectory were both specified.
      if ((![String]::IsNullOrEmpty($VHDPath)) -and (![String]::IsNullOrEmpty($WorkingDirectory))) {
        if ($WorkingDirectory -ne $pwd) {
          # If the WorkingDirectory is anything besides $pwd, tell people that the WorkingDirectory is being ignored.
          Write-LogMessage "Specifying -VHDPath and -WorkingDirectory at the same time is contradictory." -logType Warning
          Write-LogMessage "Ignoring the WorkingDirectory specification." -logType Warning

          $WorkingDirectory = Split-Path $VHDPath -Parent
        }
      }

      if ($VHDPath) {
        # Check to see if there's a conflict between the specified file extension and the VHDFormat being used.
        $extension = ([IO.FileInfo]$VHDPath).Extension.ToUpper()

        if (!($extension -ilike ".$($VHDFormat)")) {
          throw "There is a mismatch between the VHDPath file extension ($($extension.ToUpper())), and the VHDFormat (.$($VHDFormat)).  Please ensure that these match and try again."
        }

        if (Test-Path $VHDPath) {
          $VHDPathInUse = (Join-Path $WorkingDirectory $VHDPath)
          Write-LogMessage "A file ""$VHDPathInUse"" already exists and will be overwritten." -logType Warning
                
          if (Get-Disk | Where-Object { $_.Location -eq $VHDPathInUse }) {
            try {
              Write-LogMessage "Trying to dismount ""$VHDPathInUse""." -logType Warning
              Dismount-DiskImage -ImagePath $VHDPathInUse
            }
            catch {
              Write-LogMessage "The file ""$VHDPathInUse"" is already mounted and cannot be dismounted. Dismount manually and try again." -logType Error
              throw
            }
                    
          }
        }
      }

      # Create a temporary name for the VHD(x).  We'll name it properly at the end of the script.
      if ([String]::IsNullOrEmpty($VHDPath)) {
        $VHDPath = Join-Path $WorkingDirectory "$($sessionKey).$($VHDFormat.ToLower())"
      }
      else {
        # Since we can't do Resolve-Path against a file that doesn't exist, we need to get creative in determining
        # the full path that the user specified (or meant to specify if they gave us a relative path).
        # Check to see if the path has a root specified.  If it doesn't, use the working directory.
        if (![IO.Path]::IsPathRooted($VHDPath)) {
          $VHDPath = Join-Path $WorkingDirectory $VHDPath
        }

        $vhdFinalName = Split-Path $VHDPath -Leaf
        $VHDPath = Join-Path (Split-Path $VHDPath -Parent) "$($sessionKey).$($VHDFormat.ToLower())"
      }

      Write-LogMessage "Temporary $VHDFormat path is : $VHDPath" -logType Verbose

      # If we're using an ISO, mount it and get the path to the WIM file.
      if (([IO.FileInfo]$SourcePath).Extension -ilike ".ISO") {
        # If the ISO isn't local, copy it down so we don't have to worry about resource contention
        # or about network latency.
        if (Test-IsNetworkLocation $SourcePath) {
          Write-LogMessage "Copying ISO $(Split-Path $SourcePath -Leaf) to temp folder..." -logType Verbose
          robocopy $(Split-Path $SourcePath -Parent) $TempDirectory $(Split-Path $SourcePath -Leaf) | Out-Null
          $SourcePath = "$($TempDirectory)\$(Split-Path $SourcePath -Leaf)"

          $tempSource = $SourcePath
        }

        $isoPath = (Resolve-Path $SourcePath).Path

        Write-LogMessage "Opening ISO $(Split-Path $isoPath -Leaf)..." -logType Verbose
        Mount-DiskImage -ImagePath $isoPath -StorageType ISO | Out-Null
        Get-PSDrive -PSProvider FileSystem | Out-Null #Bugfix to refresh the Drive-List
        # Refresh the DiskImage object so we can get the real information about it.  I assume this is a bug.
        $openIso = Get-DiskImage -ImagePath $isoPath
        $driveLetter = (Get-Volume -DiskImage $openIso).DriveLetter

        # Check to see if there's a WIM file we can muck about with.
        Write-LogMessage "Looking for $($SourcePath)..." -logType Verbose

        if (Test-Path -Path "$($driveLetter):\sources\install.wim") {
          $SourcePath = "$($driveLetter):\sources\install.wim"
        }
        elseif (Test-Path -Path "$($driveLetter):\sources\install.esd") {
          $SourcePath = "$($driveLetter):\sources\install.esd"
        }
        else {
          throw "The specified ISO does not appear to be valid Windows installation media."
        }
      }

      # Check to see if the WIM is local, or on a network location.  If the latter, copy it locally.
      if (Test-IsNetworkLocation $SourcePath) {
        Write-LogMessage "Copying WIM $(Split-Path $SourcePath -Leaf) to temp folder..." -logType Verbose
        robocopy $(Split-Path $SourcePath -Parent) $TempDirectory $(Split-Path $SourcePath -Leaf) | Out-Null
        $SourcePath = "$($TempDirectory)\$(Split-Path $SourcePath -Leaf)"

        $tempSource = $SourcePath
      }

      $SourcePath = (Resolve-Path $SourcePath).Path

      ####################################################################################################
      # QUERY WIM INFORMATION AND EXTRACT THE INDEX OF TARGETED IMAGE
      ####################################################################################################

      Write-LogMessage "Looking for the requested Windows image in the WIM/ESD file..." -logType Verbose
            
      try {
        [Microsoft.Dism.Commands.BasicImageInfoObject[]]$WindowsImages = Get-WindowsImage -ImagePath $SourcePath
      }
      catch {
        Write-LogMessage "'$SourcePath' does not seem a valid WindowsImage" -logType Error
        throw
      }

      $EditionIndex = 0;

      if ([Int32]::TryParse($Edition, [ref]$EditionIndex) -and $WindowsImages.Count -ge $EditionIndex) {
        $EditionIndex --
        $WindowsImage = $WindowsImages[$EditionIndex]
      }
      elseif ([String]::IsNullOrWhiteSpace($Edition) -and $WindowsImages.Count -eq 1) {
        $WindowsImage = $WindowsImages[0]
        Write-LogMessage "No Edition was chosen, but selected the only WindowsImage (Edition) available in the file..." -logType Warning
        List-WindowsImages $WindowsImage
      }
      else {
        [Microsoft.Dism.Commands.BasicImageInfoObject[]]$filteredImages = $WindowsImages | Where-Object { $_.ImageName -ilike "*$($Edition)*" }

        if ($null -ne $filteredImages) {
          if ($filteredImages.Count -gt 1) {
            List-WindowsImages $filteredImages
            throw "There is more than one WindowsImage (Edition) available. Choose with -Edition using Name oder Index from the list above."
          }
          else {
            $WindowsImage = $filteredImages[0]
          }
        }
        else {
          List-WindowsImages $WindowsImages
          throw "The filter did not find any WindowsImages (Edition). Choose with -Edition using Name or Index from the list above."
        }
      }            

      Write-LogMessage "Image $($WindowsImage.ImageIndex) selected ""$($WindowsImage.ImageName)""" -logType Verbose

      if ($hyperVEnabled) {
        if (!$IsFixed) {
          Write-LogMessage "Creating sparse disk..." -logType Verbose
          $newVhd = New-VHD -Path $VHDPath -SizeBytes $SizeBytes -BlockSizeBytes $BlockSizeBytes -Dynamic
        }
        else {
          Write-LogMessage "Creating fixed disk..." -logType Verbose
          $newVhd = New-VHD -Path $VHDPath -SizeBytes $SizeBytes -BlockSizeBytes $BlockSizeBytes -Fixed
        }
                
        Write-LogMessage "Mounting $VHDFormat..." -logType Verbose
        $disk = $newVhd | Mount-VHD -PassThru | Get-Disk
      }
      else {
        <#
                    Create the VHD using the VirtDisk Win32 API.
                    So, why not use the New-VHD cmdlet here?

                    New-VHD depends on the Hyper-V Cmdlets, which aren't installed by default.
                    Installing those cmdlets isn't a big deal, but they depend on the Hyper-V WMI
                    APIs, which in turn depend on Hyper-V.  In order to prevent Convert-WindowsImage
                    from being dependent on Hyper-V (and thus, x64 systems only), we're using the
                    VirtDisk APIs directly.
                #>

        Write-LogMessage "Creating VHD disk..." -logType Verbose
        [WIM2VHD.VirtualHardDisk]::CreateVHDDisk(
          $VHDFormat,
          $VHDPath,
          $SizeBytes,
          $true,
          $IsFixed
        )

        # Attach the VHD.\
        Write-LogMessage "Attaching $VHDFormat..." -logType Verbose
        $disk = Mount-DiskImage -ImagePath $VHDPath -PassThru | Get-DiskImage | Get-Disk
      }

      switch ($DiskLayout) {
        "BIOS" {
          Write-LogMessage "Initializing disk..." -logType Verbose
          Initialize-Disk -Number $disk.Number -PartitionStyle MBR

          #
          # Create the Windows/system partition
          #
          Write-LogMessage "Creating single partition..." -logType Verbose
          $systemPartition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -MbrType IFS -IsActive
          $windowsPartition = $systemPartition

          Write-LogMessage "Formatting windows volume..." -logType Verbose
          $systemVolume = Format-Volume -Partition $systemPartition -FileSystem NTFS -Force -Confirm:$false
          $windowsVolume = $systemVolume
        }

        "UEFI" {
          Write-LogMessage "Initializing disk..." -logType Verbose
          Initialize-Disk -Number $disk.Number -PartitionStyle GPT

          if ((Get-WindowsBuildNumber) -ge 10240) {
            #
            # Create the system partition.  Create a data partition so we can format it, then change to ESP
            #
            Write-LogMessage "Creating EFI system partition..." -logType Verbose
            $systemPartition = New-Partition -DiskNumber $disk.Number -Size 200MB -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'

            Write-LogMessage "Formatting system volume..." -logType Verbose
            $systemVolume = Format-Volume -Partition $systemPartition -FileSystem FAT32 -Force -Confirm:$false

            Write-LogMessage "Setting system partition as ESP..." -logType Verbose
            $systemPartition | Set-Partition -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
            $systemPartition | Add-PartitionAccessPath -AssignDriveLetter
          }
          else {
            #
            # Create the system partition
            #
            Write-LogMessage "Creating EFI system partition (ESP)..." -logType Verbose
            $systemPartition = New-Partition -DiskNumber $disk.Number -Size 200MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter

            Write-LogMessage "Formatting ESP..." -logType Verbose
            $formatArgs = @(
              "$($systemPartition.DriveLetter):", # Partition drive letter
              "/FS:FAT32", # File system
              "/Q", # Quick format
              "/Y"                                # Suppress prompt
            )

            Run-Executable -Executable format -Arguments $formatArgs
          }

          #
          # Create the reserved partition
          #
          Write-LogMessage "Creating MSR partition..." -logType Verbose
          $reservedPartition = New-Partition -DiskNumber $disk.Number -Size 128MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'

          #
          # Create the Windows partition
          #
          Write-LogMessage "Creating windows partition..." -logType Verbose
          $windowsPartition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'

          Write-LogMessage "Formatting windows volume..." -logType Verbose
          $windowsVolume = Format-Volume -Partition $windowsPartition -FileSystem NTFS -Force -Confirm:$false
        }

        "WindowsToGo" {
          Write-LogMessage "Initializing disk..." -logType Verbose
          Initialize-Disk -Number $disk.Number -PartitionStyle MBR

          #
          # Create the system partition
          #
          Write-LogMessage "Creating system partition..." -logType Verbose
          $systemPartition = New-Partition -DiskNumber $disk.Number -Size 350MB -MbrType FAT32 -IsActive

          Write-LogMessage "Formatting system volume..." -logType Verbose
          $systemVolume = Format-Volume -Partition $systemPartition -FileSystem FAT32 -Force -Confirm:$false

          #
          # Create the Windows partition
          #
          Write-LogMessage "Creating windows partition..." -logType Verbose
          $windowsPartition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -MbrType IFS

          Write-LogMessage "Formatting windows volume..." -logType Verbose
          $windowsVolume = Format-Volume -Partition $windowsPartition -FileSystem NTFS -Force -Confirm:$false
        }
      }

      #
      # Assign drive letter to Windows partition.  This is required for bcdboot
      #

      $attempts = 1
      $assigned = $false

      do {
        $windowsPartition | Add-PartitionAccessPath -AssignDriveLetter
        $windowsPartition = $windowsPartition | Get-Partition
        if ($windowsPartition.DriveLetter -ne 0) {
          $assigned = $true
        }
        else {
          #sleep for up to 10 seconds and retry
          Get-Random -Minimum 1 -Maximum 10 | Start-Sleep

          $attempts++
        }
      }
      while ($attempts -le 100 -and -not($assigned))

      if (-not($assigned)) {
        throw "Unable to get Partition after retry"
      }

      $windowsDrive = $(Get-Partition -Volume $windowsVolume).AccessPaths[0].substring(0, 2)
      Write-LogMessage "Windows path ($windowsDrive) has been assigned." -logType Verbose
      Write-LogMessage "Windows path ($windowsDrive) took $attempts attempts to be assigned." -logType Verbose

      #
      # Refresh access paths (we have now formatted the volume)
      #
      $systemPartition = $systemPartition | Get-Partition
      $systemDrive = $systemPartition.AccessPaths[0].trimend("\").replace("\?", "??")
      Write-LogMessage "System volume location: $systemDrive" -logType Verbose

      ####################################################################################################
      # APPLY IMAGE FROM WIM TO THE NEW VHD
      ####################################################################################################

      Write-LogMessage "Applying image to $VHDFormat. This could take a while..." -logType Verbose
      if ((Get-Command Expand-WindowsImage -ErrorAction SilentlyContinue) -and ((-not $ApplyEA) -and ([string]::IsNullOrEmpty($DismPath)))) {
        Expand-WindowsImage -ApplyPath $windowsDrive -ImagePath $SourcePath -Index $WindowsImage.ImageIndex -LogPath "$($logFolder)\DismLogs.log" | Out-Null
      }
      else {
        if (![string]::IsNullOrEmpty($DismPath)) {
          $dismPath = $DismPath
        }
        else {
          $dismPath = $(Join-Path (get-item env:\windir).value "system32\dism.exe")
        }

        $applyImage = "/Apply-Image"
        if ($ApplyEA) {
          $applyImage = $applyImage + " /EA"
        }

        $dismArgs = @("$applyImage /ImageFile:`"$SourcePath`" /Index:$($WindowsImage.ImageIndex) /ApplyDir:$windowsDrive /LogPath:`"$($logFolder)\DismLogs.log`"")
        Write-LogMessage "Applying image: $dismPath $dismArgs" -logType Verbose
        $process = Start-Process -Passthru -Wait -NoNewWindow -FilePath $dismPath `
          -ArgumentList $dismArgs `

        if ($process.ExitCode -ne 0) {
          throw "Image Apply failed! See DismImageApply logs for details"
        }
      }
      Write-LogMessage "Image was applied successfully. " -logType Verbose

      #
      # Here we copy in the unattend file (if specified by the command line)
      #
      Get-PSDrive -PSProvider FileSystem | Out-Null
      if (![string]::IsNullOrEmpty($UnattendPath)) {
        Write-LogMessage "Applying unattend file ($(Split-Path $UnattendPath -Leaf))..." -logType Verbose
        Copy-Item -Path $UnattendPath -Destination (Join-Path $windowsDrive "unattend.xml") -Force
      }

      if (![string]::IsNullOrEmpty($MergeFolderPath)) {
        Write-LogMessage "Applying merge folder ($MergeFolderPath)..." -logType Verbose
        Copy-Item -Recurse -Path (Join-Path $MergeFolderPath "*") -Destination $windowsDrive -Force #added to handle merge folders
      }

      if ( $BcdInVhd -ne "NativeBoot" ) {
        if (Test-Path "$($systemDrive)\boot\bcd") {
          Write-LogMessage "Image already has BIOS BCD store..." -logType Verbose
        }
        elseif (Test-Path "$($systemDrive)\efi\microsoft\boot\bcd") {
          Write-LogMessage "Image already has EFI BCD store..." -logType Verbose
        }
        else {
          $BcdEdit = "BCDEDIT.EXE"
                    
          If (Test-Path -Path "$($env:WINDIR)\sysnative\") {
            Write-Verbose -Message "Powershell is not running as native, switching to sysnative paths for native tools"
            $BcdEdit = Join-Path -Path "$($env:WINDIR)\sysnative\" -ChildPath $BcdEdit

            # Update bcdboot parameter only if not specified by caller
            If (-Not $PSBoundParameters.ContainsKey('BcdBoot')) {
              $BcdBoot = Join-Path -Path "$($env:WINDIR)\sysnative\" -ChildPath $BcdBoot
            }
          }

          Write-LogMessage "Making image bootable..." -logType Verbose
          $bcdBootArgs = @(
            "$($windowsDrive)\Windows", # Path to the \Windows on the VHD
            "/s $systemDrive", # Specifies the volume letter of the drive to create the \BOOT folder on.
            "/v"                        # Enabled verbose logging.
          )

          switch ($DiskLayout) {
            "BIOS" {
              $bcdBootArgs += "/f BIOS"   # Specifies the firmware type of the target system partition
            }

            "UEFI" {
              $bcdBootArgs += "/f UEFI"   # Specifies the firmware type of the target system partition
            }

            "WindowsToGo" {
              # Create entries for both UEFI and BIOS if possible
              if (Test-Path "$($windowsDrive)\Windows\boot\EFI\bootmgfw.efi") {
                $bcdBootArgs += "/f ALL"
              }
            }
          }

          Run-Executable -Executable $BCDBoot -Arguments $bcdBootArgs

          # The following is added to mitigate the VMM diff disk handling
          # We're going to change from MBRBootOption to LocateBootOption.

          if ($DiskLayout -eq "BIOS") {
            Write-LogMessage "Fixing the Device ID in the BCD store on $($VHDFormat)..." -logType Verbose
            Run-Executable -Executable $BcdEdit -Arguments (
              "/store $($systemDrive)\boot\bcd",
              "/set `{bootmgr`} device locate"
            )
            Run-Executable -Executable $BcdEdit -Arguments (
              "/store $($systemDrive)\boot\bcd",
              "/set `{default`} device locate"
            )
            Run-Executable -Executable $BcdEdit -Arguments (
              "/store $($systemDrive)\boot\bcd",
              "/set `{default`} osdevice locate"
            )
          }
        }

        Write-LogMessage "Drive is bootable.  Cleaning up..." -logType Verbose

        # Are we turning the debugger on?
        if ($EnableDebugger -inotlike "None") {
          $bcdEditArgs = $null;

          # Configure the specified debugging transport and other settings.
          switch ($EnableDebugger) {
            "Serial" {
              $bcdEditArgs = @(
                "/dbgsettings SERIAL",
                "DEBUGPORT:$($ComPort.Value)",
                "BAUDRATE:$($BaudRate.Value)"
              )
            }

            "1394" {
              $bcdEditArgs = @(
                "/dbgsettings 1394",
                "CHANNEL:$($Channel.Value)"
              )
            }

            "USB" {
              $bcdEditArgs = @(
                "/dbgsettings USB",
                "TARGETNAME:$($Target.Value)"
              )
            }

            "Local" {
              $bcdEditArgs = @(
                "/dbgsettings LOCAL"
              )
            }

            "Network" {
              $bcdEditArgs = @(
                "/dbgsettings NET",
                "HOSTIP:$($IP.Value)",
                "PORT:$($Port.Value)",
                "KEY:$($Key.Value)"
              )
            }
          }

          $bcdStores = @(
            "$($systemDrive)\boot\bcd",
            "$($systemDrive)\efi\microsoft\boot\bcd"
          )

          foreach ($bcdStore in $bcdStores) {
            if (Test-Path $bcdStore) {
              Write-LogMessage "Turning kernel debugging on in the $($VHDFormat) for $($bcdStore)..." -logType Verbose
              Run-Executable -Executable $BcdEdit -Arguments (
                "/store $($bcdStore)",
                "/set `{default`} debug on"
              )

              $bcdEditArguments = @("/store $($bcdStore)") + $bcdEditArgs

              Run-Executable -Executable $BcdEdit -Arguments $bcdEditArguments
            }
          }
        }
      }
      else {
        # Don't bother to check on debugging.  We can't boot WoA VHDs in VMs, and
        # if we're native booting, the changes need to be made to the BCD store on the
        # physical computer's boot volume.

        Write-LogMessage "Image applied. It is not bootable." -logType Verbose
      }

      if ($RemoteDesktopEnable -or (-not $ExpandOnNativeBoot)) {
        $hive = Mount-RegistryHive -Hive (Join-Path $windowsDrive "Windows\System32\Config\System")

        if ($RemoteDesktopEnable) {
          Write-LogMessage "Enabling Remote Desktop" -logType Verbose
          Set-ItemProperty -Path "HKLM:\$($hive)\ControlSet001\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        }

        if (-not $ExpandOnNativeBoot) {
          Write-LogMessage "Disabling automatic $VHDFormat expansion for Native Boot" -logType Verbose
          Set-ItemProperty -Path "HKLM:\$($hive)\ControlSet001\Services\FsDepends\Parameters" -Name "VirtualDiskExpandOnMount" -Value 4
        }

        Dismount-RegistryHive -HiveMountPoint $hive
      }

      if ($Driver) {
        Write-LogMessage "Adding Windows Drivers to the Image" -logType Verbose
        $Driver | ForEach-Object -Process {
          Write-LogMessage "Driver path: $PSItem" -logType Verbose
          Add-WindowsDriver -Path $windowsDrive -Recurse -Driver $PSItem -Verbose | Out-Null
        }
      }

      If ($Feature) {
        Write-LogMessage "Installing Windows Feature(s) $Feature to the Image" -logType Verbose
        $FeatureSourcePath = Join-Path -Path "$($driveLetter):" -ChildPath "sources\sxs"
        Write-LogMessage "From $FeatureSourcePath" -logType Verbose
        Enable-WindowsOptionalFeature -FeatureName $Feature -Source $FeatureSourcePath -Path $windowsDrive -All | Out-Null
      }

      if ($Package) {
        Write-LogMessage "Adding Windows Packages to the Image" -logType Verbose

        $Package | ForEach-Object -Process {
          Write-LogMessage "Package path: $PSItem" -logType Verbose
          Add-WindowsPackage -Path $windowsDrive -PackagePath $PSItem | Out-Null
        }
      }

      if ($GPUName) {
        Copy-GPUDrivers -GPUName $GPUName -DrivePath $windowsDrive
      }

      #
      # Remove system partition access path, if necessary
      #
      if ($DiskLayout -eq "UEFI") {
        $systemPartition | Remove-PartitionAccessPath -AccessPath $systemPartition.AccessPaths[0]
      }

      if ([String]::IsNullOrEmpty($vhdFinalName)) {
        # We need to generate a file name.
        Write-LogMessage "Generating name for $($VHDFormat)..." -logType Verbose
        $hive = Mount-RegistryHive -Hive (Join-Path $windowsDrive "Windows\System32\Config\Software")

        $buildLabEx = (Get-ItemProperty "HKLM:\$($hive)\Microsoft\Windows NT\CurrentVersion").BuildLabEx
        $installType = (Get-ItemProperty "HKLM:\$($hive)\Microsoft\Windows NT\CurrentVersion").InstallationType
        $editionId = (Get-ItemProperty "HKLM:\$($hive)\Microsoft\Windows NT\CurrentVersion").EditionID
        $skuFamily = $null

        Dismount-RegistryHive -HiveMountPoint $hive

        # Is this ServerCore?
        # Since we're only doing this string comparison against the InstallType key, we won't get
        # false positives with the Core SKU.
        if ($installType.ToUpper().Contains("CORE")) {
          $editionId += "Core"
        }

        # What type of SKU are we?
        if ($installType.ToUpper().Contains("SERVER")) {
          $skuFamily = "Server"
        }
        elseif ($installType.ToUpper().Contains("CLIENT")) {
          $skuFamily = "Client"
        }
        else {
          $skuFamily = "Unknown"
        }

        #
        # ISSUE - do we want VL here?
        #
        $vhdFinalName = "$($buildLabEx)_$($skuFamily)_$($editionId)_$($WindowsImage[0].ImageDefaultLanguage).$($VHDFormat.ToLower())"
        Write-LogMessage "$VHDFormat final name is : $vhdFinalName" -logType Debug
      }

      if ($hyperVEnabled) {
        Write-LogMessage "Dismounting $VHDFormat..." -logType Verbose
        Dismount-VHD -Path $VHDPath
      }
      else {
        Write-LogMessage "Closing $VHDFormat..." -logType Verbose
        Dismount-DiskImage -ImagePath $VHDPath
      }

      $vhdFinalPath = Join-Path (Split-Path $VHDPath -Parent) $vhdFinalName
      Write-LogMessage "$VHDFormat final path is : $vhdFinalPath" -logType Debug

      if (Test-Path $vhdFinalPath) {
        Write-LogMessage "Deleting pre-existing $VHDFormat : $(Split-Path $vhdFinalPath -Leaf)..." -logType Verbose
        Remove-Item -Path $vhdFinalPath -Force
      }

      Write-LogMessage "Renaming $VHDFormat at $VHDPath to $vhdFinalName" -logType Debug
      Rename-Item -Path (Resolve-Path $VHDPath).Path -NewName $vhdFinalName -Force
      $vhd += Get-DiskImage -ImagePath $vhdFinalPath

      $vhdFinalName = $null
    }
    catch {
      Write-LogMessage $_ -logType Error
      Write-LogMessage "Log folder is $logFolder" -logType Verbose
    }
    finally {
      # If we still have a registry hive mounted, dismount it.
      if ($mountedHive -ne $null) {
        Write-LogMessage "Closing registry hive..." -logType Verbose
        Dismount-RegistryHive -HiveMountPoint $mountedHive
      }

      # If VHD is mounted, unmount it
      if (Test-Path $VHDPath) {
        if ($hyperVEnabled) {
          if ((Get-VHD -Path $VHDPath).Attached) {
            Dismount-VHD -Path $VHDPath
          }
        }
        else {
          Dismount-DiskImage -ImagePath $VHDPath
        }
      }

      # If we still have an ISO open, close it.
      if ($openIso -ne $null) {
        Write-LogMessage "Closing ISO..." -logType Verbose
        Dismount-DiskImage $ISOPath | Out-Null
      }

      if (-not $CacheSource) {
        if ($tempSource -and (Test-Path $tempSource)) {
          Remove-Item -Path $tempSource -Force
        }
      }

      # Close out the transcript and tell the user we're done.
      Write-LogMessage "Done." -logType Verbose
      if ($transcripting) {
        $null = Stop-Transcript
      }
    }
  }

  End {
    if ($Passthru) {
      return $vhd
    }
  }
  #endregion Code

}

function List-WindowsImages {
  [cmdletBinding()]
  param (
    [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline)][Microsoft.Dism.Commands.BasicImageInfoObject[]]$windowsImages
  )
  Write-LogMessage "The following images are in the image:" -logType Warning
  $windowsImages | ForEach-Object { Write-LogMessage "Name: ""$($_.ImageName)"" (Index: $($_.ImageIndex))" -logType Warning }

}


function Write-LogMessage {
  [cmdletBinding()]
  param (
    [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline)][String]$message,
    [Parameter(Position = 1, Mandatory = $False)]
    [ValidateSet('Verbose', 'Debug', 'Error', 'Output', 'Warning', 'Host')][String]$logType = "Output"
  )
		$message = "{0:s} [{1}] $($message.Replace("{","{{").Replace("}","}}"))" -f [DateTime]::UtcNow, $env:computername
  switch ($logType) {
    "Verbose" { $message | Write-Verbose }
    "Debug" { $message | Write-Debug }
    "Error" { $message | Write-Error }
    "Warning" { $message | Write-Warning } 
    "Host" { $message | Write-Host }
    default { $message | Write-Output }
  }
}

function Add-WindowsImageTypes {
  $code = (Get-Content -Path "$PSScriptRoot\Add-WindowsImageTypes.cs") -join "`n"
  Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Xml", "System.Linq", "System.Xml.Linq" -ErrorAction SilentlyContinue
}
