# Use this script to automatically create the VM, the Disks and the GPU partition.

Import-Module "$PSScriptRoot\lib\Convert-WindowsImage.psm1"

enum Edition {
  Home = 1
  HomeN = 2
  HomeSingleLanguage = 3
  Education = 4
  EducationN = 5
  Professional = 6
  ProfessionalN = 7
  ProfessionalEducation = 8
  ProfessionalEducationN = 9
  ProfessionalWorkstation = 10
  ProfessionalWorkstationN = 11
}

$VMOptions = @{
  VMName       = "Windows 11"
  ISOPath      = "$ENV:UserProfile\Downloads\Win11_23H2_English_x64v2.iso"
  Edition      = [Edition]::Professional
  DiskBytes    = 80GB
  RAMBytes     = 8GB
  CPUCores     = 8
  VHDXPath     = "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\Windows 11.vhdx"
  UnattendPath = "$PSScriptRoot\data\unattend.xml"
  GPUName      = "AUTO"
  GPUPartition = 75
}

if (!(Test-Path $VMOptions.VHDXPath)) {
  Convert-WindowsImage -SourcePath $VMOptions.ISOPath -Edition ([int]$VMOptions.Edition) -VHDFormat "VHDX" -VHDPath $VMOptions.VHDXPath -DiskLayout "UEFI" -UnattendPath $VMOptions.UnattendPath -GPUName $VMOptions.GPUName -SizeBytes $VMOptions.DiskBytes | Out-Null
}

if (!(Test-Path $VMOptions.VHDXPath)) {
  Write-Error "VHDX creation failed!"
  exit 1
}

$ConfigurationVersion = (Get-VMHostSupportedVersion).Version | Where-Object {$_.Major -lt 254} | Select-Object -Last 1 
New-VM -Name ($VMOptions.VMName) -MemoryStartupBytes ($VMOptions.RAMBytes) -VHDPath ($VMOptions.VHDXPath) -Generation 2 -SwitchName "Default Switch" -Version $ConfigurationVersion | Out-Null
Set-VM -Name ($VMOptions.VMName) -ProcessorCount ($VMOptions.CPUCores) -CheckpointType Disabled -LowMemoryMappedIoSpace 1GB -HighMemoryMappedIoSpace 8GB -GuestControlledCacheTypes $true -AutomaticStopAction ShutDown
Set-VMMemory -VMName ($VMOptions.VMName) -DynamicMemoryEnabled $false 
Set-VMProcessor -VMName ($VMOptions.VMName) -ExposeVirtualizationExtensions $true
Set-VMVideo -VMName ($VMOptions.VMName) -HorizontalResolution 1280 -VerticalResolution 800
Set-VMKeyProtector -VMName ($VMOptions.VMName) -NewLocalKeyProtector
Enable-VMTPM -VMName ($VMOptions.VMName)
Add-VMDvdDrive -VMName ($VMOptions.VMName) -Path ($VMOptions.ISOPath)

$PartitionableGPUList = Get-WmiObject -Class "Msvm_PartitionableGpu" -ComputerName $env:COMPUTERNAME -Namespace "ROOT\virtualization\v2" 
if (($VMOptions.GPUName) -eq "AUTO") {
  $DevicePathName = $PartitionableGPUList.Name[0]
  Add-VMGpuPartitionAdapter -VMName ($VMOptions.VMName)
} else {
  $DeviceID = ((Get-WmiObject Win32_PNPSignedDriver | Where-Object {($_.Devicename -eq ($VMOptions.GPUName))}).HardwareId).split('\')[1]
  $DevicePathName = ($PartitionableGPUList | Where-Object name -like "*$DeviceID*").Name
  Add-VMGpuPartitionAdapter -VMName ($VMOptions.VMName) -InstancePath $DevicePathName
}

[float] $div = [math]::round($(100 / ($VMOptions.GPUPartition)), 2)
Set-VMGpuPartitionAdapter -VMName ($VMOptions.VMName) -MinPartitionVRAM ([math]::round($(1000000000 / $div))) -MaxPartitionVRAM ([math]::round($(1000000000 / $div))) -OptimalPartitionVRAM ([math]::round($(1000000000 / $div)))
Set-VMGPUPartitionAdapter -VMName ($VMOptions.VMName) -MinPartitionEncode ([math]::round($(18446744073709551615 / $div))) -MaxPartitionEncode ([math]::round($(18446744073709551615 / $div))) -OptimalPartitionEncode ([math]::round($(18446744073709551615 / $div)))
Set-VMGpuPartitionAdapter -VMName ($VMOptions.VMName) -MinPartitionDecode ([math]::round($(1000000000 / $div))) -MaxPartitionDecode ([math]::round($(1000000000 / $div))) -OptimalPartitionDecode ([math]::round($(1000000000 / $div)))
Set-VMGpuPartitionAdapter -VMName ($VMOptions.VMName) -MinPartitionCompute ([math]::round($(1000000000 / $div))) -MaxPartitionCompute ([math]::round($(1000000000 / $div))) -OptimalPartitionCompute ([math]::round($(1000000000 / $div)))

vmconnect localhost ($VMOptions.VMName)
