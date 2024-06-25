function Copy-GPUDrivers {
  param(
    [string] $DrivePath,
    [string] $GPUName = "AUTO"
  )

  if ($GPUName -eq "AUTO") {
    $PartitionableGPUList = Get-WmiObject -Class "Msvm_PartitionableGpu" -ComputerName $ENV:ComputerName -Namespace "ROOT\virtualization\v2"
    $GPUDevicePath = $PartitionableGPUList.Name | Select-Object -First 1
    $GPU = Get-PnpDevice | Where-Object {($_.DeviceID -like "*$($GPUDevicePath.Substring(8, 16))*") -and ($_.Status -eq "OK")} | Select-Object -First 1
    $GPUName = $GPU.Friendlyname
    $GPUServiceName = $GPU.Service 
  } else {
    $GPU = Get-PnpDevice | Where-Object {($_.Name -eq "$GPUName") -and ($_.Status -eq "OK")} | Select-Object -First 1
    $GPUServiceName = $GPU.Service
  }

  New-Item -ItemType Directory -Path "$DrivePath\Windows\System32\HostDriverStore" -Force | Out-Null
  $ServicePath = (Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -eq "$GPUServiceName"}).Pathname
  $ServicePathHost = $servicepath.split('\')[0..5] -join('\')
  $ServicePathVM = ("$DrivePath" + "\" + $($servicepath.split('\')[1..5] -join('\'))).Replace("DriverStore","HostDriverStore")
  Copy-item -Path "$ServicePathHost" -Destination "$ServicePathVM" -Recurse -Force

  $GPUDrivers = Get-WmiObject Win32_PNPSignedDriver | Where-Object {$_.DeviceName -eq "$GPUName"}
  foreach ($GPUDriver in $GPUDrivers) {
    $ModifiedDeviceID = $GPUDriver.DeviceID -Replace "\\", "\\"
    $Antecedent = "\\" + $ENV:ComputerName + "\ROOT\cimv2:Win32_PNPSignedDriver.DeviceID=""$ModifiedDeviceID"""
    $DriverFiles = Get-WmiObject Win32_PNPSignedDriverCIMDataFile | Where-Object {$_.Antecedent -eq $Antecedent}
    $DriverName = $GPUDriver.DeviceName

    if ($DriverName -like "NVIDIA*") {
      New-Item -ItemType Directory -Path "$DrivePath\Windows\System32\drivers\NVIDIA Corporation\" -Force | Out-Null
    }

    foreach ($File in $DriverFiles) {
      $path = $File.Dependent.Split("=")[1] -replace '\\\\', '\'
      $path2 = $path.Substring(1,$path.Length-2)
      If ($path2 -like "c:\windows\system32\driverstore\*") {
        $DriverDir = $path2.split('\')[0..5] -join('\')
        $driverDest = ("$DrivePath" + "\" + $($path2.split('\')[1..5] -join('\'))).Replace("driverstore","HostDriverStore")
        if (!(Test-Path $driverDest)) {
          Copy-item -path "$DriverDir" -Destination "$driverDest" -Recurse
        }
      } else {
        $ParseDestination = $path2.Replace("c:", "$DrivePath")
        $Destination = $ParseDestination.Substring(0, $ParseDestination.LastIndexOf('\'))
        if (!$(Test-Path -Path $Destination)) {
          New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        Copy-Item $path2 -Destination $Destination -Force
      }
    }
  }
}
