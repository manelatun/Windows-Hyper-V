# Hyper-V GPU
Create VMs with GPU acceleration on Hyper-V.

## Instructions
1. Edit the `$VMOptions` variable in the `CreateVM.ps1` script to configure your VM.
2. Copy the `unattend-base.xml` file to `unattend.xml` and set your username and password.
3. Open Powershell with Administrator privileges and execute `CreateVM.ps1`.
4. You can now launch your VM from Hyper-V Manager!

> If the VM's VHDX already exists, `CreateVM.ps1` will only create the VM and GPU partition.<br/>
> If you wish, you can back up your VHDX and import it using the `CreateVM.ps1` script.

## Thanks ✨
* [Easy-GPU-PV](https://github.com/jamesstringerparsec/Easy-GPU-PV/) by James Stringer and contributors as most of this repo's scripts are based on their work.
* [Convert-WindowsImage](https://github.com/x0nn/Convert-WindowsImage) by Microsoft and mantained by x0nn for providing a working up-to-date version of the `Convert-WindowsImage` utility.
