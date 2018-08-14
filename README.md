# vRealize-Automation

## Install Satellite Tools
Use the *installSatelliteTools.sh* script to configure a newly provisioned RH Linux Server with Satellite by way of vRA Software Component. Ensure all variables are configured properly in the software component during configuraiton. Also requres that Satellite be configured with Activation Keys, etc...

## Prepare vRA Template Modified
Modified prepare vRA Template script to support Server 2016 Core. The standard script fails due to the extractZip function using a "shell.application" object to unpack the Java zip archive. In PowerShell 5 or later, a native cmdlet exists to unzip archives. Alternatively to this script you can follow the manual install instructions for the vRA agents which are available in the vRA 7.2 or earlier docs.

## Linux vRA Gugent Disk Setup Script Modified
This script is used by the Gugent to mount and format disks during provisioning. The script that is built-in uses a switch that doesn't work with XFS. In this modified script the switch was removed, and additional functionality was added to support XFS as well as SWAP.
