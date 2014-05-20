Posh-RecoverPoint
=================

PowerShell v4.0 or higher module for interacting with the EMC RecoverPoint 4.0 REST API

With RecoverPoint 4.0, I decided to throw away my plink xml wrappers and re-write my cmdlets using the native REST API. In an effort to support the community, I thought I would share my progress here. Feel free to use the modules and provide any feedback in this thread. I will try to reply back in a short amount of time.
 
Please note, this is my first attempt at creating a module for use in the community. It is a work in progress. Use at your own risk.
 
The latest updates should always be found here as well as on the EMC community site https://community.emc.com/thread/194087

Because the REST integration in Powershell v3.0 was buggy, this module requires Powershell v4.0 or greater installed.

Version 0.1
========
Connect-RPAppliance
Disconnect-RPAppliance
Get-RPGroup
Get-RPGroupReplicationSet
Get-RPGroupReplicationSetVolume
Get-RPGroupState
Get-RPRest
 
Installation: After downloading, right click Zip file and click Properties. Click the Unblock button.
Unzip the contents to the default module location of your choice. For example, C:\Windows\System32\WindowsPowerShell\v1.0\Modules.
From PowerShell, run "import-module Posh-RecoverPoint"
 
The cmdlets are documented with descriptions and examples. To access, type get-help and the cmdlet, for example: get-help Get-RPGroupReplicationSet -full
 
Thanks to everyone who help support the Powershell community. A special shout out goes to Hal and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
