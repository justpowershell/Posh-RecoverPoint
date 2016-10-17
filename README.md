Posh-RecoverPoint
=========

NOTE: Unfortunately, we no longer have RecoverPoint in our environment so I am no longer able to maintain this project. I hope you are able to use it as a good starting point for managing your RP environment.

PowerShell v4.0 or higher module for interacting with the EMC RecoverPoint 4.0 REST API

With RecoverPoint 4.0, I decided to throw away my plink xml wrappers and re-write my cmdlets using the native REST API. In an effort to support the community, I thought I would share my progress here. Feel free to use the modules and provide any feedback in this thread. I will try to reply back in a short amount of time.

Please note, this is my first attempt at creating a module for use in the community. It is a work in progress. Use at your own risk.

The latest updates should always be found here as well as on the EMC community site EMC community site https://community.emc.com/thread/194087

Version
----

0.2

cmdlets
-----------

More cmdlets will be added as the versions progress. The current published cmdlets are:

* Connect-RPAppliance
* Disable-RPImageAccess
* Disconnect-RPAppliance
* Enable-RPImageAccess
* Get-RPAccount
* Get-RPAlertSetting
* Get-RPCluster
* Get-RPConfiguration
* Get-RPGroup
* Get-RPGroupCopy
* Get-RPGroupCopyPolicy
* Get-RPGroupLink
* Get-RPGroupReplicationSet
* Get-RPGroupReplicationSetVolume
* Get-RPGroupSet
* Get-RPGroupUID
* Get-RPImage
* Get-RPImageAccess
* Get-RPLDAPSetting
* Get-RPLicense
* Get-RPMiscSetting
* Get-RPReportSetting
* Get-RPRole
* Get-RPSNMPSetting
* Get-RPUser
* Invoke-RPRestGet
* Invoke-RPRestPost
* New-RPBookmark
* Remove-RPConfiguration
* Set-RPConfiguration


Changelog
--------------
v0.2:
* fixed several bugs, including running get-rpgroup with a filtered parameter would overwrite the global $rproups.
* changed several cmdlets names to be canonical with PowerShell
* get-rpgroup is now get-rpgroupuid. get-rpgroup gets more information about the CG
* set the default connect-rpappliance to not ignore SSL cert
* added several more cmdlets

v0.1: initial commit

Installation
--------------
Save psm1 and psd1 into Posh-RecoverPoint folder in your modules directory
```ps
import-module Posh-RecoverPoint
```

License
----

MIT
