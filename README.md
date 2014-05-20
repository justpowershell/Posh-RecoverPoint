Posh-RecoverPoint
=========

PowerShell v4.0 or higher module for interacting with the EMC RecoverPoint 4.0 REST API

With RecoverPoint 4.0, I decided to throw away my plink xml wrappers and re-write my cmdlets using the native REST API. In an effort to support the community, I thought I would share my progress here. Feel free to use the modules and provide any feedback in this thread. I will try to reply back in a short amount of time.

Please note, this is my first attempt at creating a module for use in the community. It is a work in progress. Use at your own risk.

The latest updates should always be found here as well as on the EMC community site EMC community site https://community.emc.com/thread/194087

Version
----

0.1

cmdlets
-----------

More cmdlets will be added as the versions progress. The current published cmdlets are:

* Connect-RPAppliance
* Disconnect-RPAppliance
* Get-RPGroup
* Get-RPGroupReplicationSet
* Get-RPGroupReplicationSetVolume
* Get-RPGroupState
* Get-RPRest

Installation
--------------
Save psm1 and psd1 into Posh-RecoverPoint folder in your modules directory
```ps
import-module Posh-RecoverPoint
```

License
----

MIT
