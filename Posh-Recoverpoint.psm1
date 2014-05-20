function to-kmg { 
    param ($bytes,$precision='0') 
    foreach ($i in ("Bytes","KB","MB","GB","TB")) { 
        if (($bytes -lt 1000) -or ($i -eq "TB")){ 
            $bytes = ($bytes).tostring("F0" + "$precision") 
            return $bytes + " $i" 
        } else {
            $bytes /= 1KB
        } 
    } 
<#
.SYNOPSIS
   Displays data sizes in human readable format
.DESCRIPTION
   See Synopsis
.NOTE
   This function is not exported
.EXAMPLE
   to-kmg "100923288434"
#>
}# End Function
function to-customobject{
    [CmdletBinding()]
    Param
    (
        # Sets property values.
        [Parameter(Mandatory=$false,
                   Position=0)]
        [ValidateNotNull()]
        [System.Collections.IDictionary]
        $Property,
 
        # Sets read-only property values.
        [Parameter(Mandatory=$false,
                   Position=1)]
        [ValidateNotNull()]
        [System.Collections.IDictionary]
        $ScriptProperty,
 
        # Adds methods.
        [Parameter(Mandatory=$false,
                   Position=2)]
        [ValidateNotNull()]
        [System.Collections.IDictionary]
        $ScriptMethod,
 
        # Custom TypeName to assign the object.
        [Parameter(Mandatory=$false,
                   Position=3)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TypeName,
 
        # Defines the default display properties.
        [Parameter(Mandatory=$false,
                   Position=4)]
        [string[]]
        $DefaultProperty
    )
 
    function ConvertTo-ScriptBlock($value) {
        if ($value -is [ScriptBlock]) {
            $value
        } else {
            { $value }.GetNewClosure()
        }
    }
 
    $obj = New-Object PSObject -Property $Property
    if ($ScriptProperty) {
        $ScriptProperty.GetEnumerator() | ForEach-Object {
            $obj | Add-Member -MemberType ScriptProperty -Name $_.Key -Value (ConvertTo-ScriptBlock $_.Value)
        }
    }
    if ($ScriptMethod) {
        $ScriptMethod.GetEnumerator() | ForEach-Object {
            $obj | Add-Member -MemberType ScriptMethod -Name $_.Key -Value (ConvertTo-ScriptBlock $_.Value)
        }
    }
    if ($TypeName) {
        $obj.PSTypeNames.Insert(0, $TypeName)
    }
    if ($DefaultProperty) {
        $set = New-Object System.Management.Automation.PSPropertySet -ArgumentList 'DefaultDisplayPropertySet',$DefaultProperty
        $members = [System.Management.Automation.PSMemberInfo[]]@($set)
        $obj | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $members
    }
    $obj
<#
.SYNOPSIS
   Creates a new custom object.
.DESCRIPTION
   Creates a new custom PSObject with optional type information.
.NOTE
   This function is not exported
.EXAMPLE
   to-customobject -TypeName MyCustomType ([ordered]@{ FirstName = 'Bob'; LastName = 'Jones' }) -ScriptProperty @{ FullName = { $this.FirstName + " " + $this.LastName } } -DefaultProperty FirstName,LastName
 
   Creates a new custom object with the TypeName MyCustomType and default display properties FirstName and LastName.
#>
}# End Function
function Connect-Appliance {
   Param(  
      [Parameter(Position=0,  
         Mandatory=$True,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [String]$IPAddress,  
      [Parameter(Position=1,  
         Mandatory=$False,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [Int]$PortNumber=443,  
      [Parameter(Position=2,  
         Mandatory=$True,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [System.Management.Automation.PSCredential]$Credentials  
   )  
   $connection = ""
   #'---------------------------------------------------------------------------  
   #'Bypass SSL certificate confirmation until CA signed certificates can be loaded
   # on the appliances without causing stability issues. 
   #'---------------------------------------------------------------------------  
   #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True}  
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
 
   [String]$uri = "https://$ipAddress`:$portNumber/fapi/rest/4_0"  
   Try{  
      $connection = Invoke-RestMethod -uri $uri -Credential $credentials -method Get -ErrorAction Stop  
      $returnobj = to-customobject -TypeName MyCustomType ([ordered]@{
                BaseURL     = $uri
                Credentials = $credentials
            })
            $results += $resultobj
      $global:DefaultRPA = $returnobj
      Return $returnobj
   }Catch{  
      Write-Host ("Error """ + $Error[0] + """ Connecting to ""$uri""")  
      Break;  
   }  

<# 
.SYNOPSIS 
    Connects to a RecoverPoint appliance. 
.DESCRIPTION 
    Connects to a RecoverPoint appliance or the management interface
    via the REST API using the supplied credentials. If successful,  
    the chdlet saves the IP and credentials into the global variable
    $DefaultRPA for use by other cmdlets.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE 
    Connect-RPAppliance
.EXAMPLE 
    Connect-RPAppliance -IPAddress 192.168.0.100 -PortNumber 443 -Credentials (get-credentials)
.PARAMETER IPaddress
   Required. The IP address of the appliance, or the shared management address you want to connect to. 
.PARAMETER Port
   The TCP port to connect to. Default is 443.
   Does not appear at all. 
.PARAMETER Credential
   Required. The local credential of an account with sufficient permissions on the RecoverPoint Appliance. 
#>  

}#End Function
function Disconnect-Appliance {
	$Global:DefaultRPA = $null
<# 
.SYNOPSIS 
    Disconnects from a RecoverPoint appliance. 
.DESCRIPTION 
    All this function does is set the DefaultRPA variable to none. 
    Because there is no persistent connection to the RPA, this 
    function serves as way to more closely emulate other cmdlets that
    connect and disconnect.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE 
    Disconnect-RPAppliance
#>  
}#End Function
function Get-Rest {
   Param(  
      [Parameter(Position=0,  
         Mandatory=$True,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]
         [String]$resource  
    )
    If (!$DefaultRPA){
        Write-Host -ForegroundColor Red "No default RPA address found. Please run Connect-RPAppliance before running this cmdlet."
        Break;
    } else {
        try {
            $results = @()
            $URI = $DefaultRPA.BaseURL + $resource
            return Invoke-RestMethod -uri $URI -Method Get -Credential $DefaultRPA.Credentials
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to ""$URI""")  
        }
    }
<# 
.SYNOPSIS 
    Returns the results of a REST API call via GET to the RecoverPoint Web Services API 
.DESCRIPTION 
    This function is mostly used by other functions. It takes the 
    resource parameter and combines it with the $DefaultRPA BaseURL
    to form a URI that will be used for querying via REST API.
    $DefaultRPA must be defined (via connect-rpappliance) before running. 
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE 
    Get-RPRest /settings/groups/all_uids
.PARAMETER resource
   Required. The URL resource to be queried. Must start with a "/" 
#>  
}#End Function
function Get-Group{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*"
    )
    begin {
        $results = @()
        $return = @()  
        Write-Verbose "$(get-date) Starting Get-RPGroupUID"
        $resource = "/settings/groups/all_uids"
        $CGUIDs = Get-Rest $resource
        foreach ($CGUID in $CGUIDs){
            try {
                $resource = "/settings/groups/$($CGUID.id)/name"
                $cgnamestr = Get-Rest $resource
                if ($cgnamestr -like $CGName){
                    $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                        CGName = $CGNamestr
                        CGUID  = $CGUID.id
                    })
                    $results += $resultobj
                }
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break;
            }
        }
    }
    process {
        $return += $results | where {$_.CGName -like $CGname}
    } end {
        Write-Verbose "$(get-date) Completing Get-RPGroupUID"
        $script:rpgroups = $return
        return $return | sort CGName
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) names and uids
.DESCRIPTION 
    Almost all of the REST API's that query consistency groups 
    require the group's UID. If no parameter is specified, this 
    function will return all consistency groups by their name and their UID. 
    Note, this function makes serveral API calls (one per CG) and can be 
    slow if you have a lot of CG's. Since this function is used by all of 
    the other group functions, the results are saved in the $rpgroups variable 
    within the script scope in order to optimize subsequent lookups.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroup
.EXAMPLE
    Get-RPGroup CG001
.EXAMPLE
    Get-RPGroup CG00*
.EXAMPLE
    "CG001","CG002" | Get-RPGroupUID
.PARAMETER CGname
   Optional. The name of the consistency group(s) to be queried. 
#>  
}#End Function
function Get-GroupState {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*"
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-Group }
        Write-Verbose "$(get-date) Starting Get-RPGroup"
    }
    process {
        $CGs = @($rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/state/groups/$($CGUID)"
                $cgstate = Get-RPRest $resource
                $cgcopystate = $cgstate | select -ExpandProperty groupCopiesState
                $cglinkstate = $cgstate | select -ExpandProperty linksState
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName      = $CG.CGName
                    CGUID       = $CGUID
                    isEnabled   = $cgstate.enabled
                    Transfer    = $cglinkstate.pipeState
                    ActiveRPA   = $cgcopystate.activePrimaryRPA[0]
                }) -DefaultProperty CGName,isEnabled,Transfer,ActiveRPA
                $results += $resultobj
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break;
            }
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroupState"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) state
.DESCRIPTION 
    This function attempts to mimic the "All Consistency Groups" screen in Unisphere for RecoverPoint.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroupState
.EXAMPLE
    Get-RPGroupState CG001
.EXAMPLE
    Get-RPGroupState CG00*
.EXAMPLE
    "CG001","CG002" | Get-RPGroupState
.EXAMPLE
    Get-RPGroupState | Where {$_.Transfer -ne "Active"}
.PARAMETER CGname
   Optional. The name of the consistency group(s) to be queried. 
#>  
}#End Function}
function Get-GroupReplicationSet{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*"
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-Group }

        Write-Verbose "$(get-date) Starting Get-RPGroupReplicationSet"
    }
    process {
        $CGs = @($rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/settings/groups/$($CGUID)/full"
                $cgsettings = Get-Rest $resource
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break; 
            }
            $cgrepsets = $cgsettings | select -ExpandProperty replicationSetsSettings
            $cgcopysets = $cgsettings | select -ExpandProperty groupCopiesSettings
            $activeCopyUID = ($cgcopysets | where {($_.roleinfo).role -eq "Active"} | select -ExpandProperty copyUID | select -expand globalCopyUID).copyUID
            $activeCopyClusterUID = ($cgcopysets | where {($_.roleinfo).role -eq "Active"} | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID | select -ExpandProperty clusterUID).id
            foreach ($cgrepset in $cgrepsets){
                $volumes = $cgrepset | select -ExpandProperty Volumes
                $sourcevol = $volumes | where {(($_.GroupCopyUID | select -ExpandProperty GlobalCopyUID).CopyUID -eq $activeCopyUID) -and (($_.GroupCopyUID | select -ExpandProperty GlobalCopyUID | select -ExpandProperty clusterUID).id -eq $activeCopyClusterUID)}
                $targetvol = $volumes | where {(($_.GroupCopyUID | select -ExpandProperty GlobalCopyUID).CopyUID -ne $activeCopyUID) -or (($_.GroupCopyUID | select -ExpandProperty GlobalCopyUID | select -ExpandProperty clusterUID).id -ne $activeCopyClusterUID)}
            
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName      = $CG.CGName
                    CGUID       = $CGUID
                    RepSetName  = $cgrepset.replicationSetName
                    RepSetUID   = ($cgrepset | select -ExpandProperty replicationSetUID | select -ExpandProperty groupUID).id
                    sizeinbytes = $cgrepset.sizeInBytes
                    size        = to-kmg $cgrepset.sizeInBytes
                    SourceDev   = ($sourcevol | select -ExpandProperty volumeInfo).volumeName -replace "^DEV ID: ",""
                    TargetDev   = ($targetvol | select -ExpandProperty volumeInfo).volumeName -replace "^DEV ID: ",""
                }) -DefaultProperty RepSetName,Size,SourceDev,TargetDev
                $results += $resultobj
            }
        }
    } 
    end {
         Write-Verbose "$(get-date) Completing Get-RPGroupReplicationSet"
         return $results
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group Replication Sets
.DESCRIPTION 
    Consistency groups are comprised of one or more replication sets. Each replication 
    set consists of a production volume and any local or remote copy volumes to which 
    it is replicating. The number of replication sets in your system is equal to the 
    number of production volumes being replicated.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroupReplicationSet -CGName CG001
.EXAMPLE
    Get-RPGroupReplicationSet CG00*
.EXAMPLE
    "CG001","CG002" | Get-RPGroupReplicationSet
.EXAMPLE
    Get-RPGroup CG001 | Get-RPGroupReplicationSet
.EXAMPLE
    Get-RPGroup | select -first 10 | Get-RPGroupReplicationSet | ft *
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
#>  
}#End Function
function Get-GroupReplicationSetVolume{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*",
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$RepSetName="*",
        [Parameter(Position=2,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$copyName="*"
    )
    begin {
        $results = @()
        $return = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-Group }
        Write-Verbose "$(get-date) Starting Get-RPGroupReplicationSetVolume"
    }
    process {
        Write-Verbose "$(get-date) $CGName"
        $CGs = @($rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/settings/groups/$($CGUID)/full"
                $cgsettings = Get-Rest $resource
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break; 
            }
            $cgrepsets = $cgsettings | select -ExpandProperty replicationSetsSettings
            $cgcopysets = $cgsettings | select -ExpandProperty groupCopiesSettings
            foreach ($cgrepset in $cgrepsets){
                $volumes = $cgrepset | select -ExpandProperty Volumes
                foreach ($volume in $volumes){
                    $cgcopyUID = ($volume.GroupCopyUID | select -ExpandProperty GlobalCopyUID).CopyUID
                    $cgClusterUID = ($volume.GroupCopyUID | select -ExpandProperty GlobalCopyUID | select -ExpandProperty clusterUID).id
                    $cgcopy = $cgcopysets | where {(($_ | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID | select -ExpandProperty clusterUID).id -eq $cgClusterUID) -and (($_ | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID).copyUID -eq $cgcopyUID)}
                    $volumeinfo = $volume | select -ExpandProperty volumeInfo
                    $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                        CGName                    = $CG.CGName
                        CGUID                     = $CGUID
                        RepSetName                = $cgrepset.replicationSetName
                        RepSetUID                 = ($cgrepset | select -ExpandProperty replicationSetUID | select -ExpandProperty groupUID).id
                        CopyName                  = $cgcopy.name
                        volumeId                  = ($volumeinfo | select -expand volumeID).id
                        vendorName                = $volumeinfo.vendorName
                        productName               = $volumeinfo.productName
                        modelName                 = $volumeinfo.modelName
                        sizeInBytes               = $volumeinfo.sizeInBytes
                        Size                      = to-kmg $volumeinfo.sizeInBytes
                        vendorSpecificInformation = $volumeinfo.vendorSpecificInformation
                        volumeName                = $volumeinfo.volumeName
                        serialNumber              = $volumeinfo.serialNumber
                        onArrayWithRepository     = $volumeinfo.onArrayWithRepository
                        volumeStorageType         = $volumeinfo.volumeStorageType
                        hasLicense                = $volumeinfo.hasLicense
                        tagged                    = $volumeinfo.tagged

                    }) -DefaultProperty CopyName,RepSetName,vendorName,volumeStorageType,Size,volumeName,serialNumber
                    $results += $resultobj | where {$_.RepSetName -like $RepSetName -and $_.CopyName -like $copyName}
                }

            }
        }
    } 
    end {
         Write-Verbose "$(get-date) Completing Get-RPGroupReplicationSetVolume"
         return $results | sort CopyName,volumeName
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group Replication Set Volumes
.DESCRIPTION 
    Consistency groups are comprised of one or more replication sets. Each replication 
    set consists of a production volume and any local or remote copy volumes to which 
    it is replicating. The number of replication sets in your system is equal to the 
    number of production volumes being replicated.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
    Get-RPGroupReplicationSetVolume -CGName CG001
.EXAMPLE
    Get-RPGroup CG001 | Get-RPGroupReplicationSetVolume
.EXAMPLE
    Get-RPGroup | select -first 1 | Get-RPGroupReplicationSet | select -first 1 | Get-RPGroupReplicationSetVolume | ft
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
.PARAMETER RepSetName
   Optional. The name of the Replication Set to filter on.
.PARAMETER CopyName
   Optional. The name of the Replication Copy to filter on. 
#>  
}#End Function

export-modulemember -function Connect-*,Disconnect-*,Get-*
