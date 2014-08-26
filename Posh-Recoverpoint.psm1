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
Function to-date ($UnixDate) {
   if ($unixdate){[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliseconds($UnixDate/1000))}
}# End Function
function Connect-Appliance {
   Param(  
      [Parameter(Position=0,  
         Mandatory=$False,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [String]$Name,  
      [Parameter(Position=1,  
         Mandatory=$False,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [Int]$PortNumber,  
      [Parameter(Position=2,  
         Mandatory=$False,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]  
      [System.Management.Automation.PSCredential]$Credentials,
      [switch]$ignorecert  
   )  
   if (!$Name){
        If (($global:rpconfiguration).DefaultRPServer){
            $Name = ($global:rpconfiguration).DefaultRPServer
        } else {
            Write-Error "The Name parameter was not specified and DefaultRPServer was not found in the global configuration."
            return $null
        }
   }
   if (!$Credentials){
        If (($global:rpconfiguration).DefaultRPCreds){
            $Credentials = ($global:rpconfiguration).DefaultRPCreds
        } else {
            Write-Error "The Credentials parameter was not specified and DefaultRPCreds was not found in the global configuration."
            return $null
        }
   }
   if (!$PortNumber -and ($global:rpconfiguration).DefaultRPPort){
        $PortNumber = ($global:rpconfiguration).DefaultRPSPort
   } else {
        $PortNumber = "443"
   }
   if (!$ignorecert -and ($global:rpconfiguration).IgnoreSSL){
        $ignorecert = $true
   }

   if ($ignorecert){

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
   }
   [String]$uri = "https://$name`:$portNumber/fapi/rest/4_0"  
   Try{  
      $connection = Invoke-RestMethod -uri $uri -Credential $credentials -method Get
      $returnobj = to-customobject -TypeName MyCustomType ([ordered]@{
                BaseURL     = $uri
                Credentials = $credentials
            })
            $results += $resultobj
      $global:DefaultRPA = $returnobj
      Return $returnobj
   } catch {
      Write-Debug $URI
      #Write-Debug (Convertto-Json $_.Exception.Response)
      Write-Error $_.Exception
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
    Connect-RPAppliance -Name 192.168.0.100 -PortNumber 443 -Credentials (get-credentials)
.PARAMETER Name
   Required. The name or IP address of the appliance, or the shared management address you want to connect to. 
.PARAMETER Port
   The TCP port to connect to. Default is 443.
   Does not appear at all. 
.PARAMETER Credential
   Required. The local credential of an account with sufficient permissions on the RecoverPoint Appliance.
.PARAMETER IgnoreCert
   Optional. Does not validate the identity or validity of the target x509 certificate.    
#>  

}#End Function
function Disable-ImageAccess{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact="High")]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName,
        [Parameter(Position=2,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyName,
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID,
        [Parameter(Position=4,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterUID,
        [Parameter(Position=5,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyUID,
        [switch]$startTransfer,
        [switch]$Force     
    )
    begin {
        $PSBoundParameters.Remove('Force') | Out-Null
        $PSBoundParameters.Confirm = $false
        $results = @()
        $return = @()
        function inner{
            param([switch]$inner_test)
            write-host $inner_test
        }

        if (!($startTransfer.IsPresent) -and ($global:rpconfiguration).StartTransferOnImageDisable){$startTransfer = $True}
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Disable-RPImageAccess"
    } process {
        if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
        if (!$CGUID){Write-Error "Unable to locate CG `"$CGName`"."; Break}
        if (!$ClusterUID){$ClusterUID = ($script:rpclusters | where {$_.ClusterName -eq $ClusterName}).ClusterUID}
        if (!$ClusterUID){Write-Error "Unable to locate Cluster `"$ClusterName`"."; Break}
        if (!$CGCopyUID){$CGCopyUID = $((Get-GroupCopy -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName).CGCopyUID)}
        if (!$CGCopyUID){Write-Error "Unable to locate CGCopyName `"$CGCopyName`"."; Break}

        if ($Force -or $PSCmdlet.ShouldProcess($CGName,'Disable Image Access mode')) {            
            if ($startTransfer){
                $resource = "/settings/groups/$($CGUID)/copies/$($ClusterUID)/$($CGCopyUID)/actions/disable_image_access?startTransfer=True"
            } else {
                $resource = "/settings/groups/$($CGUID)/copies/$($ClusterUID)/$($CGCopyUID)/actions/disable_image_access"
            }
            Invoke-RestPost $resource
        }
    } end {
         Write-Verbose "$(get-date) Completing Disable-RPImageAccess"
    }
<# 
.SYNOPSIS 
    Disables image access mode for a given Consistency Group
.DESCRIPTION 
    Disables image access mode for a given Consistency Group
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
    Disable-RPImageAccess -CGName CG001 -ClusterName CL001 -CGCopyName CG001_DR
.EXAMPLE
     Get-RPImageAccess | where {$_.imageAccessEnabled -eq $true} |Disable-RPImageAccess -Whatif}
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
.PARAMETER ClusterName
   Required. The name of the RP Cluster to be filtered on.
.PARAMETER CGCopyName
   Required. The name of the Consistency Group Copy where image access is enabled.
.PARAMETER CGUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER ClusterUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER CGCopyUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER startTransfer
   Optional. By default, a CG will be paused when image access is disabled. Enabling this flag will set the CG to transferring on image disable.
   The default action can be changed by running Set-RPConfiguration -StartTransferOnImageDisable $true
.PARAMETER Force
   Optional. Will not prompt before enabling image access.
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
function Enable-ImageAccess{
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact="High")]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName,
        [Parameter(Position=2,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyName,
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID,
        [Parameter(Position=4,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterUID,
        [Parameter(Position=5,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyUID,
        [Parameter(Position=6,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        $objrpimage,
        [Parameter(Position=7,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$False)]
        $mode="LoggedAccess",
        [Parameter(Position=8,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$False)]
        $scenario="None",
        [switch]$Newest,
        [switch]$NewestBookMark,
        [switch]$Oldest,
        [switch]$OldestBookMark,
        [switch]$Force
    )
    begin {
        $PSBoundParameters.Remove('Force') | Out-Null
        $PSBoundParameters.Confirm = $false
        $results = @()
        $return = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Enable-RPImageAccess"
    } process {
        if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
        if (!$CGUID){Write-Error "Unable to locate CG `"$CGName`"."; Break}
        if (!$ClusterUID){$ClusterUID = ($script:rpclusters | where {$_.ClusterName -eq $ClusterName}).ClusterUID}
        if (!$ClusterUID){Write-Error "Unable to locate Cluster `"$ClusterName`"."; Break}
        if (!$CGCopyUID){$CGCopyUID = $((Get-GroupCopy -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName).CGCopyUID)}
        if (!$CGCopyUID){Write-Error "Unable to locate CGCopyName `"$CGCopyName`"."; Break}
        if ($Newest){$rpimage = Get-Image -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName | select -Last 1}
        elseif ($NewestBookMark){$rpimage = Get-Image -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName | Where {$_.description -ne ""} | select -Last 1}
        elseif ($Oldest){$rpimage = Get-Image -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName | select -First 1}
        elseif ($OldestBookMark){$rpimage= Get-Image -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName | Where {$_.description -ne ""} | select -First 1}
        $objrpimage = $rpimage.objrpimage
        if (!$objrpimage){Write-Error "Unable to select objrpimage from image" ; Break }
        $json = "" | select mode,scenario,snapshot
        $json.mode = $mode
        $json.scenario = $scenario
        $json.snapshot = $objrpimage
        #$json = "{
        #    ""mode"" : ""LoggedAccess"",
        #    ""scenario"" : ""None"",
        #    ""snapshot"" :  $ImageJSON
        #}"
        if ($Force -or $PSCmdlet.ShouldProcess($CGName,'Enable Image Access mode')) {            
            $resource = "/settings/groups/$($CGUID)/copies/$($ClusterUID)/$($CGCopyUID)/actions/enable_image_access"
            Invoke-RestPost $resource -body ($json | ConvertTo-Json)
            $return = Get-ImageAccess -CGName $CGname -ClusterName $ClusterName
        }
    } end {
         Write-Verbose "$(get-date) Completing Enable-RPImageAccess"
         return $return
    }
<# 
.SYNOPSIS 
    Enables image access mode for a given Consistency Group
.DESCRIPTION 
    Enables image access mode for a given Consistency Group
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
    Enable-RPImageAccess -CGName CG001 -ClusterName CL001 -CGCopyName CG001_DR -OldestBookMark 
.EXAMPLE
     Get-RPGroupUID | %{$_ |  Get-RPGroupLink | where {$_.localLink -eq $false}} | %{$_ | Get-RPGroupCopy} | %{$_ | Get-RPImage | select -Last 1 } | %{$_ | Enable-RPImageAccess -WhatIf}
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
.PARAMETER ClusterName
   Required. The name of the RP Cluster to be filtered on.
.PARAMETER CGCopyName
   Required. The name of the Consistency Group Copy where image access is enabled.
.PARAMETER CGUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER ClusterUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER CGCopyUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER ImageJSON
   Optional. This is a JSON-formatted block referencing the image. It can be created through Get-RPImage
.PARAMETER Newest
   Optional. Will select the newest point in time.
.PARAMETER NewestBookMark
   Optional. Will select the newest bookmark.
.PARAMETER Oldest
   Optional. Will select the oldest point in time.
.PARAMETER $OldestBookMark
   Optional. Will select the oldest bookmark.
.PARAMETER Force
   Optional. Will not prompt before enabling image access.
#>  
}#End Function
function Get-Account {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPAccount"
    }
    process {
        try {
            $resource = "/settings/account"
            $account = Invoke-RestGet $resource
            $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                CompanyName               = $account.companyName
                contactInfo               = $account.contactInfo
            }) -DefaultProperty CompanyName,contactInfo
            $results += $resultobj
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPAccount"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Account information.
.DESCRIPTION 
    Returns RecoverPoint Account information.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPAccount
#>  
}#End Function
function Get-AlertSetting {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPAlertSetting"
    }
    process {
        try {
            $resource = "/settings/management/system_alerts/full"
            $results = Invoke-RestGet $resource
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPAlertSetting"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Alert settings.
.DESCRIPTION 
    Returns RecoverPoint Alert settings.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPAlertSetting
.EXAMPLE
    Get-RPAlertSetting | select -expand emailFilters
#>  
}#End Function
function Get-Cluster{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$ClusterName="*",
        [switch]$force
    )
     begin {
        if (($script:rpclusters) -and (!($force))){
            return $script:rpclusters | where {$_.ClusterName -like $ClusterName}
        } else {
            $results = @()
            $return = @()  
            Write-Verbose "$(get-date) Starting Get-RPCluster"
            $resource = "/settings/full"
            $fullSettings = Invoke-RestGet $resource
            $clustersettings = $fullSettings | select -ExpandProperty systemSettings | select -ExpandProperty clustersSettings
            foreach ($clustersetting in $clustersettings){
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    ClusterName                = $clustersetting.clusterName
                    ClusterUID                 = ($clustersetting.ClusterUID).id
                    vcenterServers             = $clustersetting.vcenterServers
                    vcenterServersFilters      = $clustersetting.vcenterServersFilters
                    repositoryVolume           = $clustersetting.repositoryVolume
                    attachedPhoenixClusterName = $clustersetting.attachedPhoenixClusterName
                    raidGroupsNames            = $clustersetting.raidGroupsNames
                    throttlePolicy             = $clustersetting.throttlePolicy
                    clusterIndex               = $clustersetting.clusterIndex
                    maintenanceMode            = $clustersetting.maintenanceMode
                    softwareSerialId           = $clustersetting.softwareSerialId
                }) -DefaultProperty ClusterName,ClusterUID
                $results += $resultobj
            }
        }
    } process {
        $return += $results | where {$_.ClusterName -like $ClusterName}
    } end {
        Write-Verbose "$(get-date) Completing Get-RPCluster"
        $script:rpclusters = $results
        return $return | sort ClusterName
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Cluster names, uids, and settings
.DESCRIPTION 
    Almost all of the REST API's that query consistency groups 
    require the group's UID. If no parameter is specified, this 
    function will return all consistency groups by their name and their UID. 
    Note, this function makes serveral API calls (one per CG) and can be 
    slow if you have a lot of CG's. Since this function is used by all of 
    the other group functions, the results are saved in the $script:rpgroups variable 
    within the script scope in order to optimize subsequent lookups.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.PARAMETER Cluster
    Optional. Name of the Cluster(s) to filter on.
.PARAMETER Force
    Optional. By default the module will used cached results. Use the -force to overwrite the cached results.
.EXAMPLE
    Get-RPCluster
.EXAMPLE
    Get-RPCluster RPCL001
.EXAMPLE
    Get-RPCluster RPCL*
.EXAMPLE
    "RPCL001","RPCL001" | Get-RPCluster
.PARAMETER ClusterName
   Optional. The name of the RP cluster to be queried. 
#>  
}#End Function
function Get-Configuration{
    $FolderName = "Posh-RecoverPoint"
    $ConfigName = "MyAddOn.Config.xml"
    
    if ( Test-Path -Path "$($env:AppData)\$FolderName\$ConfigName") {
        $global:rpconfiguration = Import-Clixml "$($env:AppData)\$FolderName\$ConfigName"
    }
    return $global:rpconfiguration
<#
.SYNOPSIS
   Retrieves the Posh-RecoverPoint configuration and default servers policy
.DESCRIPTION
   See Synopsis
.EXAMPLE
   Get-RPConfiguration
#>
}#End Function
function Get-GroupUID{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*",
        [switch]$force
    )
    begin {
        if (($script:rpgroups) -and (!($force))){
            return $script:rpgroups | where {$_.CGName -like $CGname}
        } else {
            $results = @()
            $return = @()  
            Write-Verbose "$(get-date) Starting Get-RPGroupUID"
            $resource = "/settings/groups/all_uids"
            $CGUIDs = Invoke-RestGet $resource
            foreach ($CGUID in $CGUIDs){
                try {
                    $resource = "/settings/groups/$($CGUID.id)/name"
                    $cgnamestr = Invoke-RestGet $resource
                    $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                        CGName = $CGNamestr
                        CGUID  = $CGUID.id
                    })
                    $results += $resultobj
                } catch {
                    Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                    break;
                }
            }
        }
    }
    process {
        $return += $results | where {$_.CGName -like $CGname}
    } end {
        Write-Verbose "$(get-date) Completing Get-RPGroupUID"
        $script:rpgroups = $results
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
    the other group functions, the results are saved in the $script:rpgroups variable 
    within the script scope in order to optimize subsequent lookups.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.PARAMETER CGname
   Optional. The name of the consistency group to be filtered on.
.PARAMETER Force
   Optional. By default, the module will try to cache the results. Use the -Force to overwrite the cache.
.EXAMPLE
    Get-RPGroupUID
.EXAMPLE
    Get-RPGroupUID CG001
.EXAMPLE
    Get-RPGroupUID CG00*
.EXAMPLE
    "CG001","CG002" | Get-RPGroupUID
.PARAMETER CGname
   Optional. The name of the consistency group(s) to be queried. 
#>  
}#End Function
function Get-Group {
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
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        Write-Verbose "$(get-date) Starting Get-RPGroup"
    }
    process {
        $CGs = @($script:rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/state/groups/$($CGUID)"
                $cgstate = Invoke-RestGet $resource
                $sourceClusterUID = ((($cgstate.sourceCopyUID).globalCopyUID).clusterUID).id
                $sourceClusterName = (Get-Cluster | where {$_.ClusterUID -eq $sourceClusterUID}).ClusterName
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName                    = $CG.CGName
                    CGUID                     = $CGUID
                    SourceClusterUID          = $sourceClusterUID
                    SourceClusterName         = $sourceClusterName
                    Enabled                   = $cgstate.enabled
                    runningAsDistributedGroup = $cgstate.runningAsDistributedGroup
                    stateUnknown              = $cgstate.stateUnknown

                }) -DefaultProperty CGName,Enabled
                $results += $resultobj
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break;
            }
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroup"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) state and settings
.DESCRIPTION 
    Returns RecoverPoint Consistency Group (CG) state and settings.
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
    "CG001","CG002" | Get-RPGroup
.EXAMPLE
    Get-RPGroup | Where {$_.Transfer -ne "Active"}
.PARAMETER CGname
   Optional. The name of the consistency group(s) to be queried. 
#>  
}#End Function
function Get-GroupCopy {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName="*",
        [Parameter(Position=2,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyName="*",
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Get-RPGroupCopy"
    }
    process {
        try {
            if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
            if (!$CGUID){Write-Error "Unable to locate CG `"$CGName`"."; Break}
            $resource = "/settings/groups/$($CGUID)/full"
            $cgsettings = Invoke-RestGet $resource
            Write-Verbose $cgsettings
            $cgcopysettings = @($cgsettings | select -ExpandProperty groupCopiesSettings)
            Write-Verbose "`$cgcopysettings.count = $($cgcopysettings.count)"
            $resource = "/state/groups/$($CGUID)"
            $cgcopystates = @(Invoke-RestGet $resource | select -ExpandProperty groupCopiesState)
            foreach ($cgcopysetting in $cgcopysettings){
                $aCGCopyUID = (($cgcopysetting.copyUID).globalCopyUID).CopyUID
                $aClusterUID = ((($cgcopysetting.copyUID).globalCopyUID).clusterUID).id
                $aClusterName = ($script:rpclusters | where {$_.clusteruid -eq $aClusterUID}).ClusterName
                $cgcopystate = $cgcopystates | where {((($_.CopyUID).globalCopyUID).clusterUID).ID -eq $aClusterUID} | where {(($_.CopyUID).globalCopyUID).CopyUID -eq $aCGCopyUID}
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName                   = $CGName
                    CGUID                    = $CGUID
                    ClusterName              = $aClusterName
                    ClusterUID               = $aClusterUID
                    CGCopyName               = $cgcopysetting.name
                    CGCopyUID                = $aCGCopyUID
                    enabled                  = $cgcopystate.enabled
                    regulated                = $cgcopystate.regulated
                    suspended                = $cgcopystate.suspended
                    activePrimaryRPA         = $cgcopystate.activePrimaryRPA
                    activeSecondaryRPAsList  = $cgcopystate.activeSecondaryRPAList
                    accessedImage            = $cgcopystate.accessedImage
                    storageAccessState       = $cgcopystate.storageAccessState
                    splitVariant             = $cgcopystate.splitVariant
                    journalState             = $cgcopystate.journalState
                    consolidationProgress    = $cgcopystate.consolidationProgress
                    distributedFirstSnapshot = $cgcopystate.distributedFirstSnapshot
                    tspWritesCleared         = $cgcopystate.tspWritesCleared
                    stateUnknown             = $cgcopystate.stateUnknown
                    axxanaCopyStatus         = $cgcopystate.axxanaCopyStatus
                    hasPhoenixDevices        = $cgcopysetting.hasPhoenixDevices
                }) -DefaultProperty CGCopyName,Enabled,regulated,suspended,activePrimaryRPA
                $results += $resultobj | where {$_.ClusterName -like $ClusterName} | where {$_.CGCopyName -like $CGCopyName}
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroupCopy"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) Copy state and settings
.DESCRIPTION 
    Returns RecoverPoint Consistency Group (CG) Copy state and settings
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.PARAMETER CGname
   Required. The name of the consistency group to be queried.
.PARAMETER ClusterName
   Optional. The RecoverPoint Cluster to filter results by.
.PARAMETER CGCopyName
   Optional. The RecoverPoint consistency group copy name to filter results by.
.EXAMPLE
    Get-RPGroupCopy CG001
.EXAMPLE
    Get-RPGroup CG* | %{ $_ | Get-RPGroupCopy | select CGName,CGCopyName,enabled }
.EXAMPLE
    "CG001","CG002" | foreach {Get-RPGroupCopy}
#>  
}#End Function
function Get-GroupCopyPolicy {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName="*",
        [Parameter(Position=2,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyName="*",
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Get-RPGroupCopyPolicy"
    }
    process {
        try {
            if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
            if (!$CGUID){Write-Error "Unable to locate CG `"$CGName`"."; Break}
            $resource = "/settings/groups/$($CGUID)/full"
            $cgsettings = Invoke-RestGet $resource
            $cgcopysettings = @($cgsettings | select -ExpandProperty groupCopiesSettings)
            foreach ($cgcopysetting in $cgcopysettings){
                $aCGCopyUID = (($cgcopysetting.copyUID).globalCopyUID).CopyUID
                $aClusterUID = ((($cgcopysetting.copyUID).globalCopyUID).clusterUID).id
                $aClusterName = ($script:rpclusters | where {$_.clusteruid -eq $aClusterUID}).ClusterName
                $aCGCopyUID = (($cgcopysetting.copyUID).globalCopyUID).CopyUID
                $cgcopypolicy = $cgcopysetting | select -ExpandProperty policy
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName                                 = $CGName
                    CGUID                                  = $CGUID
                    ClusterName                            = $aClusterName
                    ClusterUID                             = $aClusterUID
                    CGCopyName                             = $cgcopysetting.name
                    CGCopyUID                              = $aCGCopyUID
                    journalCompressionLevel                = $cgcopypolicy.journalCompressionLevel
                    requiredProtectionWindowInMicroSeconds = $cgcopypolicy.requiredProtectionWindowInMicroSeconds
                    automaticSnapshotConsolidationPolicy   = $cgcopypolicy.automaticSnapshotConsolidationPolicy
                    RTO                                    = $cgcopypolicy.RTO
                    loggedAccessAllocationProportion       = $cgcopypolicy.loggedAccessAllocationProportion
                    journalSizeLimitInBytes                = $cgcopypolicy.journalCompressionLevel
                    hostsOS                                = $cgcopypolicy.hostsOS
                    allowDistributionOfLargeSnapshots      = $cgcopypolicy.allowDistributionOfLargeSnapshots
                    allowSymmetrixWithOneRPA               = $cgcopypolicy.allowSymmetrixWithOneRPA
                    fastForwardBound                       = $cgcopypolicy.fastForwardBound
                    phoenixProtectionPolicy                = $cgcopypolicy.phoenixProtectionPolicy
                }) -DefaultProperty CGName,CGCopyName,journalCompressionLevel,RTO,loggedAccessAllocationProportion,journalSizeLimitInBytes,hostsOS,allowDistributionOfLargeSnapshots,allowSymmetrixWithOneRPA
                $results += $resultobj | where {$_.ClusterName -like $ClusterName} | where {$_.CGCopyName -like $CGCopyName}
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroupCopyPolicy"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) Copy policy.
.DESCRIPTION 
    Returns RecoverPoint Consistency Group (CG) Copy policy.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroupCopyPolicy CG001
.EXAMPLE
    Get-RPGroup | %{ $_ | Get-RPGroupCopyPolicy | ft -autosize }
.EXAMPLE
    "CG001","CG002" | foreach {Get-RPGroupCopyPolicy}
.PARAMETER CGname
   Required. The name of the consistency group to be queried.
.PARAMETER ClusterName
   Optional. The RecoverPoint Cluster to filter results by.
.PARAMETER CGCopyName
   Optional. The RecoverPoint consistency group copy name to filter results by.
#>  
}#End Function
function Get-GroupLink {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$FirstCopyClusterName="*",
        [Parameter(Position=2,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$SecondCopyClusterName="*",
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Get-RPGroupLink"
    }
    process {
        try {
            if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
            $resource = "/state/groups/$($CGUID)"
            $cgstate = Invoke-RestGet $resource
            $resource = "/settings/groups/$($CGUID)/full"
            $cgsettings = Invoke-RestGet $resource
            $cglinksstates = @($cgstate | select -ExpandProperty linksState)
            $cglinksettings = $cgsettings | select -ExpandProperty activeLinksSettings
            foreach ($cglinksstate in $cglinksstates){
                $aFirstCopyClusterUID   = ((($cglinksstate.groupLinkUID).firstCopy).clusterUID).id
                $aFirstCopyClusterName  = ($script:rpclusters | where {$_.ClusterUID -eq $aFirstCopyClusterUID}).ClusterName
                $aSecondCopyClusterUID  = ((($cglinksstate.groupLinkUID).secondcopy).clusterUID).id
                $aSecondCopyClusterName = ($script:rpclusters | where {$_.ClusterUID -eq $aSecondCopyClusterUID}).ClusterName
                $aFirstCopyUID          = (($cglinksstate.groupLinkUID).firstCopy).copyUID
                $aSecondCopyUID         = (($cglinksstate.groupLinkUID).secondCopy).copyUID
                $cglinksetting          = $cglinksettings | where {(((($_.groupLinkUID).firstCopy).clusterUID).id -eq $aFirstCopyClusterUID -and ((($_.groupLinkUID).firstCopy).copyUID -eq $aFirstCopyUID))} | where {(((($_.groupLinkUID).secondCopy).clusterUID).id -eq $aSecondCopyClusterUID -and ((($_.groupLinkUID).secondCopy).copyUID -eq $aSecondCopyUID))}
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName                   = $CGName
                    CGUID                    = $CGUID
                    FirstCopyClusterName     = $aFirstCopyClusterName
                    FirstCopyClusterUID      = $aFirstCopyClusterUID
                    FirstCopyUID             = $aFirstCopyUID
                    SecondCopyClusterName    = $aSecondCopyClusterName
                    SecondCopyClusterUID     = $aSecondCopyClusterUID
                    SecondCopyUID            = $aSecondCopyUID
                    transferstate            = $cglinksstate.pipeState
                    pipestate                = $cglinksstate.pipeState
                    transferEnabled          = $cglinksetting.transferEnabled
                    localLink                = $cglinksetting.localLink
                    transferErrorReason      = $cglinksstate.transferErrorReason
                    inSyncMode               = $cglinksstate.inSyncMode
                    stateUnknown             = $cglinksstate.stateUnknown
                }) -DefaultProperty CGName,FirstCopyClusterName,SecondCopyClusterName,transferstate,transferEnabled,localLink
                $results += $resultobj | where {$_.FirstCopyClusterName -like $FirstCopyClusterName} | where {$_.SecondCopyClusterName -like $SecondCopyClusterName}
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroupLink"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) Copy link state.
.DESCRIPTION 
    Returns RecoverPoint Consistency Group (CG) Copy link state.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroupLink CG001
.EXAMPLE
    Get-RPGroup | %{ $_ | Get-RPGroupLink | select *name*,transferstate }
.EXAMPLE
    Get-RPGroup | %{ $_ | Get-RPGroupLink | where {$_.transferstate -ne "Active"} | select CGName,SecondCopyClusterName,transferstate }
.PARAMETER CGname
   Required. The name of the consistency group to be queried.
.PARAMETER FirstCopyClusterName
   Optional. The RecoverPoint source cluster to filter results by.
.PARAMETER SecondCopyClusterName
   Optional. The RecoverPoint target cluster to filter results by.
#>  
}#End Function
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
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }

        Write-Verbose "$(get-date) Starting Get-RPGroupReplicationSet"
    }
    process {
        $CGs = @($script:rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/settings/groups/$($CGUID)/full"
                $cgsettings = Invoke-RestGet $resource
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
                $sourcedev = ((($sourcevol | select -ExpandProperty volumeInfo).volumeName -replace "^DEV ID: ","")  -replace "^VOL ID: ","")   -replace "^Vplex lun # ",""
                $targetdev = ((($targetvol | select -ExpandProperty volumeInfo).volumeName -replace "^DEV ID: ","")  -replace "^VOL ID: ","")   -replace "^Vplex lun # ",""
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName      = $CG.CGName
                    CGUID       = $CGUID
                    RepSetName  = $cgrepset.replicationSetName
                    RepSetUID   = ($cgrepset | select -ExpandProperty replicationSetUID | select -ExpandProperty groupUID).id
                    sizeinbytes = $cgrepset.sizeInBytes
                    size        = to-kmg $cgrepset.sizeInBytes
                    SourceDev   = $sourcedev
                    TargetDev   = $targetdev
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
    Get-RPGroupUID CG001 | Get-RPGroupReplicationSet
.EXAMPLE
    Get-RPGroupUID | select -first 10 | Get-RPGroupReplicationSet | ft *
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
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        Write-Verbose "$(get-date) Starting Get-RPGroupReplicationSetVolume"
    }
    process {
        Write-Verbose "$(get-date) $CGName"
        $CGs = @($script:rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/settings/groups/$($CGUID)/full"
                $cgsettings = Invoke-RestGet $resource
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
                        volumeName                = $volumeinfo.volumeName -replace "^DEV ID: ",""
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
    Get-RPGroupUID CG001 | Get-RPGroupReplicationSetVolume
.EXAMPLE
    Get-RPGroupUID | select -first 1 | Get-RPGroupReplicationSet | select -first 1 | Get-RPGroupReplicationSetVolume | ft
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
.PARAMETER RepSetName
   Optional. The name of the Replication Set to filter on.
.PARAMETER CopyName
   Optional. The name of the Replication Copy to filter on. 
#>  
}#End Function
function Get-GroupSet {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGSetName="*"
    )
    begin {
        $results = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        Write-Verbose "$(get-date) Starting Get-RPGroup"
    }
    process {
        try {
            $resource = "/settings/group_sets/all"
            $cgsets = @(Invoke-RestGet $resource)
            foreach ($cgset in $cgsets){
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGSetName                       = $cgset.Name
                    CGSetUID                        = ($cgset.setUID).id
                    groupsUIDs                      = $cgset.groupsUIDs.id
                    Members                         = $cgset | select -ExpandProperty groupsUIDs | select @{Name="CGName";Expression={$id = $_.id ; ($script:rpgroups | where  {$_.CGUID -eq $id}).cgname}},id
                    bookmarkFrequencyInMicroSeconds = $cgset.bookmarkFrequencyInMicroSeconds
                }) -DefaultProperty CGSetName,Members,bookmarkFrequencyInMicroSeconds
                $results += $resultobj | where {$_.CGSetName -like $CGSetName}
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPGroup"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group (CG) set settings and members.
.DESCRIPTION 
    Returns RecoverPoint Consistency Group (CG) set settings and members.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPGroupSet
.EXAMPLE
    Get-RPGroupSet CGSet001
.EXAMPLE
    Get-RPGroupSet CGSet00*
.EXAMPLE
    "CGSet001","CGSet002" | %{ Get-RPGroupSet $_ }
.EXAMPLE
    Get-RPGroupSet CGSet001 | select -ExpandProperty members
.PARAMETER CGSetname
   Optional. The name of the consistency group set(s) to be queried.
#>  
}#End Function
function Get-Image{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGName,
        [Parameter(Position=1,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName,
        [Parameter(Position=2,
        Mandatory=$True,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyName,
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGUID,
        [Parameter(Position=4,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterUID,
        [Parameter(Position=5,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$CGCopyUID
    )
    begin {
        $results = @()
        $return = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Get-RPImage"
    }
    process {
        Write-Verbose "$(get-date) $CGName"
        if (!$CGUID){$CGUID = ($script:rpgroups | where {$_.CGName -eq $CGName}).CGUID}
        if (!$CGUID){Write-Error "Unable to locate CG `"$CGName`"."; Break}
        if (!$ClusterUID){$ClusterUID = ($script:rpclusters | where {$_.ClusterName -eq $ClusterName}).ClusterUID}
        if (!$ClusterUID){Write-Error "Unable to locate Cluster `"$ClusterName`"."; Break}
        if (!$CGCopyUID){$CGCopyUID = $((Get-GroupCopy -CGName $CGName -ClusterName $ClusterName -CGCopyName $CGCopyName).CGCopyUID)}
        if (!$CGCopyUID){Write-Error "Unable to locate CGCopyName `"$CGCopyName`"."; Break}
        try {
            $resource = "/settings/groups/$($CGUID)/copies/$($ClusterUID)/$($CGCopyUID)/snapshots"
            $snapshots = Invoke-RestGet $resource | select -ExpandProperty snapshots
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break; 
        }
        foreach ($snapshot in $snapshots){
            $objsnapshot = "" | select snapshotUID,description,closingTimeStamp
            $objsnapshot.snapshotUID = $snapshot.snapshotUID
            $objsnapshot.description = $snapshot.description
            $objsnapshot.closingTimeStamp = $snapshot.closingTimeStamp
             
            $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                CGName                    = $CGName
                CGUID                     = $CGUID
                ClusterName               = $ClusterName
                ClusterUID                = $ClusterUID
                CGCopyName                = $CGCopyName
                CGCopyUID                 = $CGCopyUID
                snapshotUID               = ($snapshot.snapshotUID).id
                description               = $snapshot.description
                closingTimeStamp          = to-date ($snapshot.closingTimeStamp).timeInMicroSeconds
                sizeInBytes               = $snapshot.sizeInBytes
                uncompressedSizeInBytes   = $snapshot.uncompressedSizeInBytes
                userSnapshot              = $snapshot.userSnapshot
                consistencyType           = $snapshot.consistencyType
                objrpimage                = $objsnapshot                    
            }) -DefaultProperty snapshotUID,description,closingTimeStamp,sizeInBytes,uncompressedSizeInBytes,userSnapshot,consistencyType
            $results += $resultobj
        }
    } 
    end {
         Write-Verbose "$(get-date) Completing Get-RPImage"
         return $results | sort closingTimeStamp
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group Copy Image Access state
.DESCRIPTION 
    Returns the image access state of the given Consistency Group(s)
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
     Get-RPGroupCopy -CGName CG001 | select -Last 1 | Get-RPImage
.EXAMPLE
    Get-RPImage -CGName CG001 -ClusterName CL001 -CGCopyName CGC001 | where {$_.closingTimeStamp -lt (get-date).AddDays(-2)} | select -Last 1
.PARAMETER CGname
   Required. The name of the consistency group to be queried.
.PARAMETER ClusterName
   Required. The name of the RP Cluster to be filtered on.
.PARAMETER CGCopyName
   Required. The name of the RP consistency group copy name to be filtered on.
#>  
}#End Function
function Get-ImageAccess{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$False,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName="*",
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$ClusterName="*"
    )
    begin {
        $results = @()
        $return = @()
        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
        Write-Verbose "$(get-date) Starting Get-RPImageAccess"
    }
    process {
        Write-Verbose "$(get-date) $CGName"
        $CGs = @($script:rpgroups | where {$_.CGName -like "$CGName"})
        foreach ($CG in $CGs){
            try {
                $CGUID = $CG.CGUID
                $resource = "/settings/groups/$($CGUID)/full"
                $cgsettings = Invoke-RestGet $resource
            } catch {
                Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
                break; 
            }
            $cgcopysets = @($cgsettings | select -ExpandProperty groupCopiesSettings | where {$_.imageAccessInformation -ne $null})
            foreach ($cgcopyset in $cgcopysets){
                $imageAccessInformation = $cgcopyset | select -ExpandProperty imageAccessInformation
                $imageInformation = $imageAccessInformation | select -ExpandProperty imageInformation
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    CGName                    = $CG.CGName
                    CGUID                     = $CGUID
                    ClusterName               = ($script:rpclusters | where {$_.clusterUID -eq ($cgcopyset | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID | select -ExpandProperty clusterUID).id}).clusterName
                    ClusterUID                = ($cgcopyset | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID | select -ExpandProperty clusterUID).id
                    CGCopyName                = $cgcopyset.name
                    CGCopyUID                 = $cgcopyset | select -ExpandProperty copyUID | select -ExpandProperty globalCopyUID | select -ExpandProperty copyUID
                    imageAccessEnabled        = $imageAccessInformation.imageAccessEnabled
                    timeStamp                 = to-date ($imageInformation.timeStamp).timeInMicroSeconds
                    mode                      = $imageInformation.mode
                    imageType                 = $imageInformation.imageType
                    searchText                = $imageInformation.searchText
                    searchExactText           = $imageInformation.searchExactText
                    maximumSearchRange        = $imageInformation.maximumSearchRange
                    imageName                 = $imageAccessInformation.imageName
                    scenario                  = $imageAccessInformation.scenario
                }) -DefaultProperty CGName,ClusterName,CGCopyName,imageAccessEnabled,mode,imageName,scenario
                $results += $resultobj | where {$_.CGName -like $CGName -and $_.ClusterName -like $ClusterName}
            }
        }
    } 
    end {
         Write-Verbose "$(get-date) Completing Get-RPImageAccess"
         return $results
    }
<# 
.SYNOPSIS 
    Returns RecoverPoint Consistency Group Copy Image Access state
.DESCRIPTION 
    Returns the image access state of the given Consistency Group(s)
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
    Get-RPImageAccess
.EXAMPLE
     Get-RPImageAccess -CGName CG001
.EXAMPLE
    Get-RPImageAccess | where {$_.imageAccessEnabled -eq $true}
.PARAMETER CGname
   Optional. The name of the consistency group(s) to be queried.
.PARAMETER ClusterName
   Optional. The name of the RP Cluster to be filtered on.
#>  
}#End Function
function Get-LDAPSetting {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPLDAPSetting"
    }
    process {
        try {
            $resource = "/settings/management/users/ldap/full"
            $ldap = Invoke-RestGet $resource
            $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                protocolType      = ($ldap.protocol).protocolType
                enabled                 = $ldap.enabled
                binding                 = $ldap.binding
                distinguishedNameSearch = $ldap.distinguishedNameSearch
                baseDistinguishedName   = $ldap.baseDistinguishedName
                primaryServer           = $ldap.primaryServer
                secondaryServer         = $ldap.secondaryServer
                protocol                = $ldap.protocol
                advancedsettings        = $ldap.advancedSettings
            }) -DefaultProperty protocolType,enabled,primaryServer,secondaryServer
            $results += $resultobj
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPLDAPSetting"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Account information.
.DESCRIPTION 
    Returns RecoverPoint Account information.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPLDAPSetting
.EXAMPLE
    Get-RPLDAPSetting | where {$_.roleName -eq "Admin"}
#>  
}#End Function
function Get-License {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPLicense"
        if (!($script:rpclusters)){ $script:rpclusters = Get-Cluster }
    }
    process {
        try {
            $resource = "/settings/account"
            $account = Invoke-RestGet $resource
            $licenses = $account | select -ExpandProperty licenses
            foreach ($license in $licenses){
                $aClusterUID = ($license.clusterUID).id
                $aClusterName = ($script:rpclusters | where {$_.clusteruid -eq $aClusterUID}).ClusterName
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    licenseUID               = ($license.licenseUID).id
                    capacityInTerabytes      = $license.capacityInTerabytes
                    expirationDate           = $license.expirationDate
                    licenseType              = $license.licenseType
                    localReplicationOnly     = $license.localReplicationOnly
                    ClusterName              = $aClusterName
                    ClusterUID               = $aClusterUID
                }) -DefaultProperty licenseUID,capacityInTerabytes,expirationDate,licenseType,localReplicationOnly,ClusterName
                $results += $resultobj
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPLicense"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint License information.
.DESCRIPTION 
    Returns RecoverPoint License information.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPLicense
#>  
}#End Function
function Get-MiscSetting {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPMiscSetting"
    }
    process {
        try {
            $resource = "/settings/management/system_misc/full"
            $results = Invoke-RestGet $resource
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPMiscSetting"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint miscellaneous settings.
.DESCRIPTION 
    Returns RecoverPoint miscellaneous settings.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPMiscSetting
#>  
}#End Function
function New-Bookmark {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,
        Mandatory=$True,
        ValueFromPipeLine=$True,  
        ValueFromPipeLineByPropertyName=$True)]
        [string[]]$CGName,
        [Parameter(Position=1,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$bookmarkName="PoshRP-$(get-date -Format yyyyMMddHHmmss)",
        [Parameter(Position=2,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$consistencyType="ConsistencyUnknown",
        [Parameter(Position=3,
        Mandatory=$False,
        ValueFromPipeLineByPropertyName=$True)]
        [string]$consolidationPolicy="AlwaysConsolidate"
    )
    begin {

        if (!($script:rpgroups)){ $script:rpgroups = Get-GroupUID }
        Write-Verbose "$(get-date) Starting New-RPBookmark"
    } process {
        $CGUIDs = @()
        @($CGName) | %{$CGN = $_ ; $CGUIDs += ($script:rpgroups | where {$_.CGName -eq $CGN}).CGUID}
        $resource = "/settings/groups/actions/create_bookmark"
        $jsongroups = @()
        foreach ($CGUID in $CGUIDs){
            $jsongroup = "" | select "id"
            $jsongroup.id = $CGUID
            $jsongroups += $jsongroup
        }
        
        $json = "" | select bookmarkName,consistencyType,consolidationPolicy,groups
        $json.bookmarkName = $bookmarkName
        $json.consistencyType = $consistencyType
        $json.consolidationPolicy = $consolidationPolicy
        $json.groups = $jsongroups

        Invoke-RestPost $resource -body ($json | ConvertTo-Json)

    } end {
         Write-Verbose "$(get-date) Completing New-RPBookmark"
    }
<# 
.SYNOPSIS 
    Disables image access mode for a given Consistency Group
.DESCRIPTION 
    Disables image access mode for a given Consistency Group
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.EXAMPLE
    Disable-RPImageAccess -CGName CG001 -ClusterName CL001 -CGCopyName CG001_DR
.EXAMPLE
     Get-RPImageAccess | where {$_.imageAccessEnabled -eq $true} | foreach {$_ | Disable-RPImageAccess -Whatif}
.PARAMETER CGname
   Required. The name of the consistency group(s) to be queried.
.PARAMETER ClusterName
   Required. The name of the RP Cluster to be filtered on.
.PARAMETER CGCopyName
   Required. The name of the Consistency Group Copy where image access is enabled.
.PARAMETER CGUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER ClusterUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER CGCopyUID
   Optional. When piped from another cmdlet, this value gets populated to save on lookup.
.PARAMETER startTransfer
   Optional. By default, a CG will be paused when image access is disabled. Enabling this flag will set the CG to transferring on image disable.
.PARAMETER Force
   Optional. Will not prompt before enabling image access.
#>  
}#End Function
function Get-ReportSetting {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPReportSetting"
    }
    process {
        try {
            $resource = "/settings/management/system_report/full"
            $results = Invoke-RestGet $resource
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPReportSetting"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Report settings.
.DESCRIPTION 
    Returns RecoverPoint Report settings.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPReportSetting
#>  
}#End Function
function Get-Role {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPRole"
    }
    process {
        try {
            $resource = "/settings/management/users/roles/all"
            $roles = Invoke-RestGet $resource
            foreach ($role in $roles){
                $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    name      = $role.RoleName
                    permissions  = $role.permissions
                }) -DefaultProperty name,permissions
                $results += $resultobj
            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPRole"
            return $results | sort name
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Account information.
.DESCRIPTION 
    Returns RecoverPoint Account information.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPRole
.EXAMPLE
    Get-RPRole | where {$_.permissions -contains "Security"}
#>  
}#End Function
function Get-SNMPSetting {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPSNMPSetting"
    }
    process {
        try {
            $resource = "/settings/management/snmp/full"
            $results = Invoke-RestGet $resource
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPSNMPSetting"
            return $results
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint SNMP settings.
.DESCRIPTION 
    Returns RecoverPoint SNMP settings.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPSNMPSetting
#>  
}#End Function
function Get-User {
    begin {
        $results = @()
        Write-Verbose "$(get-date) Starting Get-RPUser"
    }
    process {
        try {
            $resource = "/settings/management/users/rp_users/all"
            $users = Invoke-RestGet $resource
            foreach ($user in $users){
               $resultobj = to-customobject -TypeName MyCustomType ([ordered]@{
                    name      = $user.Name
                    userType  = $user.userType
                    roleName  = $user.roleName
                }) -DefaultProperty name,userType,roleName
                $results += $resultobj            }
        } catch {
            Write-Host ("Error """ + $Error[0] + """ Connecting to `"$resource`"")
            break;
        }
    }
    end {
            Write-Verbose "$(get-date) Finishing Get-RPUser"
            return $results | sort name
        }
<# 
.SYNOPSIS 
    Returns RecoverPoint Account information.
.DESCRIPTION 
    Returns RecoverPoint Account information.
.NOTES 
    Author     : Paul Sabin - justpaul@gmail.com
    Thanks to everyone who help support the Powershell community. A special shout out goes to Hal
    and Jon over at the PowerScripting Podcast. http://powershell.org/wp/powerscripting-podcast
.LINK 
    https://github.com/justpowershell/Posh-RecoverPoint 
.LINK
    https://community.emc.com/thread/194087
.EXAMPLE
    Get-RPUser
.EXAMPLE
    Get-RPUser | where {$_.roleName -eq "Admin"}
#>  
}#End Function
function Set-Configuration{
    param (
        [string]$defaultRPServer,
        [pscredential]$DefaultRPCreds,
        [bool]$IgnoreSSL,
        [bool]$StartTransferOnImageDisable
    )
    $FolderName = "Posh-RecoverPoint"
    $ConfigName = "MyAddOn.Config.xml"
    
    if ( -not (Test-Path -Path "$($env:AppData)\$FolderName")) {
        mkdir "$($env:AppData)\$FolderName"
    }
    if ( Test-Path -Path "$($env:AppData)\$FolderName\$ConfigName") {
        Get-Configuration | Out-Null
    }
    $parameters = "DefaultRPServer","DefaultRPPort","DefaultRPCreds","IgnoreSSL","StartTransferOnImageDisable"
    
    $expression = "`$rpconfigurationnew = `"`" | select $($parameters -join ",")"
    Invoke-Expression $expression

    foreach ($parameter in $parameters){
        $expression = @"
            if (`$$parameter){
                `$rpconfigurationnew.$parameter = `$$parameter
            } elseif ((`$global:rpconfiguration).$parameter){
                `$rpconfigurationnew.$parameter = (`$global:rpconfiguration).$parameter
            } else {
                `$rpconfigurationnew.$parameter = `$null
            }
"@
        Invoke-Expression $expression
    }
    $global:rpconfiguration = $rpconfigurationnew
    # store parameters
    $global:rpconfiguration | Export-Clixml -Path "$($env:AppData)\$FolderName\$ConfigName"
    return $global:rpconfiguration
<#
.SYNOPSIS
   Sets the Posh-RecoverPoint configuration and default servers policy
.DESCRIPTION
   This optional cmdlet sets some parameters that might be static for you. For instance, most will only connect to a single management RPA. Setting
   the configuration parameter here means it will save that value for re-use the next time you run connect-rpappliance. The settings are saved in the
   local user's appdata location. If the directory/config.xml does not exist yet, it will be created. Note: the save credentials are encrypted and can
   only be decrypted by the same user who saved the config on the same computer the config was orignally saved. The credentials, by design, are not
   portable for use in roaming profiles.
.PARAMETER DefaultRPAServer
   Optional. The server to connect to when running connect-rpappliance without supplying the name parameter. Note, if you do specify the parameter
   when using connect-rpappliance, that will take precedence.
.PARAMETER DefaultRPCreds
   Optional. The credentials to use when running connect-rpappliance without supplying the credentials parameter. Note, if you do specify the parameter
   when using connect-rpappliance, that will take precedence.
.PARAMETER DefaultRPPort
   Optional. The port to use when running connect-rpappliance without supplying the port parameter. Note, if you do specify the parameter
   when using connect-rpappliance, that will take precedence.
.PARAMETER IgnoreSSL
    Optional. If you are using the default, untrusted certificate, you can specify this value here to be used when running connect-rpa.
.PARAMETER StartTransferOnImageDisable
    Optional. The Disable-RPImageAccess will default to pausing the CG transfer after a RecoverPoint image access has been disabled. Set this value to true
    to make the default to allow the CG to resume transferring on image disable. Note, if this value is set, it will override the -StartTransfer:$false, if
    specified.
.EXAMPLE
   Set-RPConfiguration -defaultRPServer "myrpaserver" -DefaultRPCreds (Get-Credential)
#>
}#End Function
function Invoke-RestGet {
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
            Write-Debug $URI
            If ($_.Exception.Response){
                Write-Debug (Convertto-Json $_.Exception.Response)
            }
            Write-Error $_.Exception
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
    Invoke-RPRestGet /settings/groups/all_uids
.PARAMETER resource
   Required. The URL resource to be queried. Must start with a "/" 
#>  
}#End Function
function Invoke-RestPost {
   Param(  
      [Parameter(Position=0,  
         Mandatory=$True,  
         ValueFromPipeLine=$True,  
         ValueFromPipeLineByPropertyName=$True)]
         [String]$resource,
         $body  
    )
    If (!$DefaultRPA){
        Write-Host -ForegroundColor Red "No default RPA address found. Please run Connect-RPAppliance before running this cmdlet."
        Break;
    } else {
        try {
            $results = @()
            $URI = $DefaultRPA.BaseURL + $resource
            if (!$body){
                return Invoke-RestMethod -uri $URI -Method Post -Credential $DefaultRPA.Credentials
            } else {
                return Invoke-RestMethod -uri $URI -Method Post -Credential $DefaultRPA.Credentials -ContentType "application/json" -Body $body
            }
        } catch {
            Write-Host "Error Connecting to `"$URI`""
            if ($body){
                Write-Host $body
            }
            Write-Debug $URI
            Write-Debug $body
            Write-Debug (Convertto-Json $_.Exception.Response)
            Write-Error $_.Exception
        }
    }
<# 
.SYNOPSIS 
    Returns the results of a REST API call via POST to the RecoverPoint Web Services API 
.DESCRIPTION 
    This function is mostly used by other functions. It takes the 
    resource parameter and combines it with the $DefaultRPA BaseURL
    to form a URI that will be used for performing actions via REST API.
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
    Invoke-RPRestPost /settings/groups/all_uids
.PARAMETER resource
   Required. The URL resource to be queried. Must start with a "/"
.PARAMETER body
    Optional. When additional paramters are needed that cannot be set via the URI, they can be submitted as JSON requests.
    $json = "{
            ""foo"" : ""bar""
    }" 
#>  
}#End Function
function Remove-Configuration{
    param (
        [switch]$defaultRPServer,
        [switch]$DefaultRPCreds,
        [switch]$IgnoreSSL,
        [switch]$StartTransferOnImageDisable
    )
    $FolderName = "Posh-RecoverPoint"
    $ConfigName = "MyAddOn.Config.xml"
    
    if ( -not (Test-Path -Path "$($env:AppData)\$FolderName")) {
        mkdir "$($env:AppData)\$FolderName"
    }
    if ( Test-Path -Path "$($env:AppData)\$FolderName\$ConfigName") {
        Get-Configuration | Out-Null
    }
    $parameters = "DefaultRPServer","DefaultRPCreds","IgnoreSSL","StartTransferOnImageDisable"
    
    foreach ($parameter in $parameters){
        $expression = @"
            if (`$$parameter){
                write-host `"`$$parameter specified. Setting value to `$null."
                `$global:rpconfiguration.$parameter = `$null
            }
"@
        Invoke-Expression $expression
    }
    # store parameters
    $global:rpconfiguration | Export-Clixml -Path "$($env:AppData)\$FolderName\$ConfigName"
    return $global:rpconfiguration
<#
.SYNOPSIS
   Removes select Posh-RecoverPoint configurations and/or default servers policy
.DESCRIPTION
   This optional cmdlet will unset values that were saved to the default RP configuration file.
.PARAMETER DefaultRPAServer
   Optional. Will set the DefaultRPAServer value to $null
.PARAMETER DefaultRPCreds
   Optional. Will set the DefaultRPCreds value to $null
.PARAMETER IgnoreSSL
   Optional. Will set the IgnoreSSL value to $null
.PARAMETER StartTransferOnImageDisable
    Optional. Will set the StartTransferOnImageDisable value to $null
.EXAMPLE
   Remove-RPConfiguration -DefaultRPCreds (Get-Credential)
#>
}#End Function

export-modulemember -function Connect-*,Disable-*,Disconnect-*,Enable-*,Get-*,Invoke-*,New-*,Remove-*,Set-*