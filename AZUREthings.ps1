#Requires -version 5
#Requires -Module AzureRM, PKI, PowerShellGet, nx
#Requires -RunAsAdministrator
#run as admin to create self-signed certs for automation RunAsAccount etc. (it needs admin for the local cert store, etc.)

<# ToDo
  dev-test labs (or just use Visual Studio)
  setup for ASR
  https://github.com/mariuszdotnet/azure-vmss-templates/blob/master/vm-lnx-lad/azuredeploy.ps1
  service fabric with containers
  https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-get-started-containers-linux
  Containers
  https://docs.microsoft.com/en-us/azure/container-registry/container-registry-get-started-powershell
#>

#region SelectSubscription
function Get-UserPromptChoice 
{
    Param([string[]]$options)

    $arrOptions = @()
    $i = 1

    foreach ($option in $options)
    {
        $optionDesc = New-Object  -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList ("&$i - $option")
        $arrOptions += $optionDesc
        $i++
    }

    return [System.Management.Automation.Host.ChoiceDescription[]]($arrOptions)
}


$Subscriptions='Microsoft Azure Internal Consumption','Azure CXP'

$Prompt = Get-UserPromptChoice -options $Subscriptions
$Choice = $Host.UI.PromptForChoice('Azure','Please choose a subscription',$Prompt,0) 
$Subscription=$Subscriptions[$choice]
#endregion
#region LoginToAzure
Import-Module -Name AzureRM 
if (-NOT ((Get-AzureRmContext).Subscription.Name -eq $Subscription) ) {
  Connect-AzureRmAccount
}

Set-AzureRmContext -Subscription $Subscription
$MyEmail=(Get-AzureRMContext).Account.ID
$MyName =(Get-AzureRmContext).Account.ID.Split('@')[0]
if ($MyName.Length -gt 11) {
  $MyName = $MyName.Substring(0,11)   # I use this to create unique names by prepending this to things.
}
$VerbosePreference = 'Continue'
#endregion
#region TestAdminRights
function Test-AdminRights
{
	[CmdletBinding()] 
	[OutputType([bool])] 
	Param ([string]$Scope) 

   if (($PSVersionTable.PSVersion.Major -le 5) -or $IsWindows) {
      $currentUser = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
      $isAdminProcess = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   }
   else {
      # Must be Linux or OSX, so use the id util. Root has userid of 0.
      $isAdminProcess = 0 -eq (id -u)
   }

   if ($isAdminProcess -eq $false)
   {
      throw 'Administrator rights are required.'
   }

   $isAdminProcess
  }
#endregion
#region Variables
Write-Verbose -Message 'Set variables'
$RG   = $MyName + '-AZUREthings'
$RGSF = $MyName + '-ServiceFabricMel'

$AzureVMsize = 'Standard_D1_v2'

$Sydney    = 'australiaeast'
$Melbourne = 'australiasoutheast'

$ApiMgtName   = ($MyName + '-ApiMgt').ToLower()      # API management
$RegistryName = ($MyName + 'Registry')               # The registry name must be unique, 5-50 alphanumeric characters. '^[a-zA-Z0-9]*$'

$SQLdbName         = ($MyName + '-SQLdb01').ToLower()
$SQLserverName     = ($MyName + '-sqlhostsvr').ToLower()   # globally unique name, must be lowercase

$MelAutomation     = $MyName + '-MelAutomation'  
$appDisplayName    = $MelAutomation + '-AutoAppDisplayName'
$MelLogAnalyticsWS = ($MyName + '-Mel-log-analytics').ToLower()
$BackUpVaultSydney = ($MyName + '-SydBackupVault').ToLower()

$KeyVaultMelbourne =  $MyName + '-MelKeyVlt'      #'^[a-zA-Z0-9-]{3,24}$'.
$KeyVaultMelSF     =  $MyName + '-MelSFKeyVlt'    #'^[a-zA-Z0-9-]{3,24}$'.

$SydStorageAccount = ($MyName + 'sydstorage').ToLower()  # globally unique name, 1-24 chars numbers and lowercase letters ONLY
$MelStorageAccount = ($MyName + 'melstorage').ToLower()  # globally unique name, 1-24 chars numbers and lowercase letters ONLY

$runBookContainer   = 'runbooks'
$scriptContainer    = 'shellscripts'
$DSCconfigContainer = 'dscconfigs'
$DSCmoduleContainer = 'dscmodules'   # module.zip(s) have to be in a storage container
                                     # if they are to be uploaded into Automation.

$ContainerPolicyName = 'ScriptContainerPolicy'

$functionAppName   = $MyName + '-FunctionApp'

$VnetSydneySec     = 'Secure-vnet-Sydney'
$VnetSydneySecAddr = '192.168.0.0/16'
$SydDMZsubnet      = 'DMZ-subnet'
$SydDMZsubnetAddr  = '192.168.0.0/24'
$SydFEsubnet       = 'Web-FrontEnd-Subnet'
$SydFEsubnetAddr   = '192.168.1.0/24'
$SydBEsubnet       = 'SQL-BackEnd-Subnet'
$SydBEsubnetAddr   = '192.168.2.0/24'

$FW1applianceAddr  = '192.168.0.4'   # only thing in the DMZ
$SydFW1nic         = 'SYD-FW1-NIC'
$SydFW1nic0Addr    = $FW1applianceAddr
$SydFEnic0Addr     = '192.168.1.5'
$SydFEnic1addr     = '192.168.1.6'
$SydBEnic0Addr     = '192.168.2.5'
$SydBEnic1addr     = '192.168.2.6'
$SydFEnic0         = 'SYD-FE-NIC-0'
$SydFEnic1         = 'SYD-FE-NIC-1'
$SydBEnic0         = 'SYD-BE-NIC-0'
$SydBEnic1         = 'SYD-BE-NIC-1'

$VnetSydney        = 'UNIX-vnet-Sydney'
$VnetSydneyAddr    = '10.100.0.0/16'
$VnetMelbourne     = 'UNIX-vnet-Melbourne'
$VnetMelbourneAddr = '10.200.0.0/16'

$GatewaySharedKey  = '0DEADBEEF0'
$GWsubnetName      = 'GatewaySubnet'
$SydGWsubnetAddr   = '10.100.0.0/28'
$MelGWsubnetAddr   = '10.200.0.0/28'

$LXsubnetName      = 'LX-Subnet'
$SydLXsubnetAddr   = '10.100.1.0/24'
$MelLXsubnetAddr   = '10.200.1.0/24'

$SydLXnic0Addr     = '10.100.1.5'
$SydLXnic1addr     = '10.100.1.6'
$MelLXnic0Addr     = '10.200.1.5'
$MelLXnic1addr     = '10.200.1.6'

$BSDsubnetName     = 'BSD-Subnet'
$SydBSDsubnetAddr  = '10.100.2.0/24'
$MelBSDsubnetAddr  = '10.200.2.0/24'

$SydBSDnic0Addr     = '10.100.2.5'
$SydBSDnic1addr     = '10.100.2.6'
$MelBSDnic0Addr     = '10.200.2.5'
$MelBSDnic1addr     = '10.200.2.6'

$WINsubnetName     = 'WIN-Subnet'
$SydWINsubnetAddr  = '10.100.3.0/24'
$MelWINsubnetAddr  = '10.200.3.0/24'


$SydWINilbAddr      = '10.100.3.4'
$SydWINnic0Addr     = '10.100.3.5'
$SydWINnic1addr     = '10.100.3.6'
$MelWINnic0Addr     = '10.200.3.5'
$MelWINnic1addr     = '10.200.3.6'

$SydLXnic0 ='SYD-LX-NIC-0'
$SydLXnic1 ='SYD-LX-NIC-1'
$SydBSDnic0='SYD-BSD-NIC-0'
$SydBSDnic1='SYD-BSD-NIC-1'
$SydWinnic0='SYD-WIN-NIC-0'
$SydWinnic1='SYD-WIN-NIC-1'

$MelLXnic0 ='MEL-LX-NIC-0'
$MelLXnic1 ='MEL-LX-NIC-1'
$MelBSDnic0='MEL-BSD-NIC-0'
$MelBSDnic1='MEL-BSD-NIC-1'
$MelWinnic0='MEL-WIN-NIC-0'
$MelWinnic1='MEL-WIN-NIC-1'

$SydneyUbuntu ='SydUbuntu'
$SydneyCentOS ='SydCentOS'
$SydneyFreeBSD='SydFreeBSD'
$SydneyOpenBSD='SydOpenBSD'
$SydneyWinSvr ='SydWinSvr'
$SydneyWinVMSS='SydWinVMScaleSet'

$MelbourneUbuntu ='MelUbuntu'
$MelbourneCentOS ='MelCentOS'
$MelbourneFreeBSD='MelFreeBSD'
$MelbourneOpenBSD='MelOpenBSD'
$MelbourneWinSvr ='MelWinSvr'

$ServiceFabricClustername =  'winsfcluster'

$user     = 'localadmin'
$password = 'M1cr0softAzure'
$securepasswd    = ConvertTo-SecureString -String $password -AsPlainText -Force
$AdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($user, $securepasswd)

$LOCALTEMPSCRIPTS  = "$ENV:TEMP/SCRIPTS"
$LOCALTEMPCONFIGS  = "$ENV:TEMP/DSCCONFIGS"
$LOCALTEMPMODULES  = "$ENV:TEMP/DSCMODULES"
$LOCALTEMPRUNBOOKS = "$ENV:TEMP/RUNBOOKS"

$SydWinLBname='sydwinlb'
$features = @()
#endregion
#region DSCconfigs
# define the DSC configuratiion scripts that we will use to configure our VMs
Write-Verbose -Message 'Create DSCconfigs'
$DSCMODULES=@('nx')

if (-NOT (Test-Path -Path $LOCALTEMPMODULES)) {$null=New-Item -Path $LOCALTEMPMODULES -ItemType Directory -Force}
$null=Get-ChildItem -Path $LOCALTEMPMODULES | Remove-Item -Force

# ensure that any Modules required are also to be zipped, ready to be uploaded and then deployed into Automation.
foreach ($DSCMODULE in $DSCMODULES) {
  if (-NOT (Get-Module -Name $DSCMODULE -ListAvailable)) {
    Find-Module -Name $DSCMODULE | Install-Module -Force -AllowClobber -Scope CurrentUser
  }
  $moduleFolder=(Get-Module -Name $DSCMODULE -ListAvailable).ModuleBase
  $modulePath=$modulefolder.Substring(0,$modulefolder.LastIndexOf($DSCMODULE)+$DSCMODULE.Length)

  Compress-Archive -Path $modulePath -DestinationPath (Join-Path -Path $LOCALTEMPMODULES -ChildPath "$DSCMODULE.zip") -Force
}

[scriptblock] $WinWebconfig = {
  Configuration WinWEBconfig {

    $features = @(
        @{Name = "Web-Server"; Ensure = "Present"},
        @{Name = "Web-WebServer"; Ensure = "Present"},
        @{Name = "Web-Common-http"; Ensure = "Present"},
        @{Name = "Web-Default-Doc"; Ensure = "Present"},
        @{Name = "Web-Dir-Browsing"; Ensure = "Present"},
        @{Name = "Web-Http-Errors"; Ensure = "Present"},
        @{Name = "Web-Static-Content"; Ensure = "Present"},
        @{Name = "Web-Health"; Ensure = "Present"},
        @{Name = "Web-Http-Logging"; Ensure = "Present"},
        @{Name = "Web-Performance"; Ensure = "Present"},
        @{Name = "Web-Stat-Compression"; Ensure = "Present"},
        @{Name = "Web-Dyn-Compression"; Ensure = "Present"},
        @{Name = "Web-Security"; Ensure = "Present"},
        @{Name = "Web-Filtering"; Ensure = "Present"},
        @{Name = "Web-Basic-Auth"; Ensure = "Present"},
        @{Name = "Web-Windows-Auth"; Ensure = "Present"},
        @{Name = "Web-App-Dev"; Ensure = "Present"},
        @{Name = "Web-Net-Ext45"; Ensure = "Present"},
        @{Name = "Web-Asp-Net45"; Ensure = "Present"},
        @{Name = "Web-ISAPI-Ext"; Ensure = "Present"},
        @{Name = "Web-ISAPI-Filter"; Ensure = "Present"},
        @{Name = "Web-Ftp-Server"; Ensure = "Present"},
        @{Name = "Web-Mgmt-Tools"; Ensure = "Present"},
        @{Name = "Web-Mgmt-Console"; Ensure = "Present"}     
       )

    node localhost {
    
        foreach ($feature in $features){
            WindowsFeature ($feature.Name) {
                Name = $feature.Name
                Ensure = $feature.Ensure
            }
        }
    }
  }

}
[scriptblock] $NxDSCconfig  = {
  Configuration NXDSCconfig 
  {

    Import-DSCResource -Module nx

    Node localhost {

        nxUser lukeb {
        Username = "lukeb"
        Password = '517xgGp5foxbg'  # hash generated via mkpasswd
        Ensure = "Present"
        FullName = "Luke Brennan"
        Description = "A user account for Luke"
        HomeDirectory = "/home/lukeb"
      }
        nxGroup DSCgroup {
            GroupName = "DSCgroup"
            Ensure = "Present"
            Members = @("root","lukeb")
            DependsOn = "[nxUser]lukeb" 
      }
        nxFile myfile {
            DestinationPath = '/tmp/HelloLuke.sh'
            Ensure = 'Present'
            Type = 'File'
            Contents = "#!/bin/bash
            echo Hello Luke!"
        }
        nxPackage apache2Install {
            Name = "apache2"
            Ensure = "Present"
            PackageManager = "Apt"
        }
        nxService apache2Service {
            Name = "apache2"
            Controller = "init"
            Enabled = $true
            State = "Running"
        }    
        nxFile apache2File {
            Ensure = "Present"
            Type = "File"
            DestinationPath = "/var/www/index.html"
            Contents = '<!DOCTYPE html>
          <html>
          <head>
          <title>A DSC Linux Apache Test Page</title>
          </head>
          <body bgcolor="#00c87c">
          <h3 style="color:blue">This Apache server and webpage is installed and configured by DSC on Linux</h3>
          </body>
        </html>'
        }
    }
  }
}
[scriptblock] $NxApacheconfig  = {
  Configuration NxApacheconfig
  {
    PARAM([ValidateSet('Ubuntu','RedHat')][string]$Distro='RedHat')

    Import-DscResource -ModuleName NX

    if ($Distro -eq 'Ubuntu') {
      #DEBIAN
      $ApachePackages = @('apache2','php5','libapache2-mod-php5')
      $ServiceName = 'apache2'
      $VHostDir = "/etc/apache2/sites-enabled"
      $PackageManager = "apt"
      $ServiceCtl = "Init"
    }
    else {
      #RHEL
      $ApachePackages = @('httpd','mod_ssl','php','php-mysql')
      $ServiceName = 'httpd'
      $VHostDir = '/etc/httpd/conf.d'
      $PackageManager = 'yum'
      $ServiceCtl = "SystemD"
    }
 
    $rwxrr = 744

    Node localhost 
    {
        ForEach ($Package in $ApachePackages) {

            nxPackage $Package 
            {
                Ensure = 'Present'
                Name   = $Package
                PackageManager = $PackageManager
            }
        }

        nxFile vHostDirectory
        {
            DestinationPath = $VhostDir
            Type   = 'Directory'
            Ensure = 'Present'
            Owner  = 'root'
            Mode   = $rwxrr
        }

        #Ensure default content does not exist

        nxFile DefVHost
        {
            DestinationPath = "${VhostDir}/000-default.conf"
            Ensure = 'Absent'
        }

        nxFile Welcome.conf
        {
            DestinationPath = "${VhostDir}/welcome.conf"
            Ensure = 'Absent'
        }


        nxFile UserDir.conf
        {
            DestinationPath = "${VhostDir}/userdir.conf"
            Ensure = 'Absent'
        }

        #Ensure website is defined
        nxFile DefaultSiteDir
        {
            DestinationPath = '/var/www/html/defaultsite'
            Type   = 'Directory'
            Owner  = 'root'
            Mode   = $rwxrr
            Ensure = 'Present'
        }

        nxFile DefaultSite.conf
        {
            Destinationpath = "${VhostDir}/defaultsite.conf"
            Owner    = 'root'
            Mode     = $rwxrr
            Ensure   = 'Present'
            Contents = @"
<VirtualHost *:80>
DocumentRoot /var/www/html/defaultsite
ServerName $env:COMPUTERNAME
</VirtualHost>
"@
            DependsOn = '[nxFile]DefaultSiteDir'
        }


        nxFile TestPhp
        {
            DestinationPath = '/var/www/html/defaultsite/test.php'
            Ensure   = 'Present'
            Owner    = 'root'
            Mode     = $rwxrr
            Contents = @'
<?php phpinfo(); ?>

'@
        }


        #Configure Apache Service

        nxService ApacheService
        {
            Name       = $ServiceName
            Enabled    = $true
            State      = 'running'
            Controller = $ServiceCtl
            DependsOn  = '[nxFile]DefaultSite.conf'
        }

    }

  }
}
$DSCconfigs = 'WinWebconfig','NxDSCconfig','NxApacheconfig'

#endregion
#region WindowsPSscripts
# define some scripts that we will have executed upon boot using the scripting extension
Write-Verbose -Message 'Create Windows PowerShell scripts'
[scriptblock] $WinInstallIIS = {
  Add-WindowsFeature Web-Server
  Add-Content -Path 'C:\inetpub\wwwroot\Default.htm' -Value $($ENV:COMPUTERNAME)
}
$WindowsScripts = 'WinInstallIIS'
#endregion
#region UNIXshellscripts
# define some scripts that we will have executed upon boot using the scripting extension
Write-Verbose -Message 'Create Linux bash scripts'
$UbuntuInstallDocker = @'
  #!/bin/bash
  curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
  curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
  add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
  apt-get update
  #
  apt-get install -y docker-ce
  apt-get install -y powershell
  exit 0
'@
$CentOSInstallDocker = @'
  #!/bin/bash
  curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo
  yum install -y yum-utils device-mapper-persistent-data lvm2
  yum-config-manager --add-repo  https://download.docker.com/linux/centos/docker-ce.repo
  yum-config-manager --enable docker-ce-edge
  yum-config-manager --enable docker-ce-test
  yum makecache fast
  #
  yum install -y docker-ce
  systemctl start docker
  yum install -y powershell
  exit 0
'@
$OpenSuseInstallDocker = @'
  #!/bin/bash
  sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
  sudo zypper install https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-beta.6/powershell-6.0.0_beta.6-1.suse.42.1.x86_64.rpm
  exit 0
'@
$FreeBSDInstallDocker = @'
  #!/bin/sh
  cd /usr/ports/ports-mgmt/pkg
  make install
  env ASSUME_ALWAYS_YES=YES pkg bootstrap
  #
  pkg install -y docker-freebsd ca_root_nss
  zfs create -o mountpoint=/usr/docker zroot/docker
  sysrc -f /etc/rc.conf docker_enable="YES"
  service docker start
  exit 0
'@
$NXscripts ='UbuntuInstallDocker','CentOSInstallDocker','OpenSuseInstallDocker','FreeBSDInstallDocker'
#endregion
#region RunBookScripts
# define a simple runbook that we will load into automation
[scriptblock] $StopAzureVMinResponseToVMalert = {
  <#
    .SYNOPSIS
    This runbook stops a resource management VM in response to an Azure alert trigger.

    .DESCRIPTION
    This runbook stops a resource management VM in response to an Azure alert trigger.
    The input is alert data that has the information required to identify which VM to stop.

    DEPENDENCIES
    - The runbook must be called from an Azure alert via a webhook.

    REQUIRED AUTOMATION ASSETS
    - An Automation connection asset called "AzureRunAsConnection" that is of type AzureRunAsConnection.
    - An Automation certificate asset called "AzureRunAsCertificate".

    .PARAMETER WebhookData
    Optional. (The user doesn't need to enter anything, but the service always passes an object.)
    This is the data that's sent in the webhook that's triggered from the alert.

    .NOTES
    AUTHOR: Azure Automation Team
    LASTEDIT: 2017-11-22
  #>

  [OutputType('PSAzureOperationResponse')]

  param
  (
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
  )

  $ErrorActionPreference = 'stop'

  if ($WebhookData)
  {
    # Get the data object from WebhookData.
    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    # Get the info needed to identify the VM (depends on the payload schema).
    $schemaId = $WebhookBody.schemaId
    Write-Verbose -Message "schemaId: $schemaId" -Verbose
    if ($schemaId -eq 'AzureMonitorMetricAlert') {
        # This is the near-real-time Metric Alert schema
        $AlertContext = [object] ($WebhookBody.data).context
        $ResourceName = $AlertContext.resourceName
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq 'Microsoft.Insights/activityLogs') {
        # This is the Activity Log Alert schema
        $AlertContext = [object] (($WebhookBody.data).context).activityLog
        $ResourceName = (($AlertContext.resourceId).Split('/'))[-1]
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq $null) {
        # This is the original Metric Alert schema
        $AlertContext = [object] $WebhookBody.context
        $ResourceName = $AlertContext.resourceName
        $status = $WebhookBody.status
    }
    else {
        # The schema isn't supported.
        Write-Error -Message "The alert data schema - $schemaId - is not supported."
    }

    Write-Verbose -Message "status: $status" -Verbose
    if ($status -eq 'Activated')
    {
        $ResourceType = $AlertContext.resourceType
        $ResourceGroupName = $AlertContext.resourceGroupName
        $SubId = $AlertContext.subscriptionId
        Write-Verbose -Message "resourceType: $ResourceType" -Verbose
        Write-Verbose -Message "resourceName: $ResourceName" -Verbose
        Write-Verbose -Message "resourceGroupName: $ResourceGroupName" -Verbose
        Write-Verbose -Message "subscriptionId: $SubId" -Verbose

        # Use this only if this is a resource management VM.
        if ($ResourceType -eq 'Microsoft.Compute/virtualMachines')
        {
            # This is the VM.
            Write-Verbose -Message 'This is a resource management VM.' -Verbose

            # Authenticate to Azure by using the service principal and certificate. Then, set the subscription.
            Write-Verbose -Message 'Authenticating to Azure with service principal and certificate' -Verbose
            $ConnectionAssetName = 'AzureRunAsConnection'
            Write-Verbose -Message "Get connection asset: $ConnectionAssetName" -Verbose
            $Conn = Get-AutomationConnection -Name $ConnectionAssetName
            if ($Conn -eq $null)
            {
                throw "Could not retrieve connection asset: $ConnectionAssetName. Check that this asset exists in the Automation account."
            }
            Write-Verbose -Message 'Authenticating to Azure with service principal.' -Verbose
            Add-AzureRMAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint | Write-Verbose
            Write-Verbose -Message "Setting subscription to work against: $SubId" -Verbose
            Set-AzureRmContext -SubscriptionId $SubId -ErrorAction Stop | Write-Verbose

            # Stop the VM.
            Write-Verbose -Message "Stopping the VM - $ResourceName - in resource group - $ResourceGroupName -" -Verbose
            Stop-AzureRmVM -Name $ResourceName -ResourceGroupName $ResourceGroupName -Force
            # [OutputType(PSAzureOperationResponse")]
        }
        else {
            # ResourceType isn't supported.
            Write-Error -Message "$ResourceType is not a supported resource type for this runbook."
        }
    }
    else {
        # The alert status was not 'Activated', so no action taken.
        Write-Verbose -Message ('No action taken. Alert status: ' + $status) -Verbose
    }
  }
  else {
    # Error
    Write-Error -Message 'This runbook is meant to be started from an Azure alert webhook only.'
  }
}
$RunBookScripts = 'StopAzureVMinResponseToVMalert'
#endregion
#region CreateRG
Write-Verbose -Message 'Resource Groups'
if (-NOT (Get-AzureRmResourceGroup -Name $RG -EA SilentlyContinue)) {
  Write-Verbose -Message ("Creating RG '{0}'" -f $RG)
  $null = New-AzureRmResourceGroup -Name $RG -Location $Sydney
}
While (-NOT ($AZURETHINGS) ) {
  $AZURETHINGS = Get-AzureRmResourceGroup -Name $RG -Location $Sydney
  start-sleep -Seconds 2
}

if (-NOT (Get-AzureRmResourceGroup -Name $RGSF -EA SilentlyContinue)) {
  Write-Verbose -Message ("Creating RG '{0}'" -f $RGSF)
  $null = New-AzureRmResourceGroup -Name $RGSF -Location $Melbourne
}
$ServiceFabricMel = Get-AzureRmResourceGroup -Name $RGSF -Location $Melbourne
#endregion
#region RBAC
# example of granting a user from another company (e.g. a consultant) access to our things as a Contributor
Write-Verbose -Message 'Creating RBAC role assignments'
$CBellee=Get-AzureRmADUser | Where-Object {$_.DisplayName -eq 'Chris Bellee'} # Chris is from another organisation,  but in my directory
if ($CBellee) {
  if (-NOT (Get-AzureRmRoleAssignment -ObjectId $CBellee.Id -EA SilentlyContinue)) {
    $null=New-AzureRmRoleAssignment -ResourceGroupName $RG -RoleDefinitionName 'Contributor' -ObjectId $CBellee.Id
  }
}
#endregion
#region NSGs
# the firewall rules we will apply to the sub-net configs
  Write-Verbose -Message "Create NSG's"
  #NSG for SydWINsubnet
  $rule1 = New-AzureRmNetworkSecurityRuleConfig -Name rdp-rule -Description 'Allow RDP' `
                                                -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 `
                                                -SourceAddressPrefix Internet -SourcePortRange * `
                                                -DestinationAddressPrefix * -DestinationPortRange 3389

  $rule2 = New-AzureRmNetworkSecurityRuleConfig -Name web-rule -Description 'Allow HTTP' `
                                                -Access Allow -Protocol Tcp -Direction Inbound -Priority 101 `
                                                -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * `
                                                -DestinationPortRange 80

  if (-NOT (Get-AzureRmNetworkSecurityGroup -Name 'WINNSG' -ResourceGroupName $RG -EA SilentlyContinue)) {
    $WINNSG=New-AzureRmNetworkSecurityGroup -Name 'WINNSG' -ResourceGroupName $RG -Location $Sydney `
                                            -Tag @{Name='WinNSGTagName';Value=$MyName} -SecurityRules $rule1, $rule2
  }

  #NSG for Linux subnets
  $ruleSSH = New-AzureRmNetworkSecurityRuleConfig -Name SSH-rule -Description 'Allow SSH' `
                                         -Access Allow -Protocol Tcp -Direction Inbound -Priority 200 `
                                         -SourceAddressPrefix * -SourcePortRange * `
                                         -DestinationAddressPrefix *  -DestinationPortRange 22

  if (-NOT (Get-AzureRmNetworkSecurityGroup -Name 'LXNSG' -ResourceGroupName $RG -EA SilentlyContinue)) {
   $LXNSG = New-AzureRmNetworkSecurityGroup -Name 'LXNSG' -ResourceGroupName $RG -Location $Sydney `
                                            -Tag @{Name='LxNSGTagName';Value=$MyName} -SecurityRules $ruleSSH
  }
#endregion
#region Vnets
 Write-Verbose -Message 'Virtual networks'
# Sydney and Melbourne VNets are going to be basically the same, plus VPNgatewayed together
if (-NOT (Get-AzureRMVirtualNetwork -Name $VnetSydney -ResourceGroupName $RG -EA SilentlyContinue)) {

  Write-Verbose -Message 'Creating subnet configs (Sydney)'
  $SydGatewaySubnet = New-AzureRMVirtualNetworkSubnetConfig -Name $GWsubnetName  -AddressPrefix $SydGWsubnetAddr
  $SydLXsubnet      = New-AzureRMVirtualNetworkSubnetConfig -Name $LXsubnetName  -AddressPrefix $SydLXsubnetAddr -NetworkSecurityGroup $LXNSG
  $SydBSDsubnet     = New-AzureRMVirtualNetworkSubnetConfig -Name $BSDsubnetName -AddressPrefix $SydBSDsubnetAddr
  $SydWINsubnet     = New-AzureRMVirtualNetworkSubnetConfig -Name $WINsubnetName -AddressPrefix $SydWINsubnetAddr -NetworkSecurityGroup $WINNSG

  Write-Verbose -Message ("Creating Vnet '{0}'" -f $VnetSydney)
  $SydVnet=New-AzureRMVirtualNetwork -Name $VnetSydney `
                                     -ResourceGroupName $RG -Location $Sydney `
                                     -AddressPrefix $VnetSydneyAddr `
                                     -Subnet $SydGatewaySubnet, $SydLXsubnet, $SydBSDsubnet, $SydWINsubnet `
                                     -Tag @{Name='MyLocationTagHere';Value='Sydney'}
  $null=Set-AzureRMVirtualNetwork -VirtualNetwork $SydVnet
 }

if (-NOT (Get-AzureRMVirtualNetwork -Name $VnetMelbourne -ResourceGroupName $RG -EA SilentlyContinue)) {

  Write-Verbose -Message 'Creating subnet configs (Melbourne)'
  $MelGatewaySubnet = New-AzureRMVirtualNetworkSubnetConfig -Name $GWsubnetName  -AddressPrefix $MelGWsubnetAddr
  $MelLXsubnet      = New-AzureRMVirtualNetworkSubnetConfig -Name $LXsubnetName  -AddressPrefix $MelLXsubnetAddr
  $MelBSDsubnet     = New-AzureRMVirtualNetworkSubnetConfig -Name $BSDsubnetName -AddressPrefix $MelBSDsubnetAddr
  $MelWINsubnet     = New-AzureRMVirtualNetworkSubnetConfig -Name $WINsubnetName -AddressPrefix $MelWINsubnetAddr

  Write-Verbose -Message ("Creating Vnet '{0}'" -f $VnetMelbourne)
  $MelVnet=New-AzureRMVirtualNetwork -Name $VnetMelbourne `
                                     -ResourceGroupName $RG -Location $Melbourne `
                                     -AddressPrefix $VnetMelbourneAddr `
                                     -Subnet $MelGatewaySubnet, $MelLXsubnet, $MelBSDsubnet, $MelWINsubnet `
                                     -Tag @{Name='MyLocationTagHere';Value='Melbourne'}
  $null=Set-AzureRMVirtualNetwork -VirtualNetwork $MelVnet
}

# SydneySecure is meant to be a root and two subnets, forcing all traffic through the appliance via UDRs
if (-NOT (Get-AzureRMVirtualNetwork -Name $VnetSydneySec -ResourceGroupName $RG -EA SilentlyContinue)) {
  Write-Verbose -Message 'Creating subnet configs (Sydney Secure)'
  #region UDRs
  Write-Verbose -Message "Creating UDR's"
  # Create a route used to send all WFE traffic destined to the back-end (SQL) subnet (192.168.2.0/24)
  # to be routed to the FW1 virtual appliance (192.168.0.4).
  $routeToBE = New-AzureRmRouteConfig -Name RouteToBackEnd -AddressPrefix $SydBEsubnetAddr `
                                      -NextHopType VirtualAppliance -NextHopIpAddress $FW1applianceAddr

  # now create a route table that holds the route
  $FErouteTable = New-AzureRmRouteTable -ResourceGroupName $RG -Location $Sydney -Name UDR-FrontEnd -Route $routeToBE

  # same exercise for the other (SQL) subnet. Any traffic heading to WFE's must go via the FW1 virtual appliance
  $routeToFE = New-AzureRmRouteConfig -Name RouteToFrontEnd -AddressPrefix $SydFEsubnetAddr `
                                      -NextHopType VirtualAppliance -NextHopIpAddress $FW1applianceAddr

  $BErouteTable = New-AzureRmRouteTable -ResourceGroupName $RG -Location $Sydney `
                                        -Name UDR-BackEnd -Route $routeToFE
  #endregion
  $DMZSubnet = New-AzureRMVirtualNetworkSubnetConfig -Name $SydDMZsubnet -AddressPrefix $SydDMZsubnetAddr
  $FESubnet  = New-AzureRMVirtualNetworkSubnetConfig -Name $SydFEsubnet  -AddressPrefix $SydFEsubnetAddr -RouteTable $FErouteTable
  $BESubnet  = New-AzureRMVirtualNetworkSubnetConfig -Name $SydBEsubnet  -AddressPrefix $SydBEsubnetAddr -RouteTable $BErouteTable

  Write-Verbose -Message ("Creating Vnet '{0}'" -f $VnetSydneySec)
  $SydSecVnet=New-AzureRMVirtualNetwork -Name $VnetSydneySec `
                                        -ResourceGroupName $RG -Location $Sydney `
                                        -AddressPrefix $VnetSydneySecAddr `
                                        -Subnet $DMZSubnet, $FESubnet, $BESubnet `
                                        -Tag @{Name='MyLocationTagHere';Value='SydneySecure'}
  $null=Set-AzureRMVirtualNetwork -VirtualNetwork $SydSecVnet
}
#endregion
#region PublicIPs
  Write-Verbose -Message "Allocating public IP's"
  if (-NOT (   Get-AzureRmPublicIpAddress -Name 'sydgwpip' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $SydGWYpip=New-AzureRMPublicIpAddress -Name 'sydgwpip' -ResourceGroupName $RG -Location $Sydney -AllocationMethod Dynamic -DomainNameLabel 'sydgateway'
  }
  if (-NOT (   Get-AzureRmPublicIpAddress -Name 'melgwpip' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $MelGWYpip=New-AzureRMPublicIpAddress -Name 'melgwpip' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melgateway'
  }

  if (-NOT (   Get-AzureRmPublicIpAddress -Name 'sydWinLBpip' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $SydWinLBpip=New-AzureRMPublicIpAddress -Name 'sydWinLBpip' -ResourceGroupName $RG -Location $Sydney -AllocationMethod Dynamic -DomainNameLabel $SydWinLBname
  }

  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip1' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip1=New-AzureRMPublicIpAddress -Name 'sydpip1' -ResourceGroupName $RG -Location $Sydney  -AllocationMethod Dynamic -DomainNameLabel 'sydpip1'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip2' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip2=New-AzureRMPublicIpAddress -Name 'sydpip2' -ResourceGroupName $RG -Location $Sydney    -AllocationMethod Dynamic -DomainNameLabel 'sydpip2'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip3' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip3=New-AzureRMPublicIpAddress -Name 'sydpip3' -ResourceGroupName $RG -Location $Sydney    -AllocationMethod Dynamic -DomainNameLabel 'sydpip3'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip4' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip4=New-AzureRMPublicIpAddress -Name 'sydpip4' -ResourceGroupName $RG -Location $Sydney    -AllocationMethod Dynamic -DomainNameLabel 'sydpip4'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip5' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip4=New-AzureRMPublicIpAddress -Name 'sydpip5' -ResourceGroupName $RG -Location $Sydney    -AllocationMethod Dynamic -DomainNameLabel 'sydpip5'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'sydpip6' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Sydpip4=New-AzureRMPublicIpAddress -Name 'sydpip6' -ResourceGroupName $RG -Location $Sydney    -AllocationMethod Dynamic -DomainNameLabel 'sydpip6'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip1' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip1=New-AzureRMPublicIpAddress -Name 'melpip1' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip1'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip2' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip2=New-AzureRMPublicIpAddress -Name 'melpip2' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip2'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip3' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip3=New-AzureRMPublicIpAddress -Name 'melpip3' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip3'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip4' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip4=New-AzureRMPublicIpAddress -Name 'melpip4' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip4'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip5' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip4=New-AzureRMPublicIpAddress -Name 'melpip5' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip5'
  }
  if (-NOT ( Get-AzureRmPublicIpAddress -Name 'melpip6' -ResourceGroupName $RG -ErrorAction SilentlyContinue)) {
    $Melpip4=New-AzureRMPublicIpAddress -Name 'melpip6' -ResourceGroupName $RG -Location $Melbourne -AllocationMethod Dynamic -DomainNameLabel 'melpip6'
  }
#endregion
#region NICs
  Write-Verbose -Message 'Creating NICs (Syd)'
  $SydVnet      = Get-AzureRmVirtualNetwork             -Name $VnetSydney    -ResourceGroupName $RG
  $SydLXsubnet  = Get-AzureRMVirtualNetworkSubnetConfig -Name $LXsubnetName  -VirtualNetwork $SydVnet
  $SydBSDsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $BSDsubnetName -VirtualNetwork $SydVnet
  $SydWINsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $WINsubnetName -VirtualNetwork $SydVnet

  $Sydpip1=Get-AzureRmPublicIpAddress -Name 'sydpip1' -ResourceGroupName $RG
  $Sydpip2=Get-AzureRmPublicIpAddress -Name 'sydpip2' -ResourceGroupName $RG
  $Sydpip3=Get-AzureRmPublicIpAddress -Name 'sydpip3' -ResourceGroupName $RG
  $Sydpip4=Get-AzureRmPublicIpAddress -Name 'sydpip4' -ResourceGroupName $RG
  $Sydpip5=Get-AzureRmPublicIpAddress -Name 'sydpip5' -ResourceGroupName $RG
  $Sydpip6=Get-AzureRmPublicIpAddress -Name 'sydpip6' -ResourceGroupName $RG

  if (-NOT (Get-AzureRmNetworkInterface -Name $SydLXnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydLXnic0  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydLXsubnet.Id -PrivateIpAddress $SydLXnic0Addr -PublicIpAddressId $Sydpip1.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydLXnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydLXnic1  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydLXsubnet.Id -PrivateIpAddress $SydLXnic1Addr -PublicIpAddressId $Sydpip2.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydBSDnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydBSDnic0  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydBSDsubnet.Id -PrivateIpAddress $SydBSDnic0Addr -PublicIpAddressId $Sydpip3.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydBSDnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydBSDnic1  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydBSDsubnet.Id -PrivateIpAddress $SydBSDnic1Addr -PublicIpAddressId $Sydpip4.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydWINnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydWINnic0  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydWINsubnet.Id -PrivateIpAddress $SydWINnic0Addr -PublicIpAddressId $Sydpip5.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydWINnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydWINnic1  -ResourceGroupName $RG -Location $Sydney -SubnetId $SydWINsubnet.Id -PrivateIpAddress $SydWINnic1Addr -PublicIpAddressId $Sydpip6.Id
  }

  Write-Verbose -Message 'Creating NICs (Mel)'
  $MelVnet      = Get-AzureRmVirtualNetwork             -Name $VnetMelbourne -ResourceGroupName $RG
  $MelLXsubnet  = Get-AzureRMVirtualNetworkSubnetConfig -Name $LXsubnetName  -VirtualNetwork $MelVnet
  $MelBSDsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $BSDsubnetName -VirtualNetwork $MelVnet
  $MelWINsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $WINsubnetName -VirtualNetwork $MelVnet

  $Melpip1=Get-AzureRmPublicIpAddress -Name 'melpip1' -ResourceGroupName $RG
  $Melpip2=Get-AzureRmPublicIpAddress -Name 'melpip2' -ResourceGroupName $RG
  $Melpip3=Get-AzureRmPublicIpAddress -Name 'melpip3' -ResourceGroupName $RG
  $Melpip4=Get-AzureRmPublicIpAddress -Name 'melpip4' -ResourceGroupName $RG
  $Melpip5=Get-AzureRmPublicIpAddress -Name 'melpip5' -ResourceGroupName $RG
  $Melpip6=Get-AzureRmPublicIpAddress -Name 'melpip6' -ResourceGroupName $RG

  if (-NOT (Get-AzureRmNetworkInterface -Name $MelLXnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelLXnic0  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelLXsubnet.Id -PrivateIpAddress $MelLXnic0Addr -PublicIpAddressId $Melpip1.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $MelLXnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelLXnic1  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelLXsubnet.Id -PrivateIpAddress $MelLXnic1Addr -PublicIpAddressId $Melpip2.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $MelBSDnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelBSDnic0  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelBSDsubnet.Id -PrivateIpAddress $MelBSDnic0Addr -PublicIpAddressId $Melpip3.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $MelBSDnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelBSDnic1  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelBSDsubnet.Id -PrivateIpAddress $MelBSDnic1Addr -PublicIpAddressId $Melpip4.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $MelWINnic0  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelWINnic0  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelWINsubnet.Id -PrivateIpAddress $MelWINnic0Addr -PublicIpAddressId $Melpip5.Id
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $MelWINnic1  -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $MelWINnic1  -ResourceGroupName $RG -Location $Melbourne -SubnetId $MelWINsubnet.Id -PrivateIpAddress $MelWINnic1Addr -PublicIpAddressId $Melpip6.Id
  }

  Write-Verbose -Message 'Creating NICs (Syd Secure)'
  $SydSecVnet = Get-AzureRMVirtualNetwork -Name $VnetSydneySec -ResourceGroupName $RG
  $DMZSubnet  = Get-AzureRMVirtualNetworkSubnetConfig -Name $SydDMZsubnet -VirtualNetwork $SydSecVnet
  $FESubnet   = Get-AzureRMVirtualNetworkSubnetConfig -Name $SydFEsubnet  -VirtualNetwork $SydSecVnet
  $BESubnet   = Get-AzureRMVirtualNetworkSubnetConfig -Name $SydBEsubnet  -VirtualNetwork $SydSecVnet

  if (-NOT (Get-AzureRmNetworkInterface -Name $SydFW1nic -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydFW1nic -ResourceGroupName $RG -Location $Sydney -SubnetId $DMZSubnet.Id -PrivateIpAddress $SydFW1nic0Addr
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydFEnic0 -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydFEnic0 -ResourceGroupName $RG -Location $Sydney -SubnetId $FESubnet.Id -PrivateIpAddress $SydFEnic0Addr
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydFEnic1 -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydFEnic1 -ResourceGroupName $RG -Location $Sydney -SubnetId $FESubnet.Id -PrivateIpAddress $SydFEnic1addr
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydBEnic0 -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydBEnic0 -ResourceGroupName $RG -Location $Sydney -SubnetId $BESubnet.Id -PrivateIpAddress $SydBEnic0Addr
  }
  if (-NOT (Get-AzureRmNetworkInterface -Name $SydBEnic1 -ResourceGroupName $RG -EA SilentlyContinue)) {
      $null=New-AzureRmNetworkInterface -Name $SydBEnic1 -ResourceGroupName $RG -Location $Sydney -SubnetId $BESubnet.Id -PrivateIpAddress $SydBEnic1addr
  }
#endregion
#region LoadBalancers
  Write-Verbose -Message 'Creating External load-balancers (Syd)'
  $SydwinLBpip    = Get-AzureRmPublicIpAddress -name 'SydWinLBpip' -ResourceGroupName $RG
  $SydWinLBconfig = New-AzureRmLoadBalancerFrontendIpConfig -Name 'SydWinLBConfig' -PublicIpAddressId $SydwinLBpip.Id
  $SydWinBEpool   = New-AzureRmLoadBalancerBackendAddressPoolConfig -Name 'SydWinBEpool' 
  if (-NOT (Get-AzureRmLoadBalancer -name $SydWinLBname -ResourceGroupName $RG -EA SilentlyContinue)) {
      $SydWinLB = New-AzureRmLoadBalancer -Name $SydWinLBname  -ResourceGroupName $RG -Location $Sydney `
                                            -FrontendIpConfiguration $SydWinLBconfig `
                                            -BackendAddressPool $SydWinBEpool `
                                            -Tag @{Name='MyLoadBalancerTagHere';Value='Sydney Windows LB'}

      # Create a load balancer health probe on port 80
      $probe=Add-AzureRmLoadBalancerProbeConfig -Name 'SydWinLBHealthProbe' `
                                                -LoadBalancer $SydWinLB `
                                                -Protocol tcp `
                                                -Port 80 `
                                                -IntervalInSeconds 15 `
                                                -ProbeCount 2

      # Create a load balancer rule to distribute traffic on port 80
      $cfg=Add-AzureRmLoadBalancerRuleConfig -Name 'SydWinLBRule' -LoadBalancer $SydWinLB `
                                             -FrontendIpConfiguration $SydWinLB.FrontendIpConfigurations[0] `
                                             -BackendAddressPool $SydWinLB.BackendAddressPools[0] `
                                             -Protocol Tcp `
                                             -FrontendPort 80 `
                                             -BackendPort 80

      # Update the load balancer configuration
      $update=Set-AzureRmLoadBalancer -LoadBalancer $SydWinLB
  }

  $SydWinLB=Get-AzureRmLoadBalancer -name $SydWinLBname -ResourceGroupName $RG

#endregion
#region AVsets
# define the availability sets our VMs will be leveraging
  Write-Verbose -Message 'Creating AV sets (Syd)'
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-LX-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Syd-LX-AVset  -ResourceGroupName $RG -Location $Sydney
  }
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-BSD-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Syd-BSD-AVset -ResourceGroupName $RG -Location $Sydney
  }
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-WIN-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Syd-WIN-AVset -ResourceGroupName $RG -Location $Sydney
  }
  Write-Verbose -Message 'Creating AV sets (Mel)'
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-LX-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Mel-LX-AVset  -ResourceGroupName $RG -Location $Melbourne
  }
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-BSD-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Mel-BSD-AVset -ResourceGroupName $RG -Location $Melbourne
  }
  if (-NOT (Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-WIN-AVset -EA SilentlyContinue)) {
     $null=New-AzureRmAvailabilitySet -Name Mel-WIN-AVset -ResourceGroupName $RG -Location $Melbourne
  }
  $SydLXavSet  = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-LX-AVset
  $SydBSDavSet = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-BSD-AVset
  $SydWINavSet = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Syd-WIN-AVset
  $MelLXavSet  = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-LX-AVset
  $MelBSDavSet = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-BSD-AVset
  $MelWINavSet = Get-AzureRmAvailabilitySet -ResourceGroupName $RG -Name Mel-WIN-AVset
#endregion
#region KeyVault
 $tags = @{'function' = 'AzureThings'}

 $MKVP=Register-AzureRmResourceProvider -ProviderNamespace 'Microsoft.KeyVault'
 Write-Verbose -Message 'Creating (standard) Key Vault (Mel)'
 if (-NOT ( Get-AzureRmKeyVault -ResourceGroupName $RG -VaultName $KeyVaultMelbourne -EA SilentlyContinue)) {
  $MelKeyVault=New-AzureRmKeyVault -ResourceGroupName $RG -Location $Melbourne `
                                   -VaultName $KeyVaultMelbourne `
                                   -EnabledForTemplateDeployment `
                                   -EnabledForDeployment `
                                   -EnabledForDiskEncryption `
                                   -Tag $tags
 }
 $MelKeyVault=Get-AzureRmKeyVault -VaultName $KeyVaultMelbourne -ResourceGroupName $RG

 Write-Verbose -Message 'Creating (Service Fabric) Key Vault (Mel)'
 #Service Fabric needs its own RG and Vault.
 if (-NOT ( Get-AzureRmKeyVault -ResourceGroupName $RGSF -VaultName $KeyVaultMelSF -EA SilentlyContinue)) {
  $MelKeyVaultSF=New-AzureRmKeyVault -ResourceGroupName $RGSF -Location $Melbourne `
                                   -VaultName $KeyVaultMelSF `
                                   -EnabledForTemplateDeployment `
                                   -EnabledForDeployment `
                                   -EnabledForDiskEncryption `
                                   -Tag $tags
 }
 $MelKeyVaultSF=Get-AzureRmKeyVault -VaultName $KeyVaultMelSF -ResourceGroupName $RGSF
 
# By default, the Web App RP doesn’t have access to a customers KeyVault. 
# In order to use a KV for certificate deployment, you need to authorize the RP.
# See https://blogs.msdn.microsoft.com/appserviceteam/2016/05/24/deploying-azure-web-app-certificate-through-key-vault/

Set-AzureRmKeyVaultAccessPolicy -VaultName $KeyVaultMelbourne -ServicePrincipalName abfa0a7c-a6b6-4736-8310-5855508787cd -PermissionsToSecrets get
Set-AzureRmKeyVaultAccessPolicy -VaultName $KeyVaultMelSF     -ServicePrincipalName abfa0a7c-a6b6-4736-8310-5855508787cd -PermissionsToSecrets get

$secretvalue = ConvertTo-SecureString -String $user -AsPlainText -Force
Set-AzureKeyVaultSecret -VaultName $KeyVaultMelbourne -Name 'AdminUsername' -SecretValue $secretvalue

$secretvalue = ConvertTo-SecureString -String $password -AsPlainText -Force
Set-AzureKeyVaultSecret -VaultName $KeyVaultMelbourne -Name 'Adminpassword' -SecretValue $secretvalue


#region Create VSTS Auth header
# using existing personal Access token:
# https://docs.microsoft.com/en-us/vsts/accounts/use-personal-access-tokens-to-authenticate
$VSTSpersonalAccessToken='p5e47hn3egkkztqlycuou54oodf5ytls7elwti2bmoolquzsbena'
$vstsUserName='LukeBrennan'

Write-Verbose -Message 'Creating new VSTS auth headers using supplied Personal Access Token'
# will be consumed by the VSTS REST endpoints
    $basicAuth = ('{0}:{1}' -f $vstsUserName, $vstsPersonalAccessToken)
    $basicAuth = [System.Text.Encoding]::UTF8.GetBytes($basicAuth)
    $basicAuth = [System.Convert]::ToBase64String($basicAuth) 
    $headers = @{
      Authorization = ('Basic {0}' -f $basicAuth)
    }
    $headers.Add('Accept','application/json')
$vstsAuthHeader=$headers

    $basicAuth = ('{0}:{1}' -f $vstsUserName, $vstsPersonalAccessToken)
    $basicAuth = [System.Text.Encoding]::UTF8.GetBytes($basicAuth)
    $basicAuth = [System.Convert]::ToBase64String($basicAuth)
    $headers = @{
      Authorization = ('Basic {0}' -f $basicAuth)
    }
$vstsBasicAuthHeader=$headers
#endregion
#endregion
#region Storage
  #not Managed storage, specific storage. We will put DSC and scripts up there also.
  Write-Verbose -Message 'Creating Storage Account (Syd)'
  if (-NOT (  Get-AzureRmStorageAccount -ResourceGroupName $RG -Name $SydStorageAccount -EA SilentlyContinue)) {
  $SydStorage=New-AzureRmStorageAccount -ResourceGroupName $RG -Location $Sydney -Name $SydStorageAccount `
                                        -Type Standard_LRS -Tag @{Name='StorageTagHere';Value='Sydney'}

  }

  Write-Verbose -Message 'Get storage context'
  $SydStorage=Get-AzureRmStorageAccount    -ResourceGroupName $RG -Name $SydStorageAccount
  $SydKeys   =Get-AzureRmStorageAccountKey -ResourceGroupName $RG -Name $SydStorageAccount
  $SydKey = $SydKeys[0].Value
  $SydContext = New-AzureStorageContext -StorageAccountName $SydStorageAccount -StorageAccountKey $SydKey
 #$SydContext = New-AzureStorageContext -StorageAccountName $SydStorageAccount -UseConnectedAccount 

  Write-Verbose -Message 'Create storage Containers (Syd)'
  if (-NOT (Get-AzureStorageContainer -Name $DSCconfigContainer -Context $Sydcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $DSCconfigContainer -Context $Sydcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $DSCmoduleContainer -Context $Sydcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $DSCmoduleContainer -Context $Sydcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $scriptContainer    -Context $Sydcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $scriptContainer    -Context $Sydcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $runBookContainer   -Context $Sydcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $runBookContainer   -Context $Sydcontext -Permission Container
  }
  
  Write-Verbose -Message 'Creating Storage Account (Mel)'
  if (-NOT (  Get-AzureRmStorageAccount -ResourceGroupName $RG -Name $MelStorageAccount -EA SilentlyContinue)) {
  $MelStorage=New-AzureRmStorageAccount -ResourceGroupName $RG -Location $Melbourne -Name $MelStorageAccount `
                                        -Type Standard_LRS -Tag @{Name='StorageTagHere';Value='Melbourne'}
  }

  Write-Verbose -Message 'Get storage context'
  $MelStorage=Get-AzureRmStorageAccount    -ResourceGroupName $RG -Name $MelStorageAccount
  $MelKeys   =Get-AzureRmStorageAccountKey -ResourceGroupName $RG -Name $MelStorageAccount
  $MelKey = $MelKeys[0].Value
  $MelContext = New-AzureStorageContext -StorageAccountName $MelStorageAccount -StorageAccountKey $MelKey
 #$MelContext = New-AzureStorageContext -StorageAccountName $MelStorageAccount -UseConnectedAccount 

  Write-Verbose -Message 'Create storage Containers (Mel)'
  if (-NOT (Get-AzureStorageContainer -Name $DSCconfigContainer -Context $Melcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $DSCconfigContainer -Context $Melcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $DSCmoduleContainer -Context $Melcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $DSCmoduleContainer -Context $Melcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $scriptContainer    -Context $Melcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $scriptContainer    -Context $Melcontext -Permission Container
  }
  if (-NOT (Get-AzureStorageContainer -Name $runBookContainer   -Context $Melcontext -EA SilentlyContinue)) {
      $null=New-AzureStorageContainer -Name $runBookContainer   -Context $Melcontext -Permission Container
  }

  $StartTime  = (Get-Date).ToUniversalTime().AddMinutes(-5)
  $ExpiryTime = (Get-Date).ToUniversalTime().AddYears(10) 

  # Sets up a Stored Access Policy and a Shared Access Signature for a container  
  $policy = New-AzureStorageContainerStoredAccessPolicy -Container $scriptContainer -Policy $ContainerPolicyName -Context $MelContext -StartTime $StartTime -ExpiryTime $ExpiryTime  -Permission rwld

  # Gets the Shared Access Signature for the policy  
  $sas = New-AzureStorageContainerSASToken -name $scriptContainer -Policy $ContainerPolicyName -Context  $MelContext
  Write-Host "Shared Access Signature= '$($sas.Substring(1))'"

# see https://docs.microsoft.com/en-us/rest/api/storageservices/Constructing-an-Account-SAS
# New-AzureStorageAccountSASToken -service Blob -ResourceType Container `
#                                    -Permission
#                                 -ExpiryTime $ExpireDateTime
#                                 -Context $ctx

#endregion
#region UploadThingsToStorage
  Write-Verbose -Message 'Uploading things to Storage.'
  Write-Verbose -Message 'Get storage contexts'
  $SydStorage=Get-AzureRmStorageAccount    -ResourceGroupName $RG -Name $SydStorageAccount
  $SydKeys   =Get-AzureRmStorageAccountKey -ResourceGroupName $RG -Name $SydStorageAccount
  $SydKey = $SydKeys[0].Value
  $SydContext = New-AzureStorageContext -StorageAccountName $SydStorageAccount -StorageAccountKey $SydKey
 
  $MelStorage=Get-AzureRmStorageAccount    -ResourceGroupName $RG -Name $MelStorageAccount
  $MelKeys   =Get-AzureRmStorageAccountKey -ResourceGroupName $RG -Name $MelStorageAccount
  $MelKey = $MelKeys[0].Value
  $MelContext = New-AzureStorageContext -StorageAccountName $MelStorageAccount -StorageAccountKey $MelKey

  Write-Verbose -Message 'Write items to TEMP files'
  if (-NOT (Test-Path -Path $LOCALTEMPSCRIPTS))  {$null=New-Item -Path $LOCALTEMPSCRIPTS  -ItemType Directory -Force}
  if (-NOT (Test-Path -Path $LOCALTEMPCONFIGS))  {$null=New-Item -Path $LOCALTEMPCONFIGS  -ItemType Directory -Force}
  if (-NOT (Test-Path -Path $LOCALTEMPRUNBOOKS)) {$null=New-Item -Path $LOCALTEMPRUNBOOKS -ItemType Directory -Force}
  
  $null=Get-ChildItem -Path $LOCALTEMPSCRIPTS  | Remove-Item -Force
  $null=Get-ChildItem -Path $LOCALTEMPCONFIGS  | Remove-Item -Force
  $null=Get-ChildItem -Path $LOCALTEMPRUNBOOKS | Remove-Item -Force

  # write the scripts to local disk
  foreach ($script in $NXscripts) {
    $var= Get-Variable -name $script
    $var.Value  | Set-Content -Path "$LOCALTEMPSCRIPTS\$script.sh"  -Force -Verbose
  }

  foreach ($script in $WindowsScripts) {
    $var= Get-Variable -name $script
    $var.Value  | Set-Content -Path "$LOCALTEMPSCRIPTS\$script.ps1"  -Force -Verbose
  }

  #and the Automation RunBooks
  foreach ($script in $RunBookScripts) {
    $var= Get-Variable -name $script
    $var.Value  | Set-Content -Path "$LOCALTEMPRUNBOOKS\$script.ps1"  -Force -Verbose
  }

  #and the DSC configs
  foreach ($config in $DSCconfigs) {
    $var= Get-Variable -name $config
    $var.Value  | Set-Content -Path "$LOCALTEMPCONFIGS\$config.ps1"  -Force -Verbose
  }
    
  Write-Verbose -Message 'Upload files to Containers (Sydney)'
  #push them up
  $null=Get-ChildItem -Path $LOCALTEMPSCRIPTS  |
    Set-AzureStorageBlobContent -Container $scriptContainer    -Context $Sydcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPCONFIGS  |
    Set-AzureStorageBlobContent -Container $DSCconfigContainer -Context $Sydcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPMODULES  |
    Set-AzureStorageBlobContent -Container $DSCmoduleContainer -Context $Sydcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPRUNBOOKS  |
    Set-AzureStorageBlobContent -Container $runBookContainer   -Context $Sydcontext -Force
    

  Write-Verbose -Message 'Upload files to Containers (Melbourne)'
  #push them up
  $null=Get-ChildItem -Path $LOCALTEMPSCRIPTS |
    Set-AzureStorageBlobContent -Container $scriptContainer    -Context $Melcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPCONFIGS  |
    Set-AzureStorageBlobContent -Container $DSCconfigContainer -Context $Melcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPMODULES  |
    Set-AzureStorageBlobContent -Container $DSCmoduleContainer -Context $Melcontext -Force

  $null=Get-ChildItem -Path $LOCALTEMPRUNBOOKS  |
    Set-AzureStorageBlobContent -Container $runBookContainer   -Context $Melcontext -Force
   

  Write-Verbose -Message "get Container Uri's"
  $SydScriptContainer   =Get-AzureStorageContainer -Name $scriptContainer    -Context $Sydcontext
  $SydDSCConfigContainer=Get-AzureStorageContainer -Name $DSCconfigContainer -Context $Sydcontext
  $SydDSCmoduleContainer=Get-AzureStorageContainer -Name $DSCmoduleContainer -Context $Sydcontext
  $SydRunBookContainer  =Get-AzureStorageContainer -Name $runBookContainer   -Context $Sydcontext
  $MelScriptContainer   =Get-AzureStorageContainer -Name $scriptContainer    -Context $Melcontext
  $MelDSCConfigContainer=Get-AzureStorageContainer -Name $DSCconfigContainer -Context $Melcontext
  $MelDSCmoduleContainer=Get-AzureStorageContainer -Name $DSCmoduleContainer -Context $Melcontext
  $MelRunBookContainer  =Get-AzureStorageContainer -Name $runBookContainer   -Context $Melcontext

  $SydScrContainerUri   =$SydScriptContainer.CloudBlobContainer.Uri.AbsoluteUri
  $SydDSCcfgContainerUri=$SydDSCConfigContainer.CloudBlobContainer.Uri.AbsoluteUri
  $SydDSCModContainerUri=$SydDSCModuleContainer.CloudBlobContainer.Uri.AbsoluteUri
  $SydRBContainerUri    =$SydRunBookContainer.CloudBlobContainer.Uri.AbsoluteUri

  $MelScrContainerUri   =$MelScriptContainer.CloudBlobContainer.Uri.AbsoluteUri
  $MelDSCcfgContainerUri=$MelDSCConfigContainer.CloudBlobContainer.Uri.AbsoluteUri
  $MelDSCModContainerUri=$MelDSCModuleContainer.CloudBlobContainer.Uri.AbsoluteUri
  $MelRBContainerUri    =$MelRunBookContainer.CloudBlobContainer.Uri.AbsoluteUri

    Write-Verbose -Message "Build HT's for Extensions Settings"
  # build the HashTable that we will pass into the Extension
  $SydUbuntuCustomSettings=@{
  'fileUris'= @("$SydScrContainerUri/UbuntuInstallDocker.sh")
  'commandToExecute'= './UbuntuInstallDocker.sh >/tmp/DockerInstall.log'
  }
  $SydCentOSCustomSettings=@{
  'fileUris'= @("$SydScrContainerUri/CentOSInstallDocker.sh")
  'commandToExecute'= './CentOSInstallDocker.sh >/tmp/DockerInstall.log'
  }
  $SydFreeBSDCustomSettings=@{
  'fileUris'= @("$SydScrContainerUri/FreeBSDInstallDocker.sh")
  'commandToExecute'= './FreeBSDInstallDocker.sh >/tmp/DockerInstall.log'
  }
  $SydVMSSCustomSettings=@{
  'fileUris'= @("$SydScrContainerUri/WinInstallIIS.ps1")
  'commandToExecute'= 'powerShell -ExecutionPolicy Unrestricted -File WinInstallIIS.ps1'
  }

  $MelUbuntuCustomSettings=@{
  'fileUris'= @("$MelScrContainerUri/UbuntuInstallDocker.sh")
  'commandToExecute'= './UbuntuInstallDocker.sh >/tmp/DockerInstall.log'
  }
  $MelCentOSCustomSettings=@{
  'fileUris'= @("$MelScrContainerUri/CentOSInstallDocker.sh")
  'commandToExecute'= './CentOSInstallDocker.sh >/tmp/DockerInstall.log'
  }
  $MelFreeBSDCustomSettings=@{
  'fileUris'= @("$MelScrContainerUri/FreeBSDInstallDocker.sh")
  'commandToExecute'= './FreeBSDInstallDocker.sh >/tmp/DockerInstall.log'
  }

  # HT for access to StorageAccount also passed to Extension
  $SydProtectedSettings = @{'storageAccountName' = $SydStorageAccount; 'storageAccountKey' = $SydKey}
  $MelProtectedSettings = @{'storageAccountName' = $MelStorageAccount; 'storageAccountKey' = $MelKey}
  
#endregion
#region Automation
 Write-Verbose -Message 'creating Automation account. (Melbourne)'
 if (-NOT (Get-AzureRmAutomationAccount -ResourceGroupName $RG -Name $MelAutomation -EA SilentlyContinue)) {
    #automation only runs in the Melbourne datacentre, not Sydney
    $MelAutomationAcc=New-AzureRmAutomationAccount -ResourceGroupName $RG -Name $MelAutomation -Location $Melbourne `
                                                -plan Basic `
                                                -Tag @{Name='AutomationTagHere';Value='Melbourne Automation'} 
 }

 Write-Verbose -Message 'creating HT for Automation access'
 $MelAutomationAcc=Get-AzureRmAutomationAccount -ResourceGroupName $RG -Name $MelAutomation  
 $MelAutomationRegistration = $MelAutomationAcc | Get-AzureRmAutomationRegistrationInfo
 $RegistrationUrl = $MelAutomationRegistration.Endpoint
 $RegistrationKey = $MelAutomationRegistration.PrimaryKey
 # HT for access to Automation, will be passed to Linux Extension
 $MelAutomationPrivateConfig = @{'RegistrationUrl'= $RegistrationUrl; 'RegistrationKey'= $RegistrationKey}

 #region variables
 $SubscriptionId=(Get-AzureRmContext).Subscription.Id
 if (-NOT (Get-AzureRmAutomationVariable -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'SubscriptionId' -EA SilentlyContinue)) {
   New-AzureRmAutomationVariable -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'SubscriptionId' -Value $SubscriptionId -Encrypted $True 
 }
 #endregion
 #region connections
 <#
  $Conn = Get-AzureRmAutomationConnection -Name AzureRunAsConnection `
                                         -ResourceGroupName $RG `
                                         -AutomationAccountName $MelAutomation

  Add-AzureRMAccount -ServicePrincipal -Tenant $Conn.TenantID `
                    -ApplicationId $Conn.ApplicationID `
                    -CertificateThumbprint $Conn.CertificateThumbprint
#>
#endregion
 #region DSC
 $configs = Get-ChildItem -path $LOCALTEMPCONFIGS
 foreach ($config in $configs) {
   Write-Verbose -Message 'Importing DSC configs from TEMP'
   $null=Import-AzureRmAutomationDscConfiguration -SourcePath $config.FullName `
                                                  -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                                  -Published -Force `
                                                  -Tag @{Name='AutomationDSC';Value="$($config.BaseName)"} 
 }

 # grab any modules from Storage and upload into Automation
  Write-Verbose -Message 'Importing DSC modules (.zip) from Storage into Automation'
  $blobs=Get-AzureStorageBlob -Container $DSCmoduleContainer -Context $Melcontext
  foreach ($blob in $blobs) {
    $Name=($blob.Name).ToLower()
    if ($name.LastIndexOf('.zip') -gt 0) {$name = $name.Substring(0,$name.LastIndexOf('.zip'))}
    $ContentLink=$blob.ICloudBlob.StorageUri.PrimaryUri.OriginalString
    $upload=New-AzureRmAutomationModule -Name $Name -ContentLink $ContentLink -ResourceGroupName $RG -AutomationAccountName $MelAutomation 
    while ($Upload.ProvisioningState -ne 'Succeeded' -and $Upload.ProvisioningState -ne 'Failed') {
        $Upload = $Upload | Get-AzureRmAutomationModule
        $Upload.ProvisioningState
        Start-Sleep -Seconds 10
    }
  }
  Write-Verbose -Message 'Compiling DSC configs to MOFs'
  $configs=Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation
  foreach ($config in $configs) {
    $config.ConfigurationName
    $CompilationJob=Start-AzureRmAutomationDscCompilationJob -ConfigurationName $config.Name -ResourceGroupName $RG -AutomationAccountName $MelAutomation
    #the -WAIT switch is not yet available, so test in a loop :-(
    while($CompilationJob.EndTime –eq $null -and $CompilationJob.Exception –eq $null) {
      $CompilationJob = $CompilationJob | Get-AzureRmAutomationDscCompilationJob
      Start-Sleep -Seconds 3
    }
    $CompilationJob.Status
  }
  `
 #endregion
 #region PublishRunBooks

 $RBooksOnDisk=Get-ChildItem -Path $LOCALTEMPRUNBOOKS

 foreach ($RB in $RBooksOnDisk) {
   Import-AzureRmAutomationRunbook -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                 -Path $RB.Fullname -Name $RB.Basename -Type PowerShell `
                                 -Description 'A powershell Runbook' `
                                 -Tag @{Name='RunbookTagName';Value=$MyName} `
                                 -Force
   Publish-AzureRmAutomationRunbook -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                  -Name $RB.Basename
 }

 #endregion
 #region Automation RBAC
 # example of granting a contractior rights to Automation
 Write-Verbose -Message 'Automation access RBAC'
  $SubscriptionID=(Get-AzureRmContext).Subscription.ID
  $RBACscope='/subscriptions/{0}/resourcegroups/{1}/Providers/Microsoft.Automation/automationAccounts/{2}' -f $SubscriptionID, $RG, $MelAutomation
  if ($CBellee) {
    if (-NOT (Get-AzureRmRoleAssignment -ObjectId $CBellee.Id -Scope $RBACscope -RoleDefinitionName 'Automation operator')) {
      New-AzureRmRoleAssignment -ObjectId $CBellee.Id -RoleDefinitionName 'Automation operator' -Scope $RBACscope
    }
  }
 #endregion
 #region RunAsAccount
  Add-Type -AssemblyName System.Security
    
  function New-RunAsAccount {

  Param (
        [Parameter(Mandatory = $true)]  [String]  $ResourceGroup,
        [Parameter(Mandatory = $true)]  [String]  $AutomationAccountName,
        [Parameter(Mandatory = $true)]  [String]  $ApplicationDisplayName,
        [Parameter(Mandatory = $true)]  [String]  $SubscriptionId,
        [Parameter(Mandatory = $true)]  [Boolean] $CreateClassicRunAsAccount,
        [Parameter(Mandatory = $true)]  [String]  $SelfSignedCertPlainPassword,
        [Parameter(Mandatory = $false)] [int]     $SelfSignedCertNoOfMonthsUntilExpired = 12
       )

    Add-Type -AssemblyName Microsoft.Azure.Commands.Common.Graph.RBAC
    private:function Create-SelfSignedCertificate {
 
      param([Parameter(Mandatory = $true)] [string] $certificateName, 
            [Parameter(Mandatory = $true)] [string] $selfSignedCertPlainPassword,
            [Parameter(Mandatory = $true)] [string] $certPath,
            [Parameter(Mandatory = $true)] [string] $certPathCer, 
            [Parameter(Mandatory = $true)] [string] $selfSignedCertNoOfMonthsUntilExpired )

        Write-Verbose -Message 'Create Self-Signed Certificate'
        $CertStoreLocation='cert:\LocalMachine\My'

        # need to be running as Admin for this cert store!
        $Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation $CertStoreLocation `
                                          -KeyExportPolicy Exportable -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
                                          -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) `
                                          -HashAlgorithm SHA256

        $CertPassword = ConvertTo-SecureString -String $selfSignedCertPlainPassword -AsPlainText -Force
        Export-PfxCertificate -Cert ($CertStoreLocation + '\' + $Cert.Thumbprint) -FilePath $certPath -Password $CertPassword -Force | Write-Verbose
        Export-Certificate    -Cert ($CertStoreLocation + '\' + $Cert.Thumbprint) -FilePath $certPathCer -Type CERT | Write-Verbose
    }

    private:function Create-ServicePrincipal {  

      param ([Parameter(Mandatory = $true)] [Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert, 
             [Parameter(Mandatory = $true)] [string] $applicationDisplayName)

        Write-Verbose -Message 'Create Service Principal'
        $CurrentDate = Get-Date
        $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
        $KeyId = (New-Guid).Guid

       #$KeyCredential = New-Object  Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
        $KeyCredential = New-Object Microsoft.Azure.Graph.RBAC.Version1_6.ActiveDirectory.PSADKeyCredential
        $KeyCredential.StartDate = $CurrentDate
        $KeyCredential.EndDate = Get-Date -Date $PfxCert.GetExpirationDateString()
        $KeyCredential.EndDate = $KeyCredential.EndDate.AddDays(-1)
        $KeyCredential.KeyId = $KeyId
        $KeyCredential.CertValue  = $keyValue

        # Use key credentials and create an Azure AD application
        $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ('http://' + $applicationDisplayName) -IdentifierUris ('http://' + $KeyId) -KeyCredentials $KeyCredential
        $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId 
        $GetServicePrincipal = Get-AzureRmADServicePrincipal -ObjectId $ServicePrincipal.Id

        # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
        Start-Sleep -Seconds 15
        $NewRole = New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
        $Retries = 0;
        While ($NewRole -eq $null -and $Retries -le 6) {
            Start-Sleep -Seconds 10
            New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId | Write-Verbose -ErrorAction SilentlyContinue
            $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
            $Retries++;
        }
        return $Application.ApplicationId.ToString();
    }

    private:function Create-AutomationCertificateAsset {
        
      param ([Parameter(Mandatory = $true)] [string] $resourceGroup, [Parameter(Mandatory = $true)] [string] $automationAccountName, [Parameter(Mandatory = $true)] [string] $certificateAssetName, [Parameter(Mandatory = $true)] [string] $certPath, [Parameter(Mandatory = $true)] [string] $certPlainPassword, [Parameter(Mandatory = $true)] [bool] $Exportable)

        Write-Verbose -Message 'Create Automation Certificate Asset'
        $CertPassword = ConvertTo-SecureString -String $certPlainPassword -AsPlainText -Force   
        Remove-AzureRmAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $certificateAssetName -ErrorAction SilentlyContinue
        New-AzureRmAutomationCertificate    -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $certificateAssetName -Path $certPath -Password $CertPassword -Exportable:$Exportable  | write-verbose
    }

    private:function Create-AutomationConnectionAsset {
        
      param([Parameter(Mandatory = $true)] [string] $resourceGroup, [Parameter(Mandatory = $true)] [string] $automationAccountName, [Parameter(Mandatory = $true)] [string] $connectionAssetName, [Parameter(Mandatory = $true)] [string] $connectionTypeName, [Parameter(Mandatory = $true)] [hashtable] $connectionFieldValues)
        Write-Verbose -Message 'Create Automation Connection Asset'
        Remove-AzureRmAutomationConnection -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue
        New-AzureRmAutomationConnection    -ResourceGroupName $ResourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues
    }


    $Subscription = Set-AzureRmContext -SubscriptionId $SubscriptionId

    # Create a Run As account by using a service principal
    $CertificateAssetName = 'AzureRunAsCertificate'
    $ConnectionAssetName  = 'AzureRunAsConnection'
    $ConnectionTypeName   = 'AzureServicePrincipal'

    $CertificateName = $AutomationAccountName + $CertificateAssetName
    $PfxCertPathForRunAsAccount = Join-Path -Path $env:TEMP -ChildPath ($CertificateName + '.pfx')
    $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
    $CerCertPathForRunAsAccount = Join-Path -Path $env:TEMP -ChildPath ($CertificateName + '.cer')
    Create-SelfSignedCertificate -certificateName $CertificateName -selfSignedCertPlainPassword $PfxCertPlainPasswordForRunAsAccount -certPath $PfxCertPathForRunAsAccount -certPathCer $CerCertPathForRunAsAccount -selfSignedCertNoOfMonthsUntilExpired $SelfSignedCertNoOfMonthsUntilExpired


    # Create a service principal
    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    $ApplicationId = Create-ServicePrincipal -PfxCert $PfxCert -applicationDisplayName $ApplicationDisplayName

    # Create the Automation certificate asset
    Create-AutomationCertificateAsset -resourceGroup $ResourceGroup -automationAccountName $AutomationAccountName -certificateAssetName $CertificateAssetName -certPath $PfxCertPathForRunAsAccount -certPlainPassword $PfxCertPlainPasswordForRunAsAccount -Exportable $true

    # Populate the ConnectionFieldValues
    $SubscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
    $TenantID = $SubscriptionInfo.TenantId 
    $Thumbprint = $PfxCert.Thumbprint
    $ConnectionFieldValues = @{'ApplicationId' = $ApplicationId; 'TenantId' = $TenantID.TenantId; 'CertificateThumbprint' = $Thumbprint; 'SubscriptionId' = $SubscriptionId}

    # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
    Create-AutomationConnectionAsset -resourceGroup $ResourceGroup -automationAccountName $AutomationAccountName -connectionAssetName $ConnectionAssetName -connectionTypeName $ConnectionTypeName -connectionFieldValues $ConnectionFieldValues

  }
  if (Test-AdminRights) {
 
    New-RunAsAccount -ResourceGroup $RG `
                     -ApplicationDisplayName $appDisplayName `
                     -AutomationAccountName $MelAutomation `
                     -SubscriptionId $SubscriptionId `
                     -CreateClassicRunAsAccount $false `
                     -SelfSignedCertPlainPassword $password `
                     -SelfSignedCertNoOfMonthsUntilExpired 12
                      
  }
  Else {
    Write-Warning -Message 'Skipping New-RunAsAccount, as local Cert generation and store requires Administrator rights.'
    }
 #endregion
#endregion
#region Azure Functions
# create the azure function App engine, then upload a PS script as a function to be called.
  ## see https://docs.microsoft.com/en-us/azure/azure-functions/functions-infrastructure-as-code
  ## see https://gist.github.com/mikehowell/8562b81e24a3b0c16839578f8680a192

 $functionAppResource = Get-AzureRmResource | Where-Object {$_.ResourceName -eq $functionAppName -And $_.ResourceType -eq 'Microsoft.Web/Sites'}
 if ($null -eq $functionAppResource) {
   $functionAppResource=New-AzureRmResource -ResourceType 'Microsoft.Web/Sites' -ResourceName $functionAppName -Kind 'functionapp' -Location $Sydney -ResourceGroupName $RG -Properties @{} -Force
 } 

 # OK now we have the underpinnings, go create an Azure function to call
 # create an Azure function : CSharp JavaScript FSharp Java or for PowerShell, Python, and Batch, create your own custom function. 

 # heck let's do a PowerShell function, of course! This will be stored in the site as 'run.ps1'.
 $functionName = 'HttpTriggeredPS'

 $SB = {
# POST method: $req
$requestBody = Get-Content $req -Raw | ConvertFrom-Json
$name = $requestBody.name

# GET method: each querystring parameter is its own variable
if ($req_query_name) 
{
    $name = $req_query_name 
}

Out-File -Encoding Ascii -FilePath $res -inputObject "Hello $name"
}

#now the definition of the function.json, which is stored alongside run.ps1
#NOTE the $false will become False in the json, but it seems to expect false (lowercase) 
#     if we put 'false' with quotes, again doesn't see it as false...
#     It's a bug. But who is at fault?

$props = @{
  config = @{
   'bindings' = @(
      @{
         'name'      = 'req'
         'type'      = 'httpTrigger'
         'direction' = 'in'
         'authlevel' = 'function'
       },
    @{
         'name'      = 'res'
         'type'      = 'http'
         'direction' = 'out'
     }
   )
   'disabled' = "false"
  }
  files = @{ 'run.ps1' = $SB }
}


$ResourceName='{0}/{1}' -f $functionAppResource.Name, $functionName # check for existing item
$Params = @{
    ResourceGroupName = $RG
    ResourceType      = 'Microsoft.Web/sites/functions'
    ResourceName      = $ResourceName
    ApiVersion        = '2015-08-01'
}

if (-NOT (Get-AzureRmResource @Params -EA SilentlyContinue) ) { # check if it already exists
  #this new function  will be placed into the correct location
  $newResourceId = '{0}/functions/{1}' -f $functionAppResource.ResourceId, $functionName 
  New-AzureRmResource -ResourceID $newResourceId -Properties $props -Force -ApiVersion 2016-08-01
}

#endregion
#region RecoveryServicesVault
Write-Verbose -Message 'creating Recovery Services Vault. (Sydney)'
# see also https://github.com/anthonyonazure/AzureSiteRecoverySetup/blob/master/ASRAutomatesSetup.ps1
$MRSP=Register-AzureRmResourceProvider -ProviderNamespace 'Microsoft.RecoveryServices'

if (-NOT (Get-AzureRmRecoveryServicesVault -Name $BackUpVaultSydney -ResourceGroupName $RG -EA SilentlyContinue)) {
   $BackupVault=New-AzureRmRecoveryServicesVault -Name $BackUpVaultSydney `
                                                 -ResourceGroupName $RG `
                                                 -Location $Sydney 
}
$BackupVault = Get-AzureRmRecoveryServicesVault –Name $BackUpVaultSydney
Set-AzureRmRecoveryServicesBackupProperties  -Vault $BackupVault `
                                             -BackupStorageRedundancy GeoRedundant

#endregion
#region OMS
 Write-Verbose -Message 'Operational Insights Workspace. (Melbourne)'
# https://docs.microsoft.com/en-us/azure/virtual-machines/scripts/virtual-machines-linux-powershell-sample-create-vm-oms
if (-NOT (Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $RG -Name $MelLogAnalyticsWS -EA SilentlyContinue)) {
  $OMSLAWS=New-AzureRmOperationalInsightsWorkspace -ResourceGroupName  $RG -Name $MelLogAnalyticsWS -Location $Melbourne
}

$OIWS=Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $RG -Name $MelLogAnalyticsWS
$OIWSkeys=Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $RG -Name $MelLogAnalyticsWS 
$OIWSurl=$OIWS.PortalUrl

#endregion
#region VMconfigs
# create the configs that we will use later to spin up actual VM instances.

  if (-NOT ($SydLXavSet)) {Write-Error -Message 'Run the AVset region first'}
  if (-NOT ($SydStorage)) {Write-Error -Message 'Run the Storage region first'}

  Write-Verbose -Message 'Creating VM configs (Sydney)'

  $vmName=$SydneyUbuntu
  $SydUbuntu=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $SydLXavSet.Id 
  $SydUbuntu=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $SydUbuntu -Credential $AdminCredential
  $SydUbuntu=Set-AzureRmVMSourceImage -PublisherName 'canonical' -Offer 'UbuntuServer' -Skus '16.04-LTS' -version latest -VM $SydUbuntu


  ## If deploying a 'special' image, e.g. Data Science Virtual Machine - Windows 2016
  ## Set-AzureRmVMPlan 
##  $vm = Set-AzureRmVMPlan -VM $vm -Name windows2016 -Product windows-data-science-vm -Publisher microsoft-ads
## 
#Have to accept terms
##Get-AzureRmMarketplaceTerms -Name windows2016 -Product windows-data-science-vm -Publisher microsoft-ads |
##    Set-AzureRmMarketplaceTerms -Accept

  $NIC=Get-AzureRmNetworkInterface -Name $SydLXnic0 -ResourceGroupName $RG
  $SydUbuntu=Add-AzureRmVMNetworkInterface -VM $SydUbuntu -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $SydStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $SydUbuntu=Set-AzureRmVMOSDisk -VM $SydUbuntu -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage


  $vmName=$SydneyCentOS
  $SydCentOS=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $SydLXavSet.Id 
  $SydCentOS=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $SydCentOS -Credential $AdminCredential
  $SydCentOS=Set-AzureRmVMSourceImage -PublisherName 'openlogic' -Offer 'CentOS' -Skus '7.3' -version latest -VM $SydCentOS

  $NIC=Get-AzureRmNetworkInterface -Name $SydLXnic1 -ResourceGroupName $RG
  $SydCentOS=Add-AzureRmVMNetworkInterface -VM $SydCentOS -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $SydStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $SydCentOS=Set-AzureRmVMOSDisk -VM $SydCentOS -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  $vmName=$SydneyFreeBSD
  $SydFreeBSD=New-AzureRmVMConfig -VMName $vmName -VMSize $AzureVMsize -AvailabilitySetId $SydBSDavSet.Id
  $SydFreeBSD=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $SydFreeBSD -Credential $AdminCredential
  $SydFreeBSD=Set-AzureRmVMSourceImage -PublisherName 'MicrosoftOSTC' -Offer 'FreeBSD' -Skus '11.1' -Version latest -VM $SydFreeBSD

  $NIC=Get-AzureRmNetworkInterface -Name $SydBSDnic0 -ResourceGroupName $RG
  $SydFreeBSD=Add-AzureRmVMNetworkInterface -VM $SydFreeBSD -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $SydStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $SydFreeBSD=Set-AzureRmVMOSDisk -VM $SydFreeBSD -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  $vmName=$SydneyOpenBSD
  $SydOpenBSD=New-AzureRmVMConfig -VMName $vmName -VMSize $AzureVMsize -AvailabilitySetId $SydBSDavSet.Id

  $vmName=$SydneyWinSvr
  $SydWinSvr=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $SydWINavSet.Id 
  $SydWinSvr=Set-AzureRmVMOperatingSystem -Windows -ComputerName $vmName -VM $SydWinSvr -Credential $AdminCredential
  $SydWinSvr=Set-AzureRmVMSourceImage -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2016-Datacenter-with-Containers' -version latest -VM $SydWinSvr

  $NIC=Get-AzureRmNetworkInterface -Name $SydWINnic0 -ResourceGroupName $RG
  $SydWinSvr=Add-AzureRmVMNetworkInterface -VM $SydWinSvr -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $SydStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $SydWinSvr=Set-AzureRmVMOSDisk -VM $SydWinSvr -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  Write-Verbose -Message 'Creating VM configs (Melbourne)'

  $vmName=$MelbourneUbuntu
  $MelUbuntu=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $MelLXavSet.Id 
  $MelUbuntu=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $MelUbuntu -Credential $AdminCredential
  $MelUbuntu=Set-AzureRmVMSourceImage -PublisherName 'canonical' -Offer 'UbuntuServer' -Skus '16.04-LTS' -version latest -VM $MelUbuntu

  $NIC=Get-AzureRmNetworkInterface -Name $MelLXnic0 -ResourceGroupName $RG
  $MelUbuntu=Add-AzureRmVMNetworkInterface -VM $MelUbuntu -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $MelStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $MelUbuntu=Set-AzureRmVMOSDisk -VM $MelUbuntu -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  $vmName=$MelbourneCentOS
  $MelCentOS=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $MelLXavSet.Id 
  $MelCentOS=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $MelCentOS -Credential $AdminCredential
  $MelCentOS=Set-AzureRmVMSourceImage -PublisherName 'openlogic' -Offer 'CentOS' -Skus '7.3' -version latest -VM $MelCentOS

  $NIC=Get-AzureRmNetworkInterface -Name $MelLXnic1 -ResourceGroupName $RG
  $MelCentOS=Add-AzureRmVMNetworkInterface -VM $MelCentOS -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $MelStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $MelCentOS=Set-AzureRmVMOSDisk -VM $MelCentOS -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  $vmName=$MelbourneFreeBSD
  $MelFreeBSD=New-AzureRmVMConfig -VMName $vmName -VMSize $AzureVMsize -AvailabilitySetId $MelBSDavSet.Id
  $MelFreeBSD=Set-AzureRmVMOperatingSystem -Linux -ComputerName $vmName -VM $MelFreeBSD -Credential $AdminCredential
  $MelFreeBSD=Set-AzureRmVMSourceImage -PublisherName 'MicrosoftOSTC' -Offer 'FreeBSD' -Skus '11.1' -version latest -VM $MelFreeBSD

  $NIC=Get-AzureRmNetworkInterface -Name $MelBSDnic0 -ResourceGroupName $RG
  $MelFreeBSD=Add-AzureRmVMNetworkInterface -VM $MelFreeBSD -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $MelStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $MelFreeBSD=Set-AzureRmVMOSDisk -VM $MelFreeBSD -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

  $vmName=$MelbourneOpenBSD
  $MelOpenBSD=New-AzureRmVMConfig -VMName $vmName -VMSize $AzureVMsize -AvailabilitySetId $MelBSDavSet.Id

  $vmName=$MelbourneWinSvr
  $MelWinSvr=New-AzureRmVMConfig  -VMName $vmName  -VMSize $AzureVMsize -AvailabilitySetId $MelWINavSet.Id 
  $MelWinSvr=Set-AzureRmVMOperatingSystem -Windows -ComputerName $vmName -VM $MelWinSvr -Credential $AdminCredential
  $MelWinSvr=Set-AzureRmVMSourceImage -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2016-Datacenter-with-Containers' -version latest -VM $MelWinSvr

  $NIC=Get-AzureRmNetworkInterface -Name $MelWINnic0 -ResourceGroupName $RG
  $MelWinSvr=Add-AzureRmVMNetworkInterface -VM $MelWinSvr -Id $NIC.Id

  $OSDiskName=$vmName + 'OSDisk'
  $OSDiskUri = $MelStorage.PrimaryEndpoints.Blob.ToString() + 'vhds/' + $OSDiskName +'.vhd'
  $MelWinSvr=Set-AzureRmVMOSDisk -VM $MelWinSvr -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

#endregion
#region VMSSconfigs
  Write-Verbose -Message 'Creating VMSS config (Sydney)'


# Create a VMSS config object
$SydVMSSConfig = New-AzureRmVmssConfig -Location $Sydney `
                                       -SkuCapacity 2 -SkuName Standard_DS2 `
                                       -UpgradePolicyMode Automatic `
                                       -Tag @{Name='AnotherTagName';Value=$MyName}
<#
  ### cannot get this to work?
  #Get-AzureRmVMExtensionImageType
  # Use the CustomScriptExtension (for Windows) to install IIS and configure basic website
  $SydVMSSConfig = Add-AzureRmVmssExtension -VirtualMachineScaleSet $SydVMSSConfig `
                                          -Name 'SydWinVMSSextension' `
                                          -Publisher 'Microsoft.Compute' `
                                          -Type 'CustomScriptExtension' `
                                          -TypeHandlerVersion 1.9 `
                                          -Setting $SydVMSSCustomSettings `
                                          -ProtectedSetting $SydProtectedSettings


#>

# Reference a virtual machine image from the gallery
$SydVMSSConfig=Set-AzureRmVmssStorageProfile -VirtualMachineScaleSet $SydVMSSConfig `
                             -ImageReferencePublisher MicrosoftWindowsServer `
                             -ImageReferenceOffer WindowsServer `
                             -ImageReferenceSku 2016-Datacenter `
                             -ImageReferenceVersion latest `
                             -OsDiskCreateOption 'FromImage' -OsDiskCaching 'None'

# Set up information for authenticating with the virtual machine
$SydVMSSConfig=Set-AzureRmVmssOsProfile -VirtualMachineScaleSet $SydVMSSConfig `
                                        -AdminUsername $user -AdminPassword $password `
                                        -ComputerNamePrefix SydWin

$SydVnet      = Get-AzureRmVirtualNetwork -Name $VnetSydney -ResourceGroupName $RG
$SydWINsubnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $WINsubnetName -VirtualNetwork $SydVnet
$ipConfig = New-AzureRmVmssIpConfig -Name 'VMSSIPConfig' `
                                    -LoadBalancerBackendAddressPoolsId $SydWinLB.BackendAddressPools[0].Id `
                                    -SubnetId $SydWINsubnet.Id

# Attach the virtual network to the config object
$SydVMSSConfig=Add-AzureRmVmssNetworkInterfaceConfiguration -VirtualMachineScaleSet $SydVMSSConfig `
                                                            -Name 'network-config'  `
                                                            -Primary $true `
                                                            -IPConfiguration $ipConfig

#endregion
#region create VM's
# now spin up the actual VMs
#region   inSydney
#region     Analytics
if (Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $RG -Name $MelLogAnalyticsWS -EA SilentlyContinue){
  $OIWS=Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $RG -Name $MelLogAnalyticsWS
  $OIWSkeys=Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $RG -Name $MelLogAnalyticsWS 
  $OMSid=$OIWS.CustomerId
  $OMSkey=$OIWSKEYS.PrimarySharedKey

  $PublicSettings    = New-Object -TypeName psobject | Add-Member -PassThru -MemberType NoteProperty -Name workspaceId  -Value $omsId  | ConvertTo-Json
  $protectedSettings = New-Object -TypeName psobject | Add-Member -PassThru -MemberType NoteProperty -Name workspaceKey -Value $omsKey | ConvertTo-Json

  #  $PublicSettings    = @{'workspaceId'  = $OMSid}
  #  $ProtectedSettings = @{'workspaceKey' = $OMSkey
  $OpInsights=$true
}
else {
  $OpInsights=$false
}
#endregion
  Write-Verbose -Message "Creating VM's (Sydney)"
#region     SydUbuntu
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $SydneyUbuntu -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Sydney -VM $SydUbuntu -Tag @{Name='VMTagHere';Value='Sydney Ubuntu'} -Verbose
  }
  Write-Verbose -Message 'Set-AzureRMVmExtension (Ubuntu)' # 'CustomScript' extension is used for Linux
  Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                         -VM $SydneyUbuntu `
                         -Publisher 'Microsoft.Azure.Extensions' `
                         -Settings $SydUbuntuCustomSettings `
                         -ProtectedSettings $SydProtectedSettings `
                         -TypeHandlerVersion 2.0 `
                         -ResourceGroupName $RG `
                         -Name 'CustomScript' `
                         -Location $Sydney -Verbose 


  if ($OpInsights) {
  Set-AzureRmVMExtension -ExtensionType 'OmsAgentForLinux' `
                         -ExtensionName 'OMS' `
                         -ResourceGroupName $RG `
                         -VMName $SydneyUbuntu `
                         -Publisher 'Microsoft.EnterpriseCloud.Monitoring' `
                         -TypeHandlerVersion 1.4 `
                         -SettingString $PublicSettings `
                         -ProtectedSettingString $protectedSettings `
                         -Location $Sydney -Verbose
  }

  Write-Verbose -Message 'Checking for NXDSCconfig'
  if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'NXDSCconfig' -EA SilentlyContinue) {
      $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'NXDSCconfig'}
      if ($nodeconf) {
         Write-Verbose -Message 'Registering for NXDSCconfig'
        <#
         # the std PowerShell cmdlet does NOT yet support Linux. 
         Register-AzureRmAutomationDscNode -AzureVMName $SydneyUbuntu -AzureVMLocation $Sydney -AzureVMResourceGroup $RG `
                                           -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                           -NodeConfigurationName $nodeconf.Name `
                                           -RefreshFrequencyMins 30 `
                                           -ConfigurationMode 'ApplyAndAutocorrect' `
                                           -ConfigurationModeFrequencyMins 15 `
                                           -RebootNodeIfNeeded $true -AllowModuleOverwrite $true
         #>
         if ($MelAutomationPrivateConfig) { # was created when we generated Automation earlier
           $MelAutomationPublicConfig = @{
             'ExtensionAction'       = 'Register';
             'NodeConfigurationName' = $nodeconf.Name;
             'RefreshFrequencyMins'  = 30;
             'ConfigurationMode'     = 'ApplyAndAutoCorrect';
             'ConfigurationModeFrequencyMins'= 15  }

           Set-AzureRmVMExtension -ExtensionType 'DSCForLinux' `
                                  -VMName $SydneyUbuntu `
                                  -Publisher 'Microsoft.OSTCExtensions' `
                                  -Settings $MelAutomationPublicConfig `
                                  -ProtectedSettings $MelAutomationPrivateConfig `
                                  -TypeHandlerVersion 2.7 `
                                  -ResourceGroupName $RG `
                                  -Name 'DSCForLinux' `
                                  -Location $Sydney -Verbose
         }
         else {
           'automation keys not defined'
         }
         
      }
  }

#endregion
#region     SydCentOS
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $SydneyCentOS -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Sydney -VM $SydCentOS -Tag @{Name='VMTagHere';Value='Sydney CentOS'} -Verbose
  }
  Write-Verbose -Message 'Set-AzureRMVmExtension (CentOS)' # 'CustomScript' extension is used for Linux
  Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                         -VM $SydneyCentOS -Publisher 'Microsoft.Azure.Extensions' `
                         -Settings $SydCentOSCustomSettings `
                         -ProtectedSettings $SydProtectedSettings `
                         -TypeHandlerVersion 2.0 `
                         -ResourceGroupName $RG `
                         -Name 'CustomScript' `
                         -Location $Sydney -Verbose 

  Write-Verbose -Message 'Checking for NxApacheconfig'
  if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'NxApacheconfig' -EA SilentlyContinue) {
      $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'NxApacheconfig'}
      if ($nodeconf) {
         Write-Verbose -Message 'Registering for NxApacheconfig'
        <#
         # the std PowerShell cmdlet does NOT yet support Linux. 
         Register-AzureRmAutomationDscNode -AzureVMName $SydneyCentOS -AzureVMLocation $Sydney -AzureVMResourceGroup $RG `
                                           -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                           -NodeConfigurationName $nodeconf.Name `
                                           -RefreshFrequencyMins 30 `
                                           -ConfigurationMode 'ApplyAndAutocorrect' `
                                           -ConfigurationModeFrequencyMins 15 `
                                           -RebootNodeIfNeeded $true -AllowModuleOverwrite $true
         #>
         if ($MelAutomationPrivateConfig) { # was created when we generated Automation earlier
           $MelAutomationPublicConfig = @{
             'ExtensionAction'       = 'Register';
             'NodeConfigurationName' = $nodeconf.Name;
             'RefreshFrequencyMins'  = 30;
             'ConfigurationMode'     = 'ApplyAndAutoCorrect';
             'ConfigurationModeFrequencyMins'= 15  }

           Set-AzureRmVMExtension -ExtensionType 'DSCForLinux' `
                                  -VMName $SydneyCentOS `
                                  -Publisher 'Microsoft.OSTCExtensions' `
                                  -Settings $MelAutomationPublicConfig `
                                  -ProtectedSettings $MelAutomationPrivateConfig `
                                  -TypeHandlerVersion 2.7 `
                                  -ResourceGroupName $RG `
                                  -Name 'DSCForLinux' `
                                  -Location $Sydney -Verbose
         }
         else {
           'automation keys not defined'
         }
       }
  }

  if ($OpInsights) {
  Set-AzureRmVMExtension -ExtensionType 'OmsAgentForLinux' `
                         -ExtensionName 'OMS' `
                         -ResourceGroupName $RG -VMName $SydneyCentOS `
                         -Publisher 'Microsoft.EnterpriseCloud.Monitoring' `
                         -TypeHandlerVersion 1.4 `
                         -SettingString $PublicSettings `
                         -ProtectedSettingString $protectedSettings `
                         -Location $Sydney -Verbose
  }
#endregion
#region     SydFreeBSD
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $SydneyFreeBSD -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Sydney -VM $SydFreeBSD -Tag @{Name='VMTagHere';Value='Sydney FreeBSD'}
  }
  #
  #CustomScript extension 2.0 does NOT yet work for FreeBSD
  #
<#
    Write-Verbose -Message 'Set-AzureRMVmExtension (FreeBSD)'
    Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                     -VM $SydneyFreeBSD -Publisher 'Microsoft.Azure.Extensions' `
                     -Settings $SydFreeBSDCustomSettings `
                     -ProtectedSettings $SydProtectedSettings `
                     -TypeHandlerVersion 2.0 `
                     -ResourceGroupName $RG -Name 'SydFreeBSDExtension' -Location $Sydney -Verbose 
#>  
#endregion
#region     SydWinServer
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $SydneyWinSvr -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Sydney -VM $SydWinSvr -Tag @{Name='VMTagHere';Value='Sydney Windows'} -Verbose
  }
  #pull 'WinWebconfig' from Automation DSC
  Write-Verbose -Message 'Checking for WinWebconfig'
  if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'WinWebconfig' -EA SilentlyContinue) {
       $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'WinWebconfig'}
       if ($nodeconf) {
         Write-Verbose -Message 'Registering for WinWebconfig'
         $Registration=Register-AzureRmAutomationDscNode -AzureVMName $SydneyWinSvr -AzureVMLocation $Sydney `
                                                         -AzureVMResourceGroup $RG -ResourceGroupName $RG `
                                                         -AutomationAccountName $MelAutomation `
                                                         -NodeConfigurationName $nodeconf.Name `
                                                         -ConfigurationMode 'ApplyAndAutocorrect' `
                                                         -AllowModuleOverwrite $true  `
                                                         -RebootNodeIfNeeded $true
       }
  }
#endregion
#endregion
#region   inMelbourne
  Write-Verbose -Message "Creating VM's (Melbourne)"
#region     MelUbuntu
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $MelbourneUbuntu -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Melbourne -VM $MelUbuntu -Tag @{Name='VMTagHere';Value='Melbourne Ubuntu'} -Verbose
  }
  Write-Verbose -Message 'Set-AzureRMVmExtension (Ubuntu)' # 'CustomScript' extension is used for Linux
  Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                         -VM $MelbourneUbuntu `
                         -Publisher 'Microsoft.Azure.Extensions' `
                         -Settings $MelUbuntuCustomSettings `
                         -ProtectedSettings $MelProtectedSettings `
                         -TypeHandlerVersion 2.0 `
                         -ResourceGroupName $RG `
                         -Name 'CustomScript' `
                         -Location $Melbourne -Verbose 

    Write-Verbose -Message 'Checking for NxDSCconfig'
    if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'NxDSCconfig' -EA SilentlyContinue) {
       $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'NxDSCconfig'}
      if ($nodeconf) {
         Write-Verbose -Message 'Registering for NxDSCconfig'
        <#
         # the std PowerShell cmdlet does NOT yet support Linux
         Register-AzureRmAutomationDscNode -AzureVMName $MelbourneUbuntu -AzureVMLocation $Melbourne -AzureVMResourceGroup $RG `
                                           -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                           -NodeConfigurationName $nodeconf.Name `
                                           -RefreshFrequencyMins 30 `
                                           -ConfigurationModeFrequencyMins 15 `
                                           -ConfigurationMode 'ApplyAndAutocorrect' `
                                           -RebootNodeIfNeeded $true `
                                           -AllowModuleOverwrite $true
         #>
         if ($MelAutomationPrivateConfig) { # was created when we generated Automation earlier
           $MelAutomationPublicConfig = @{
             'ExtensionAction'       = 'Register';
             'NodeConfigurationName' = $nodeconf.Name;
             'RefreshFrequencyMins'  = 30;
             'ConfigurationMode'     = 'ApplyAndAutoCorrect';
             'ConfigurationModeFrequencyMins'= 15  }

           Set-AzureRmVMExtension -ExtensionType 'DSCForLinux' `
                                  -VMName $MelbourneUbuntu `
                                  -Publisher 'Microsoft.OSTCExtensions' `
                                  -Settings $MelAutomationPublicConfig `
                                  -ProtectedSettings $MelAutomationPrivateConfig `
                                  -TypeHandlerVersion 2.7 `
                                  -ResourceGroupName $RG `
                                  -Name 'DSCForLinux' `
                                  -Location $Melbourne -Verbose
         }
         else {
           'automation keys not defined'
         }
         
      }
    }

  if ($OpInsights) {
  Set-AzureRmVMExtension -ExtensionType 'OmsAgentForLinux' `
                         -ExtensionName 'OMS' `
                         -ResourceGroupName $RG `
                         -VMName $MelbourneUbuntu `
                         -Publisher 'Microsoft.EnterpriseCloud.Monitoring' `
                         -TypeHandlerVersion 1.4 `
                         -SettingString $PublicSettings `
                         -ProtectedSettingString $protectedSettings `
                         -Location $Melbourne -Verbose
  }
#endregion
#region     MelCentOS
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $MelbourneCentOS -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Melbourne -VM $MelCentOS -Tag @{Name='VMTagHere';Value='Melbourne CentOS'} -Verbose
  }
  Write-Verbose -Message 'Set-AzureRMVmExtension (CentOS)' # 'CustomScript' extension is used for Linux
  Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                         -VM $MelbourneCentOS `
                         -Publisher 'Microsoft.Azure.Extensions' `
                         -Settings $MelCentOSCustomSettings `
                         -ProtectedSettings $MelProtectedSettings `
                         -TypeHandlerVersion 2.0 `
                         -ResourceGroupName $RG `
                         -Name 'CustomScript' `
                         -Location $Melbourne -Verbose 

  Write-Verbose -Message 'Checking for NxApacheconfig'
  if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'NxApacheconfig' -EA SilentlyContinue) {
      $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'NxApacheconfig'}
      if ($nodeconf) {
         Write-Verbose -Message 'Registering for NxApacheconfig'
        <#
         # the std PowerShell cmdlet does NOT yet support Linux. 
         Register-AzureRmAutomationDscNode -AzureVMName $MelbourneCentOS -AzureVMLocation $Sydney -AzureVMResourceGroup $RG `
                                           -ResourceGroupName $RG -AutomationAccountName $MelAutomation `
                                           -NodeConfigurationName $nodeconf.Name `
                                           -RefreshFrequencyMins 30 `
                                           -ConfigurationMode 'ApplyAndAutocorrect' `
                                           -ConfigurationModeFrequencyMins 15 `
                                           -RebootNodeIfNeeded $true -AllowModuleOverwrite $true
         #>
         if ($MelAutomationPrivateConfig) { # was created when we generated Automation earlier
           $MelAutomationPublicConfig = @{
             'ExtensionAction'       = 'Register';
             'NodeConfigurationName' = $nodeconf.Name;
             'RefreshFrequencyMins'  = 30;
             'ConfigurationMode'     = 'ApplyAndAutoCorrect';
             'ConfigurationModeFrequencyMins'= 15  }

           Set-AzureRmVMExtension -ExtensionType 'DSCForLinux' `
                                  -VMName $MelbourneCentOS `
                                  -Publisher 'Microsoft.OSTCExtensions' `
                                  -Settings $MelAutomationPublicConfig `
                                  -ProtectedSettings $MelAutomationPrivateConfig `
                                  -TypeHandlerVersion 2.7 `
                                  -ResourceGroupName $RG `
                                  -Name 'DSCForLinux' `
                                  -Location $Melbourne -Verbose
         }
         else {
           'automation keys not defined'
         }
       }
  }

  if ($OpInsights) {
  Set-AzureRmVMExtension -ExtensionType 'OmsAgentForLinux' `
                         -ExtensionName 'OMS' `
                         -ResourceGroupName $RG `
                         -VMName $MelbourneCentOS `
                         -Publisher 'Microsoft.EnterpriseCloud.Monitoring' `
                         -TypeHandlerVersion 1.4 `
                         -SettingString $PublicSettings `
                         -ProtectedSettingString $protectedSettings `
                         -Location $Melbourne -Verbose
  }
#endregion
#region     MelFreeBSD
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $MelbourneFreeBSD -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Melbourne -VM $MelFreeBSD -Tag @{Name='VMTagHere';Value='Melbourne FreeBSD'} -Verbose
  }
  #
  #CustomScript extension 2.0 does NOT yet work for FreeBSD
  #
<#
    Write-Verbose -Message 'Set-AzureRMVmExtension (FreeBSD)'
    Set-AzureRmVMextension -ExtensionType 'CustomScript' `
                     -VM $MelbourneFreeBSD -Publisher 'Microsoft.Azure.Extensions' `
                     -Settings $MelFreeBSDCustomSettings `
                     -ProtectedSettings $MelProtectedSettings `
                     -TypeHandlerVersion 2.0 `
                     -ResourceGroupName $RG -Name 'MelFreeBSDExtension' -Location $Melbourne -Verbose 
#>
#endregion
#region     MelWinServer
  if (-NOT (Get-AzureRmVM -ResourceGroupName $RG -Name $MelbourneWinSvr -EA SilentlyContinue)) {
    New-AzureRmVM -ResourceGroupName $RG -Location $Melbourne -VM $MelWinSvr -Tag @{Name='VMTagHere';Value='Melbourne Windows'} -Verbose
  }
  #pull 'WEBconfig' from Automation DSC
  Write-Verbose -Message 'Checking for WinWebconfig'
  if (Get-AzureRmAutomationDscConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation -Name 'WinWebconfig' -EA SilentlyContinue) {
       $nodeconf=Get-AzureRmAutomationDscNodeConfiguration -ResourceGroupName $RG -AutomationAccountName $MelAutomation | Where-Object {$_.ConfigurationName -eq 'WinWebconfig'}
       if ($nodeconf) {
         Write-Verbose -Message 'Registering for WinWebconfig'
         $Registration=Register-AzureRmAutomationDscNode -AzureVMName $MelbourneWinSvr -AzureVMLocation $Melbourne `
                                                         -AzureVMResourceGroup $RG -ResourceGroupName $RG `
                                                         -AutomationAccountName $MelAutomation `
                                                         -NodeConfigurationName $nodeconf.Name `
                                                         -ConfigurationMode 'ApplyAndAutocorrect' `
                                                         -AllowModuleOverwrite $true  `
                                                         -RebootNodeIfNeeded $true
       } 
  }
#endregion
#endregion
#endregion
#region create VMSS
  Write-Verbose -Message 'Creating VMSS (Sydney)'

  If (-NOT (Get-AzureRmVmss -ResourceGroupName $RG -VMScaleSetName $SydneyWinVMSS -EA SilentlyContinue)) {
    # Create the scale set with the config object (this step might take a few minutes)
    New-AzureRmVmss -ResourceGroupName $RG -Name $SydneyWinVMSS -VirtualMachineScaleSet $SydVMSSConfig -Verbose
  }

  $scaleset = Get-AzureRmVmss -ResourceGroupName $RG -VMScaleSetName $SydneyWinVMSS
  # Loop through the instances in the scale set
  for ($i=1; $i -le ($scaleset.Sku.Capacity - 1); $i++) {
    Get-AzureRmVmssVM -ResourceGroupName $RG -VMScaleSetName $SydneyWinVMSS -InstanceId $i
  }
#endregion
#region enableVMSSautoscale

  If (Get-AzureRmVmss -ResourceGroupName $RG -VMScaleSetName $SydneyWinVMSS -EA SilentlyContinue) {
    Write-Verbose -Message 'Creating VMSS autoscale rules (Sydney)'

    $SubscriptionCTX=Get-AzureRmContext
    $subid = $SubscriptionCTX.Subscription.Id
    $MetricResourceId = "/subscriptions/$subid/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachineScaleSets/$SydneyWinVMSS"
    $TargetResourceId = $MetricResourceId

    $rule1 = New-AzureRmAutoscaleRule -MetricName 'Percentage CPU' `
                                      -MetricResourceId $MetricResourceId `
                                      -Operator GreaterThan `
                                      -MetricStatistic Average -Threshold 60 -TimeGrain 00:01:00 -TimeWindow 00:05:00 `
                                      -ScaleActionCooldown 00:05:00 -ScaleActionDirection Increase -ScaleActionValue 1

    $rule2 = New-AzureRmAutoscaleRule -MetricName 'Percentage CPU' `
                                      -MetricResourceId $MetricResourceId `
                                      -Operator LessThan `
                                      -MetricStatistic Average -Threshold 30 -TimeGrain 00:01:00 -TimeWindow 00:05:00 `
                                      -ScaleActionCooldown 00:05:00 -ScaleActionDirection Decrease -ScaleActionValue 1

    $profile1 = New-AzureRmAutoscaleProfile -DefaultCapacity 3 -MaximumCapacity 10 -MinimumCapacity 2 `
                                            -Rules $rule1,$rule2 -Name 'autoprofile1'

    Add-AzureRmAutoscaleSetting -Name 'autosetting1' -Location $Sydney -ResourceGroup $RG `
                                -TargetResourceId $MetricResourceId -AutoscaleProfiles $profile1 
  }
  else {
    $ErrorActionPreference='SilentlyContinue'
  }

#endregion
#region Databases
    Write-Verbose -Message 'Creating SQL server'
    if (-NOT (Get-AzureRmSqlServer -ResourceGroupName $RG -ServerName $SQLserverName -ErrorAction SilentlyContinue) ) {
      New-AzureRmSqlServer -ResourceGroupName $RG -ServerName $SQLserverName -Location $Sydney -SqlAdministratorCredentials $AdminCredential
    }
    Write-Verbose -Message 'Creating SQL database'
    if (-NOT (Get-AzureRmSqlDatabase -ResourceGroupName $RG -DatabaseName $SQLdbName -ServerName $SQLserverName -EA SilentlyContinue) ) {
      $tags=@{key0='value0';key1='value1';key2='value2'}
      New-AzureRmSqlDatabase -ResourceGroupName $RG -DatabaseName $SQLdbName -ServerName $SQLserverName  -Edition Standard -Tags $tags
    }
#endregion
#region VPNgateways
    Write-Verbose -Message 'Creating VPN between Sydney and Melbourne Vnets.'
    $MelVnet = Get-AzureRmVirtualNetwork -Name $VnetMelbourne -ResourceGroupName $RG
    $SydVnet = Get-AzureRmVirtualNetwork -Name $VnetSydney    -ResourceGroupName $RG

    Write-Verbose -Message 'Get gateway subnet configs'
    $SydGWsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $GWsubnetName -VirtualNetwork $SydVnet
    $MelGWsubnet = Get-AzureRMVirtualNetworkSubnetConfig -Name $GWsubnetName -VirtualNetwork $MelVnet

    Write-Verbose -Message 'applying the public IP to the gateway configs'
    $SydGWYpip=Get-AzureRMPublicIpAddress -Name 'sydgwpip' -ResourceGroupName $RG 
    $MelGWYpip=Get-AzureRMPublicIpAddress -Name 'melgwpip' -ResourceGroupName $RG

    $Sydgwipconfig = New-AzureRMVirtualNetworkGatewayIpConfig -Name 'Sydgwipconfig' -SubnetId $SydGWsubnet.Id -PublicIpAddressId $SydGWYpip.Id 
    $Melgwipconfig = New-AzureRMVirtualNetworkGatewayIpConfig -Name 'Melgwipconfig' -SubnetId $MelGWsubnet.Id -PublicIpAddressId $MelGWYpip.Id 

    Write-Verbose -Message 'Creating the Gateway... (this can take a while) - Sydney'
    if (-NOT (Get-AzureRMVirtualNetworkGateway -Name 'SydVnetgw' -ResourceGroupName $RG -EA SilentlyContinue)) {
      New-AzureRMVirtualNetworkGateway -Name 'SydVnetgw' -ResourceGroupName $RG -Location $Sydney `
                                       -IpConfigurations $Sydgwipconfig `
                                       -GatewayType Vpn -VpnType RouteBased `
                                       -Tag @{Name='VPNTagHere';Value='Sydney Gateway'}
    }

    Write-Verbose -Message 'Creating the Gateway... (this can take a while) - Melbourne'
    if (-NOT (Get-AzureRMVirtualNetworkGateway -Name 'MelVnetgw' -ResourceGroupName $RG -EA SilentlyContinue)) {
      New-AzureRMVirtualNetworkGateway -Name 'MelVnetgw' -ResourceGroupName $RG -Location $Melbourne `
                                       -IpConfigurations $Melgwipconfig `
                                       -GatewayType Vpn -VpnType RouteBased `
                                       -Tag @{Name='VPNTagHere';Value='Melbourne Gateway'}
    }

    Write-Verbose -Message 'create site-to-site VPN (Syd)'

    $Sydgateway = Get-AzureRMVirtualNetworkGateway -Name 'SydVnetgw' -ResourceGroupName $RG
    $Melgateway = Get-AzureRMVirtualNetworkGateway -Name 'MelVnetgw' -ResourceGroupName $RG

    if (-NOT (Get-AzureRMVirtualNetworkGatewayConnection -Name 'SydtoMel' -ResourceGroupName $RG -EA SilentlyContinue)) {
      New-AzureRMVirtualNetworkGatewayConnection -Name 'SydtoMel' -ResourceGroupName $RG -Location $Sydney `
                                                 -VirtualNetworkGateway1 $Sydgateway -VirtualNetworkGateway2 $Melgateway  `
                                                 -ConnectionType Vnet2Vnet -RoutingWeight 10 `
                                                 -SharedKey $GatewaySharedKey `
                                                 -Tag @{Name='VPNConnectionTag';Value='Sydney to Melbourne'}
    }
    Get-AzureRMVirtualNetworkGatewayConnection -Name 'SydtoMel' -ResourceGroupName $RG

    Write-Verbose -Message 'create site-to-site VPN (Mel)'
    $Melgateway = Get-AzureRMVirtualNetworkGateway -Name 'MelVnetgw' -ResourceGroupName $RG
    $Sydgateway = Get-AzureRMVirtualNetworkGateway -Name 'SydVnetgw' -ResourceGroupName $RG

    if (-NOT (Get-AzureRMVirtualNetworkGatewayConnection -Name 'MeltoSyd' -ResourceGroupName $RG -EA SilentlyContinue)) {
      New-AzureRMVirtualNetworkGatewayConnection -Name 'MeltoSyd' -ResourceGroupName $RG -Location $Melbourne `
                                                 -VirtualNetworkGateway1 $Melgateway -VirtualNetworkGateway2 $Sydgateway `
                                                 -ConnectionType Vnet2Vnet -RoutingWeight 10 `
                                                 -SharedKey $GatewaySharedKey `
                                                 -Tag @{Name='VPNConnectionTag';Value='Melbourne to Sydney'}
    }
    Get-AzureRMVirtualNetworkGatewayConnection -Name 'MeltoSyd' -ResourceGroupName $RG


#endregion
#region ServiceFabric
Write-Verbose -Message 'Creating Service Fabric Cluster'

# A service Fabric cluster MUST be in the same location as the KeyVault.
# AND must be in the same location as the RG
# ergo this requires an RG/KeyVault/Service Fabric cluster to all be in Melbourne, 
# as there is no KeyVault capability in Sydney

$SubscriptionCTX=Get-AzureRmContext
$subscriptionId = $SubscriptionCTX.Subscription.Id

# Certificate variables.
$certpwd = $password | ConvertTo-SecureString -AsPlainText -Force
$certfolder="$HOME\mycertificates\"
if (-NOT (Test-Path -Path $certfolder)) {
  New-Item -Path $certfolder -ItemType Directory -Force
}

Write-Verbose -Message 'generate Cert subject name'
$certSubjectName="$ServiceFabricClustername.$Melbourne.cloudapp.azure.com"

# Set the number of cluster nodes. Possible values: 1, 3-99
$clustersize=5

# Create the Service Fabric cluster.
# Also, drop the KeyVault-generated certificate into a folder
Write-Verbose -Message 'Creating Service Fabric Cluster'
If (-NOT (Get-AzureRmServiceFabricCluster -Name $ServiceFabricClustername -ResourceGroupName $RGSF -ErrorAction SilentlyContinue)) {
  $SFC=New-AzureRmServiceFabricCluster -Name $ServiceFabricClustername `
                                       -ResourceGroupName $RGSF -Location $Melbourne `
                                       -ClusterSize $clustersize `
                                       -VmUserName $user -VmPassword $securepasswd `
                                       -CertificateSubjectName $certSubjectName `
                                       -CertificatePassword $certpwd `
                                       -CertificateOutputFolder $certfolder `
                                       -OS WindowsServer2016DatacenterwithContainers `
                                       -VmSku $AzureVMsize `
                                       -KeyVaultName $KeyVaultMelSF
}
Write-Verbose -Message 'retrieving certificate (.pfx)'
$certfile=Get-ChildItem -path "$certfolder\$RGSF*.pfx" | 
            Sort-Object -Property Name -Descending | 
              Select-Object -First 1

Write-Verbose -Message 'Importing into Cert: '
Import-PfxCertificate -FilePath $certfile.FullName -Password $certpwd `
                      -CertStoreLocation 'Cert:\CurrentUser\My' -Exportable 
#endregion
#region APImanagement
Write-Verbose -Message 'creating API Management. (Sydney)'  # WARNING: this takes 30 minutes..
if (-NOT (Get-AzureRmApiManagement -ResourceGroupName $RG -Name $ApiMgtName -ErrorAction SilentlyContinue)) {
New-AzureRmApiManagement -ResourceGroupName $RG -Location $Sydney -Name $ApiMgtName -Organization 'myOrganization' -AdminEmail $MyEmail -Sku 'Developer'
}
#endregion
#region SetPolicy
if (-NOT ($Subscription -eq 'Azure CXP')) {    # CXP use a shared subscription, so do NOT do policy!
  Write-Verbose -Message 'Creating Regional Policy'
  $AZURETHINGS = Get-AzureRmResourceGroup -Name $RG -Location $Sydney
  if (-NOT (Get-AzureRmPolicyAssignment -Name locationPolicyAssignment -Scope $AZURETHINGS.ResourceId)) {
    $Locations = Get-AzureRmLocation | Where-Object {$_.displayname -like '*australia*'}
    $AllowedLocations = @{'listOfAllowedLocations'=($Locations.location)}
    $Policy = Get-AzureRmPolicyDefinition | Where-Object {$_.Properties.DisplayName -eq 'Allowed locations' -and $_.Properties.PolicyType -eq 'BuiltIn'}
    # this will probably wreck something, so I'll need to TEST this first!
    # $null=New-AzureRmPolicyAssignment -Name locationPolicyAssignment -PolicyDefinition $Policy -Scope $AZURETHINGS.ResourceId -PolicyParameterObject $AllowedLocations
  }
}
#endregion
#region DockerContainerRegistry
#https://docs.microsoft.com/en-us/azure/container-registry/container-registry-get-started-powershell
 if (-NOT (Get-AzureRmContainerRegistry -ResourceGroupName $RG -Name $RegistryName -EA SilentlyContinue) ) {
  if (Test-AzureRmContainerRegistryNameAvailability -Name $RegistryName) {
    New-AzureRmContainerRegistry -ResourceGroupName $RG -Name $RegistryName -EnableAdminUser -Sku 'Basic' #-StorageAccountName $SydStorageAccount
  }
  else {
    Write-Verbose  -Message ( 'Registry name {0} is already in use.' -f $RegistryName )
  }
 }
 $Registry=Get-AzureRmContainerRegistry -ResourceGroupName $RG -Name $RegistryName -ErrorAction SilentlyContinue
 if ($registry) {
   # we will need creds when we use Docker to upload container images to our repo in this registry
   $creds = Get-AzureRmContainerRegistryCredential -Registry $Registry 
   # assume GIT and DOCKER are installed
   # https://github.com/git-for-windows/git/releases/download/v2.17.0.windows.1/Git-2.17.0-64-bit.exe
   # https://download.docker.com/win/stable/Docker%20for%20Windows%20Installer.exe

   $DockerExe='C:\Program Files\Docker\Docker\Docker for Windows.exe'
   $GitExe='C:\Program Files\Git\cmd\git.exe'

   if ( (Test-Path -path $DockerExe) -AND (Test-Path -path $GitExe) ) {
     if (-NOT (Test-Path -Path $HOME\Documents\Git)) {
       New-Item -Path "$HOME\Documents\Git" -ItemType Directory
     }

     $CurrentLocation = Get-Location
     Set-Location -Path "$HOME\Documents\Git" 

     #pull down the example from github
     if (-NOT (Test-Path -Path "$HOME\Documents\Git\aci-helloworld")) {
      git clone https://github.com/Azure-Samples/aci-helloworld.git
     }

     #build the image
     docker build ./aci-helloworld -t aci-tutorial-app
     #docker images  should show the built image

     # now have Docker connect to our Azure container registry
     $creds.Password | docker login $registry.LoginServer -u $creds.Username --password-stdin

     #tag our aci-tutorial-app image with its new target image information
     $image = $registry.LoginServer + '/aci-helloworld:v1'
     docker tag  aci-tutorial-app $image

     #and finally, push it up to the Azure contaner registry
     docker push $image

     ### OK! We can now spin up a running container!
     # must convert the Registry password to a credential
     $secpasswd = ConvertTo-SecureString -String $creds.Password -AsPlainText -Force
     $pscred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($creds.Username, $secpasswd)

     #and use a unique DNS name
     $dnsname = 'aci-demo-' + (Get-Random -Maximum 9999)
     # locations to run containers currently: 'westus,eastus,westeurope,westus2,northeurope,southeastasia'.

     New-AzureRmContainerGroup -ResourceGroup $RG  -Location southeastasia `
                               -Name 'mycontainer' -Image $image `
                               -RegistryCredential $pscred `
                               -Cpu 1 -MemoryInGB 1 -DnsNameLabel $dnsname
    #
    Set-Location -Path $CurrentLocation
   }
   else {
     Write-Verbose -Message 'GIT and/or DOCKER not installed. Skipping...'
   }
 }
#endregion
#region EncryptVMdisk
## apply encryption to an existing/running VM
## this will need a reboot to take effect

  # this app-service will need permission to the KeyVault.
  $AADClientID     = '<clientID of your Azure AD app>'
  $AADClientSecret = '<clientSecret of your Azure AD app>'

  # which keyvault will hold the encryption keys.
  $VaultName= 'MyKeyVault'
  $MelKeyVault=Get-AzureRmKeyVault -VaultName $KeyVaultMelbourne -ResourceGroupName $RG


  #Get-AzureRmVMDiskEncryptionStatus [-ResourceGroupName] <String> [-VMName] <String> [[-Name] <String>] [-DefaultProfile <IAzureContextContainer>] [-ExtensionPublisherName 
  #  <String>] [-ExtensionType <String>] [<CommonParameters>]
  #Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $RGName -VMName $VMName -Force `
  #                                     -AadClientID $AADClientID -AadClientSecret $AADClientSecret `
  #                                     -DiskEncryptionKeyVaultUrl $MelKeyVault.VaultUri -DiskEncryptionKeyVaultId $MelKeyVault.ResourceId
#endregion