<#
.SYNOPSIS
    Connects via SSH to a Cisco DVTI hub and parses the Virtual Templates for a public IP.
.DESCRIPTION
    Connect-DMVPN-HE.ps1 can verify connectivity to a range of network devices and perform various show and other commands. A $Stream.Write must be performed to execute any commands. This should be followed by a sleep command to allow the router time to generate the output.
.PROTIP
  Grab the output of long commands by setting the terminal length to 0 to disable pagination. "term len 0"
.NOTES
  File Name: Connect-DMVPN-HE.ps1
  Author: Tyler Applebaum
  Requires: PowerShell v3
  Last Contributor:
  Last Edited: 01/29/2015
  Version: 1.1
.LINK
  http://tylerapplebaum.github.io
.EXAMPLE
  C:\PS> .\Connect-CiscoIOS.ps1 -Subnet 10.160.1.1-10.160.1.254 -Username root
  This will query the entirety of Active Directory to run the report against. Can take a bit of time.
.PARAMETER subnet
  Specify a single IP or a range of IPs to attempt to connect to
.PARAMETER sublist
  Specify a .txt file with one entry per line containing the IPs or hostnames to attempt to connect to
.PARAMETER username
  Specify the username to use to connect to the network devices
#>
#Requires -version 3.0
[CmdletBinding()]
    param(
        [Parameter(mandatory=$false, HelpMessage="Specify the range of IPs to connect to (192.162.5.1-192.168.5.15)")]
		[Alias("range")]
        [string]$Subnet,

		[Parameter(mandatory=$false, HelpMessage="Specify a text file containing the list of IPs or hostnames to connect to")]
		[Alias("list")]
        [string]$Sublist,

        [Parameter(mandatory=$false, HelpMessage="Specify the username to SSH to the device")]
		[Alias("u")]
        [string]$Username = 'adminta'
	)

Function script:Dependencies {
	If ($(Get-Module -ListAvailable | ? Name -like "Posh-SSH") -eq $null) {
	iex (New-Object Net.WebClient).DownloadString("https://gist.github.com/darkoperator/6152630/raw/c67de4f7cd780ba367cccbc2593f38d18ce6df89/instposhsshdev")
	}
}#End Dependencies

Function script:Credentials {
$SSH_Username = "adminta"
$SSH_CredPath = "C:\PS\CiscoSSH_TACACS.pwd"
#If the password file does not exist, create it
	If ((Test-Path -Path $SSH_CredPath) -eq $False) {
    (Get-Credential).Password | ConvertFrom-SecureString | Out-File $SSH_CredPath
	}
#Read the password
$SSH_Password = Get-Content $SSH_CredPath | ConvertTo-SecureString
#Create the PSCredential Object
$SSH_Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $SSH_Username, $SSH_Password
}#End Credentials

Function script:CheckConnection {
$Devices = @()
$DeviceRange = @(2) #Needs to be parameterized.
	Foreach ($IP in $DeviceRange) {
	$DeviceIP =  "10.95.2.$IP"
		If (Test-Connection -count 1 -computername $DeviceIP -quiet){
		$Devices += $DeviceIP
		}
	}
}#End CheckConnection

Function script:Connect {
$Session = New-SSHSession -ComputerName $Device -Credential $SSH_Cred -AcceptKey $True
$Stream = $Session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
}#End Connect

Function script:Disconnect {
#$Stream.Write("logout`n") #Using this leaves the socket in a CLOSE_WAIT state. PowerShell sends FIN, and receives ACK. The socket remains until the PowerShell process is ended. There is apparently a maximum of 63 CLOSE_WAIT sockets per process. PowerShell will hang and do nothing once it reaches this point.
Remove-SSHSession -Index 0 | Out-Null #Using this leaves the socket in a TIME_WAIT state, which times out after 60 seconds. PowerShell sends a FIN, and never receives an ACK. Pipes to null, because it returns a boolean.
}#End Disconnect

Function script:Get-ViInfo { #Absolutely must set sleep between commands to allow them time to execute. If you have a slow connection, slow router, or a massive show command, you will need to adjust the sleep time.
sleep 2
$Prompt = $Stream.Read()

$Stream.Write("term len 0`n")
sleep 1
$Stream.Read() | Out-Null #Don't care about this output

$Stream.Write("sh ip eigrp vrf NEW topo | i Virtual-Access`n")
sleep 3
$SARoutes = $Stream.Read()
}#End Get-RTRInfo

Function script:Show-ViInfo {
$SARoutes = $SARoutes.Replace("$Prompt",'').Replace("sh ip eigrp vrf NEW topo | i Virtual-Access",'')
#Write-Host $SARoutes -fo green
$h = $SARoutes.Replace('        via','')
$i = $h -Replace "\((.*)\)", "" #Regex to replace parenthesis and all chars between
$i = $i.Replace(' , ',',')
$temparr = $i.split("`r`n")
$temparr = $tempArr | where {$_ -notlike $null } | foreach { $_.trim() } | Select -uniq
}#End Show-RTRInfo

Function script:Get-PubIP {
$PubIP = $null
$Stream.Write("sh int $Intf | i destination`n")
sleep -milliseconds 2000
$PubIP = $Stream.Read()
}#End Get-PubIP

Function script:Show-PubIP {
$PubIP = $PubIP.Replace("$Prompt",'').Replace("sh int $Intf | i destination",'').Replace('  Tunnel source 67.51.253.126 (Loopback3), destination ','').Trim()
	If ($PubIP -notmatch "/(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|[a-zA-Z]+") {
	$PubIPs += $PubIP
	}
	Elseif ($PubIP -match "/(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|[a-zA-Z]+"){
	$PubIP = $null
	$PubIPs += $PubIP
	}
}

Function script:Get-ASN {
$ASN = $null
$ASNinfo = $null
$ASNRequest = $null
$ASNRequest = curl ipinfo.io/$PubIP -UserAgent Chrome
$ASNInfo = $ASNRequest.ParsedHtml.getElementsByTagName("pre") | Select -exp innerHTML #bunch of info
$ASN = $ASNRequest.Links[2].innerHTML #AS num isolated
$Info = $ASNinfo.Split("`r`n")
$Info = $Info.Trim()
#$InfoHostname = $Info[6].split(':')[1].Replace('"','').Trim(',').Trim()
$InfoRegion = $Info[10].split(':')[1].Replace('"','').Trim(',').Trim()
$InfoCity = $Info[8].split(':')[1].Replace('"','').Trim(',').Trim()
#$InfoLatLong = $Info[14].split(':')[1].Replace('"','').Trim(',').Trim()
$InfoASNOwner = $Info[16].split(':')[1].Replace('"','').Trim(',').Trim().Replace('amp;','')
$InfoZIP = $Info[18].split(':')[1].Replace('"','').Trim(',').Trim()
}

Function script:Show-NextHop {
$NextHop = $null
$NextHop = Test-NetConnection $PubIP -TraceRoute -Hops 5 #Hop count is from ES datacenter. If run from an office machine, you will need to change this.
}#End Show-NextHop

Function script:ConnectHop2 {
$Device2 = "RTR-INET-A"
$Session2 = New-SSHSession -ComputerName $Device2 -Credential $SSH_Cred -AcceptKey $True
$Stream2 = $Session2.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
}#End Connect

Function script:Get-ExitProvider {
$ExitRoute = $null
sleep -milliseconds 2000
$Prompt2 = $Stream2.Read()
$Stream2.Write("sho ip route $PubIP | i , from`n")
sleep -milliseconds 2700 #Long delay...
$ExitRoute = $Stream2.Read()
}#End Get-ExitProvider


Function script:Show-ExitProvider {
$ExPro = $null
$ExPro = $ExitRoute.Replace("$Prompt",'').Replace("sho ip route $PubIP | i , from",'').Replace('*','').Trim().split(',')[0]
write-host $ExPro -fo green
}

Function script:DisconnectHop2 {
Remove-SSHSession -Index 0 | Out-Null
}#End DisconnectHop2

Function script:Generate-Report {
#Path to save report
$ReportPath = "C:\PS"
$ReportTitle = "DMVPN_Report.html"
$Report = "$ReportPath\$ReportTitle"
$CSS = "\\wsus\it$\Powershell\Style.css" #Path to CSS file

$PreContent = @'
<script src="file://wsus/it$/Powershell/sorttable.js"></script>
'@

$Head = @"
<title>$ReportTitle</title>
<link rel="stylesheet" type="text/css" href="file://wsus/it$/Powershell/Style.css" />
<script src="file://wsus/it$/Powershell/sorttable.js"></script>
"@
Write-Output $DataArr #Dump the array to the screen
$DataArr | ConvertTo-HTML -Head $Head -As Table | ForEach-Object {$_ -replace "<table>", '<table class="sortable" id="table">'} | Set-Content $Report #Generate the report
}

function script:Execute-MTR {
param ($TraceIP)
mtr.exe -w -c 5 $TraceIP
}

function script:Capture-MTR {
$LastSection = $null
$MTRJob = Start-Job -Args $TraceIP -Scriptblock ${function:Execute-MTR}
Wait-Job $MTRJob | Out-Null
$MTROutput = $(Receive-Job $MTRJob -keep)
$CleanOutput = $MTROutput.split('(X)').trim('Exit').split("`n`r")
$CleanString = $CleanOutput | ? {$_.trim() -ne "" }
$ArrLength = $($CleanString -like "*Loss*").Count
$SectionLength = $($CleanString.length / $ArrLength)
$StartPos = $($CleanString.length - $SectionLength)
$EndPos = $CleanString.length
$LastSection = $CleanString[$StartPos..$EndPos]
$LastSection | Out-File C:\Temp\DMVPN_Traceroute\$($ServiceArea."Service Area").txt -Encoding utf8
}


$DataArr = @() #Array to hold data
$PubIPs = @() #Array to hold collection of public IPs
. Dependencies
. Credentials
. CheckConnection
Foreach ($Device in $Devices) {
$z++ #Progress bar increment
Write-Progress -Activity "Gathering Network Device Data" -Status "Connected to $Device - $z of $($Devices.Count)" -PercentComplete ($z / $Devices.Count*100)
. Connect
. ConnectHop2
. Get-ViInfo
. Show-ViInfo
	$PSObj = $null #Clean up any old values from the last child run in case the next run returns null data
	Foreach ($item in $temparr) {
		$Intf = $item.split(',')[1]
		. Get-PubIP
		. Show-PubIP
		. Get-ASN
		#. Show-NextHop
		#Write-Host $NextHop
		#pause
		$script:SA = "SA"+$($item.split(',')[0].subString(9)) #Newly added for MTR function
		If ($PubIP -notlike $null) {
		. Get-ExitProvider
		. Show-ExitProvider
		}
		$PSObj = [pscustomobject]@{
		"Service Area" = "SA"+$($item.split(',')[0].subString(9))
		"NAT IP" = "10.160."+$($item.split(',')[0].subString(9))+".1"
		"IP" = $item.split(',')[0]
		"Interface" = $item.split(',')[1]
		"Public IP" = $PubIP
		"ASN" = $ASN
		"Exit Provider" = $ExPro
		"Hostname" = $InfoHostname
		"City" = $InfoCity
		"Region" = $InfoRegion
		"Zip" = $InfoZIP
		"Lat/Long" = $InfoLatLong
		"ASN Owner" = $InfoASNOwner
		#"Upstream Route" = $NextHop.TraceRoute[4]
		#"Ping status" = $NextHop.PingSucceeded
		#"Ping RTT" = $NextHop.PingReplyDetails.RoundtripTime
		}#End PSCustomObj

		$DataArr += $PSObj

	}#End child ForEach loop
	$global:DataArr = $DataArr | Sort "IP"
. DisconnectHop2
. Disconnect
}#End parent ForEach loop

. Generate-Report

$y = 0
foreach ($ServiceArea in $DataArr){
$TraceIP = $ServiceArea."Public IP"
$y++
Write-Progress -Activity "Generating Traceroute" -Status "Running MTR on $($ServiceArea."Service Area") - $y of $($DataArr.Count)" -PercentComplete ($y / $DataArr.Count*100)
	If ($TraceIP -notmatch "/(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|[a-zA-Z]+" -AND $TraceIP -notlike $Null) {
		. Capture-MTR
	}
}
