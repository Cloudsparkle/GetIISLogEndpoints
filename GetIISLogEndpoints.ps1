<#
.SYNOPSIS
  Get al unique endpoints accessing and IIS webserver
.DESCRIPTION
  This script parses IIS logs and produces a list of unique endpoints, IP and hostnames
.PARAMETER <Parameter_Name>
    None
.INPUTS
  IIS Logfiles
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Bart Jacobs - @Cloudsparkle
  Creation Date:  02/07/2020
  Purpose/Change: Parse IIS Logs for unique endpoints
.EXAMPLE
  None
#>

#Initialize variables
$LogPath = "C:\logs\"
$TempFile = $env:temp +"\WebLog.csv"
$OutputFile = $env:temp + "\Endpoints.csv"
$DNSServer = ""
$CsvContents = @()

$LogFiles = Get-ChildItem –Path $LogPath -Filter *.log -Recurse

#Checks
If ($LogFiles -eq $null)
    {
    Write-Host -ForegroundColor Yellow "No logfiles found in specified path. Exiting..."
    exit 1
    }

$TempFileExists = Test-Path $TempFile
If ($TempFileExists -eq $True)
    {Remove-Item $TempFile}

#Process all logfiles
Foreach ($logfile in $LogFiles)
{
Write-Host -ForegroundColor Green "Reading logfile" ($logfile.FullName)
(Get-Content $logfile.FullName | Where-Object {$_ -notlike "#[S,V,D]*"}) -replace "#Fields: ","" | Out-File -append $TempFile
}

# Import the CSV file to memory
$webLog = Import-Csv $TempFile -Delimiter " "

#Extracting all unique IP's
Write-Host -ForegroundColor Green "Gathering IP addresses..."
$IPList = $weblog | Select-Object -Property 'c-ip' -Unique | Sort-Object -Property 'c-ip' -Descending

#Resolving IP to hostname
Write-Host -ForegroundColor Green "Resolving IP addresses..."
Foreach ($IP in $IPList) {
    $HostName = (Resolve-DnsName -Server $DNSServer $IP.'c-ip' -ErrorAction SilentlyContinue).NAMEHOST
    # write-host $HostName, $IP.'c-ip'
    $row = New-Object System.Object # Create an object to append to the array
    $row | Add-Member -MemberType NoteProperty -Name "HostName" -Value $hostname
    $row | Add-Member -MemberType NoteProperty -Name "IP" -Value $IP.'c-ip'

    $csvContents += $row # append the new data to the array#
}

Write-Host -ForegroundColor Green "Writing outpunt CSV File..."
$csvContents | Export-CSV -path $OutputFile -NoTypeInformation
Write-Host -ForegroundColor Green "Output file located in :" $OutputFile
