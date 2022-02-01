<#
.SYNOPSIS
  Get al unique endpoints accessing and IIS webserver
.DESCRIPTION
  This script parses IIS logs and produces a list of unique endpoints, IP and hostnames. Hostnames are produced using Remote Registry
.PARAMETER <Parameter_Name>
    None
.INPUTS
  IIS Logfiles
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Bart Jacobs - @Cloudsparkle
  Creation Date:  20/12/2021
  Purpose/Change: Parse IIS Logs for unique endpoints using Remote Registry
.EXAMPLE
  None
#>

#Initialize variables
$LogPath = "C:\logs\"
$TempFile = $env:temp +"\WebLog-RR.csv"
$OutputFile = $env:temp + "\Endpoints.csv"
$CsvContents = @()

Function Ping([string]$hostname, [int]$timeout = 500, [int]$retries = 3)
{
$result = $true
$ping = new-object System.Net.NetworkInformation.Ping #creates a ping object
$i = 0
do {
    $i++
		#write-host "Count: $i - Retries:$retries"

		try
    {
      #write-host "ping"
			$result = $ping.send($hostname, $timeout).Status.ToString()
    }
    catch
    {
			#Write-Host "error"
			continue
		}
		if ($result -eq "success") { return $true }

    } until ($i -eq $retries)
    return $false
}

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
Foreach ($IP in $IPList) 
{
    if (($IP.'c-ip' -eq 'c-ip') -or ($IP.'c-ip' -eq "127.0.0.1") -or ($IP.'c-ip' -eq "::1"))
    {
        continue
    }
    
    $RegLM = ""
    $RegKeyLM = $null
    $RegKeyLM2 = $null
    $Computername = ""
    $User = ""
    $aduser = ""
    $IPOnline = $false
    
    Write-Host "Processing IP:"$IP.'c-ip'
    $IPonline = Ping $IP.'c-ip' 100
    if ($IPonline -eq $True)
    { 
        Try
        {
            $RegLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$IP.'c-ip')
        }
        Catch
        {
            Write-Host "Error accessing remote registry for IP:"$ip.'c-ip' -ForegroundColor red
        }
        
        if ($RegLM -ne "")
        {
            Try
            {
                $RegKeyLM = $RegLM.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName")
            }
            Catch
            {
                Write-Host "Error accessing remote registry for IP:"$ip.'c-ip' -ForegroundColor red
            }
                       
            if ($RegKeyLM -ne $null)
            {
                $Computername = $RegKeyLM.GetValue("ComputerName")
                Try
                {
                    $RegKeyLM2 = $RegLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI")
                }
                Catch
                {
                    
                }

                if ($RegKeyLM2 -ne $null)
                {
                    $User = $RegKeyLM2.GetValue("LastLoggedOnUser")
                        
                    if ($user -ne $null)
                    {
                        $aduser = $user.Split("\")
                        $aduser = $aduser[1]                 
                    }
                }

            
            }

            
            
        
        
            #Write-Host "Error accessing remote registry for IP:"$ip.'c-ip' -ForegroundColor red
        }
        
        
    }            
        
    $row = New-Object System.Object # Create an object to append to the array
    $row | Add-Member -MemberType NoteProperty -Name "HostName" -Value $Computername
    $row | Add-Member -MemberType NoteProperty -Name "IP" -Value $IP.'c-ip'
    $row | Add-Member -MemberType NoteProperty -Name "Username" -Value $aduser
        

    $csvContents += $row # append the new data to the array#
}

Write-Host -ForegroundColor Green "Writing outpunt CSV File..."
$csvContents | Export-CSV -path $OutputFile -NoTypeInformation
Write-Host -ForegroundColor Green "Output file located in :" $OutputFile