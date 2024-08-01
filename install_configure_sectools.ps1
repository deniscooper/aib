<#
DESCRIPTION
    This Powershell script will install the below softwares
    Author: Geoffrey O'Neill
    Site: amcor.com
    Version: 1.0.0
#>

# Applications to install, in order:
#
# 1. Cisco Umbrella
# 2. Rapid 7 
# 3. Symantec
#   a) SEP Scheduled Activation Task
# 4. .NET 6.0.x
# 5. Azure Storage Explorer
#

#=================================================== Set Static Variables ===================================================#

$stdPrefix = "C:\Temp\Imagebuilder"
$ciscoVpnPath = Get-ChildItem -Path "$($stdPrefix)\umbrella\cisco-secure-client-win-*-core-vpn-predeploy-k9.msi"
$ciscoDartPath = Get-ChildItem -Path "$($stdPrefix)\umbrella\cisco-secure-client-win-*-dart-predeploy-k9.msi"
$ciscoUmbrellaPath = Get-ChildItem -Path "$($stdPrefix)\umbrella\cisco-secure-client-win-*-umbrella-predeploy-k9.msi"
$dotNetPath = Get-ChildItem -Path "$($stdPrefix)\dotnet-sdk-*-win-x64.exe"

#=================================================== Set logging ===================================================#

$logFile = "$($stdPrefix)\Logs\" + (get-date -format 'yyyyMMdd') + '_softwareinstall.log'
function Write-Log {
    Param($message)
    Write-Output "$(get-date -format 'yyyyMMdd HH:mm:ss') $message" | Out-File -Encoding utf8 $logFile -Append
}

#=================================================== Cisco Umbrella Installation ===================================================#

try {
    Start-Process -FilePath "$($env:windir)\System32\msiexec.exe" -ErrorAction Stop -ArgumentList '/i', $ciscoVpnPath, '/norestart', '/quiet', 'PRE_DEPLOY_DISABLE_VPN=1', 'LOCKDOWN=1', '/lvx*', "$($stdPrefix)\umbrella\cisco-secure-client-win-5.1.2.42-core-vpn-predeploy-k9.log" 

    Start-Process -FilePath "$($env:windir)\System32\msiexec.exe" -ErrorAction Stop -ArgumentList '/i', $ciscoDartPath, '/norestart', '/quiet', '/lvx*', "$($stdPrefix)\umbrella\cisco-secure-client-win-5.1.2.42-dart-predeploy-k9.log" 
    
    Start-Process -FilePath "$($env:windir)\System32\msiexec.exe" -ErrorAction Stop -ArgumentList '/i', $ciscoUmbrellaPath, '/norestart', '/quiet', 'LOCKDOWN=1', 'ARPNOREMOVE=1', '/lvx*', "$($stdPrefix)\umbrella\cisco-secure-client-win-5.1.2.42-umbrella-predeploy-k9.log" 
    if (Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Cisco\Cisco Secure Client\Cisco Secure Client.lnk" -ErrorAction SilentlyContinue) {
        Write-Log "Umbrella has been installed"
    }
    else {
        write-log "Error locating the Umbrella installation files"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Umbrella: $ErrorMessage"
}



#=================================================== Rapid 7 Installation ===================================================#

try {
    Start-Process -filepath "$($env:windir)\System32\msiexec.exe" -Wait -ErrorAction Stop -ArgumentList '/i', "$($stdPrefix)\agentInstaller-x86_64.msi", '/quiet', 'CUSTOMTOKEN=us:6fe89c5e-c502-41b2-bf59-123e561307c1'
    if (Get-WmiObject -Class win32_product -filter "Name Like 'rapid7%'" -ErrorAction SilentlyContinue) {
        Write-Log "Insight Agent has been installed"

    }
    else {
        write-log "Error locating the Insight Agent executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Insight Agent: $ErrorMessage"
}

#=================================================== SEP Installation ===================================================#

try {
    cmd.exe /c $stdPrefix\SEP\Symantec_Agent_install.exe /Silent /IMAGE /NPVDI
    if (Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Symantec Endpoint Protection\Symantec Endpoint Protection.lnk" -ErrorAction SilentlyContinue) {
        Write-Log "SEP has been installed"
    }
    else {
        write-log "Error locating the SEP executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing SEP: $ErrorMessage"
}

#=================================================== SEP Scheduled Task ===================================================#

##Define Scheduled Task Variables
$time = (Get-Date).AddMinutes(45)
$principal = New-ScheduledTaskPrincipal -UserId "$($env:COMPUTERNAME)\SYSTEM" -RunLevel Highest
$action = New-ScheduledTaskAction -Execute "$($stdPrefix)\SEP\Symantec_Agent_install.exe"
$trigger = New-ScheduledTaskTrigger -At $time -Once -RandomDelay 00:03:00
$tasksettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3) -Priority 5 
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $tasksettings -Principal $principal

try {
    Register-ScheduledTask -TaskPath \SEP\ -TaskName "Enroll_SEP" -InputObject $task -User "NT Authority\SYSTEM" 

    if (Get-ScheduledTask -TaskName "Enroll_SEP")
    {
        Write-Log "SEP Enrollment Task successfully registered"
    }
}
catch {
    write-log "Error registering scheduled task: $ErrorMessage"
}

#=================================================== Install .NET 6.0.x ===================================================#

try {
    cmd.exe /c $dotNetPath /quiet /norestart 
    if (Get-WmiObject -Class win32_product -filter "Name Like '%.NET Runtime%'" -ErrorAction SilentlyContinue) {
        Write-Log "DotNET has been installed"
    }
    else {
        write-log "Error locating the DotNET executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing DotNET: $ErrorMessage"
}

#=================================================== Install Storage Explorer ===================================================#

try {
    cmd.exe /c "$($stdPrefix)\StorageExplorer-windows-x64.exe" /VERYSILENT /norestart /ALLUSERS
    if (Get-ChildItem -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Azure Storage Explorer\Microsoft Azure Storage Explorer.lnk" -ErrorAction SilentlyContinue) {
        Write-Log "StorageExplorer has been installed"
    }
    else {
        write-log "Error locating the StorageExplorer executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing StorageExplorer: $ErrorMessage"
}
