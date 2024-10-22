# Initialize counters
$script:passes = 0
$script:fails = 0



function getProzent {
    param (
        [int]$a,
        [int]$b
    )

    $total = $a + $b

    $percentage = [math]::Round(($a / $total) * 100)


    return $percentage
}



# Unicode Method
$checkMark = [char]0x2705
$NoEntry = [char]0x26D4
$BulletPoint = [char]0x2022




# Define the Test function
function Test {
    param (
        [string]$TestName,  # The name of the test
        [scriptblock]$Func  # The function to be tested as a script block
    )

    try {
        $result = & $Func  # Call the function using the call operator

        # Output success message
        if ($result) {
            Write-Host "$checkMark $TestName $BulletPoint $result"
        } else {
            Write-Host "$checkMark $TestName"
        }

        # Increment passes
        $script:passes += 1
    } catch {
        # Increment fails and output error message
        $script:fails += 1
        Write-Host "$NoEntry $TestName failed: $_" -ForegroundColor Yellow
    }
}  # <-- Ensure this closing brace is present



Write-Host "UNC Windows Check"
Write-Host "$checkMark - Pass, $NoEntry - Fail"
Write-Host " "


Write-Host "Protection: "

# Example function to test
function RealTimeProtection {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring


    if ($realTimeProtectionStatus) {
        throw "RealTime-Protection is Disabled! Making the PC Vulnerable agenst Virus!"

        return
    }

    return "RealTime Protection is Enabled"
}




Test -TestName "RealTime-Protection" -Func { RealTimeProtection }



function checkFor_CheckForSignaturesBeforeRunningScan {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty CheckForSignaturesBeforeRunningScan


    if ($realTimeProtectionStatus) {
        throw "This can make Downloading or Running Programs not posible!"

        return
    }
}


Test -TestName "CheckForSignaturesBeforeRunningScan" -Func { checkFor_CheckForSignaturesBeforeRunningScan }



function checkFor_DisableCatchupQuickScan {
    $realTimeProtectionStatus = Get-MpPreference | Select-Object -ExpandProperty DisableCatchupQuickScan


    if ($realTimeProtectionStatus) {
        throw "This can make Virus Scans miss potensial Virus-/Malware's"

        return
    }
}


function checkFor_DisableScriptScanning {
    $e = Get-MpPreference | Select-Object -ExpandProperty DisableScriptScanning


    if ($e) {
        throw "This can make your PC Vulnerable"
    }
}




Test -TestName "DisableScriptScanning" -Func { checkFor_DisableScriptScanning }




Test -TestName "DisableCatchupQuickScan" -Func { checkFor_DisableCatchupQuickScan }




function checkFor_memoryIntegrity {
    $t = Get-WmiObject -Namespace "root\Microsoft\Windows\DeviceGuard" -Class "Win32_DeviceGuard" | Select-Object -ExpandProperty RequiredSecurityProperties

    if ($t -contains "1") {
        throw "Memory-integrity is Disabled! This can make your PC Vulnerable"
    } else {
        
    }
}




Test -TestName "MemoryIntegrity" -Func { checkFor_memoryIntegrity }




Write-Host " "
Write-Host "Profile"




function checkFor_HasUserAdmin {
    # Get the current user
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

    # Create a WindowsPrincipal object
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)

    # Check if the user is in the Administrator role
    $isAdmin = $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Output the result
    if ($isAdmin) {
        
    } else {
        throw "The User dose not have Admin. Making it so- if a Virus is Admin, the User cannot save the PC"
    }
}



Test -TestName "UserHasAdmin" -Func { checkFor_HasUserAdmin }






Write-Host " "
Write-Host "Installed Apps"



function checkFor_Kalkulator_App_Installed {
    # Path to the Calculator executable
    $calculatorApp = Get-AppxPackage -Name "*Calculator*"

    if ($calculatorApp) {
        return "Kalkulator is Installed"
    } else {
        throw "Kalkulator is not Installed. Can have something to do with how Windows got Installed"
    }
}


Test -TestName "Kalkulator" -Func { checkFor_Kalkulator_App_Installed }



function checkFor_voiceRecorderApp {
    $voiceRecorderApp = Get-AppxPackage -Name "*VoiceRecorder*"

    if ($voiceRecorderApp) {
        return "Voice Recorder (Stemmeopptak) is installed."
    } else {
        throw "Voice Recorder (Stemmeopptak) is not installed. Can have something to do with how Windows got Installed"
    }
}



Test -TestName "Voice Recorder (Stemmeopptak)" -Func { checkFor_voiceRecorderApp }




function checkFor_MicrosoftEdge_App {
    # Check if Microsoft Edge is installed
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

    if (Test-Path $edgePath) {
        return "Microsoft Edge is installed."
    } else {
        throw "Microsoft Edge is not installed. Can have something to do with how Windows got Installed"
    }
}



Test -TestName "Microsoft Edge" -Func { checkFor_MicrosoftEdge_App }


function checkFor_GoogleChrome_App {
    # Check if Google Chrome is installed
    $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"

    if (Test-Path $chromePath) {
        return "Google Chrome is installed."
    } else {
        throw "Google Chrome is not installed."
    }
}


Test -TestName "Google Chrome" -Func { checkFor_GoogleChrome_App }



function checkFor_MicrosoftStore_App {
    # Check if Microsoft Store is installed
    $storeApp = Get-AppxPackage -Name "*Microsoft.Store*"

    if ($storeApp) {
        return "Microsoft Store is installed."
    } else {
        throw "Microsoft Store is not installed."
    }
}



Test -TestName "Microsoft Store" -Func { checkFor_MicrosoftStore_App }




function checkFor_Camera_App {
    # Check if the Camera app is installed
    $cameraApp = Get-AppxPackage -Name "*WindowsCamera*"
    if ($cameraApp) {
        return "Camera is installed."
    } else {
        throw "Camera app is not installed."
    }
}


Test -TestName "Camera" -Func { checkFor_Camera_App }



function checkFor_Cleanmgr_App {
    $cleanupPath = "$env:SystemRoot\System32\cleanmgr.exe"
    if (Test-Path $cleanupPath) {
        return "Disk Cleanup is installed."
    } else {
        throw "Disk Cleanup is not installed."
    }
}


Test -TestName "Cleanup Manager" -Func { checkFor_Cleanmgr_App }





Write-Host " "
Write-Host "Windows"



function checkFor_WindowsVersion {
    # Initialize COM object for Windows Update
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for available updates
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Check if updates are available
    if ($SearchResult.Updates.Count -gt 0) {
        throw "Updates are available. Your Windows version is not up to date. $($SearchResult.Updates.Count) updates found."
    } else {
        return "Your Windows version is up to date."
    }
}



Test -TestName "Windows Update" -Func { checkFor_WindowsVersion }



function checkFor_WindowsVersionV2 {
    # Initialize COM object for Windows Update
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for available updates
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Get current Windows version and build number from the registry
    #$currentBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    #$currentVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId


    # Check if updates are available
    if ($SearchResult.Updates.Count -gt 0) {
        throw "There are updates available. Your Windows version may not be the latest."
    } else {
        throw "Your Windows version is up to date."
    }
}


Test -TestName "Windows Version" -Func { checkFor_WindowsVersionV2 }







Write-Host " "
Write-Host " "







$rate = getProzent -a $script:passes -b $script:fails


$all = $script:passes + $script:fails

$outOf = "$script:passes out of $all"



# Output total passes and fails
Write-Host "$checkMark Tested with a $rate% success rate ($outOf)"
Write-Host "$NoEntry $script:fails tests failed"
