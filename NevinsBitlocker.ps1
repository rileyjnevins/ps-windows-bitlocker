## RILEY'S WINDOWS BITLOCKER DRIVE ENCRYPT POWERSHELL SCRIPT
## AUTHOR: RILEY J. NEVINS 
## CREATED ON: 9/27/2021
## MODIFIED ON: 10/11/2021
## INTENT: Provide users an interactive command line way to easily maintain/execute
##         Bitlocker Drive Encryption. 

###################################################

# Create Advanced Startup Key if it doesn't exist. If it does, set it's value to 1. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableNonTPM" -Value "1" -Type Dword

## Edit the registry to set UseAdvancedStartup to "1" or true. 
## Reference: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.VolumeEncryption::ConfigureAdvancedStartup_Name
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value "1" -Type Dword


## Create filesystem.
$nevins_bitlocker_root = 'C:\NevinsBitlocker'
$nevins_bitlocker_logs_path = 'C:\NevinsBitlocker\Logs'
$nevins_error_path = 'C:\NevinsBitlocker\Logs\error.txt'

## Check if root dir exists already, and create entire filesystem.
if (Test-Path -Path $nevins_bitlocker_root) { ## Assume exists.
    if (Test-Path -Path $nevins_bitlocker_logs_path) { ## Assume exists.
        ## DO NOTHING!
    }

    else {
        ## CREATE LOG PATH...
        New-Item -Path $nevins_bitlocker_logs_path -ItemType Directory | Out-Null ## Mute output (silent).
    }

    if (Test-Path -Path $nevins_error_path -PathType leaf) { ## Assume exists
    }

    else {
        New-Item -Path $nevins_error_path -ItemType File
    }
}

else { ## Does not exist.
    ## Since root does not exist, we can assume none of the the below exist, and need to be created. 
    New-Item -Path $nevins_bitlocker_root -ItemType Directory | Out-Null ## Mute output (silent).

    if (Test-Path -Path $nevins_bitlocker_logs_path) { ## Assume exists.
    }

    else {
        ## CREATE LOG PATH...
        New-Item -Path $nevins_bitlocker_logs_path -ItemType Directory | Out-Null ## Mute output (silent).
    }

    if (Test-Path -Path $nevins_error_path -PathType leaf) { ## Assume exists.
    }

    else {
        New-Item -Path $nevins_error_path -ItemType File
    }
}

function menu {
    Clear-Host
    Write-Host "#############################################################" -ForegroundColor Blue -BackgroundColor Blue
    Write-Host ""
    Write-Host "       ____  _ _   _               _                    " -ForegroundColor White -BackgroundColor Blue
    Write-Host "      | __ )(_) |_| |    ___   ___| | _____ _ __        " -ForegroundColor White -BackgroundColor Blue
    Write-Host "      |  _ \| | __| |   / _ \ / __| |/ / _ \ '__|       " -ForegroundColor White -BackgroundColor Blue
    Write-Host "      | |_) | | |_| |__| (_) | (__|   <  __/ |          " -ForegroundColor White -BackgroundColor Blue
    Write-Host "      |____/|_|\__|_____\___/ \___|_|\_\___|_|  v.1.0.0 " -ForegroundColor White -BackgroundColor BLue
    Write-Host ""
    Write-Host "#############################################################" -ForegroundColor Blue -BackgroundColor Blue
    Write-Host ""
    Write-Host "# [i] Welcome to Nevins BitLocker! An interactive PowerShell" -ForegroundColor Yellow
    Write-Host "#     script that encrypts your disk on startup. To get started," -ForegroundColor Yellow
    Write-Host "#     simply enter a drive letter as shown below." -ForegroundColor Yellow
    Write-Host "#" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "# [i] Windows Bitlocker Options:" -ForegroundColor Green
    Write-Host "#    1 - Encrypt Drive" -ForegroundColor Gray
    Write-Host "#    2 - Exit Now" -ForegroundColor Gray
    Write-Host ""
    $menuselection = Read-Host "Enter a menu selection --------> "
    
    # Menu selection.
    Switch ($menuselection)
    {
        1 { DO_ENCRYPT }
        2 { EXIT_APP }
    }

    menu

}

function GET_TIME {
    return "[{0:MM/dd/yy}]" -f (Get-Date)
    ## All this is used for is appending the time to each progress log line. 
}

function DO_ENCRYPT {

    Write-Host ""
    $drive = Read-Host "Enter drive to encrypt 'C:', 'D:', etc (CTRL + X TO QUIT)"
    $path_exists = Test-Path -Path $drive

    ## Check if the entered drive letter is valid. 
    if (!$path_exists -like "True") {
        Clear-Host
        Write-Warning "You've entered in invalid or offline disk. Please try again!"
        pause
        Clear-Host
        menu
    }

    ## Somewhat secure way to handle and interact with user's password entry.
    ## SecureStrings are type of objects much like int or string, optimal for this kind of script. Replaces visible entry with *'s 
    $pass1 = Read-Host -AsSecureString "Passowrd Required for Startup: "
    $pass2 = Read-Host -AsSecureString "Re-enter Password Required for Startup: "
    
    ## Compared to a read-host on it's own, this is more secure generally speaking.
    ## Credits to Julius Bezaras for providing an example online.
    
    ## Format each of the entries as needed (SECURESTRING --> BSTR).
    
    # "Allocates an unmanaged binary string (BSTR) and copies the contents of a managed SecureString object into it."
    # So, in this case, we're creating two BSTR's and copying contents of pass1 and pass2 (secure string objects) to it. 
    $pass1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1))

    ## DEBUG (JUST WANTED TO SEE WHAT THE STRINGS LOOKED LIKE)
    ##Write-Host "PASS1: $pass1" ## REMOVE ME
    ##Write-Host "PASS1_TEXT: $pass1_text"

    $pass2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2))
    
    ## Check if first entry is equal to second entry.
    if ($pass1_text -ceq $pass2_text){
        Write-Host "Passwords matched! Starting encryption."
        
    
    } else {
        ## Exit script with a message when passwords do not match
        Write-Warning 'Passwords ARE NOT THE SAME! Stopping encryption!'
        pause ## So user can atleast read message above.
        menu
    
    }
    
    ## Will attempt to encrypt the valid selected disk given specifications in instructions. 
    ## Also my attempt at custom error handling :(

    $enable_recovery = Read-Host "Would you like to enable recovery password? (YES/NO): "

    if ($enable_recovery -like "YES") { ## Run encrypy command with recovery flag.
        try { 
            Enable-BitLocker -MountPoint "$drive" -EncryptionMethod Aes256 -UsedSpaceOnly -PasswordProtector -Password $pass1 -SkipHardwareTest
            Add-BitLockerKeyProtector $drive -RecoveryPasswordProtector

            (Get-BitLockerVolume -MountPoint $drive).KeyProtector.recoverypassword > C:\NevinsBitlocker\bitlockerkey.txt
            
            }
            
            catch {
                Write-Warning -Message â€œFailed to invoke Enable-Bitlocker on Disk: $driveâ€
            
            }
    }

    else {

    }

    if ($enable_recovery -like "NO") { ## Run encrypt command without recovery flag. 
        try { 

            Enable-BitLocker -MountPoint "$drive" -EncryptionMethod Aes256 -UsedSpaceOnly -Password $pass1 -SkipHardwareTest
            
            }
            
            catch {
                Write-Warning -Message â€œFailed to invoke Enable-Bitlocker on Disk: $driveâ€
            
            }
    }
   
    ## Get initial starting point of encryption.
    try {
        ## Define encrypion progress (by fetching the EncryptionPercentage)
        $encryption_progress = (Get-BitLockerVolume -MountPoint $drive | Select-Object EncryptionPercentage).EncryptionPercentage
    
    }
    
    catch {
        Write-Host ""
        Write-Warning -Message â€œFailed to Get-BitLockerVolume on Disk: $driveâ€
        ## Just move on. My attempt at custom error handling.
    }
    
    # While progress is not equal to 100 (percent).
    while ($encryption_progress -ne 100) {
        ## Execute the following.
        ## Allows us to view the encryption status live.
    
        Start-Sleep -Milliseconds 1 #
        Write-Progress -Id 1 -Activity "Encryption progress" -Status "$(GET_TIME) Current Count: $encryption_progress" -PercentComplete $encryption_progress -CurrentOperation "Counting ..."
        Add-Content $nevins_error_path "`n$(GET_DATE) $encryption_progress%" ## Write to log file timestamp + progress update (and add % to end) each round!
        ## Credits to Julius Bezaras for providing an example online of interval based progress updates.
    
        ## Get updated progress value each round.
        $encryption_progress = (Get-BitLockerVolume -MountPoint $drive | Select-Object EncryptionPercentage).EncryptionPercentage
    }
    
    ## Inform when completed.

    Clear-Host
    Write-Host "#############################################################" -ForegroundColor Blue -BackgroundColor Blue
    Write-Host ""
    Write-Host "    ____   ___  _   _ _____ _      " -ForegroundColor White -BackgroundColor Blue
    Write-Host "    |  _ \ / _ \| \ | | ____| |    " -ForegroundColor White -BackgroundColor Blue
    Write-Host "    | | | | | | |  \| |  _| | |    " -ForegroundColor White -BackgroundColor Blue
    Write-Host "    | |_| | |_| | |\  | |___|_|    " -ForegroundColor White -BackgroundColor Blue
    Write-Host "    |____/ \___/|_| \_|_____(_)    " -ForegroundColor White -BackgroundColor Blue
    Write-Host ""
    Write-Host "# [i] Encryption of drive " -ForegroundColor white -NoNewLine; Write-Host $drive -ForegroundColor Yellow -NoNewline; Write-Host " is" -ForegroundColor White -NoNewline; Write-Host " complete!" -ForegroundColor Green
    Write-Host "# [i] Your recovery code had been saved to C:\NevinsBitlocker" -ForegroundColor Green
    Write-Host ""
    Write-Host "#############################################################" -ForegroundColor Blue -BackgroundColor Blue

    ## !!!! PURGE CONTENTS OF THE PLAINTEXT AND HASHED VARIABLES !!!!
    Write-Warning "Do you agree to remove the following? (RECOMMENDED)"
    Remove-Variable pass1
    Remove-Variable pass2
    Remove-Variable pass1_text

    Write-Host ""
    Write-Warning "The hashed and plaintext variables have been DESTROYED!"
    Write-Host ""

    pause ## Wait so it can be read.
    menu  
}

function EXIT_APP {
    exit
}

menu
