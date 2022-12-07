Import-Module ActiveDirectory

$noSET = New-Object -TypeName 'System.Collections.ArrayList'
$badSET = New-Object -TypeName 'System.Collections.ArrayList'
$rc4only = New-Object -TypeName 'System.Collections.ArrayList'
$AESonlyDC = New-Object -TypeName 'System.Collections.ArrayList'

$computers = Get-ADComputer -filter * -Properties msDS-SupportedEncryptionTypes,operatingSystem,operatingSystemVersion,userAccountControl
$users = Get-ADUser -Filter * -Properties msDS-supportedEncryptionTypes,servicePrincipalName 
 
foreach($computer in $computers) {
    if(!$computer.Enabled) {continue}

    #Look for legacy Windows OS's (pre 2008/Vista)
    if($computer.operatingSystem -match "Windows") {
        [int]$version = ($computer.OperatingSystemVersion.Split("."))[0]
        if($version -lt 6) {
            Write-Host "*****************************************"
            Write-Host "Legacy OS detected: " -NoNewline
            Write-Host $computer -ForegroundColor Red
            Write-Host "This OS is not compatible with the new default behavior, and authentication to this computer will fail after installing Windows Update released on November 2022 or newer."
            continue
        }
    }

    #Look for computer objects with msDS-SupportedEncryptionTypes not configured
    if(!$computer.'msDS-SupportedEncryptionTypes') {
        $noSET.Add($computer) | Out-Null
    }
    else {
        $set = $computer.'msDS-SupportedEncryptionTypes'

        #Look for computer objects with msDS-SupportedEncryptionTypes configured but no etype enabled
        #Example: only CompoundIdentity is set
        if(($set -band 0x1F) -eq 0) {
            $badSET.Add($computer) | Out-Null
        }
        #Keep track of objects where AES is disabled
        elseif(($set -band 0x18) -eq 0) {
            $rc4only.Add($computer) | Out-Null
        }

        #Look for DCs with msDS-SupportedEncryptionTypes RC4 disabled
        if($computer.'userAccountControl' -band 0x2000 -and ($set -band 0x4) -eq 0) {
            $AESonlyDC.Add($computer) | Out-Null
        }
    }
}

foreach($user in $users) {
    if(!$user.Enabled) {continue}

    if($user.servicePrincipalName) {
        #ignore krbtgt
        if($user.Name -match "krbtgt") {continue}
        
        #This is most likely a service account
        #Look for objects with msDS-SupportedEncryptionTypes not configured
        if(!($user.'msDS-SupportedEncryptionTypes')) {
            $noSET.Add($user) | Out-Null
        }
        else {
            $set = $user.'msDS-SupportedEncryptionTypes'

            #Look for objects with msDS-SupportedEncryptionTypes configured but no etype enabled
            if(($set -band 0x1F) -eq 0) {
                $badSET.Add($user) | Out-Null
            }
            #Keep track of objects where AES is disabled
            elseif(($set -band 0x18) -eq 0) {
                $rc4only.Add($user) | Out-Null
            }
        }
    }
}

 
if($noSET.Cout -ne 0) {
    Write-Host "======================================"
    Write-Host "There are $($noSET.Count) objects that do not have msDS-SupportedEncryptionTypes configured."
    Write-Host "When authenticating to this target, Kerberos will default to the setting of DefaultDomainSupportedEncTypes registry on the authenticating DC."
    Write-Host "This defaults to a value of 0x27, which means 'use AES for session keys and RC4 for ticket encryption'"
    Write-Host "If this target service does not support AES, please set msDS-SupportedEncryptionTypes to 4 on this object so that only RC4 is used."
    foreach($obj in $noSET) {
        Write-Host "`t"$obj
    }
}

if($badSET.Count -ne 0) {
    Write-Host "======================================"
    Write-Host "There are $($badSET.Count) objects that have msDS-SupportedEncryptionTypes configured, but no encryption protocol is allowed."
    Write-Host "This can cause authentication to/from this object to fail."
    Write-Host "Please either delete the existing msDS-SupportedEncryptionTypes settings, or add supported etypes."
    Write-Host "Example: Add 0x1C to signify support for AES128, AES256, and RC4"
    foreach($obj in $badSET) {
        Write-Host "`t"$obj
    }
}

if($rc4only.Count -ne 0) {
    Write-Host "======================================"
    Write-Host "There are $($rc4only.Count) computers/services that are configured for RC4/DES only"
    Write-Host "If you have any clients or DCs that are configured to only support AES, authentication will fail"
    Write-Host "Here is the list of objects that are RC4/DES only:"
    foreach($obj in $rc4only) {
        Write-Host "`t"$obj
    }

    Write-Host "`nA common scenario where authentication fails after installing November update on DCs in this condition is if DCs are configured to only support AES"
    Write-Host "Example: Setting the 'Configure encryption types allowed for Kerberos' policy to AES only on DCs"
    if($AESonlyDC.Count -eq 0) {
        Write-Host "No DCs were detected that are configured for AES only"
    }
    else {
        Write-Host "Here are the DCs configured for AES only:"
        foreach($obj in $AESonlyDC) {
            Write-Host "`t"$obj
        }
    }
}

