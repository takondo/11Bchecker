################################################################################################
#
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service.
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for
# any damages whatsoever (including, without limitation, damages for loss of business profits,
# business interruption, loss of business information, or other pecuniary loss) arising out of
# the use of or inability to use the sample or documentation, even if Microsoft has been advised
# of the possibility of such damages.
################################################################################################

Import-Module ActiveDirectory

$noSET = New-Object -TypeName 'System.Collections.ArrayList'
$badSET = New-Object -TypeName 'System.Collections.ArrayList'
$rc4only = New-Object -TypeName 'System.Collections.ArrayList'
$AESonlyDC = New-Object -TypeName 'System.Collections.ArrayList'
$NoAESKeys = New-Object -TypeName 'System.Collections.ArrayList'
$hasLegacyOS = $false

$computers = Get-ADComputer -filter * -Properties msDS-SupportedEncryptionTypes, operatingSystem, operatingSystemVersion, userAccountControl, passwordLastSet
$users = Get-ADUser -Filter * -Properties msDS-supportedEncryptionTypes, servicePrincipalName, passwordLastSet
$dateAESadded = (Get-ADGroup "Read-only Domain Controllers" -Properties WhenCreated).WhenCreated

foreach ($computer in $computers) {
    if (!$computer.Enabled) { continue }

    #Look for legacy Windows OS's (pre 2008/Vista)
    if ($computer.operatingSystem -match "Windows") {
        [int]$version = ($computer.OperatingSystemVersion.Split("."))[0]
        if ($version -lt 6) {
            Write-Host "*****************************************"
            Write-Host "Legacy OS detected: " -NoNewline -ForegroundColor Red
            Write-Host $computer 
            Write-Host "This OS is not compatible with the new behavior, and authentication to this computer will fail after installing Windows Update released on November 2022 or newer on DCs."
            $hasLegacyOS = $true
            continue
        }
    }

    #Look for computer objects with msDS-SupportedEncryptionTypes not configured
    if (!$computer.'msDS-SupportedEncryptionTypes') {
        $noSET.Add($computer) | Out-Null
    }
    else {
        $set = $computer.'msDS-SupportedEncryptionTypes'

        #Look for computer objects with msDS-SupportedEncryptionTypes configured but no etype enabled
        #Example: only CompoundIdentity is set
        if (($set -band 0x1F) -eq 0) {
            $badSET.Add($computer) | Out-Null
        }
        #Keep track of objects where AES is disabled
        elseif (($set -band 0x18) -eq 0) {
            $rc4only.Add($computer) | Out-Null
        }

        #Look for DCs with msDS-SupportedEncryptionTypes RC4 disabled
        if ($computer.'userAccountControl' -band 0x2000 -and ($set -band 0x4) -eq 0) {
            $AESonlyDC.Add($computer) | Out-Null
        }
    }

    if ($computer.passwordlastset -le $dateAESadded) {
        $NoAESKeys.Add($computer) | Out-Null
    }
}

foreach ($user in $users) {
    if (!$user.Enabled) { continue }

    if ($user.servicePrincipalName) {
        #ignore krbtgt
        if ($user.Name -match "krbtgt") { continue }
        
        #This is most likely a service account
        #Look for objects with msDS-SupportedEncryptionTypes not configured
        if (!($user.'msDS-SupportedEncryptionTypes')) {
            $noSET.Add($user) | Out-Null
        }
        else {
            $set = $user.'msDS-SupportedEncryptionTypes'

            #Look for objects with msDS-SupportedEncryptionTypes configured but no etype enabled
            if (($set -band 0x1F) -eq 0) {
                $badSET.Add($user) | Out-Null
            }
            #Keep track of objects where AES is disabled
            elseif (($set -band 0x18) -eq 0) {
                $rc4only.Add($user) | Out-Null
            }
        }
    }

    if ($user.passwordlastset -le $dateAESadded) {
        $NoAESKeys.Add($user) | Out-Null
    }
}

Write-Host "======================================"
if ($badSET.Count -ne 0) {
    Write-Host "There are $($badSET.Count) objects that have msDS-SupportedEncryptionTypes configured, but no etypes are enabled." -ForegroundColor Red
    Write-Host "etypes are configured in the low 6 bits of msDS-SupportedEncryptionTypes, and having a value configured without etypes can cause authentication to/from this object to fail."
    Write-Host "Please either delete the existing msDS-SupportedEncryptionTypes settings, or add supported etypes to the existing msDS-SupportedEncryptionTypes value."
    Write-Host "Example: Add 0x1C (or 28 in decimal) to signal support for AES128, AES256, and RC4"
    Write-Host "Here are the objects with no etypes enabled"
    foreach ($obj in $badSET) {
        Write-Host "`t"$obj
    }
}
else {
    Write-Host "There were no objects with msDS-SupportedEncryptionTypes configured without any etypes enabled." -ForegroundColor Green
}

Write-Host "======================================"
if ($NoAESKeys.Count -ne 0) {
    Write-Host "There are $($NoAESKeys.Count) objects that do not have AES Keys generated." -ForegroundColor Red
    Write-Host "This can occur if the account's password has not been changed after adding Server 2008 or newer DCs"
    Write-Host "Authentication to this target can fail if AES is required by either the client or the KDC."
    Write-Host "Please change/reset the accounts' password, and AES keys will be automatically generated." 
    Write-Host "Here are the objects with no AES keys"
    foreach ($obj in $NoAESKeys) {
        Write-Host "`t"$obj
    }
}
else {
    Write-Host "There were no accounts whose passwords predate AES capabilities." -ForegroundColor Green
}

Write-Host "======================================" 
Write-Host "A common scenario where authentication fails after installing November 2022 update or newer on DCs is when DCs are configured to only support AES."
Write-Host "Example: Setting the 'Configure encryption types allowed for Kerberos' policy on DCs to disable RC4 and only enable AES`n"
if ($AESonlyDC.Count -eq 0) {
    Write-Host "No DCs were detected that are configured for AES only"
}
else {
    Write-Host "DCs with RC4 disabled detected."
    Write-Host "In this environment, Kerberos authentication can fail if the target server/service does not have msDS-SupportedEncryptionTypes configured,"
    Write-Host "or has configured msDS-SupportedEncryptionTypes and has explitcitly enabled only RC4."
    Write-Host "Setting the DefaultDomainSupportedEncTypes registry value on DCs to 0x18 will set the default supported etypes to AES only,"
    Write-Host "and may prevent Kerberos authentication issues due to unexpected RC4 use after installing November 2022 update or newer on DCs."
    Write-Host "Here are the DCs that have RC4 disabled"
    foreach ($obj in $AESonlyDC) {
        Write-Host "`t"$obj
    }
}

Write-Host "======================================" 
if ($noSET.Count -ne 0) {
    Write-Host "There are $($noSET.Count) objects that do not have msDS-SupportedEncryptionTypes configured or is set to zero." -ForegroundColor Red
    Write-Host "When authenticating to this target, Kerberos will use the DefaultDomainSupportedEncTypes registry value on the authenticating DC to determinte supported etypes."
    Write-Host "If the registry value is not configured, the default value is 0x27, which means 'use AES for session keys and RC4 for ticket encryption'"
    Write-Host "  - If this target server does not support AES, you must set msDS-SupportedEncryptionTypes to 4 on this object so that only RC4 is used."
    Write-Host "    (Please consider working with your vendor to upgrade or configure this server to support AES. Using RC4 is not recommended)"
    Write-Host "  - If this target server does not support RC4, or you have disabled RC4 on DCs, please set DefaultDomainSupportedEncTypes on DCs to 0x18"
    Write-Host "    or msDS-SupportedEncryptionTypes on this object to 0x18 to specify that AES must be used. The target server must support AES in this case."
    Write-Host "Here are the objects that do not have msDS-SupportedEncryptionTypes configured"
    foreach ($obj in $noSET) {
        Write-Host "`t"$obj
    }
}
else {
    Write-Host "There were no objects with msDS-SupportedEncryptionTypes not configured."  -ForegroundColor Green
    Write-Host "During Kerberos authentication, supported etypes will be determined based on the value of msDS-SupportedEncryptionTypes"
}

Write-Host "======================================"
if ($rc4only.Count -ne 0) {
    Write-Host "There are $($rc4only.Count) objects that are configured for RC4 only." -ForegroundColor Red
    Write-Host "Authentication to this target can fail if AES is required by either the client or the DC."
    Write-Host "We do not recommend the use of RC4. Please consider working with your vendor to upgrade or configure this server to support AES."
    Write-Host "Here are the objects that are configured for RC4 only:"
    foreach ($obj in $rc4only) {
        Write-Host "`t"$obj
    }
}
else {
    Write-Host "There were no objects configured for RC4 only."  -ForegroundColor Green
}


if (!$hasLegacyOS -and $badSET.Count -eq 0 -and $noSET.Count -eq 0 -and $NoAESKeys.Count -eq 0 -and $rc4only.Count -eq 0) {
    Write-Host "======================================"
    Write-Host "Configurations known to cause Kerberos authentication failures after installing November 2022 update or newer on DCs were not detected." -ForegroundColor Green -BackgroundColor Black
    Write-Host "Please contact Microsoft Support if you do see any failures after updating your DCs."
}

# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3A4VzPa4gYZx0
# IvyEScNGEFbmmTrHjk91MH+LNDavI6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKCNh0EHuaFROHIBivnCWppD
# zgO3joGW141hmFrBnbgoMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCnF3yrQoMPTwfF3tV1uDO2ZB09uzqQHGdvgALp/02xMGC+Oo5bgIVI
# IncZ/SGqpKUslgclrJdG0kGwknHbPaZ6CMotYPiKXMu3pHIU/XFBNDnC20itFSWM
# TYvfFClGQuFOYWW6DjQkz411d7Fn8Wu68d3C96cLLRrjcZJMXBFfxnPbdDlDDuVt
# Lon4NPh1smOuZf3RGjwgV1vbDpVEW/YVcncJjbkCMrDjbDZNMb+8DA6X3lPfMcsB
# fl1Of3//THVp+yGlKLwROjn7QuTXFyv1DiU45ew3VWz5v6ZWhgfuDNSDJlPyjP4J
# zhUC/NYUVOls0DaPfRu5Hlak/bMVY9PhoYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDnTukallPdU6BcHruP77J9HP3jc7vWYjaS9LVILncR4AgZjc47D
# clIYEzIwMjIxMjE1MTUxMDA3LjU5NVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjow
# QTU2LUUzMjktNEQ0RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABpzW7LsJkhVApAAEAAAGnMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyMloXDTIzMDUxMTE4NTEyMlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowQTU2LUUzMjktNEQ0
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAO0jOMYdUAXecCWm5V6TRoQZ4hsPLe0V
# p6CwxFiTA5l867fAbDyxnKzdfBsf/0XJVXzIkcvzCESXoklvMDBDa97SEv+CuLEI
# ooMbFBH1WeYgmLVO9TbbLStJilNITmQQQ4FB5qzMEsDfpmaZZMWWgdOjoSQed9Ur
# jjmcuWsSskntiaUD/VQdQcLMnpeUGc7CQsAYo9HcIMb1H8DTcZ7yAe3aOYf766P2
# OT553/4hdnJ9Kbp/FfDeUAVYuEc1wZlmbPdRa/uCx4iKXpt80/5woAGSDl8vSNFx
# i4umXKCkwWHm8GeDZ3tOKzMIcIY/64FtpdqpNwbqGa3GkJToEFPR6D6XJ0WyqebZ
# vOZjMQEeLCJIrSnF4LbkkfkX4D4scjKz92lI9LRurhMPTBEQ6pw3iGsEPY+Jrcx/
# DJmyQWqbpN3FskWu9xhgzYoYsRuisCb5FIMShiallzEzum5xLE4U5fuxEbwk0uY9
# ZVDNVfEhgiQedcSAd3GWvVM36gtYy6QJfixD7ltwjSm5sVa1voBf2WZgCC3r4RE7
# VnovlqbCd3nHyXv5+8UGTLq7qRdRQQaBQXekT9UjUubcNS8ZYeZwK8d2etD98mSI
# 4MqXcMySRKUJ9OZVQNWzI3LyS5+CjIssBHdv19aM6CjXQuZkkmlZOtMqkLRg1tmh
# gI61yFC+jxB3AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUH2y4fwWYLjCFb+EOQgPz
# 9PpaRYMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEATxL6MfPZOhR91DHShlzal7B8vOCUvzlvbVha0UzhZfvIcZA/
# bT3XTXbQPLnIDWlRdjQX7PGkORhX/mpjZCC5J7fD3TJMn9ZQQ8MXnJ0sx3/QJIlN
# gPVaOpk9Yk1YEqyItOyPHr3Om3v/q9h5f5qDk0IMV2taosze0JGlM3M5z7bGkDly
# +TfhH9lI03D/FzLjjzW8EtvcqmmH68QHdTsl84NWGkd2dUlVF2aBWMUprb8H9EhP
# UQcBcpf11IAj+f04yB3ncQLh+P+PSS2kxNLLeRg9CWbmsugplYP1D5wW+aH2mdyB
# lPXZMIaERJFvZUZyD8RfJ8AsE3uU3JSd408QBDaXDUf94Ki3wEXTtl8JQItGc3ix
# RYWNIghraI4h3d/+266OB6d0UM2iBXSqwz8tdj+xSST6G7ZYqxatEzt806T1BBHe
# 9tZ/mr2S52UjJgAVQBgCQiiiixNO27g5Qy4CDS94vT4nfC2lXwLlhrAcNqnAJKmR
# qK8ehI50TTIZGONhdhGcM5xUVeHmeRy9G6ufU6B6Ob0rW6LXY2qTLXvgt9/x/XEh
# 1CrnuWeBWa9E307AbePaBopu8+WnXjXy6N01j/AVBq1TyKnQX1nSMjU9gZ3EaG8o
# S/zNM59HK/IhnAzWeVcdBYrq/hsu9JMvBpF+ZEQY2ZWpbEJm7ELl/CuRIPAwggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjowQTU2LUUzMjktNEQ0RDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAwH7vHimSAzeD
# LN0qzWNb2p2vRH+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOdFmXcwIhgPMjAyMjEyMTUxNzAyNDdaGA8yMDIy
# MTIxNjE3MDI0N1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA50WZdwIBADAKAgEA
# AgIFlgIB/zAHAgEAAgIRUjAKAgUA50bq9wIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAEh9uDKYb69fCZYnHJTqZsQlLT+JJUvhvHbE56/gG+lxxWNZiyO5saEY
# rHqypXx325sL55SdyejayWXzSZi87KyTZ7LLsBkD1fJLwxq8B8G352PslY0qbnN6
# VTqbLRKe3878AKexsTDNUS8YiDaxVIR0XLmY8PjGL8lTV2VH/yPbMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGnNbsuwmSF
# UCkAAQAAAacwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgkMGn7xkqTM15hyk7sdt2S0F/ei8W+Gx5
# nURSVfjlawYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBH8H/nCZUC4L0Y
# qbz3sH3w5kzhwJ4RqCkXXKxNPtqOGzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABpzW7LsJkhVApAAEAAAGnMCIEIPTd2vDQlx4CBL+3
# wxJ5zBZbQ+lPtf3txS3UEs+zBhbAMA0GCSqGSIb3DQEBCwUABIICAHHe2Viqaq/k
# UT+Ql7ml9bHNv0PuhEzysBID+gskoirp8BDohQ9sNbC1W4TJ8796JjxwLlbHiDQ9
# tfc9vhYSsB3Hl5YEELy9plyL4AGN2AQkmpFt4nuq+Mks3ND7/GLmryopwfH1Y34U
# pfnkpaqO0VbJdbopsXS9quDcEF+QYYvad3Cmi/NK/B5HvKacvw3XLBQR4Rr0cL8u
# dohE43Ko/5m9FODhS/jD1MAo8Nv+O0Y3tsiM5Kz8AYPjsNNCO+6bl+rC7Jq7paCF
# nOZz8Ll/laCLFvemKYqN6CJBd4pkC94gBjyCRiWZUa4PUdHLqSNgDF9bjTf+Hnsb
# V4yqOb0rXKF7d4gHgecjYZ65b0PVLoIqwkXCnM+co/mHcV1tfUnZ2Rk8TiSfqJnQ
# w+z3FPD5jBCuKmVLITKatTocMHK+XIBWwmdDcKj8XDT8PyIU6VcvbfYEeQyBOhEN
# xY5vT4hou2pxTp3/LLdOXVX2RThnpzLv+dZzvEyHydnJMJeS9FbHGSp+pJED6K6F
# w6qfW/BNtnoSCl24F7Mnhbh9KT+9n9ZZKFgeku/rcquEVhh9yltymhVAoB4njGGq
# F4oqQ5iy2k48Z07hTGY0ftiyUQhDxpcr/Bny6P/D4fHUdY5t1sdYY0ld4z6qwLtM
# hqQa5Q9Iv7nOEwsswxGOPb0CuSlV9hwu
# SIG # End signature block
