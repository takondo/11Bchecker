################################################################################################
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
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
$dateAESadded = (Get-ADGroup -filter * -properties SID,WhenCreated | where-object {$_.SID -like '*-521'}).WhenCreated

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

    if ($user.passwordlastset -and $user.passwordlastset -le $dateAESadded) {
        $NoAESKeys.Add($user) | Out-Null
    }
}

Write-Host "======================================"
if ($badSET.Count -ne 0) {
    Write-Host "There are $($badSET.Count) objects that have msDS-SupportedEncryptionTypes configured, but no etypes are enabled." -ForegroundColor Red
    Write-Host "etypes are configured in the low 6 bits of msDS-SupportedEncryptionTypes, and having a value configured without etypes can cause authentication to/from this object to fail."
    Write-Host "Please either delete the existing msDS-SupportedEncryptionTypes settings, or add supported etypes to the existing msDS-SupportedEncryptionTypes value."
    Write-Host "Example: Add 0x1C (or 28 in decimal) to signal support for AES128, AES256, and RC4"
    Write-Host "Windows Update released January 10, 2023 addresses this, so if you are installing the January update or newer to your DCs this configuration should not cause any issues."
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
