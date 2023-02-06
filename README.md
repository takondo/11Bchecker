# 11B checker

This is a sample PowerShell script to help detect potential authentication issues that may occur in an AD environment after installing Windows Update from November 2022 or newer. 

The msDS-SupportedEncryptionTypes attribute that is mentioned in the script is an attribute that can be configured on AD objects such as computers and users to signify as a bitmap the types of encryption types (etypes) that can be used when authenticating to that target server/service. You can use the AD Users and Computers MMC console to edit this value. Please see the reference section for more details on this attribute. 

## Usage

Run the script in PowerShell with domain administrator privileges from a machine with AD RSAT tools installed, such as on a domain controller. The script will output any detected compatibility issues found in the domain related to changes made for CVE-2022-37966.

Note that this will enumerate every user and computer object in your AD environment. This may take some time to complete. For very large AD environments, consider limiting the number of objects queried at once by specifying an OU with the SearchBase option in Get-ADComputer and Get-ADUser. By default, the query is recursive and any child OUs will be queried asd well.

Example:
```
$computers = Get-ADComputer -filter * -Properties msDS-SupportedEncryptionTypes, operatingSystem, operatingSystemVersion, userAccountControl, passwordLastSet -SearchBase "OU=OU1,DC=example,DC=domain"
$users = Get-ADUser -Filter * -Properties msDS-supportedEncryptionTypes, servicePrincipalName, passwordLastSet -SearchBase "OU=OU1,DC=example,DC=domain"
```

## Reference

- [KB5021131: How to manage the Kerberos protocol changes related to CVE-2022-37966](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d) 
- [What happened to Kerberos Authentication after installing the November 2022/OOB updates?](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351)
- [2.2.7 Supported Encryption Types Bit Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919)
- [Decrypting the Selection of Supported Kerberos Encryption Types](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797)
