# 11B checker

This is a sample PowerShell script to help detect potential authentication issues that may occur in an AD environment after installing Windows Update from November 2022 or newer. 

## Usage

Run the script in PowerShell with domain administrator privileges from a machine with AD RSAT tools installed, such as on a domain controller. The script will output any detected compatibility issues found in the domain related to changes made for CVE-2022-37966.

Note:
- This will enumerate every user and computer object in your AD environment. This may take some time to complete.
- DES is assumed to be disabled

## Reference

- [KB5021131:](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d) How to manage the Kerberos protocol changes related to CVE-2022-37966
- [Decrypting the Selection of Supported Kerberos Encryption Types](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797)
- [What happened to Kerberos Authentication after installing the November 2022/OOB updates?](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351)
