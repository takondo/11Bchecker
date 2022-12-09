# 11B checker
This is a sample PowerShell script to help detect potential authentication issues that may occur in an AD environment after installing Windows Update from November 2022 or newer. 

## Usage
Run the script as a domain administrator privileges from a machine with AD RSAT tools installed, such as on a domain controller. The script will output any detected compatibility issues found in the domain related to changes made for CVE-2022-37966.
Note that this will enumerate every user and computer object in your AD environment. This may take some time to complete.

## Reference
* [KB5021131:](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d) How to manage the Kerberos protocol changes related to CVE-2022-37966
