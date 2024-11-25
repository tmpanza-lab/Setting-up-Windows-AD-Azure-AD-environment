# Setting up Windows AD & Azure AD environment

## Objective

The Windows AD & Azure AD environment Lab project aimed to build and configure a Windows AD and Azure AD environment. The primary focus was to ensures your on-premises Active Directory integrates seamlessly with Azure AD using Azure AD Connect, generating test telemetry to mimic real-world scenarios. This hands-on experience was designed to deepen understanding of network security, Azure Active Directory and hybrid identity solutions.

### Skills Learned

- Setting up a VMware or Hyper-V lab environment.
- User Account Automation: Test user provisioning and deletion.
- Client Domain Join: Confirming that client PCs apply group policies and DNS resolves internal resources
- Azure AD Sync verifying that on-prem users are visible in Azure AD.
- NAT/PAT and Remote Access: Checking external access through NAT configurations
- DNS and DHCP: Ensuring clients get the right IP and resolve internal domain names.
- File Server Quotas: Confirming that file shares enforce quotas and permissions as configured.
- Automating server configurations and application deployments.
- Managing AD domains, forests, trusts, and group policies.
- Knowledge of Windows Server (2016/2019/2022) and Linux (Kali OS, Ubuntu).
- Proficiency in PowerShell, Bash scripting, and task automation.
- Managing OS-level updates, patches, and security hardening.
- TCP/IP networking, DNS, DHCP, VPNs, FTP, GPO and firewalls

### Tools Used

- Windows Server (2022) for on-prem AD environment.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- PowerShell and Command line interface (CMD) for scripting.
- Administration Tools AD, DHCP, DNS, GPO, FTP and WDS.
- Windows OS (10/11) and Linux (Kali OS, Ubuntu)

## Steps

1. Set Up Your Lab Environment
Use VMware Workstation to create your virtual environment.
• Create VMs:
o VM1 - Windows Server 2022 (for Domain Controller)
o VM2 - Windows 10 (Client machine)
![image](https://github.com/user-attachments/assets/be68cf4c-93e2-455d-af8c-256e42e82205)

Networking Configuration:
o Set up a custom: Specific virtual network for your VMs to communicate with each other simulating an isolated network environment.
![image](https://github.com/user-attachments/assets/bb1e72ca-2526-42db-baeb-73354b0353d9)

2. Install and Configure Active Directory Domain Services (AD DS)

1. Install Windows Server 2022 and configure basic settings:
o Set a static IP address (e.g., 192.168.18.73)
o Assign a hostname (e.g., JHB-SRV29).
 ![image](https://github.com/user-attachments/assets/6437963b-5aa5-498a-ba52-3c489c4097ad)
2. Install AD DS Role:
![image](https://github.com/user-attachments/assets/adc2d4d8-3a16-4028-b0e2-87b2b69ad1af)
![image](https://github.com/user-attachments/assets/1e3fdc87-aeb8-4a13-b599-3182114d926b)

3. Promote the Server to a Domain Controller:
o Set a Directory Services Restore Mode (DSRM) password.
o Complete the installation, which will automatically reboot the server
![image](https://github.com/user-attachments/assets/c14a50a7-ea75-45fd-b748-b9372bc055a5)

4. Automate User Account Management

• Script for Provisioning User Accounts:
o Open PowerShell ISE and write scripts to create user accounts in AD.
• Automate User Provisioning:
# Variables 
$FirstName = "Thokozane" $LastName = "Mpanza"
$Password = ConvertTo-SecureString "Password123" -AsPlainText -Force
$OU = "OU=Users,DC=mylab,DC=local"
# Create user
New-ADUser -Name "$FirstName $LastName" -GivenName $FirstName -Surname $LastName -SamAccountName "tmpanza" -UserPrincipalName "tmpanza@mylab.local" - Path $OU -AccountPassword $Password -Enabled $true

![image](https://github.com/user-attachments/assets/cd74507c-5afc-4a17-ad68-774e2be762f0)
![image](https://github.com/user-attachments/assets/71ce28eb-c8de-4ac0-9c6d-3cae52219483)
Automate Deprovisioning:
o Use Remove-ADUser to remove user accounts:
Remove-ADUser -Identity "jdoe"

5. Join Windows 10 Client to Domain via PowerShell
• Prerequisite: Ensure that the client VM has DNS settings pointing to your Domain Controller's IP (e.g., 192.168.18.73)
![image](https://github.com/user-attachments/assets/c52d7a2f-93b0-437b-b6fb-bd85fd14b2bf)

• Run this PowerShell command on the Windows 10 client:
Add-Computer -DomainName "mylab.local" -Credential mylab\Administrator -Restart
• Replace "Administrator" with the domain admin account, and the client will restart to apply the domain join.
![image](https://github.com/user-attachments/assets/f38d00d1-e42a-4a37-9090-5b3490c1e426)
Install Remote Server Administration Tools (RSAT) on Windows 10 Client PC
![image](https://github.com/user-attachments/assets/2f35c7b7-da54-4f85-8157-1d7ad75cfa13)
List all RSAT features and the installed state using PowerShell
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State
![image](https://github.com/user-attachments/assets/2140ea26-6bb0-4e5f-814d-86f6aa1952e7)

![image](https://github.com/user-attachments/assets/8cb609b8-3c2a-45ca-bfaf-a0de36c5fb42)

6. Install and Configure Azure AD Connect
Lab Setup Requirements
1.	Windows Server 2022 configured as a Domain Controller (DC).
![image](https://github.com/user-attachments/assets/cd70745f-57eb-42cd-8409-31861f332d9c)

2.	Active Directory domain (e.g., contoso.com).
![image](https://github.com/user-attachments/assets/c546aa46-70be-4fbe-b2e1-bbe742ab812c)

3.	Azure AD tenant (with a Global Administrator account).
![image](https://github.com/user-attachments/assets/ea45db2a-d77b-423e-bfa8-ba567729ce2b)
4.	Internet connectivity.
![image](https://github.com/user-attachments/assets/982c222c-30a4-4208-a6d3-614ca201b97c)
5.	Administrative credentials for both on-premises AD and Azure AD.
Step 1: Download Azure AD Connect
1.	Open a web browser on the Domain Controller.
2.	Navigate to the Azure AD Connect download page.
![image](https://github.com/user-attachments/assets/291801a6-fb62-4559-bb04-7f5a7e2d868f)
3.	Click Download and save the installer (AzureADConnect.msi) to your server.
![image](https://github.com/user-attachments/assets/d58cfdcc-82ee-4e60-8e04-22e58294392c)
Step 2: Prepare Your Environment
Before proceeding with installation, ensure the following:
1.	Verify system requirements:
o	Windows Server 2022.
o	.NET Framework 4.7.2 or higher (already included in Server 2022).
2.	Create or validate the Azure AD tenant:
o	Log in to the Azure portal using your Global Administrator account.
o	Confirm your Azure AD tenant is active and ready for synchronization.
3.	DNS and UPN Suffix:
o	Ensure the Active Directory UPN suffix (e.g., @contoso.com) matches a routable domain used in Azure AD.
Step 3: Install Azure AD Connect
1.	Run the Azure AD Connect Installer:
o	Double-click the AzureADConnect.msi file to begin the installation.
o	Accept the license agreement and click Continue.
![image](https://github.com/user-attachments/assets/2b19048f-2e77-41f5-8b34-bd5391be5107)
2.	Select Installation Type:
![image](https://github.com/user-attachments/assets/c671c830-13d0-4030-83b6-bdef27ab3ee7)
o	Choose Express Settings for a basic configuration.
![image](https://github.com/user-attachments/assets/0fb56bde-fe7b-40ed-8aaa-ae48db64b4a0)
o	Click Install to proceed
![image](https://github.com/user-attachments/assets/af1fd4b8-781d-4db3-a193-d6003929a777)
To enable TLS 1.2 on a Windows Server, follow these steps
![image](https://github.com/user-attachments/assets/0208c81d-0860-4ca8-a509-80b7d4368c20)
Step 4: Configure Azure AD Connect
1.	After installation, the configuration wizard launches automatically.
2.	Connect to Azure AD:
o	Enter your Azure AD Global Admin credentials to authenticate
![image](https://github.com/user-attachments/assets/21b7d1e6-e65b-49b1-8f10-cb040f05662c)
o	Click Next to proceed.
3.	Connect to On-Premises AD:
o	Enter your on-premises AD Domain Admin credentials
![image](https://github.com/user-attachments/assets/12fc8bdc-de6e-4ae5-b23e-f796849a2577)
o	Azure AD Connect will detect your domain automatically. Confirm it is listed correctly.
4.	Verify UPN Suffix:
![image](https://github.com/user-attachments/assets/04c225a3-a8c7-46d7-aab3-983ff73439cb)
o	Ensure the UPN suffix for your domain is routable (e.g., contoso.com) rather than non-routable (e.g., contoso.local).
6.	Click Install and Configure to complete the setup.
![image](https://github.com/user-attachments/assets/d14109a0-f74b-4c7b-9b23-0ea79cc2a8ef)
![image](https://github.com/user-attachments/assets/deb2bc21-ac36-4332-af06-635fa9bb76a0)
Step 5: Verify Synchronization
1.	Open the Azure AD portal:
![image](https://github.com/user-attachments/assets/82ea11c6-b5bb-40e7-9dd6-0a2239526224)
o	Navigate to Azure Active Directory > Users.
o	Check if your on-prem AD users are listed in the Azure AD user list.
3.	Force a Manual Synchronization:
o	Open PowerShell as Administrator and run
Start-ADSyncSyncCycle -PolicyType Delta
![image](https://github.com/user-attachments/assets/e63f2e7c-eeaf-4579-ab93-ab4017a59fec)
Verify Sync Results:
•	After running the sync, check the Azure AD portal to ensure newly added or modified on-prem AD users appear in Azure AD.


Step 6: Post-Configuration Validation
1.	Password Synchronization:
o	Change a user’s password in on-prem AD.
o	Test logging into Azure AD using the updated password.
2.	Monitor Synchronization Health:
o	Install Azure AD Connect Health from the Azure portal to monitor sync health and troubleshoot issues.

This hands-on lab ensures your on-premises Active Directory integrates seamlessly with Azure AD using Azure AD Connect.

7. Implement Group Policy to Harden Desktops

• Open the Group Policy Management Console (GPMC) on your Domain Controller.
![image](https://github.com/user-attachments/assets/5028a5ed-8322-42b0-9594-bfa2acaf3b5e)
• Create a New GPO:
o Right-click your domain > Create a GPO in this domain, and link it here.
o Name it something like Desktop Hardening.
• Edit GPO Settings:
o To disable USB storage: Computer Configuration > Policies > Administrative Templates
> System > Removable Storage Access.
▪ Deny write and read access to removable storage.
![image](https://github.com/user-attachments/assets/355381be-4e63-45a5-a478-18baa6731630)
o Enable Windows Defender and configure firewall rules:
![image](https://github.com/user-attachments/assets/e17d4c18-96a4-48e5-92cc-5a08dc24070d)
Computer Configuration > Policies > Administrative Templates > Windows
Components > Microsoft Defender Antivirus.
![image](https://github.com/user-attachments/assets/63853944-9e9b-4517-b74c-22b8bee1bdd7)

o Link the GPO to your Desktops OU and ensure the policy applies to client machines.
![image](https://github.com/user-attachments/assets/64598e12-4ee4-48eb-afa6-876599448fc1)

8. Set Up Remote Access Server (RAS) for NAT/PAT

• In Server Manager, go to Add Roles and Features > select Remote Access and Routing and Remote Access
![image](https://github.com/user-attachments/assets/7d860404-ca2a-4568-8d61-f49729c2f8d7)
• Configure Routing and Remote Access:
![image](https://github.com/user-attachments/assets/856a3f47-bb75-47a1-a843-ce3d0e860a5f)
Open Routing and Remote Access > right-click the server > Configure and Enable
Routing and Remote Access.
o Select Network Address Translation (NAT) and specify your internal network.
![image](https://github.com/user-attachments/assets/fac616c2-8a87-4fc7-ad04-1c3cceb61a08)
![image](https://github.com/user-attachments/assets/8d49a9f7-9fe1-481d-85b0-13d0c12b68ec)
• Setup NPS network policy:
![image](https://github.com/user-attachments/assets/9a256d4b-4b4b-4217-b23d-9b8e7e47e65b)
![image](https://github.com/user-attachments/assets/6783a7aa-058b-404b-8059-f6128830cc39)

Configure port forwarding on my ROUTER to map external requests to internal IP addresses (e.g., RDP to virtual machine).
![image](https://github.com/user-attachments/assets/22fa4d8b-93c9-48ec-bd05-53fcca1cb5c2)
9. Implement DNS and DHCP Servers

• DNS Configuration:
o In Server Manager, install the DNS Server role.
o Open DNS Manager and create a Forward Lookup Zone (e.g., yourdomain.local).
o Create Host (A) records for your server and clients.
![image](https://github.com/user-attachments/assets/d5aa3fbf-62c9-4e6a-8bbe-bf09e4f37087)
• DHCP Configuration:
o Install the DHCP Server role.
![image](https://github.com/user-attachments/assets/ad198657-f722-470c-a27d-f06682f2ced6)
o Configure DHCP Scopes:
▪ Define a range of IPs to assign to clients (e.g., 192.168.18.100 to 192.168.18.200).
▪ Configure Scope Options like DNS and Default Gateway.
![image](https://github.com/user-attachments/assets/eda678af-3fae-4c1b-91ee-9060ebaa3f11)


10. Configure Windows File Server with Quotas and NTFS Permissions

• Install File Server Role:
o In Server Manager, add the File and Storage Services role.


• Create Shared Folders:
o Create folders (e.g., DepartmentShares) and set NTFS permissions (e.g., restrict HR
folder to HR users).


• Configure Quotas:
o Use File Server Resource Manager (FSRM).
o Go to Quota Management > Create Quota and define storage limits for specific
directories.



• Test NTFS Permissions and Quotas:
o Log in with different user accounts to verify access permissions and storage quotas.



