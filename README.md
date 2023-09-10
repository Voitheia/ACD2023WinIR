# ACD2023WinIR

Code for the Active Cyber Defense class' Windows Incident Response lab.
Simulates an insider threat adversary gaining complete control of a Windows server and installing persistence.

## Executable Components
The code is divided into seven executable components.
Uses a nesting doll embedding approach so that the student only needs to run one executable.
The executable components are listed here in order of execution during the scenario:

### 1. Prep
Performs actions to ensure the student's vm has necessary users and file for the lab. Required to be run as an administrator
- Create `C:\Temp` folder
- Add new administrator user
- Add multiple regular users
- Create administrator password text document
- Spawns the `dropper` with the threat actor user's credentials

### 2. Dropper
Simulates the adversary's recon and compromising of the admin account:
- Locate the password document with a powershell command
- Attempt to login to the administrator user's account using the passwords found to find valid credentials
- Run the `elevate` with the admin's credentials

### 3. Elevate
Spawn `privesc` in a high integrity context using [fodhelper UAC bypass](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-4---bypass-uac-using-fodhelper---powershell)

### 4. Privesc
Uses token impersonation of a system process to obtain SYSTEM access, and then run the `loader` with that access.
- Processes which we are able to obtain a SYSTEM token from:
  -  wininit.exe, smss.exe, services.exe, winlogon.exe, unsecapp.exe, csrss.exe, dllhost.exe, lsass.exe

### 5. Loader
Sink our teeth into the victim machine. Remove defenses and establish persistence
- Disables Windows Defender through the registry
- Disables Windows Firewall through the registry
- Create the working directory for the malware `C:\Windows\System32\Persistence\`
- Drop `persistence` and `listener` components in the working directory
- Create the malware config file
- Hook `TerminateProcess`, `ExitProcess` and `ExitThread` to ensure that the `persistence` and `listener` stay active
- Installs `persistence` as a service and configure the service
- Run the persistence service

### 6. Persistence
Ensure listener stays open, start on boot
- Spawns the listener and ensures that it is running (exe)
- Injecs a second listener into a process and reinjects the listener if the initial host dies (dll)

### 7. Listener
Opens a socket on a port and listens. No actual functionality
- considering having this component spawn netcat instead of just listening on a socket
- prevent closing with API hooking on Terminate process and EndProcess

## Non-Executable Components

### Logging
Logs are created to ensure that the code functioned properly. Logs are base64 encoded XOR'd to protect lab integrity (having logs would make the lab significantly easier)

### Admin password document
Lists a few passwords that the administrator uses for other services, with one password that is reused for the administrator account

### Config file
Encoded with base 64. Give the students some hints to malware functionality. Not actually used by the malware.

### `Build-Header.ps1`
Read an executable file's bytes and place them into an array of bytes in a header file.

### Remote Debugging
1. Enter Solution Explorer in VS
1. Go to CMake Targets View
1. Open the project dropdown
1. Right click on `prep` and select "Add debug configuration"
1. Add/modify the following:
```
"configurations": [
    {
      "type": "remoteWindows",
      "remoteMachineName": "<IP ADDRESS>",
      "authenticationType": "windows"
    }
  ]
```

## TODO:
1. pop message box when execution is complete
1. create working directory
1. drop persistence asnd listener to working directory
1. create config file
1. run persistence service
1. spawn listener from persistence
1. inject a listener into a process and monitor host
1. listener open socket
1. get logging to a single file working
1. (stretch) hook TerminateProcess, ExitProcess
1. (stretch) investigate having listener run netcat, potentially self inject
1. (stretch) move to more dlls over exes
1. (stretch) make defender evasion more reliable
1. (stretch) fix GetUserAndContext