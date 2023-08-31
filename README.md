# ACD2023WinIR

Code for the Active Cyber Defense class' Windows Incident Response lab.
Simulates an insider threat adversary gaining complete control of a Windows server and installing persistence.

## Executable Components
The code is divided into six executable components.
Uses a nesting doll embedding approach so that the student only needs to run one executable ‼️ **(TODO)**.
The executable components are listed here in order of execution during the scenario:

### 1. Prep
Performs actions to ensure the student's vm has necessary users and file for the lab. Required to be run as an administrator
- Add new administrator user
- Add multiple regular users
- Create administrator password text document
- Spawns the `dropper` with the threat actor user's credentials

### 2. Dropper
Simulates the adversary's initial actions to obtain admin access:
- Locate the password document with a powershell command ‼️ **(TODO)**
- Attempt to login to the administrator user's account using the passwords found to find valid credentials
- Run the `privesc` with the admin's credentials

### 3. Privesc
Uses token impersonation of a system process to obtain SYSTEM access, and then run the `loader` with that access.
- Processes which we are able to obtain a SYSTEM token:
  -  wininit.exe, smss.exe, services.exe, winlogon.exe, unsecapp.exe, csrss.exe, dllhost.exe, lsass.exe

### 4. Loader
Sink our teeth into the victim machine. Remove defenses and establish persistence
- Disables Windows Defender through the registry
- Disables Windows Firewall through the registry ‼️ **(TODO)**
- Create the working directory for the malware `C:\Windows\System32\Persistence\` ‼️ **(TODO)**
- Drop `persistence` and `listener` components in the working directory ‼️ **(TODO)**
- Create the malware config file ‼️ **(TODO)**
- Hook `TerminateProcess`, `ExitProcess` and `ExitThread` to ensure that the `persistence` and `listener` stay active ‼️ **(TODO)**
- Installs `persistence` as a service and configure the service
- Run the persistence service ‼️ **(TODO)**

### 5. Persistence
Emulate a backdoor listener
- Spawns the listener and ensures that it is running (exe) ‼️ **(TODO)**
- Injecs a second listener into a process and reinjects the listener if the initial host dies (dll) ‼️ **(TODO)**

### 6. Listener
Opens a socket on a port and listens. No actual functionality ‼️ **(TODO)**
- considering having this component spawn netcat instead of just listening on a socket
- prevent closing with API hooking on Terminate process and EndProcess

## Non-Executable Components

### Logging
Logs are created to ensure that the code functioned properly. Logs are base64 encoded XOR'd to protect lab integrity (having logs would make the lab significantly easier)

### Admin password document
List a few passwords that the administrator uses for other services, with one password that is reused for the administrator account

### Config file ‼️ **(TODO)**
Encoded with base 64. Give the students some hints to malware functionality. Not actually used by the malware.

## TODO:
1. implement embedding executable files
1. pop message box when execution is complete
1. add powershell command from dropper to scan for password documents
1. disable windows firewall through registry from loader
1. create working directory
1. drop persistence asnd listener to working directory
1. create config file
1. hook TerminateProcess, ExitProcess
1. run persistence service
1. spawn listener from persistence
1. inject a listener into a process and monitor host
1. listener open socket
1. (stretch) investigate having listener run netcat, potentially self inject