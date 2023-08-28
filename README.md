# ACD2023WinIR

Code for the Active Cyber Defense class' Windows Incident Response lab.
Simulates an insider threat adversary gaining complete control of a server and installing persistence.
The code is divided into six portions:

## 1. Prep
Performs actions to ensure the student's vm has necessary users and file for the lab.

## 2. Dropper
Simulates the adversary's initial actions:
- locate the password document
- use those passwords with the admin account to find valid credentials
- run malware with the admin's credentials

## 3. Privesc
Uses token impersonation of a system process to obtain SYSTEM access.

## 4. Loader
- Disables Windows Defender through the registry
- Installs `Persistence` as a service

## 5. Persistence
- Spawns the listener and ensures that it is running
- Injecs a second listener into a process and reinjects the listener if the initial host dies
- Spawns a third listener and hides it from task manager with API hooking

## 6. Listener
Opens a socket on a port and listens. No actual functionality

## Logging
Logs are created to ensure that the code is functioning properly. Logs are XOR'd to protect lab integrity (having logs would make the lab significantly easier)