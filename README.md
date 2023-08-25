# ACD2023WinIR

1. prep performs preparations so that the student's vm has necessary users and file for the lab
2. dropper is the first part of the attack, where the threat actor locates plaintext passwords,
   attempts to use them to log into the admin account, and when successful, spawns the privesc as the admin
3. privesc performs token impersonation on a process running as SYSTEM, then spawns the loader as SYSTEM
4. loader disables defender, creates a service that runs persistence, and starts it
5. persistence injects the listener into a process, and if that host process dies, repeats the injection
6. the listener opens a socket on a port and listens for incoming connections
