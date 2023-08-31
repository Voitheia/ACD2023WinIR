#include "prep.hpp"

int wmain()
{
    std::filesystem::create_directory(L"C:\\Temp");
    std::filesystem::permissions(L"C:\\Temp", std::filesystem::perms::all);
    
    prep::CreateUser(L"NineBall", L"SuperSecurePassword1!");
    prep::CreateUser(L"Raven", L"Password1!");
    prep::CreateUser(L"Rusty", L"Password2@");
    prep::CreateUser(L"Snail", L"Password3#");
    prep::CreateUser(L"Hawkins", L"Password4$");
    prep::CreateUser(L"Maeterlinck", L"Password5%");
    prep::CreateUser(L"Swinburne", L"Password6^");
    prep::CreateUser(L"Pater", L"Password7&");

    // create password doc
    if (!CreateDirectoryW(L"C:\\Users\\NineBall", NULL)) {
        logger::Log("[!] Failed to create NineBall user directory.");
    }
    if (!CreateDirectoryW(L"C:\\Users\\NineBall\\Desktop", NULL)) {
        logger::Log("[!] Failed to create NineBall desktop directory");
    }
    std::ofstream fs("C:\\Users\\NineBall\\Desktop\\notmypasswords.txt");
    if (!fs) {
        logger::Log("[!] Failed to create NineBall password document.");
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

    // create dropper process as user Raven
    HANDLE hToken;
    if (!LogonUserW(
        L"Raven",
        L".",
        L"Password1!",
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    )) {
        logger::Log("[!] Failed to logon as user.");
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessAsUserW(
        hToken,
        L"dropper.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        logger::Log("[!] Failed to create dropper process.");
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // TODO: pop message box saying completed

    return 0;
}

namespace prep {

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
        logger::Log("[+] User " + std::string(username.begin(), username.end()) + " successfully created.");
        break;
    case NERR_UserExists:
        logger::Log("[!] User " + std::string(username.begin(), username.end()) + " already exists.");
        err = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        logger::Log("[!] Invalid parameter error adding user " + std::string(username.begin(), username.end()) + "; parameter index = " + std::to_string(param_err));
        break;
    default:
        logger::Log("[!] Error adding user " + std::string(username.begin(), username.end()) + " : " + std::to_string(err));
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
        logger::Log("[+] User " + std::string(username.begin(), username.end()) + " successfully added to local group.");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        logger::Log("[!] User " + std::string(username.begin(), username.end()) + " already in local group.");
        err = 0;
        break;
    default:
        logger::Log("[!] Error adding user " + std::string(username.begin(), username.end()) + " to local group: " + std::to_string(err));
        break;
    }
}
}