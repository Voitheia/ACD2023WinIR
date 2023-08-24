#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>

#pragma comment(lib, "netapi32.lib")

int wmain()
{
    LPWSTR adminName = L"NineBall";
    LPWSTR adminPass = L"SuperSecurePassword1!";
    LPWSTR userName = L"Raven";
    LPWSTR userPass = L"Password1!";
    
    NET_API_STATUS err = 0;
    DWORD parm_err = 0;
    
    // create administrator user
    USER_INFO_1 user_info_admin;

    user_info_admin.usri1_name = adminName;
    user_info_admin.usri1_password = adminPass;
    user_info_admin.usri1_priv = USER_PRIV_USER;
    user_info_admin.usri1_home_dir = TEXT("");
    user_info_admin.usri1_comment = TEXT("Administrator");
    user_info_admin.usri1_flags = UF_SCRIPT;
    user_info_admin.usri1_script_path = TEXT("");

    err = NetUserAdd(NULL, // PDC name 
        1, // level 
        (LPBYTE)&user_info_admin, // input buffer 
        &parm_err); // parameter in error 

    switch (err)
    {
    case 0:
        printf("User successfully created.\n");
        break;
    case NERR_UserExists:
        printf("User already exists.\n");
        err = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("Invalid parameter error adding user; parameter index = %d\n",
            parm_err);
        return(err);
    default:
        printf("Error adding user: %d\n", err);
        return(err);
    }
    
    // add user to Administrators
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members_admin;
    localgroup_members_admin.lgrmi3_domainandname = adminName;

    err = NetLocalGroupAddMembers(
        NULL,
        L"Administrators",
        3,
        (LPBYTE)&localgroup_members_admin,
        1);

    switch (err)
    {
    case 0:
        printf("User successfully added to local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("User already in local group.\n");
        err = 0;
        break;
    default:
        printf("Error adding user to local group: %d\n", err);
        break;
    }

    // create regular user
    USER_INFO_1 user_info_user;

    user_info_user.usri1_name = userName;
    user_info_user.usri1_password = userPass;
    user_info_user.usri1_priv = USER_PRIV_USER;
    user_info_user.usri1_home_dir = TEXT("");
    user_info_user.usri1_comment = TEXT("User");
    user_info_user.usri1_flags = UF_SCRIPT;
    user_info_user.usri1_script_path = TEXT("");

    err = NetUserAdd(NULL, // PDC name 
        1, // level 
        (LPBYTE)&user_info_user, // input buffer 
        &parm_err); // parameter in error 

    switch (err)
    {
    case 0:
        printf("User successfully created.\n");
        break;
    case NERR_UserExists:
        printf("User already exists.\n");
        err = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("Invalid parameter error adding user; parameter index = %d\n",
            parm_err);
        return(err);
    default:
        printf("Error adding user: %d\n", err);
        return(err);
    }

    // add user to users
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members_user;
    localgroup_members_user.lgrmi3_domainandname = userName;

    err = NetLocalGroupAddMembers(
        NULL,
        L"Users",
        3,
        (LPBYTE)&localgroup_members_user,
        1);

    switch (err)
    {
    case 0:
        printf("User successfully added to local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("User already in local group.\n");
        err = 0;
        break;
    default:
        printf("Error adding user to local group: %d\n", err);
        break;
    }

    // create password doc
    if (!CreateDirectoryW(L"C:\\Users\\NineBall", NULL)) {
        printf("couldn't create first dir");
    }
    if (!CreateDirectoryW(L"C:\\Users\\NineBall\\Desktop", NULL)) {
        printf("couldn't create second dir");
    }
    std::ofstream fs("C:\\Users\\NineBall\\Desktop\\notmypasswords.txt");
    if (!fs) {
        printf("couldn't create file");
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
}

