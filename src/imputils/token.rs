
use std::{io::Error, mem::size_of};
use std::ffi::{c_void, c_ulong};
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, FALSE};
use windows_sys::Win32::System::Memory::LocalAlloc;
use std::ptr::null_mut;
use obfstr::obfstr;
use windows_sys::{
    Win32::{
        Foundation::{HANDLE, CloseHandle}, 
        Security::{
            SecurityImpersonation,
            TokenPrimary,
            GetTokenInformation,
            TokenUser,
            TokenStatistics,
            TOKEN_USER,
            TOKEN_QUERY,
            LookupAccountSidW,
            SID_NAME_USE,
            TokenSessionId,
            TOKEN_STATISTICS,
            TokenImpersonation,
            TokenIntegrityLevel,
            GetSidSubAuthority,
            TOKEN_MANDATORY_LABEL,
            GetSidSubAuthorityCount,
            TokenImpersonationLevel,
            SECURITY_IMPERSONATION_LEVEL,
            SecurityDelegation,
            SecurityAnonymous,
            SecurityIdentification,
            TOKEN_TYPE}
        },
    core::PWSTR};
use windows_sys::Win32::System::{
    Threading::PROCESS_QUERY_INFORMATION,
    SystemServices::{SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_SYSTEM_RID, SECURITY_MANDATORY_UNTRUSTED_RID, SECURITY_MANDATORY_PROTECTED_PROCESS_RID},
    Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken};

use crate::imputils::impersonate::{ImpersonationLevel,IntegrityLevel};
use crate::imputils::common::*;

use crate::TOK;

// Structure for one Windows Token
pub struct Token {
    pub handle: HANDLE,
    pub process_id: u32,
    pub process_name: String,
    pub session_id: u32,
    pub username: String,
    pub token_type: TOKEN_TYPE,
    pub token_impersonation: ImpersonationLevel,
    pub token_integrity: IntegrityLevel,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tokendisplay = "";
        if vec!["High","System"].contains(&self.token_integrity.display_str()) {
            tokendisplay = self.token_integrity.display_str();
        } else {
            tokendisplay = self.token_integrity.display_str();
        }
        if self.token_type == TokenPrimary {
            write!(
                f,
                "[{: <32}] [PROCESS: {: <5}] [SESSION: {: <2}] [TYPE: Primary] [{: <9}] [USER: {: <28}]",
                self.process_name,
                self.process_id.to_string(),
                self.session_id.to_string(),
                tokendisplay,
                self.username
            )
        } else {
            write!(
                f,
                "[{: <32}] [PROCESS: {: <5}] [SESSION: {: <2}] [TYPE: Impersonation] [{: <9}] [USER: {: <28}]",
                self.process_name,
                self.process_id.to_string(),
                self.session_id.to_string(),
                self.token_impersonation.display_str(),
                self.username
            )
        }
    }
}


/// Function to get all informations about Token
#[allow(non_upper_case_globals)]
pub fn get_token_information(token: *mut Token) -> Result<bool,String>{
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenStatistics,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenStatistics,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };
        let token_stat_info: TOKEN_STATISTICS = std::ptr::read(buffer as *const TOKEN_STATISTICS);
        (*token).token_type = token_stat_info.TokenType;
        if (*token).token_type == TokenPrimary {
            let mut primary_size: u32 = 0;
            GetTokenInformation((*token).handle, TokenIntegrityLevel,null_mut() , primary_size , &mut primary_size);
            let buffer = LocalAlloc(0, size as usize);
            if GetTokenInformation((*token).handle, TokenIntegrityLevel,buffer as *mut c_void, size, &mut size) == 0 {
                return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
            };
            let token_mandatory_label: TOKEN_MANDATORY_LABEL = std::ptr::read(buffer as *const TOKEN_MANDATORY_LABEL);
            let integrity_level = *GetSidSubAuthority(token_mandatory_label.Label.Sid, (*GetSidSubAuthorityCount(token_mandatory_label.Label.Sid)) as u32 -1) as i32;
            (*token).token_integrity = match integrity_level {
                SECURITY_MANDATORY_UNTRUSTED_RID => IntegrityLevel::Untrusted,
                SECURITY_MANDATORY_LOW_RID => IntegrityLevel::Low,
                SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel::Medium,
                FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID => IntegrityLevel::MediumPlus,
                SECURITY_MANDATORY_HIGH_RID => IntegrityLevel::High,
                SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel::System,
                SECURITY_MANDATORY_PROTECTED_PROCESS_RID => IntegrityLevel::ProtectedProcess,
                _ => IntegrityLevel::Untrusted,
            };
        } else if (*token).token_type == TokenImpersonation {
            let mut impersonate_size: u32 = 0;
            GetTokenInformation((*token).handle, TokenImpersonationLevel,null_mut() , impersonate_size , &mut impersonate_size);
            let buffer = LocalAlloc(0, size as usize);
            if GetTokenInformation((*token).handle, TokenImpersonationLevel,buffer as *mut c_void, size, &mut size) == 0 {
                return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
            };
            let security_impersonation_level: SECURITY_IMPERSONATION_LEVEL = std::ptr::read(buffer as *const SECURITY_IMPERSONATION_LEVEL);
            (*token).token_impersonation = match security_impersonation_level {
                SecurityImpersonation => ImpersonationLevel::Impersonation,
                SecurityAnonymous => ImpersonationLevel::Anonymous,
                SecurityDelegation => ImpersonationLevel::Delegation,
                SecurityIdentification => ImpersonationLevel::Identification,
                _ => ImpersonationLevel::Anonymous,
            };
        }   
    }
    Ok(true)
}

/// Function to get user information about one Token
pub fn get_token_user_info(token: *mut Token) -> Result<bool, String>{
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenUser,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenUser,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };

        let token_user_info: TOKEN_USER = std::ptr::read(buffer as *const TOKEN_USER);
        let mut name_buffer = Vec::<u16>::with_capacity(256);
        let name: PWSTR = name_buffer.as_mut_ptr();
        let mut cchname: u32 = 256;

        let mut refdomain_buffer = Vec::<u16>::with_capacity(256);
        let referenceddomainname: PWSTR = refdomain_buffer.as_mut_ptr();
        let mut cchreferenceddomainname: u32 = 256;

        let mut sid = SID_NAME_USE::default();
        if LookupAccountSidW(null_mut(), token_user_info.User.Sid, name, &mut cchname, referenceddomainname, &mut cchreferenceddomainname, &mut sid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupAccountSidW"), Error::last_os_error()).to_owned());
        }
        let username = pwstr_to_string(name);
        let domain = pwstr_to_string(referenceddomainname);
        (*token).username = domain + "\\" + &username;
        return Ok(true);
    }
}

/// Function to get session id from one Token
pub fn get_token_session_id(token: *mut Token) -> Result<bool, String> {
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenSessionId,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenSessionId,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };
        let session_id = std::ptr::read(buffer as *const c_ulong);
        (*token).session_id = session_id as u32;
        return Ok(true);
    }
}

/// Function tu enumerate all Tokens
pub fn enum_token() -> Result<String, String>{
    unsafe {
        let hsnapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut lppe: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>();
        lppe.dwSize = size_of::<PROCESSENTRY32> as u32;

        if Process32First(hsnapshot, &mut lppe) != 0 {
            loop {
                if Process32Next(hsnapshot, &mut lppe) == 0 {
                    // No more process in list
                    // return Ok(true);
                    return Ok(String::from("true"));
                };

                // Check if process is in blacklist
                // let blacklist = vec!["lsass.exe","winlogon.exe","svchost.exe"];
                // if blacklist.iter().any(|&i| i == array_to_string(lppe.szExeFile)){
                //     // println!("Process in blacklist, continue...");
                //     continue
                // }
                let process_name = array_to_string(lppe.szExeFile);

                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lppe.th32ProcessID);
                if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
                    CloseHandle(process_handle);
                    continue;
                }

                let mut token_handle: HANDLE = std::mem::zeroed();
                if OpenProcessToken(process_handle as HANDLE,  TOKEN_QUERY, &mut token_handle) == 0 {
                    CloseHandle(process_handle);
                    CloseHandle(token_handle);
                    continue;
                };
                let mut token = Token {
                    handle: token_handle,
                    username: "".to_owned(),
                    process_id: lppe.th32ProcessID,
                    process_name: process_name.to_owned(),
                    session_id: 0,
                    token_impersonation: ImpersonationLevel::Anonymous,
                    token_integrity: IntegrityLevel::Untrusted,
                    token_type: 0,
                };

                if let Ok(_) = get_token_user_info(&mut token){
                    if let Ok(_) = get_token_session_id(&mut token){
                        if let Ok(_) = get_token_information(&mut token){
                            TOK.push(format!("{}", token));
                            //println!("{token}")
                        }
                    } else {
                        CloseHandle(process_handle);
                        CloseHandle(token_handle);
                    // Handle error
                    }
                } else {
                    CloseHandle(process_handle);
                    CloseHandle(token_handle);
                    // Handle error
                }
                CloseHandle(process_handle);
                CloseHandle(token_handle);
            }
        } else {
            return Err("Error when calling Process32Next".to_owned());
        }
    }
}