use std::slice;
use windows_sys::{Win32::System::{ SystemServices::{SECURITY_MANDATORY_MEDIUM_PLUS_RID}}, core::PWSTR};

pub const FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID: i32 = SECURITY_MANDATORY_MEDIUM_PLUS_RID as i32;

pub fn pwstr_to_string(buffer: PWSTR) -> String{
    let transate  = unsafe {slice::from_raw_parts(buffer, 256)};
    return array_to_string_utf16( transate);
}

pub fn array_to_string_utf16(buffer: &[u16]) -> String {
    let mut string: Vec<u16> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf16(&string).unwrap()
}

pub fn array_to_string(buffer: [u8; 260]) -> String {
    let mut string: Vec<u8> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf8(string).unwrap()
}