use crate::chromium::decryption_core::{aes_gcm_256, crypt_unprotect_data};
use crate::chromium::dumper::DumperError;
use rusqlite::Result;
use serde::*;
#[derive(Debug, Deserialize)]
pub struct LocalState<'a> {
    #[serde(borrow)]
    pub os_crypt: OsCrypt<'a>,
}

#[derive(Debug, Deserialize)]
pub struct OsCrypt<'a> {
    pub encrypted_key: &'a str,
}

#[derive(Debug, Clone)]
pub struct ChromeAccount {
    pub website: String,
    pub username_value: String,
    pub encrypted_pwd: Vec<u8>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DecryptedAccount {
    pub website: String,
    pub username_value: String,
    pub pwd: String,
}


impl DecryptedAccount {
    pub fn from_chrome_acc(
        mut chrome_acc: ChromeAccount,
        master_key: Option<&mut [u8]>,
    ) -> Result<DecryptedAccount, DumperError> {
        match master_key {
            Some(master_key) => {
                let pwd_buf = chrome_acc.encrypted_pwd.as_slice();
                let pwd = aes_gcm_256(master_key, pwd_buf)?;
                Ok(DecryptedAccount {
                    website: chrome_acc.website,
                    username_value: chrome_acc.username_value,
                    pwd,
                })
            }
            None => {
                let pwd_buf = crypt_unprotect_data(chrome_acc.encrypted_pwd.as_mut_slice())?;
                let pwd = String::from_utf8(pwd_buf).map_err(|_| DumperError::FromUtf8Error)?;
                Ok(DecryptedAccount {
                    website: chrome_acc.website,
                    username_value: chrome_acc.username_value,
                    pwd,
                })
            }
        }
    }
}


impl ChromeAccount {
    pub fn new(website: String, username_value: String, password_value: Vec<u8>) -> Self {
        ChromeAccount {
            website,
            username_value,
            encrypted_pwd: password_value,
        }
    }
}

impl From<std::io::Error> for DumperError {
    fn from(_: std::io::Error) -> Self {
        DumperError::IoError
    }
}