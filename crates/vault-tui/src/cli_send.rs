//! `send` (create / list / delete / link) and `receive` CLI commands.
//!
//! Creation and listing run through the shared [`crate::cli::Backend`] (so they work with the
//! unlock daemon); `receive` is a public, unauthenticated flow built on
//! [`vault_session::receive_send`].

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use vault_session::{
    format_file_size, is_send_password_error, receive_send, save_received_file, SEND_TYPE_FILE,
};

use crate::cli::{call, read_arg_or_stdin, CliCtx};

#[derive(Default)]
pub struct SendCreateOpts {
    /// Text to send (`-` or absent with no `--file` reads stdin).
    pub text: Option<String>,
    pub file: Option<PathBuf>,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub password: Option<String>,
    pub max_access: Option<u32>,
    /// Absolute date or relative offset (`30m`, `12h`, `7d`, `2w`).
    pub expires: Option<String>,
    pub delete_in: Option<String>,
    pub hide_email: bool,
    pub hidden: bool,
}

pub async fn cmd_send_create(ctx: &CliCtx, opts: SendCreateOpts) -> Result<()> {
    if opts.text.is_some() && opts.file.is_some() {
        bail!("pass either text or --file, not both");
    }
    let mut params = json!({
        "hideEmail": opts.hide_email,
        "hidden": opts.hidden,
    });
    if let Some(file) = &opts.file {
        params["file"] = file.display().to_string().into();
    } else {
        let text = read_arg_or_stdin(opts.text.as_deref())?;
        let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
        if text.is_empty() {
            bail!("send text is empty");
        }
        params["text"] = text.into();
    }
    for (k, v) in [
        ("name", opts.name.clone()),
        ("notes", opts.notes.clone()),
        ("password", opts.password.clone()),
        ("expires", opts.expires.clone()),
        ("deleteIn", opts.delete_in.clone()),
        ("maxAccess", opts.max_access.map(|n| n.to_string())),
    ] {
        if let Some(v) = v {
            params[k] = v.into();
        }
    }
    let v = call(ctx, "send.create", params).await?;
    if ctx.json {
        println!("{v}");
    } else {
        match v["url"].as_str() {
            Some(url) => println!("{url}"),
            None => println!("{}", v["id"].as_str().unwrap_or("")),
        }
    }
    Ok(())
}

pub async fn cmd_send_list(ctx: &CliCtx) -> Result<()> {
    let v = call(ctx, "send.list", Value::Null).await?;
    let rows = v.as_array().cloned().unwrap_or_default();
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    for s in &rows {
        let kind = if s["type"].as_u64() == Some(u64::from(SEND_TYPE_FILE)) {
            "File"
        } else {
            "Text"
        };
        println!(
            "{}\t{}\t{}\t{}",
            s["id"].as_str().unwrap_or(""),
            kind,
            s["name"].as_str().unwrap_or("").replace('\t', " "),
            s["deletionDate"].as_str().unwrap_or("-"),
        );
    }
    Ok(())
}

pub async fn cmd_send_delete(ctx: &CliCtx, query: &str) -> Result<()> {
    let v = call(ctx, "send.delete", json!({ "query": query })).await?;
    println!("deleted\t{}", v["deleted"].as_str().unwrap_or(query));
    Ok(())
}

pub async fn cmd_send_link(ctx: &CliCtx, query: &str) -> Result<()> {
    let v = call(ctx, "send.link", json!({ "query": query })).await?;
    println!("{}", v["url"].as_str().unwrap_or(""));
    Ok(())
}

/// `receive <url>`: fetch a Send. Text is printed (or JSON with `--json`); file Sends are
/// saved to `output` (a path or directory, default: current directory).
pub async fn cmd_receive(
    json_out: bool,
    url: &str,
    password: Option<&str>,
    output: Option<PathBuf>,
) -> Result<()> {
    let password = match password {
        Some(p) => Some(p.to_string()),
        None => std::env::var("BW_SEND_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty()),
    };
    let received = match receive_send(url, password.as_deref()).await {
        Ok(r) => r,
        Err(e) if is_send_password_error(&e) => {
            if password.is_some() {
                bail!("incorrect Send password");
            }
            bail!("this Send is password protected — pass --password (or BW_SEND_PASSWORD)");
        }
        Err(e) => return Err(e.into()),
    };

    if received.is_file() {
        let dest = output.unwrap_or_else(|| PathBuf::from("."));
        let saved = save_received_file(&received, &dest).await?;
        let size = received
            .file
            .as_ref()
            .and_then(|f| f.size)
            .map(format_file_size);
        if json_out {
            println!(
                "{}",
                json!({
                    "name": received.name,
                    "type": "file",
                    "path": saved.display().to_string(),
                    "size": size,
                })
            );
        } else {
            eprintln!("saved\t{}", saved.display());
        }
        return Ok(());
    }

    let text = received.text.clone().unwrap_or_default();
    if let Some(out) = output {
        std::fs::write(&out, &text)?;
        if !json_out {
            eprintln!("saved\t{}", out.display());
            return Ok(());
        }
    }
    if json_out {
        println!(
            "{}",
            json!({
                "name": received.name,
                "type": "text",
                "text": text,
                "hidden": received.text_hidden,
                "expirationDate": received.expiration_date,
            })
        );
    } else {
        println!("{text}");
    }
    Ok(())
}
