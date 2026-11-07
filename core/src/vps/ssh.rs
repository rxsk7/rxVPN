//! SSH к своему серверу: подключение с проверкой ключа сервера (TOFU),
//! выполнение фиксированных команд и заливка файлов по SFTP.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Куда подключаться.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Отпечаток ключа сервера (`SHA256:…`), который человек подтвердил.
    /// None — только чтобы узнать отпечаток (без входа).
    pub host_key: Option<String>,
}

/// Чем входить. Пароль и чужой ключ живут только на время установки.
pub enum Login {
    Password(Zeroizing<String>),
    /// Ключ человека (OpenSSH / PEM / PuTTY) и пароль от него.
    KeyText { key: Zeroizing<String>, passphrase: Option<Zeroizing<String>> },
    /// Свой ключ rxvpn (после установки — только им).
    Key(Arc<PrivateKey>),
}

struct Handler {
    pinned: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

pub fn fingerprint(k: &PublicKeyOrCertificate) -> String {
    let key = match k {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
        PublicKeyOrCertificate::Certificate(c) => c.public_key().clone().into(),
    };
    key.fingerprint(HashAlg::Sha256).to_string()
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = fingerprint(key);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp.clone());
        Ok(match &self.pinned {
            Some(p) => p == &fp,
            // Без отпечатка — только узнать его: дальше Probe отключится без входа.
            None => true,
        })
    }
}

pub struct Ssh {
    h: client::Handle<Handler>,
}

/// Вывод команды.
#[derive(Debug)]
pub struct Out {
    pub code: u32,
    pub out: String,
    pub err: String,
}

const MAX_OUT: usize = 4 << 20;

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(600)),
        keepalive_interval: Some(Duration::from_secs(20)),
        keepalive_max: 6,
        nodelay: true,
        ..Default::default()
    })
}

fn addr(t: &Target) -> String {
    if t.host.contains(':') { format!("[{}]:{}", t.host, t.port) } else { format!("{}:{}", t.host, t.port) }
}

async fn tcp(t: &Target) -> Result<tokio::net::TcpStream, String> {
    let a = addr(t);
    tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect(&a))
        .await
        .map_err(|_| tr!("{a}: сервер не отвечает (15 с) — проверь IP и порт SSH"))?
        .map_err(|e| tr!("{a}: не подключиться — {e}"))
}

/// Узнать отпечаток ключа сервера, не входя.
pub async fn host_fingerprint(host: &str, port: u16) -> Result<String, String> {
    let t = Target { host: host.into(), port, user: "root".into(), host_key: None };
    let seen = Arc::new(Mutex::new(None));
    let h = Handler { pinned: None, seen: seen.clone() };
    let s = tcp(&t).await?;
    let r = tokio::time::timeout(Duration::from_secs(20), client::connect_stream(config(), s, h)).await;
    let fp = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match (r, fp) {
        (Ok(Ok(h)), Some(fp)) => {
            let _ = h.disconnect(russh::Disconnect::ByApplication, "", "").await;
            Ok(fp)
        }
        (_, Some(fp)) => Ok(fp),
        (Ok(Err(e)), None) => Err(tr!("это не SSH или он оборвал связь: {e}")),
        (Err(_), None) => Err(trs!("SSH не ответил за 20 с").into()),
        (Ok(Ok(_)), None) => Err(trs!("сервер не показал ключ").into()),
    }
}

/// Какие способы входа сервер предлагает сейчас (запущенный sshd, а не файлы).
/// true — пароль (и keyboard-interactive) больше не предлагается.
pub async fn password_refused(t: &Target) -> Result<bool, String> {
    let pinned = t.host_key.clone().ok_or(trs!("нет подтверждённого отпечатка сервера"))?;
    let s = tcp(t).await?;
    let mut h = tokio::time::timeout(
        Duration::from_secs(20),
        client::connect_stream(config(), s, Handler { pinned: Some(pinned), seen: Arc::new(Mutex::new(None)) }),
    )
    .await
    .map_err(|_| trs!("SSH не ответил за 20 с").to_string())?
    .map_err(|e| format!("SSH: {e}"))?;
    let r = h.authenticate_none(&t.user).await.map_err(|e| format!("SSH: {e}"))?;
    let _ = h.disconnect(russh::Disconnect::ByApplication, "", "").await;
    Ok(match r {
        russh::client::AuthResult::Success => false,
        russh::client::AuthResult::Failure { remaining_methods, .. } => {
            !remaining_methods.contains(&russh::MethodKind::Password) && !remaining_methods.contains(&russh::MethodKind::KeyboardInteractive)
        }
    })
}

impl Ssh {
    pub async fn connect(t: &Target, login: &Login) -> Result<Self, String> {
        let pinned = t.host_key.clone().ok_or(trs!("нет подтверждённого отпечатка сервера"))?;
        let seen = Arc::new(Mutex::new(None));
        let s = tcp(t).await?;
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            client::connect_stream(config(), s, Handler { pinned: Some(pinned.clone()), seen: seen.clone() }),
        )
        .await
        .map_err(|_| trs!("SSH не ответил за 20 с").to_string())?;
        let mut h = match r {
            Ok(h) => h,
            Err(e) => {
                let got = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
                return Err(match got {
                    Some(g) if g != pinned => tr!("ВНИМАНИЕ: ключ сервера не совпал (ждали {pinned}, пришёл {g}). Сервер переустановили — или \
                         кто-то посередине. Ничего не делаю"
                    ),
                    _ => format!("SSH: {e}"),
                });
            }
        };
        let auth = match login {
            Login::Password(p) => h.authenticate_password(&t.user, p.as_str()).await,
            Login::KeyText { key, passphrase } => {
                let k = russh::keys::decode_secret_key(key, passphrase.as_ref().map(|p| p.as_str()))
                    .map_err(|e| tr!("ключ не прочитать (не тот формат или пароль от ключа): {e}"))?;
                let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
                h.authenticate_publickey(&t.user, PrivateKeyWithHashAlg::new(Arc::new(k), hash)).await
            }
            Login::Key(k) => {
                let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
                h.authenticate_publickey(&t.user, PrivateKeyWithHashAlg::new(k.clone(), hash)).await
            }
        }
        .map_err(|e| format!("SSH: {e}"))?;
        if !auth.success() {
            return Err(match login {
                Login::Password(_) => trs!("сервер не пустил: неверный логин или пароль (или вход по паролю уже выключен)").into(),
                _ => trs!("сервер не пустил по ключу").into(),
            });
        }
        Ok(Self { h })
    }

    /// Выполнить команду. Команды — только фиксированные строки из этого модуля;
    /// всё изменяемое — числа или `sh_quote`.
    pub async fn run(&self, cmd: &str, timeout: Duration) -> Result<Out, String> {
        let mut ch = self.h.channel_open_session().await.map_err(|e| format!("SSH: {e}"))?;
        ch.exec(true, cmd).await.map_err(|e| format!("SSH: {e}"))?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut code = None;
        let work = async {
            while let Some(msg) = ch.wait().await {
                match msg {
                    ChannelMsg::Data { data } if out.len() < MAX_OUT => out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, .. } if err.len() < MAX_OUT => err.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    _ => {}
                }
            }
        };
        tokio::time::timeout(timeout, work).await.map_err(|_| tr!("команда не закончилась за {} с", timeout.as_secs()))?;
        Ok(Out {
            code: code.unwrap_or(255),
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        })
    }

    /// Команда должна пройти, иначе ошибка с хвостом вывода.
    pub async fn ok(&self, what: &str, cmd: &str, timeout: Duration) -> Result<String, String> {
        let o = self.run(cmd, timeout).await?;
        if o.code == 0 {
            return Ok(o.out);
        }
        let tail: String = format!("{}\n{}", o.out.trim(), o.err.trim()).trim().lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
        Err(tr!("{what}: не вышло (код {}): {}", o.code, clean(&tail, 600)))
    }

    /// Залить файл по SFTP (каталог уже есть). Права ставит `install` следом.
    pub async fn put(&self, path: &str, data: &[u8]) -> Result<(), String> {
        let ch = self.h.channel_open_session().await.map_err(|e| format!("SFTP: {e}"))?;
        ch.request_subsystem(true, "sftp").await.map_err(|e| format!("SFTP: {e}"))?;
        let sftp = russh_sftp::client::SftpSession::new(ch.into_stream()).await.map_err(|e| format!("SFTP: {e}"))?;
        let mut f = sftp.create(path).await.map_err(|e| format!("SFTP {path}: {e}"))?;
        f.write_all(data).await.map_err(|e| format!("SFTP {path}: {e}"))?;
        f.shutdown().await.map_err(|e| format!("SFTP {path}: {e}"))?;
        let _ = sftp.close().await;
        Ok(())
    }

    pub async fn close(self) {
        let _ = self.h.disconnect(russh::Disconnect::ByApplication, "", "").await;
    }
}

/// В одинарных кавычках для sh: внутри ничего не раскрывается.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Вывод сервера в лог: без управляющих символов и не длиннее `max`.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(max).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoting() {
        assert_eq!(super::sh_quote("a b"), "'a b'");
        assert_eq!(super::sh_quote("x'; rm -rf / #"), r"'x'\''; rm -rf / #'");
        assert_eq!(super::clean("a\x1b[31mb\nc", 100), "a [31mb c");
    }
}
