//! «Свой сервер»: VPN на своём VPS одной кнопкой. rxvpn по SSH сам ставит
//! официальный Xray (VLESS + Reality), закрывает сервер (ключ вместо пароля,
//! ufw, fail2ban, автообновления) и потом управляет им: друзья, обновление,
//! перезапуск, удаление.
//!
//! Правила безопасности:
//! - ключ сервера подтверждает человек (TOFU), дальше он сверяется при каждом входе;
//! - пароль используется для одного входа и нигде не хранится;
//! - команды на сервере — фиксированные строки; из ввода в них попадают только
//!   числа (порты) и строки после `sh_quote`; файлы заливаются по SFTP;
//! - Xray качает и сверяет по SHA-256 сам rxvpn (никаких `curl | bash`);
//! - вход по паролю выключается, только когда новым подключением проверено,
//!   что вход по ключу работает; не вышло — откат через ещё открытую сессию.

pub mod plan;
pub mod ssh;

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use russh::keys::{HashAlg, PrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use ssh::{host_fingerprint, Login, Target};
use plan::*;
use ssh::{sh_quote, Ssh};

/// Друг на сервере: свой UUID, отключается одним кликом.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Friend {
    /// [0-9a-f]{10}: «email» в статистике Xray (`f-{id}@rxvpn`).
    pub id: String,
    pub name: String,
    pub uuid: String,
    pub enabled: bool,
    /// Лимит трафика, ГБ (вверх + вниз, накопительно). 0 — без лимита.
    #[serde(default)]
    pub limit_gb: u32,
    /// Доступ до (unix, секунды). 0 — бессрочно.
    #[serde(default)]
    pub expires: i64,
}

impl Friend {
    pub fn email(&self) -> String {
        format!("f-{}@rxvpn", self.id)
    }

    /// Срок вышел (по часам этого компа; сервер сверяет по своим).
    pub fn expired(&self, now: i64) -> bool {
        self.expires > 0 && now >= self.expires
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Свой сервер в state.json. Секреты (ключ SSH, приватный ключ Reality) — в
/// `sealed`: всегда под DPAPI, даже если шифрование state.json выключено.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vps {
    pub id: String,
    pub name: String,
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    /// Отпечаток ключа SSH сервера, подтверждённый человеком.
    pub host_key: String,
    pub port: u16,
    pub sni: String,
    pub public_key: String,
    pub short_id: String,
    pub owner_uuid: String,
    #[serde(default)]
    pub friends: Vec<Friend>,
    /// id сервера в списке rxvpn.
    pub node_id: String,
    #[serde(default)]
    pub xray_version: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub os: String,
    /// Отпечаток своего ключа SSH (для показа).
    #[serde(default)]
    pub key_fp: String,
    /// Вход по паролю выключен (проверено).
    #[serde(default)]
    pub password_off: bool,
    /// Публичные адреса сервера — закрыты для клиентов (см. server_config).
    #[serde(default)]
    pub server_ips: Vec<String>,
    #[serde(default)]
    pub sealed: String,
}

/// Секреты сервера (в памяти — только на время операции).
#[derive(Serialize, Deserialize)]
pub struct Secrets {
    pub ssh_key: Zeroizing<String>,
    pub reality_private: Zeroizing<String>,
    /// К какому серверу привязаны: подменить в бэкапе адрес и отпечаток,
    /// оставив чужой `sealed`, не выйдет (иначе ключ Reality ушёл бы на чужой сервер).
    pub host: String,
    pub ssh_port: u16,
    pub host_key: String,
}

const ENTROPY: &[u8] = b"rxvpn vps secrets v1";

/// Секреты сервера → base64(DPAPI): всегда шифруются ключом учётки Windows.
pub fn seal(sec: &Secrets) -> Result<String, String> {
    use base64::Engine;
    let blob = crate::winsys::dpapi(&sec.to_json(), ENTROPY, true)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

pub fn unseal(v: &Vps) -> Result<Secrets, String> {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(&v.sealed).map_err(|_| trs!("секреты сервера испорчены").to_string())?;
    let plain = Zeroizing::new(crate::winsys::dpapi(&blob, ENTROPY, false).map_err(|_| {
        trs!("ключ от этого сервера не открыть: он зашифрован на другом компе или под другой учёткой Windows").to_string()
    })?);
    let s = Secrets::from_json(&plain)?;
    if s.host != v.host || s.ssh_port != v.ssh_port || s.host_key != v.host_key {
        return Err(trs!("ключ этого сервера записан для другого адреса — запись подменена, не использую").into());
    }
    Ok(s)
}

/// В логи и отладку секреты не попадают.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(скрыто)") // i18n-skip: файл на сервере / отладка
    }
}

impl Secrets {
    pub fn key(&self) -> Result<Arc<PrivateKey>, String> {
        russh::keys::decode_secret_key(&self.ssh_key, None).map(Arc::new).map_err(|e| tr!("свой ключ SSH испорчен: {e}"))
    }
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(serde_json::to_vec(self).expect("сериализуется"))
    }
    pub fn from_json(b: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(b).map_err(|_| trs!("секреты сервера испорчены").to_string())
    }
}

impl Vps {
    pub fn target(&self) -> Target {
        Target { host: self.host.clone(), port: self.ssh_port, user: self.user.clone(), host_key: Some(self.host_key.clone()) }
    }

    fn reality(&self, s: &Secrets) -> Reality {
        Reality { v6: self.host.contains(':'), port: self.port, sni: self.sni.clone(), private_key: s.reality_private.to_string(), short_id: self.short_id.clone() }
    }

    pub fn owner_link(&self, s_name: &str) -> String {
        let r = Reality { v6: false, port: self.port, sni: self.sni.clone(), private_key: String::new(), short_id: self.short_id.clone() };
        link(&self.host, &r, &self.public_key, &self.owner_uuid, s_name)
    }

    pub fn friend_link(&self, f: &Friend) -> String {
        let r = Reality { v6: false, port: self.port, sni: self.sni.clone(), private_key: String::new(), short_id: self.short_id.clone() };
        link(&self.host, &r, &self.public_key, &f.uuid, &format!("{} · {}", self.name, f.name))
    }

    fn clients(&self) -> Vec<Client> {
        let mut v = vec![Client { uuid: self.owner_uuid.clone(), email: OWNER_EMAIL.into() }];
        let now = now_unix();
        v.extend(self.friends.iter().filter(|f| f.enabled && !f.expired(now)).map(|f| Client { uuid: f.uuid.clone(), email: f.email() }));
        v
    }

    /// Лимиты для серверного скрипта (только включённые друзья).
    pub fn limits(&self) -> serde_json::Value {
        let l: Vec<(String, u32, i64)> = self.friends.iter().filter(|f| f.enabled).map(|f| (f.email(), f.limit_gb, f.expires)).collect();
        limits_json(&l)
    }

    /// Поля из чужого файла (бэкап) — в порядке? Кривое — не берём.
    pub fn sane(&self) -> bool {
        let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
        valid_host(&self.host).is_ok_and(|h| h == self.host)
            && self.ssh_port > 0
            && self.port > 0
            && self.user == "root"
            && self.host_key.starts_with("SHA256:")
            && SNI_CANDIDATES.contains(&self.sni.as_str())
            && self.public_key.len() == 43
            && self.public_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && hex(&self.short_id, 16)
            && is_uuid(&self.owner_uuid)
            && self.server_ips.len() <= 16
            && self.server_ips.iter().all(|x| x.parse::<std::net::IpAddr>().is_ok())
            && self.friends.iter().all(|f| hex(&f.id, 10) && is_uuid(&f.uuid) && friend_name(&f.name).is_ok() && f.limit_gb <= 100_000 && f.expires >= 0)
    }
}

/// Скачать архив Xray под архитектуру сервера (со сверкой хеша).
pub type Fetch<'a> = &'a (dyn Fn(&'static str) -> BoxFuture<'static, Result<Vec<u8>, String>> + Send + Sync);
pub type Log<'a> = &'a (dyn Fn(String) + Send + Sync);

const T_SHORT: Duration = Duration::from_secs(60);
const T_APT: Duration = Duration::from_secs(1200);

/// Достать `xray` из архива релиза.
pub fn xray_from_zip(zip: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut a = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|e| tr!("архив Xray: {e}"))?;
    let mut f = a.by_name("xray").map_err(|_| trs!("в архиве нет xray").to_string())?;
    let mut buf = Vec::new();
    (&mut f).take(200 << 20).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() < 1 << 20 || !buf.starts_with(b"\x7fELF") {
        return Err(trs!("xray в архиве не похож на программу для Linux").into());
    }
    Ok(buf)
}

pub struct InstallOpts {
    pub name: String,
    pub port: u16,
}

/// Новый ключ SSH rxvpn: ed25519.
fn new_key() -> Result<PrivateKey, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&random(32));
    let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let mut k = PrivateKey::from(kp);
    k.set_comment("rxvpn");
    Ok(k)
}

async fn stage(s: &Ssh) -> Result<String, String> {
    let d = s.ok(trs!("временная папка"), "umask 077; mktemp -d /root/.rxvpn-XXXXXXXX", T_SHORT).await?;
    let d = d.trim().to_string();
    let ok = d.strip_prefix("/root/.rxvpn-").is_some_and(|r| r.len() == 8 && r.bytes().all(|b| b.is_ascii_alphanumeric()));
    if !ok {
        return Err(trs!("сервер вернул странную временную папку").into());
    }
    Ok(d)
}

async fn version(s: &Ssh) -> String {
    let o = s.run("/usr/local/bin/xray version 2>/dev/null | head -n1", T_SHORT).await.map(|o| o.out).unwrap_or_default();
    o.split_whitespace().nth(1).filter(|v| v.len() < 20 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.')).unwrap_or("?").to_string()
}

/// Поставить VPN на сервер. Возвращает сервер и его секреты (сохранить — дело вызывающего).
pub async fn install(t: &Target, login: Login, o: InstallOpts, fetch: Fetch<'_>, log: Log<'_>) -> Result<(Vps, Secrets), String> {
    if t.user != "root" {
        return Err(trs!("нужен вход под root").into());
    }
    log(tr!("подключаюсь к {}:{} (ключ сервера {})…", t.host, t.port, t.host_key.as_deref().unwrap_or("?")));
    let s = Ssh::connect(t, &login).await?;
    // Чужой ключ/пароль больше не нужны: дальше — только своим ключом.
    drop(login);

    let id = s.ok(trs!("проверка прав"), "id -u", T_SHORT).await?;
    if id.trim() != "0" {
        return Err(trs!("вход не под root (id ≠ 0)").into());
    }
    let os = os_supported(&s.ok(trs!("система"), "cat /etc/os-release", T_SHORT).await?)?;
    let (arch, asset) = arch_asset(&s.ok(trs!("процессор"), "uname -m", T_SHORT).await?)?;
    log(tr!("система: {os}, {arch}"));
    // Порт sshd на самом сервере (за NAT/LXC он другой) — его и открываем в ufw.
    let sport = ssh_server_port(&s.run("echo $SSH_CONNECTION", T_SHORT).await?.out).unwrap_or(t.port);
    let server_ips = parse_ips(&s.run("ip -o addr show scope global 2>/dev/null", T_SHORT).await?.out);
    let busy = s.run(&format!("ss -Htlnp 'sport = :{}' 2>/dev/null", o.port), T_SHORT).await?.out;
    if !busy.trim().is_empty() && !busy.contains("\"xray\"") {
        return Err(tr!("порт {} на сервере уже занят: {}", o.port, ssh::clean(busy.trim(), 200)));
    }

    log(tr!("качаю Xray ({asset}) с GitHub и сверяю хеш…"));
    let zip_f = fetch(asset);
    log(trs!("ставлю пакеты: ufw, fail2ban, unattended-upgrades, openssl (пару минут)…").into());
    let apt = s.ok(
        "apt",
        "export DEBIAN_FRONTEND=noninteractive; apt-get -o DPkg::Lock::Timeout=300 update -q >/dev/null && \
         apt-get -o DPkg::Lock::Timeout=300 install -y -q --no-install-recommends ufw fail2ban python3-systemd unattended-upgrades openssl iproute2 >/dev/null",
        T_APT,
    );
    let (zip, apt) = tokio::join!(zip_f, apt);
    apt?;
    let bin = xray_from_zip(&zip?)?;

    log(trs!("подбираю сайт-маскировку (TLS 1.3 + h2, ближайший к серверу)…").into());
    let probe = s.run(&sni_probe_script(), Duration::from_secs(120)).await?.out;
    let sni = match pick_sni(&probe) {
        Some(d) => d,
        None => {
            log(trs!("ни один сайт-маскировка не ответил с сервера — беру www.microsoft.com").into());
            "www.microsoft.com".into()
        }
    };
    log(tr!("маскировка: {sni}"));

    let (private, public) = reality_keys();
    let key = new_key()?;
    let secrets = Secrets {
        ssh_key: key.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| e.to_string())?,
        reality_private: Zeroizing::new(private),
        host: t.host.clone(),
        ssh_port: t.port,
        host_key: t.host_key.clone().unwrap_or_default(),
    };
    let mut v = Vps {
        id: crate::node::fnv64(&format!("vps|{}|{}", t.host, t.port)),
        name: o.name.clone(),
        host: t.host.clone(),
        ssh_port: t.port,
        user: t.user.clone(),
        host_key: t.host_key.clone().unwrap_or_default(),
        port: o.port,
        sni,
        public_key: public,
        short_id: short_id(),
        owner_uuid: uuid_v4(),
        friends: Vec::new(),
        node_id: String::new(),
        xray_version: String::new(),
        arch: arch.into(),
        os,
        key_fp: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        password_off: false,
        server_ips,
        sealed: String::new(),
    };

    let st = stage(&s).await?;
    let q = sh_quote(&st);
    let cfg = serde_json::to_vec_pretty(&server_config(&v.reality(&secrets), &v.clients(), &v.server_ips)).unwrap();
    let pubkey = key.public_key().to_openssh().map_err(|e| e.to_string())? + "\n";
    let jail = fail2ban_jail(sport);
    let files: [(&str, &[u8]); 7] = [
        ("xray", &bin),
        ("config.json", &cfg),
        ("xray.service", unit().as_bytes()),
        ("bbr.conf", sysctl_bbr().as_bytes()),
        ("jail.local", jail.as_bytes()),
        ("20auto-upgrades", auto_upgrades().as_bytes()),
        ("rxvpn.pub", pubkey.as_bytes()),
    ];
    log(trs!("заливаю файлы по SFTP…").into());
    let mut up = Ok(());
    for (name, data) in files.iter().copied().chain([("00-rxvpn.conf", sshd_dropin().as_bytes())]) {
        up = s.put(&format!("{st}/{name}"), data).await;
        if up.is_err() {
            break;
        }
    }
    if let Err(e) = up {
        let _ = s.run(&format!("rm -rf {q}"), T_SHORT).await;
        return Err(e);
    }

    log(trs!("ставлю Xray и службу…").into());
    let r = s.ok(
        "Xray",
        &format!(
            "set -e; S={q}; id -u xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray; \
             install -d -m 0755 {XRAY_DIR}; install -m 0755 -o root -g root \"$S/xray\" {XRAY_BIN}.new; \
             {XRAY_BIN}.new run -test -c \"$S/config.json\"; \
             install -m 0640 -o root -g xray \"$S/config.json\" {XRAY_CONF}; mv -f {XRAY_BIN}.new {XRAY_BIN}; \
             install -m 0644 \"$S/xray.service\" {UNIT}; systemctl daemon-reload; systemctl enable xray >/dev/null 2>&1; \
             systemctl restart xray; sleep 1; systemctl is-active --quiet xray"
        ),
        Duration::from_secs(120),
    )
    .await;
    if let Err(e) = r {
        let _ = s.run(&format!("rm -rf {q} {XRAY_BIN}.new"), T_SHORT).await;
        return Err(e);
    }
    v.xray_version = version(&s).await;
    log(tr!("Xray {} работает на порту {}", v.xray_version, v.port));

    // Защита: каждое — отдельно, сбой одного не ломает остальное.
    let soft = |what: &'static str, r: Result<String, String>| match r {
        Ok(_) => log(tr!("{what}: готово")),
        Err(e) => log(format!("{what}: {e}")),
    };
    let bbr = s
        .ok("BBR", &format!("S={q}; install -m 0644 \"$S/bbr.conf\" /etc/sysctl.d/99-rxvpn-bbr.conf; modprobe tcp_bbr 2>/dev/null; sysctl -q -p /etc/sysctl.d/99-rxvpn-bbr.conf; test \"$(sysctl -n net.ipv4.tcp_congestion_control)\" = bbr"), T_SHORT)
        .await;
    soft("BBR", bbr);
    soft(
        "fail2ban",
        s.ok("fail2ban", &format!("S={q}; install -m 0644 \"$S/jail.local\" /etc/fail2ban/jail.d/rxvpn-sshd.local; systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban; sleep 1; systemctl is-active --quiet fail2ban"), T_SHORT).await,
    );
    soft(
        trs!("автообновления"),
        s.ok(trs!("автообновления"), &format!("S={q}; install -m 0644 \"$S/20auto-upgrades\" /etc/apt/apt.conf.d/20auto-upgrades"), T_SHORT).await,
    );
    let lim = match put_limits(&s, &st, &v).await {
        Ok(()) => s.ok(trs!("лимиты друзей"), &format!("S={q}; {}", install_limits_cmd()), T_SHORT).await,
        Err(e) => Err(e),
    };
    soft(trs!("лимиты друзей"), lim);
    // Сначала SSH, потом включаем — иначе запрёмся.
    soft(
        "ufw",
        s.ok("ufw", &format!("ufw allow {sport}/tcp >/dev/null && ufw allow {}/tcp >/dev/null && ufw --force enable >/dev/null && ufw status | grep -q active", v.port), T_SHORT).await,
    );

    log(trs!("кладу свой ключ SSH и проверяю вход по нему…").into());
    s.ok(
        trs!("ключ SSH"),
        &format!(
            "S={q}; install -d -m 0700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; \
             grep -qxF \"$(cat \"$S/rxvpn.pub\")\" /root/.ssh/authorized_keys || cat \"$S/rxvpn.pub\" >> /root/.ssh/authorized_keys"
        ),
        T_SHORT,
    )
    .await?;
    let own = Login::Key(secrets.key()?);
    let k = match Ssh::connect(t, &own).await {
        Ok(k) => k,
        Err(e) => {
            // Вдруг это ufw отрезал новые подключения — выключаем, пока сессия жива.
            let _ = s.run("ufw --force disable >/dev/null 2>&1", T_SHORT).await;
            let _ = s.run(&format!("rm -rf {q}"), T_SHORT).await;
            return Err(tr!("вход по своему ключу не работает ({e}) — пароль НЕ выключаю, ufw выключил"));
        }
    };
    k.ok(trs!("вход по ключу"), "true", T_SHORT).await?;
    k.close().await;

    log(trs!("выключаю вход по паролю…").into());
    let r = s
        .ok(
            "sshd",
            &format!(
                "S={q}; grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf' /etc/ssh/sshd_config || exit 3; \
                 install -m 0644 \"$S/00-rxvpn.conf\" {SSHD_DROPIN}; D=$(command -v sshd || echo /usr/sbin/sshd); \
                 $D -t || {{ rm -f {SSHD_DROPIN}; exit 4; }}; systemctl reload ssh 2>/dev/null || systemctl reload sshd || {{ rm -f {SSHD_DROPIN}; exit 5; }}; sleep 1; \
                 $D -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -i '^passwordauthentication'"
            ),
            T_SHORT,
        )
        .await;
    match r {
        Ok(out) if out.trim().eq_ignore_ascii_case("passwordauthentication no") => {
            // Новое подключение по ключу — точно пускает после перезагрузки sshd?
            match Ssh::connect(t, &own).await {
                Ok(k) => {
                    k.close().await;
                    // Спрашиваем запущенный sshd, а не файлы: предлагает ли он ещё пароль.
                    match ssh::password_refused(t).await {
                        Ok(true) => {
                            v.password_off = true;
                            log(trs!("вход по паролю выключен (sshd его больше не предлагает), по ключу — работает").into());
                        }
                        Ok(false) => log(trs!("sshd всё ещё предлагает вход по паролю — что-то в его настройках сильнее; проверь вручную").into()),
                        Err(e) => log(tr!("не проверить, выключен ли пароль: {e}")),
                    }
                }
                Err(e) => {
                    log(tr!("после выключения пароля вход по ключу не прошёл ({e}) — откатываю"));
                    let _ = s.run(&format!("rm -f {SSHD_DROPIN}; systemctl reload ssh 2>/dev/null || systemctl reload sshd"), T_SHORT).await;
                }
            }
        }
        Ok(_) => {
            log(trs!("sshd не принял настройку (что-то в его конфиге переопределяет) — пароль оставил, откатываю").into());
            let _ = s.run(&format!("rm -f {SSHD_DROPIN}; systemctl reload ssh 2>/dev/null || systemctl reload sshd"), T_SHORT).await;
        }
        Err(e) => log(tr!("пароль не выключил: {e}")),
    }
    let _ = s.run(&format!("rm -rf {q}"), T_SHORT).await;
    s.close().await;
    Ok((v, secrets))
}

async fn own(v: &Vps, sec: &Secrets) -> Result<Ssh, String> {
    Ssh::connect(&v.target(), &Login::Key(sec.key()?)).await
}

/// Переписать конфиг (друзья поменялись) и перезапустить Xray.
pub async fn apply(v: &Vps, sec: &Secrets) -> Result<(), String> {
    let s = own(v, sec).await?;
    let st = stage(&s).await?;
    let q = sh_quote(&st);
    let cfg = serde_json::to_vec_pretty(&server_config(&v.reality(sec), &v.clients(), &v.server_ips)).unwrap();
    s.put(&format!("{st}/config.json"), &cfg).await?;
    put_limits(&s, &st, v).await?;
    let r = s
        .ok(
            trs!("конфиг"),
            &format!(
                "S={q}; set -e; {XRAY_BIN} run -test -c \"$S/config.json\"; install -m 0640 -o root -g xray \"$S/config.json\" {XRAY_CONF};                  {}; systemctl restart xray; sleep 1; systemctl is-active --quiet xray; systemctl start rxvpn-limits.service || true",
                install_limits_cmd()
            ),
            T_SHORT,
        )
        .await;
    let _ = s.run(&format!("rm -rf {q}"), T_SHORT).await;
    s.close().await;
    r.map(|_| ())
}

/// Залить скрипт лимитов, его таймер и сами лимиты во временную папку.
async fn put_limits(s: &Ssh, st: &str, v: &Vps) -> Result<(), String> {
    let lim = serde_json::to_vec(&v.limits()).unwrap();
    s.put(&format!("{st}/limits.py"), limits_script().as_bytes()).await?;
    s.put(&format!("{st}/rxvpn-limits.json"), &lim).await?;
    s.put(&format!("{st}/rxvpn-limits.service"), limits_service().as_bytes()).await?;
    s.put(&format!("{st}/rxvpn-limits.timer"), limits_timer().as_bytes()).await
}

/// Разложить их из `$S` и включить таймер (идемпотентно: и при установке, и при каждом apply).
fn install_limits_cmd() -> String {
    format!(
        "install -d -m 0755 /usr/local/lib/rxvpn; install -m 0755 -o root -g root \"$S/limits.py\" {LIMITS_SCRIPT};          install -m 0640 -o root -g xray \"$S/rxvpn-limits.json\" {LIMITS_JSON};          install -m 0644 \"$S/rxvpn-limits.service\" {LIMITS_SERVICE}; install -m 0644 \"$S/rxvpn-limits.timer\" {LIMITS_TIMER};          systemctl daemon-reload; systemctl enable --now rxvpn-limits.timer >/dev/null 2>&1"
    )
}

/// Обнулить накопленный трафик друга (и снять отключение по лимиту).
pub async fn reset_usage(v: &Vps, sec: &Secrets, f: &Friend) -> Result<(), String> {
    let s = own(v, sec).await?;
    let email = sh_quote(&f.email());
    let r = s.ok(trs!("сброс трафика"), &format!("/usr/bin/python3 {LIMITS_SCRIPT} --reset {email}"), T_SHORT).await;
    s.close().await;
    r.map(|_| ())
}

pub async fn restart(v: &Vps, sec: &Secrets) -> Result<(), String> {
    let s = own(v, sec).await?;
    let r = s.ok(trs!("перезапуск"), "systemctl restart xray; sleep 1; systemctl is-active --quiet xray", T_SHORT).await;
    s.close().await;
    r.map(|_| ())
}

/// Свежий Xray: проверяется на текущем конфиге до замены. Возвращает версию.
pub async fn update_xray(v: &Vps, sec: &Secrets, fetch: Fetch<'_>) -> Result<String, String> {
    let (_, asset) = arch_asset(if v.arch == "arm64" { "aarch64" } else { "x86_64" })?;
    let bin = xray_from_zip(&fetch(asset).await?)?;
    let s = own(v, sec).await?;
    let st = stage(&s).await?;
    let q = sh_quote(&st);
    s.put(&format!("{st}/xray"), &bin).await?;
    let r = s
        .ok(
            trs!("обновление Xray"),
            &format!(
                "S={q}; set -e; install -m 0755 -o root -g root \"$S/xray\" {XRAY_BIN}.new; {XRAY_BIN}.new run -test -c {XRAY_CONF}; \
                 mv -f {XRAY_BIN}.new {XRAY_BIN}; systemctl restart xray; sleep 1; systemctl is-active --quiet xray"
            ),
            Duration::from_secs(120),
        )
        .await;
    let _ = s.run(&format!("rm -rf {q} {XRAY_BIN}.new"), T_SHORT).await;
    let ver = version(&s).await;
    s.close().await;
    r.map(|_| ver)
}

/// Трафик по клиентам: email → вверх/вниз и «отключён сервером». Есть скрипт лимитов —
/// накопительно; старый сервер без него — с последнего запуска Xray.
pub async fn traffic(v: &Vps, sec: &Secrets) -> Result<std::collections::HashMap<String, Usage>, String> {
    let s = own(v, sec).await?;
    let r = s
        .ok(
            trs!("статистика"),
            &format!("if [ -x {LIMITS_SCRIPT} ]; then /usr/bin/python3 {LIMITS_SCRIPT} --json; else {XRAY_BIN} api statsquery --server=127.0.0.1:{API_PORT}; fi"),
            T_SHORT,
        )
        .await;
    s.close().await;
    Ok(parse_usage(&r?))
}

/// Убрать Xray с сервера и вернуть вход по паролю (ключ rxvpn уходит вместе с
/// записью — без пароля в сервер было бы не попасть). ufw, fail2ban остаются.
pub async fn uninstall(v: &Vps, sec: &Secrets) -> Result<(), String> {
    let s = own(v, sec).await?;
    let r = s
        .ok(
            trs!("удаление"),
            &format!(
                "systemctl disable --now xray >/dev/null 2>&1; rm -f {UNIT} {XRAY_BIN} {XRAY_BIN}.new; rm -rf {XRAY_DIR}; \
                 systemctl daemon-reload; (command -v ufw >/dev/null && ufw delete allow {}/tcp >/dev/null 2>&1); \
                 userdel xray >/dev/null 2>&1; rm -f {SSHD_DROPIN}; systemctl reload ssh 2>/dev/null || systemctl reload sshd; true",
                v.port
            ),
            T_SHORT,
        )
        .await;
    s.close().await;
    r.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn dpapi_seal_roundtrip() {
        let k = new_key().unwrap();
        let s = Secrets { ssh_key: k.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap(), reality_private: Zeroizing::new("priv".into()), host: "1.2.3.4".into(), ssh_port: 22, host_key: "SHA256:x".into() };
        let mut v: Vps = serde_json::from_value(serde_json::json!({"id":"x","name":"n","host":"1.2.3.4","ssh_port":22,"user":"root",
            "host_key":"SHA256:x","port":443,"sni":"www.apple.com","public_key":"p","short_id":"s","owner_uuid":"u","node_id":"n"})).unwrap();
        v.sealed = seal(&s).unwrap();
        assert!(!v.sealed.contains("PRIVATE KEY"));
        let back = unseal(&v).unwrap();
        assert_eq!(back.reality_private.as_str(), "priv");
        assert_eq!(back.key().unwrap().public_key(), k.public_key());
        let mut moved = v.clone();
        moved.host = "6.6.6.6".into();
        assert!(unseal(&moved).unwrap_err().contains("подменена"), "ключ не уходит на другой адрес");
        v.sealed = "AAAA".into();
        assert!(unseal(&v).is_err());
    }

    #[test]
    fn expired_and_disabled_friends_leave_config_and_limits() {
        let mk = |id: &str, enabled: bool, limit_gb: u32, expires: i64| Friend {
            id: id.into(), name: "Друг".into(), uuid: uuid_v4(), enabled, limit_gb, expires,
        };
        let mut v: Vps = serde_json::from_value(serde_json::json!({"id":"x","name":"n","host":"1.2.3.4","ssh_port":22,"user":"root",
            "host_key":"SHA256:x","port":443,"sni":"www.apple.com","public_key":"p","short_id":"s","owner_uuid":"u","node_id":"n"})).unwrap();
        v.friends = vec![
            mk("aaaaaaaaaa", true, 50, 0),
            mk("bbbbbbbbbb", true, 0, 1), // срок давно вышел
            mk("cccccccccc", false, 10, 0), // выключен руками
        ];
        let emails: Vec<String> = v.clients().into_iter().map(|c| c.email).collect();
        assert_eq!(emails, ["owner@rxvpn", "f-aaaaaaaaaa@rxvpn"], "просроченный и выключенный — не в конфиге");
        let l = v.limits();
        assert!(l.get("f-aaaaaaaaaa@rxvpn").is_some() && l.get("f-bbbbbbbbbb@rxvpn").is_some());
        assert!(l.get("f-cccccccccc@rxvpn").is_none(), "выключенного сервер и так не пускает");
        // Старая запись без новых полей читается (serde default)
        let old: Friend = serde_json::from_str(r#"{"id":"aaaaaaaaaa","name":"Друг","uuid":"x","enabled":true}"#).unwrap();
        assert_eq!((old.limit_gb, old.expires), (0, 0));
    }

    #[test]
    fn key_and_secrets_roundtrip() {
        let k = new_key().unwrap();
        let s = Secrets { ssh_key: k.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap(), reality_private: Zeroizing::new("p".into()), host: "h".into(), ssh_port: 22, host_key: "k".into() };
        let back = Secrets::from_json(&s.to_json()).unwrap();
        assert_eq!(back.key().unwrap().public_key(), k.public_key());
        assert!(k.public_key().to_openssh().unwrap().starts_with("ssh-ed25519 "));
        assert_ne!(new_key().unwrap().public_key(), k.public_key());
    }
}
