//! rxvpn-core — всё, что не зависит от интерфейса.
//! GUI (Tauri) и будущая мобильная версия используют этот же крейт.

#[macro_use]
pub mod i18n;
pub mod autostart;
pub mod backup;
pub mod protect;
pub mod batch;
pub mod defang;
pub mod diag;
pub mod doh;
pub mod export;
pub mod filter;
pub mod checks;
pub mod geodata;
pub mod health;
pub mod jsonsub;
pub mod link;
pub mod qr;
pub mod report;
pub mod winsys;
pub mod net;
pub mod node;
pub mod runner;
pub mod services;
pub mod stats;
pub mod store;
pub mod sysdns;
pub mod sysproxy;
pub mod tgproxy;
pub mod tor;
pub mod update;
pub mod v2rayn;
pub mod vps;
pub mod warp;
pub mod whitelist;
pub mod xray;
pub mod zapret;

pub use link::{parse_link, parse_many, LinkError};
pub use node::{Node, Protocol};
pub use store::{ImportResult, Store, Subscription, AUTO_ID};
pub use xray::{
    app_names, auto_tag, build_config, build_run_config, build_test_config, parse_rule,
    site_routes, site_tags, validate_apps, validate_rule, validate_rules, validate_settings, Action, AppsMode, RouteMode,
    Rule, RuleTarget, RunOpts, Settings, SiteRoute, SiteServer, Upstream, GEOIP_RU, GEOSITE_RU,
    PROBE_URLS_HTTP,
};
