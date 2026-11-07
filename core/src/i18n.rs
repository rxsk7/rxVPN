//! Язык интерфейса. Исходный язык — русский: ключ перевода = русский текст как в коде,
//! английский подставляется при компиляции из `locales/en.json` (крейт `rxvpn-i18n-macros`).
//!
//! - `tr!("Порт {p} занят", p = x)` → `String` (всё как у `format!`, включая `{x}` из места вызова);
//! - `trs!("Текст")` → `&'static str`;
//! - `trc!("Текст")` → [`Text`] — для `const`/`static`-таблиц, `.get()` на месте показа.
//!
//! Язык — глобальный атомик: строка переводится в момент создания (ошибка, лог, уведомление).
//! Уже созданные строки при смене языка не переписываются.

use std::sync::atomic::{AtomicU8, Ordering};

pub use rxvpn_i18n_macros::{en_format, en_lit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }
}

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn lang() -> Lang {
    if LANG.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Ru
    }
}

#[inline]
pub fn en() -> bool {
    LANG.load(Ordering::Relaxed) == 1
}

pub fn set_lang(l: Lang) {
    LANG.store(matches!(l, Lang::En) as u8, Ordering::Relaxed);
}

/// Значение настройки `Settings.lang`: "" — как в системе, "ru", "en". Мусор — как "".
pub fn resolve(setting: &str) -> Lang {
    match setting {
        "ru" => Lang::Ru,
        "en" => Lang::En,
        _ => system_lang(),
    }
}

/// Нормализация настройки (из окна, state.json, бэкапа).
pub fn sanitize(setting: &str) -> String {
    match setting {
        "ru" | "en" => setting.to_string(),
        _ => String::new(),
    }
}

/// Язык Windows: русский (и белорусский/казахский — там русский интерфейс привычнее английского) → ru,
/// иначе en. Вне Windows — по LC_ALL/LC_MESSAGES/LANG.
pub fn system_lang() -> Lang {
    #[cfg(windows)]
    {
        // Первичный язык — младшие 10 бит LANGID.
        let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() } & 0x3ff;
        from_primary(id)
    }
    #[cfg(not(windows))]
    {
        let v = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        from_locale(&v)
    }
}

/// 0x19 — русский, 0x23 — белорусский, 0x3F — казахский.
pub fn from_primary(id: u16) -> Lang {
    match id {
        0x19 | 0x23 | 0x3f => Lang::Ru,
        _ => Lang::En,
    }
}

pub fn from_locale(v: &str) -> Lang {
    let p = v.split(['_', '.', '-', '@']).next().unwrap_or("").to_ascii_lowercase();
    match p.as_str() {
        "ru" | "be" | "kk" => Lang::Ru,
        _ => Lang::En,
    }
}

/// Пара «русский/английский» для константных таблиц (`trc!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text(pub &'static str, pub &'static str);

impl Text {
    pub fn get(self) -> &'static str {
        if en() {
            self.1
        } else {
            self.0
        }
    }
    pub fn ru(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.get())
    }
}

/// Перевод с подстановкой, как `format!`. Возвращает `String`.
#[macro_export]
macro_rules! tr {
    ($lit:literal $($rest:tt)*) => {
        if $crate::i18n::en() {
            $crate::i18n::en_format!($lit $($rest)*)
        } else {
            ::std::format!($lit $($rest)*)
        }
    };
}

/// Перевод без подстановки: `&'static str`.
#[macro_export]
macro_rules! trs {
    ($lit:literal) => {
        if $crate::i18n::en() {
            $crate::i18n::en_lit!($lit)
        } else {
            $lit
        }
    };
}

/// Пара для `const`: `const X: Text = trc!("…");` → `X.get()`.
#[macro_export]
macro_rules! trc {
    ($lit:literal) => {
        $crate::i18n::Text($lit, $crate::i18n::en_lit!($lit))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_lang_mapping() {
        assert_eq!(from_primary(0x19), Lang::Ru);
        assert_eq!(from_primary(0x0419 & 0x3ff), Lang::Ru);
        assert_eq!(from_primary(0x09), Lang::En);
        assert_eq!(from_primary(0x22), Lang::En);
        assert_eq!(from_locale("ru_RU.UTF-8"), Lang::Ru);
        assert_eq!(from_locale("en_US.UTF-8"), Lang::En);
        assert_eq!(from_locale("C"), Lang::En);
        assert_eq!(resolve("en"), Lang::En);
        assert_eq!(resolve("ru"), Lang::Ru);
        assert_eq!(sanitize("de"), "");
        assert_eq!(sanitize("en"), "en");
    }

    #[test]
    fn text_pair() {
        // Глобальный язык в тестах не трогаем (тесты идут параллельно и сверяют русский текст).
        let t = Text("Да", "Yes");
        assert_eq!(t.ru(), "Да");
        assert_eq!(t.get(), if en() { "Yes" } else { "Да" });
    }
}

#[cfg(test)]
mod macro_probe {
    #[test]
    fn both_branches() {
        let p = 5;
        let x = 1.25f64;
        // Русская ветка — как format!, английская — тот же format! с текстом из en.json.
        assert_eq!(super::en_format!("Порт {p} занят, {x:.1}"), "Port 5 is busy, 1.2");
        if !super::en() {
            assert_eq!(tr!("Порт {p} занят, {x:.1}"), "Порт 5 занят, 1.2");
            assert_eq!(trs!("Да"), "Да");
        }
        const T: super::Text = trc!("Да");
        assert_eq!((T.0, T.1), ("Да", "Yes"));
    }
}
