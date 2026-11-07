//! Переводы при компиляции. Ключ — русский текст как в коде (как msgid в gettext),
//! английский берётся из `locales/en.json` в корне репозитория.
//!
//! Сами макросы `tr!`/`trs!`/`trc!` объявлены в `rxvpn_core::i18n`: там выбирается язык
//! во время работы, а отсюда приходит только английский литерал. Нет перевода —
//! ошибка компиляции, поэтому в сборку не попадёт непереведённая строка.
//!
//! Литерал английского текста получает span исходного русского: тогда `format!`
//! видит его как написанный в коде и подхватывает переменные `{name}` из места вызова.

use proc_macro::{Delimiter, Group, Literal, Spacing, Punct, Span, TokenStream, TokenTree};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Английский литерал: `en_lit!("русский")` → `"English"`.
#[proc_macro]
pub fn en_lit(input: TokenStream) -> TokenStream {
    let mut it = input.into_iter();
    let (lit, span) = match first_literal(&mut it) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if it.next().is_some() {
        return error(span, "en_lit!: ожидается один строковый литерал");
    }
    match translate(&lit, span) {
        Ok(en) => {
            let mut l = Literal::string(&en);
            l.set_span(span);
            TokenStream::from(TokenTree::Literal(l))
        }
        Err(e) => e,
    }
}

/// `en_format!("русский {x}", args…)` → `::std::format!("English {x}", args…)`.
#[proc_macro]
pub fn en_format(input: TokenStream) -> TokenStream {
    let mut it = input.into_iter();
    let (lit, span) = match first_literal(&mut it) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let en = match translate(&lit, span) {
        Ok(en) => en,
        Err(e) => return e,
    };
    let mut l = Literal::string(&en);
    l.set_span(span);
    let mut args = TokenStream::new();
    args.extend([TokenTree::Literal(l)]);
    args.extend(it);
    let mut out = TokenStream::new();
    for (i, name) in ["std", "format"].iter().enumerate() {
        out.extend([
            TokenTree::Punct(Punct::new(':', Spacing::Joint)),
            TokenTree::Punct(Punct::new(':', Spacing::Alone)),
        ]);
        out.extend([TokenTree::Ident(proc_macro::Ident::new(name, Span::call_site()))]);
        if i == 1 {
            out.extend([TokenTree::Punct(Punct::new('!', Spacing::Alone))]);
        }
    }
    out.extend([TokenTree::Group(Group::new(Delimiter::Parenthesis, args))]);
    out
}

/// Первый токен — строковый литерал (macro_rules может завернуть его в невидимую группу).
fn first_literal(it: &mut proc_macro::token_stream::IntoIter) -> Result<(String, Span), TokenStream> {
    let mut tok = it.next();
    loop {
        match tok {
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::None => {
                let mut inner = g.stream().into_iter();
                tok = inner.next();
                if inner.next().is_some() {
                    return Err(error(g.span(), "ожидается строковый литерал"));
                }
            }
            Some(TokenTree::Literal(l)) => {
                let span = l.span();
                return match unescape(&l.to_string()) {
                    Some(s) => Ok((s, span)),
                    None => Err(error(span, "ожидается обычный строковый литерал \"…\" или r\"…\"")),
                };
            }
            Some(t) => return Err(error(t.span(), "ожидается строковый литерал")),
            None => return Err(error(Span::call_site(), "ожидается строковый литерал")),
        }
    }
}

fn translate(ru: &str, span: Span) -> Result<String, TokenStream> {
    let table = match table() {
        Ok(t) => t,
        Err(e) => return Err(error(span, e)),
    };
    match table.get(ru) {
        Some(en) if !en.trim().is_empty() => Ok(en.clone()),
        _ => Err(error(span, &format!("нет перевода в locales/en.json: {ru:?} (scripts/i18n_check.py --add добавит заготовку)"))),
    }
}

fn table() -> Result<&'static HashMap<String, String>, &'static str> {
    static T: OnceLock<Result<HashMap<String, String>, String>> = OnceLock::new();
    T.get_or_init(|| {
        let dir = std::env::var("CARGO_MANIFEST_DIR").map_err(|_| "нет CARGO_MANIFEST_DIR".to_string())?;
        let path = std::path::Path::new(&dir).join("..").join("locales").join("en.json");
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str::<HashMap<String, String>>(&text).map_err(|e| format!("{}: {e}", path.display()))
    })
    .as_ref()
    .map_err(|e| Box::leak(e.clone().into_boxed_str()) as &str)
}

fn error(span: Span, msg: &str) -> TokenStream {
    let mut l = Literal::string(msg);
    l.set_span(span);
    let mut out: TokenStream = "::core::compile_error!".parse().unwrap();
    out.extend([TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::from(TokenTree::Literal(l))))]);
    out.into_iter()
        .map(|mut t| {
            t.set_span(span);
            t
        })
        .collect()
}

/// Значение строкового литерала Rust по его исходному тексту ("…" или r#"…"#).
pub(crate) fn unescape(src: &str) -> Option<String> {
    if let Some(rest) = src.strip_prefix('r') {
        let hashes = rest.chars().take_while(|&c| c == '#').count();
        let body = rest.get(hashes..)?.strip_prefix('"')?;
        let body = body.strip_suffix(&"#".repeat(hashes))?.strip_suffix('"')?;
        return Some(body.to_string());
    }
    let body = src.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut ch = body.chars().peekable();
    while let Some(c) = ch.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match ch.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '\'' => out.push('\''),
            'x' => {
                let h: String = [ch.next()?, ch.next()?].iter().collect();
                out.push(u8::from_str_radix(&h, 16).ok()? as char);
            }
            'u' => {
                if ch.next()? != '{' {
                    return None;
                }
                let mut h = String::new();
                loop {
                    match ch.next()? {
                        '}' => break,
                        '_' => {}
                        c => h.push(c),
                    }
                }
                out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
            }
            '\n' | '\r' => {
                while matches!(ch.peek(), Some(c) if c.is_whitespace()) {
                    ch.next();
                }
            }
            _ => return None,
        }
    }
    Some(out)
}
