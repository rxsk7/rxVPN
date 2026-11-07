//! QR-код (SVG) — чтобы перенести сервер или подписку на телефон камерой.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// Сколько символов ещё нормально сканируется камерой телефона.
pub const MAX_LEN: usize = 1800;

pub fn svg(text: &str) -> Result<String, String> {
    if text.len() > MAX_LEN {
        return Err(tr!("слишком длинно для QR ({} символов): телефон не отсканирует. \
             Для таких серверов передай на телефон ссылку на подписку",
            text.len()
        ));
    }
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| format!("QR: {e}"))?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(260, 260)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    #[test]
    fn makes_svg_and_rejects_huge() {
        let s = super::svg("vless://u@h:443?type=tcp#x").unwrap();
        assert!(s.starts_with("<?xml") && s.contains("<svg"));
        assert!(super::svg(&"x".repeat(5000)).is_err());
    }
}
