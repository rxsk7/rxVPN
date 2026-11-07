fn main() {
    // Английские строки подставляются при компиляции (rxvpn-i18n-macros) — пересобрать при правке перевода.
    println!("cargo:rerun-if-changed=../locales/en.json");
}
