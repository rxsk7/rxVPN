//! Диагностика: какую сетевую карту rxvpn считает настоящей (для привязки пробных Xray).
// i18n-skip-begin: инструмент автора, не для пользователя.
fn main() {
    let tun = rxvpn_core::xray::TUN_NAME;
    let name = |i: Option<u32>| i.map(|i| format!("{i} «{}»", rxvpn_core::winsys::iface_alias(i).unwrap_or_default()));
    println!("best_interface:     {:?}", name(rxvpn_core::winsys::best_interface()));
    println!("physical_interface: {:?}", name(rxvpn_core::winsys::physical_interface(tun)));
    println!("gateway_interface:  {:?}", name(rxvpn_core::winsys::gateway_interface(tun)));
    println!("local_ipv6:         {}", rxvpn_core::winsys::local_ipv6(tun).len());
}
// i18n-skip-end
