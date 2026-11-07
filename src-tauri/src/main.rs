// В релизной сборке не показываем чёрное окно консоли на Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    rxvpn_lib::run()
}
