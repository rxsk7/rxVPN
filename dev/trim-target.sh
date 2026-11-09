#!/bin/sh
# Подрезать target: каждая новая версия rxvpn оставляет в target старые копии наших
# крейтов (у них в имени хеш версии — cargo их сам не удаляет), и папка растёт на
# сотни мегабайт за релиз. Убираем только наши крейты: зависимости остаются в кэше,
# следующая сборка не начнётся с нуля.
# Запуск: sh dev/trim-target.sh   (из папки репозитория, когда ничего не собирается)
set -e
cd "$(dirname "$0")/.."
before=$(du -sh target 2>/dev/null | cut -f1)
for prof in "" "--release"; do
    cargo clean -q $prof -p rxvpn -p rxvpn-core -p rxvpn-i18n-macros
done
rm -rf target/debug/incremental
echo "target: было $before, стало $(du -sh target | cut -f1)"
