#!/bin/bash
echo "=== DevOS Update Utility ==="
case "$1" in
    mirrors)
        echo "--> Обновление списка зеркал (самые быстрые в вашей стране)..."
        sudo reflector --country $(curl -s ipinfo.io/country) --latest 20 --sort rate --save /etc/pacman.d/mirrorlist
        echo "--> Готово!"
        ;;
    system)
        echo "--> Поиск обновлений системы..."
        sudo pacman -Syu
        ;;
    *)
        echo "Использование: d-update <команда>"
        echo "Команды:"
        echo "  mirrors   - Оптимизировать список зеркал"
        echo "  system    - Проверить и установить обновления системы"
        ;;
esac