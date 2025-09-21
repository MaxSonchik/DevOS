#!/bin/bash
set -e

# Путь уже настроен для работы внутри Docker-контейнера этого пайплайна
AIROOTFS_PATH="/data/archiso/airootfs"

echo ">>> Настройка автозапуска Calamares..."

if [ ! -d "$AIROOTFS_PATH" ]; then
    echo "ОШИБКА: Директория '$AIROOTFS_PATH' не найдена!"
    exit 1
fi

echo "    [1/3] Создание файла /etc/systemd/system/calamares.service"
cat <<EOF > "${AIROOTFS_PATH}/etc/systemd/system/calamares.service"
[Unit]
Description=Calamares Installer
After=graphical.target

[Service]
Type=simple
ExecStart=/usr/bin/calamares -d
Restart=on-failure
User=root
Environment=DISPLAY=:0

[Install]
WantedBy=graphical.target
EOF

# Используем chroot для выполнения команд внутри live-окружения
echo "    [2/3] Отключение сервиса GDM внутри chroot..."
chroot "${AIROOTFS_PATH}" systemctl disable gdm.service

echo "    [3/3] Включение сервиса Calamares внутри chroot..."
chroot "${AIROOTFS_PATH}" systemctl enable calamares.service

echo ">>> Настройка автозапуска успешно завершена!"