#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="devos"
iso_label="DEVOS_$(date +%Y%m)"
iso_publisher="DevOS Project <https://your-website.com>"
iso_application="DevOS Linux"
iso_version="$(date +%Y.%m.%d)"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux.mbr' 'bios.syslinux.eltorito'
           'uefi-x64.systemd-boot.esp' 'uefi-x64.systemd-boot.eltorito')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_tool_options=('-comp' 'zstd' '-b' '1M')
file_permissions=(
  #["/etc/shadow"]="0:0:400"
)