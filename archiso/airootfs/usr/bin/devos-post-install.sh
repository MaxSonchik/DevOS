#!/bin/bash

snapper -c root create-config /

btrfs subvolume delete /.snapshots

sed -i 's/GRUB_BTRFS_SUBMENUNAME="Snapshots"/GRUB_BTRFS_SUBMENUNAME="Резервные копии системы"/g' /etc/default/grub-btrfs/config

grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=DevOS

grub-mkconfig -o /boot/grub/grub.cfg

systemctl enable snapper-cleanup.timer
systemctl enable grub-btrfs.path