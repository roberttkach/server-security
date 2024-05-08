#!/bin/bash

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "Не удалось определить ваш дистрибутив Linux."
    exit 1
fi

# Установка net-tools (включает netstat) для Debian/Ubuntu
if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
    sudo apt-get update
    sudo apt-get install net-tools -y

# Установка net-tools для CentOS/RHEL
elif [ "$OS" == "CentOS Linux" ] || [ "$OS" == "Red Hat Enterprise Linux" ]; then
    sudo yum install net-tools -y

# Установка net-tools для Fedora
elif [ "$OS" == "Fedora" ]; then
    sudo dnf install net-tools -y

# Установка net-tools для openSUSE
elif [ "$OS" == "openSUSE Leap" ]; then
    sudo zypper install net-tools -y

# Установка net-tools для Arch Linux и Manjaro
elif [ "$OS" == "Arch Linux" ] || [ "$OS" == "Manjaro Linux" ]; then
    sudo pacman -Syu
    sudo pacman -S net-tools

# Установка net-tools для Gentoo
elif [ "$OS" == "Gentoo" ]; then
    sudo emerge --sync
    sudo emerge net-tools

# Установка net-tools для Mageia
elif [ "$OS" == "Mageia" ]; then
    sudo urpmi.update -a
    sudo urpmi net-tools

else
    echo "Ваш дистрибутив Linux ($OS) не поддерживает net-tools."
    exit 1
fi

echo "Установка net-tools завершена."
