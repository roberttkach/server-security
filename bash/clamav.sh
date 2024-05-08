#!/bin/bash

# Determine Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "Could not determine your Linux distribution."
    exit 1
fi

# Install ClamAV for Debian/Ubuntu
if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
    sudo apt-get update
    sudo apt-get install clamav clamav-daemon -y
    sudo systemctl stop clamav-daemon
    sudo freshclam
    sudo systemctl start clamav-daemon

# Install ClamAV for CentOS/RHEL
elif [ "$OS" == "CentOS Linux" ] || [ "$OS" == "Red Hat Enterprise Linux" ]; then
    sudo yum install epel-release -y
    sudo yum install clamav clamav-update -y
    sudo freshclam
    sudo systemctl start clamd

# Install ClamAV for Fedora
elif [ "$OS" == "Fedora" ]; then
    sudo dnf install clamav clamav-update -y
    sudo freshclam
    sudo systemctl start clamd

# Install ClamAV for openSUSE
elif [ "$OS" == "openSUSE Leap" ]; then
    sudo zypper install clamav -y
    sudo freshclam
    sudo systemctl start clamd

# Install ClamAV for Arch Linux and Manjaro
elif [ "$OS" == "Arch Linux" ] || [ "$OS" == "Manjaro Linux" ]; then
    sudo pacman -Syu
    sudo pacman -S clamav
    sudo freshclam
    sudo systemctl start clamd.service

# Install ClamAV for Gentoo
elif [ "$OS" == "Gentoo" ]; then
    sudo emerge --sync
    sudo emerge clamav
    sudo freshclam
    sudo rc-service clamd start

# Install ClamAV for Mageia
elif [ "$OS" == "Mageia" ]; then
    sudo urpmi.update -a
    sudo urpmi clamav
    sudo freshclam
    sudo systemctl start clamd

else
    echo "Your Linux distribution ($OS) is not supported by ClamAV."
    exit 1
fi

echo "ClamAV installation completed."
