#!/bin/bash

SPLUNK_URL=$1
SPLUNK_TOKEN=$2
SUDO_USERNAME=$3
SUDO_PASSWORD=$4

export TERM=xterm
export SPLUNK_URL
export SPLUNK_TOKEN
export SUDO_USERNAME
export SUDO_PASSWORD

mkdir -p /home/$SUDO_USERNAME/server-security && cd /home/$SUDO_USERNAME/server-security;

echo $SUDO_PASSWORD | sudo -S chmod 755 .;

for package in libpcap snapd bison gcc make curl; do
    if ! pacman -Q $package; then
        echo "Установка $package...";
        echo $SUDO_PASSWORD | sudo -S pacman -Syu --noconfirm $package
        if pacman -Q $package; then
            echo "$package успешно установлен.";
        else
            echo "Установка $package не удалась.";
            exit 1;
        fi
    else
        echo "$package уже установлен.";
    fi
done

if ! command -v go &> /dev/null; then
    echo "Go не установлен. Установка сейчас...";
    curl -O https://dl.google.com/go/go1.22.2.src.tar.gz;
    tar -xvf go1.22.2.src.tar.gz;
    cd go/src;
    export GOROOT=$HOME/go
    ./make.bash;
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc;
    source ~/.bashrc;
    if command -v go &> /dev/null; then
        echo "Go успешно установлен.";
    else
        echo "Установка Go не удалась.";
        exit 1;
    fi
else
    echo "Go уже установлен.";
fi

if ! go version | grep -q "go1.22.2"; then
    echo "Версия Go не 1.22.2.";
    exit 1;
else
    echo "Версия Go 1.22.2 уже установлена.";
fi


cd /home/$SUDO_USERNAME/server-security;

for script in checkSSL.sh clamav.sh netstat.sh; do
    echo "$SUDO_USERNAME ALL=NOPASSWD:/home/$SUDO_USERNAME/server-security/$script" | sudo EDITOR='tee -a' visudo
done

go mod init server-security;
go mod tidy
