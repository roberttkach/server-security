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

for package in libpcap-devel snapd bison gcc make curl; do
    if ! rpm -q $package; then
        echo $SUDO_PASSWORD | sudo -S dnf install -y $package
    fi
done

if ! command -v go &> /dev/null || ! go version | grep -q "go1.22.2"; then
    echo $SUDO_PASSWORD | sudo -S dnf install -y golang;
    if go version | grep -q "go1.22.2"; then
        echo "Go installed successfully.";
    else
        echo "Go installation failed.";
        exit 1;
    fi
fi

cd /home/$SUDO_USERNAME/server-security;

for script in checkSSL.sh clamav.sh netstat.sh; do
    echo "$SUDO_USERNAME ALL=NOPASSWD:/home/$SUDO_USERNAME/server-security/$script" | sudo EDITOR='tee -a' visudo
done

go mod init server-security;
go mod tidy
