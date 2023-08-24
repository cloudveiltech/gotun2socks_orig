#!/bin/bash
cp goicap /usr/local/bin/goremote

echo "Copying service to /lib/systemd/system/"
sudo cp goremote.service /lib/systemd/system/.
sudo useradd -s /sbin/nologin -M goremote

echo "Copying config to /etc/goremote"
sudo mkdir /etc/goremote
sudo cp config.yml /etc/goremote/.

echo "Enabling service"
sudo chmod 755 /lib/systemd/system/goremote.service
sudo systemctl daemon-reload
sudo systemctl enable goremote.service

echo "Done."
