#!/bin/bash
echo "Copiin service to /lib/systemd/system/\n"
sudo cp goremote.service /lib/systemd/system/.

echo "Copiing config to /etc/goremote\n"
sudo mkdir /etc/goremote
sudo cp config.yml /etc/goremote/.

echo "Enabling service\n"
sudo chmod 755 /lib/systemd/system/goremote.service
sudo systemctl daemon-reload
sudo systemctl enable sleepservice.service

echo "Done."