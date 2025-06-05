#!/bin/bash

echo "[*] Cleaning apt cache..."
apt clean

echo "[*] Removing /tmp files..."
rm -rf /tmp/*

echo "[*] Restarting swap..."
swapoff /data/data/com.termux/files/usr/var/swap
swapon /data/data/com.termux/files/usr/var/swap

echo "[*] Killing zombie bash sessions..."
for pid in $(ps aux | grep bash | awk '{print $2}'); do
  if [ "$pid" != "$$" ]; then
    kill -9 $pid 2>/dev/null
  fi
done

echo "[✓] Done!"
