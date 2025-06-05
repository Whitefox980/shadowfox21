#!/data/data/com.termux/files/usr/bin/bash

# Clear cache
echo "🧹 Čistim cache..."
sync; echo 3 > /proc/sys/vm/drop_caches

# Resetuj swap
echo "🔁 Resetujem swap..."
swapoff -a && swapon -a

# Očisti velike JSON izveštaje preko 5MB
echo "🗑️ Brišem stare izveštaje preko 5MB..."
find reports/ -type f -name "*.json" -size +5M -delete

echo "✅ Gotovo."
