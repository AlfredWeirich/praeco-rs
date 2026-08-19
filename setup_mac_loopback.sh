#!/bin/bash
# ==============================================================================
# macOS Local Loopback Setup für Praeco SNI-Routing
# ==============================================================================
# macOS aktiviert standardmäßig nur 127.0.0.1. 
# Da wir für das lokale Testen des mTLS SNI-Routings unterschiedliche 
# IP-Adressen (127.0.0.2 - 127.0.0.5) benötigen, um das HTTP/2 
# Connection-Coalescing des Browsers zu verhindern, müssen diese 
# temporär hinzugefügt werden.
# ==============================================================================

echo "Füge lokale Loopback-Aliase für Praeco-Testing hinzu..."
echo "Es wird das Administrator-Passwort (sudo) benötigt."

sudo ifconfig lo0 alias 127.0.0.2 up
sudo ifconfig lo0 alias 127.0.0.3 up
sudo ifconfig lo0 alias 127.0.0.4 up
sudo ifconfig lo0 alias 127.0.0.5 up

echo "✅ Fertig! Die lokalen IP-Adressen sind nun aktiv."
echo "Tipp: Nach einem Neustart deines Macs müssen diese Aliase erneut ausgeführt werden."
