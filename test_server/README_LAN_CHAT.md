
# LAN Secure Chat on Raspberry Pi (Hotspot + Local Server)

This merges your `bdd.py` messenger (Flask + SQLite + templates) with signaling + account API into **one** Flask app with Socket.IO: `lan_chat_server.py`.

## Layout
Place files like this on the Pi:
```
project/
  lan_chat_server.py
  templates/
    login.html
    code.html
    messagerie.html
    register.html
    index.html
```

## Install & Run
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
python3 -m venv venv && source venv/bin/activate
pip install --upgrade pip
pip install flask flask-socketio eventlet flask-cors pynacl itsdangerous
python lan_chat_server.py
```

## Hotspot (quick sketch)
Install: `sudo apt install hostapd dnsmasq` then configure:
- Give wlan0 static `10.0.0.1/24`
- dnsmasq DHCP range `10.0.0.100-10.0.0.200`
- hostapd SSID `LAN-Chat`, WPA2 pass
Start: `sudo systemctl restart dnsmasq hostapd`
Clients open `http://10.0.0.1:5000/`.
