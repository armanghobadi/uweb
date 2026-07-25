import network
import time
import uasyncio as asyncio
from uweb import UWeb

# ==================== WiFi Settings ====================
WIFI_SSID = "SSID"
WIFI_PASSWORD = "PASS"

# ==================== Connect to WiFi ====================
def connect_wifi(ssid, password, timeout=20):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if wlan.isconnected():
        ip = wlan.ifconfig()[0]
        print("Already connected to WiFi")
        print("IP Address:", ip)
        return wlan, ip

    print(f"Connecting to {ssid} ...")
    wlan.connect(ssid, password)

    start = time.time()
    while not wlan.isconnected():
        if time.time() - start > timeout:
            print("Error: Failed to connect to WiFi")
            return None, None
        print(".", end="")
        time.sleep(0.5)

    ip = wlan.ifconfig()[0]
    print("\nConnected successfully!")
    print("=================================")
    print("  IP Address:", ip)
    print("=================================")
    return wlan, ip


# Connect to WiFi and get IP
wlan, device_ip = connect_wifi(WIFI_SSID, WIFI_PASSWORD)

if device_ip is None:
    print("Cannot start server without WiFi connection")
    raise SystemExit

# ==================== Create UWeb App ====================
app = UWeb(secret_key="your-super-secret-key-change-me", debug=True)

@app.get("/")
def home(req):
    html = f"""
    <html>
    <head><title>UWeb Device</title></head>
    <body style="font-family: Arial; text-align: center; margin-top: 50px;">
        <h1>Hello from UWeb!</h1>
        <h2>Device IP: <span style="color: green;">{device_ip}</span></h2>
        <p>Server is running on port 80</p>
    </body>
    </html>
    """
    return app.html(html)

@app.get("/api/hello/<name:str>")
def hello(req, name):
    return {"message": f"Hello, {name}!", "ip": device_ip}

@app.get("/api/info")
def info(req):
    return {
        "ip": device_ip,
        "ssid": WIFI_SSID,
        "status": "online"
    }



# Run the server
print(f"Starting UWeb server at http://{device_ip}:80")
asyncio.run(app.run(host="0.0.0.0", port=80))