from flask import Flask, render_template
from scapy.all import ARP, Ether, srp, IP, ICMP
import smtplib
import requests
import socket
import time
from dotenv import load_dotenv

app = Flask(__name__)

# Load any environmental variables from .env
load_dotenv()

# Route to report/contact page
@app.route('/report')
def report():
    return render_template('report.html')


# Function to get hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Function to measure response time
def measure_response_time(ip):
    try:
        start_time = time.time()
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        if result:
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            return f"{response_time:.2f} ms"
    except Exception:
        return "No Response"
    return "No Response"

def guess_role(ip):
    
    if ip == "192.168.1.1":  # Assume router is at 192.168.1.1 (change as per your network)
        return "Router"
    
    # A simple heuristic for switches: Devices with MAC addresses that start with common switch vendors
    switch_vendors = ["00:1B:44", "00:1D:A1", "00:14:22"]  # Example MAC prefix for some vendors
    if any(ip.startswith(vendor) for vendor in switch_vendors):
        return "Switch"
    
    return "Client"  # Default to client if it's not a router or switch

# Function to guess OS based on TTL
def guess_os(ttl):

    if ttl is None:
        return "Unknown"
    try:
        ttl = int(ttl)
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Other/Network Device (e.g., Router)"
    except ValueError:
        return "Invalid TTL"


def get_vendor(mac):
    # Get the API token from the .env file
    API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN")

    try:
        # API URL and Authorization Header
        url = f"https://api.macvendors.com/v1/lookup/{mac}"
        headers = {
        "Authorization": API_AUTH_TOKEN  
        }
        
        # Send the GET request
        response = requests.get(url, headers=headers)
        
        # Log the status code and response for debugging
        if response.status_code == 200:
            data = response.json()  # Parse the JSON response
            company = data.get("company", "Unknown Vendor")
            return company
        elif response.status_code == 404:
            return "Unknown Vendor"
        elif response.status_code == 401:
            return "Unauthorized"
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return "Unknown Vendor"

# Scan function

def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        ttl = None  # Default value for TTL
        try:
            icmp_packet = IP(dst=received.psrc) / ICMP()
            reply = srp(icmp_packet, timeout=1, verbose=0)
            if reply and reply[0]:
                ttl = reply[0][1][IP].ttl
        except Exception as e:
            pass

        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc),
            'response_time': measure_response_time(received.psrc),
            'os': guess_os(ttl),
            'role': guess_role(received.psrc),
            'vendor': get_vendor(received.hwsrc)  # Get the vendor from MAC address
        })

    return devices


@app.route("/")
def index():
    return render_template('index.html')

@app.route("/scan", methods=["GET"])
def scan_devices():
    network = "192.168.1.70/24"  # Replace with your network range
    devices = scan(network)
    # Return the HTML table with devices
    return render_template('devices_table.html', devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
