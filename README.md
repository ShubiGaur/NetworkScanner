# NetworkScanner
A Python-based network scanner using Flask and Scapy.

DISCLAIMER: 
This tool is for educational and testing purposes only. Unauthorized network scanning may violate laws or regulations. Use responsibly and only on networks you own or have explicit permission to scan.

** Currently doing more testing to make it compatible on Mac/Apple devices...So far, installing libpcap with "brew install libpcap" seems to solve the issue but it's not * * 100% guaranteed * *  
Note: This will only work on LANs! Public networks often have advanced security configurations, and it is a violation of privacy to access them without permission.

---
**Features:**

- Scan devices on your local network.
- Retrieve information such as IP address, MAC address, hostname, and other device details.
- Simple and intuitive browser-based interface.

---
**Prerequisites:**  
Ensure you have the following installed on your system:

- Python 3.8+
- pip (Python package manager)

---
**Installation:**

**Clone the Repository**  
Run the following command to clone the repository to your local machine:
> git clone https://github.com/ShubiGaur/NetworkScanner

**Install Dependencies**  
Navigate to the project directory and install the required Python packages:
>pip install -r requirements.txt

**Starting App**  
Run the following command to start the Flask server:
>python app.py

**Access the Application**    
Once the server is running, you will see a server link in the terminal output (e.g., http://127.0.0.1:5000). 
Click the link or copy it into your browser to access the network scanner.

