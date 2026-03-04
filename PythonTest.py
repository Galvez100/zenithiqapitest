from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import urllib3
import socket
from urllib.parse import urlparse
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app) 

IMASTER_IP = os.getenv("IMASTER_IP", "119.8.11.5:18002")
API_USERNAME = os.getenv("API_USERNAME", "Ziqapis")
API_PASSWORD = os.getenv("API_PASSWORD", "Huawei123..")

def format_mac_colon(mac_str):
    if not mac_str: return ""
    clean_mac = mac_str.replace(":", "").replace("-", "").upper()
    return ":".join(clean_mac[i:i+2] for i in range(0, 12, 2))

def format_mac_hyphen(mac_str):
    if not mac_str: return ""
    clean_mac = mac_str.replace(":", "").replace("-", "").upper()
    return "-".join(clean_mac[i:i+2] for i in range(0, 12, 2))

@app.route('/authorize', methods=['POST'])
def authorize_user():
    data = request.get_json()
    
    # --- ADD THESE PRINT STATEMENTS FOR LOGGING ---
    print("----- NEW AUTHORIZATION REQUEST -----")
    print(f"Received payload: {data}")
    # ----------------------------------------------
    
    try:
        if not data.get('userMac') or not data.get('apMac'):
            print("Error: Missing MAC addresses in payload") # Log this too
            return jsonify({"status": "error", "message": "Missing required MAC addresses"}), 400

        print(f"Attempting to contact iMaster at {IMASTER_IP}...") # Log the connection attempt
        
        token_url = f"https://{IMASTER_IP}/controller/v2/tokens"
        auth_payload = {"userName": API_USERNAME, "password": API_PASSWORD}
        
        token_response = requests.post(token_url, json=auth_payload, verify=False, timeout=10)
        if token_response.status_code != 200:
            return jsonify({"status": "error", "message": "Failed to get API token"}), 401
            
        token = token_response.json().get('data', {}).get('token_id')

        user_mac_formatted = format_mac_hyphen(data.get('userMac'))
        ap_mac_formatted = format_mac_colon(data.get('apMac'))
        b64_ssid = data.get('ssid', '') # Passed directly, AP already encoded it

        raw_node_ip = data.get('nodeIp', '')
        if raw_node_ip.startswith('http'):
            clean_node_ip = urlparse(raw_node_ip).hostname
            try:
                final_node_ip = socket.gethostbyname(clean_node_ip)
            except Exception:
                final_node_ip = clean_node_ip 
        else:
            final_node_ip = raw_node_ip

        auth_url = f"https://{IMASTER_IP}/controller/cloud/v2/northbound/accessuser/haca/authorization"
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-ACCESS-TOKEN": token
        }
        
        haca_payload = {
            "deviceMac": ap_mac_formatted,
            "apMac": ap_mac_formatted,
            "ssid": b64_ssid,
            "terminalIpV4": data.get('userIp'),
            "terminalMac": user_mac_formatted,
            "userName": "api.sop",  
            "nodeIp": final_node_ip
        }
        
        auth_response = requests.post(auth_url, json=haca_payload, headers=headers, verify=False, timeout=10)
        
        if auth_response.status_code == 200:
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "iMaster rejected: " + auth_response.text}), 400

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
