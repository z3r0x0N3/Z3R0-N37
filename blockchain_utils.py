#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Z3R0-N37 blockchain utility — Geth + Clef Sepolia integration
Author: Z3R0
Purpose: compile, deploy, and interact with the C2UrlRegistry.sol contract
"""

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, Optional
from solcx import install_solc, set_solc_version, compile_source
from web3 import Web3

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
C2_RPC_URL = "http://127.0.0.1:7545"  # Local Geth + Clef RPC
C2_ACCOUNT = "0xDC1f9e5d73dCf36e599669e20c8A46B87821Fc9a"
SOLC_VERSION = "0.8.20"
LOCAL_META_FILE = Path("contract_meta.json")
CONTRACT_FILE = Path("C2UrlRegistry.sol")

# ──────────────────────────────────────────────────────────────────────────────
# INITIAL SETUP
# ──────────────────────────────────────────────────────────────────────────────
install_solc(SOLC_VERSION)
set_solc_version(SOLC_VERSION)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# ──────────────────────────────────────────────────────────────────────────────
# CORE CONNECTION UTILITIES
# ──────────────────────────────────────────────────────────────────────────────
def get_web3() -> Web3:
    print(f"🔗 Connecting to blockchain at {C2_RPC_URL} ...")
    w3 = Web3(Web3.HTTPProvider(C2_RPC_URL))
    if not w3.is_connected():
        raise ConnectionError("❌ Could not connect to Geth RPC at 7545.")
    print(f"✅ Connected to {w3.client_version}")
    w3.eth.default_account = C2_ACCOUNT
    print(f"Using default account: {C2_ACCOUNT}")
    try:
        bal = w3.eth.get_balance(C2_ACCOUNT)
        print(f"Account balance: {w3.from_wei(bal, 'ether')} ETH")
    except Exception:
        print("⚠️  Unable to fetch account balance (possibly not funded yet).")
    return w3

# ──────────────────────────────────────────────────────────────────────────────
# CONTRACT COMPILATION / DEPLOYMENT
# ──────────────────────────────────────────────────────────────────────────────
def compile_contract(source_code: str) -> dict:
    print("🧩 Compiling Solidity contract (London EVM target)...")
    compiled = compile_source(
        source_code,
        output_values=["abi", "bin"],
        solc_version="0.8.20",
        evm_version="london"   # 👈 Add this line
    )
    _, interface = compiled.popitem()
    print("✅ Compilation successful.")
    return interface



def deploy_contract(w3: Web3, contract_interface: dict) -> str:
    print("🚀 Deploying smart contract ...")
    contract = w3.eth.contract(
        abi=contract_interface["abi"],
        bytecode=contract_interface["bin"]
    )
    tx_hash = contract.constructor().transact({"from": C2_ACCOUNT})
    print(f"⏳ Waiting for transaction receipt: {tx_hash.hex()}")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if not tx_receipt or not tx_receipt.contractAddress:
        raise RuntimeError("❌ Deployment failed or no contract address returned.")
    address = tx_receipt.contractAddress
    print(f"✅ Contract deployed at: {address}")
    return address


def save_contract_metadata(address: str, abi: dict) -> None:
    data = {"address": address, "abi": abi}
    LOCAL_META_FILE.write_text(json.dumps(data, indent=2))
    print(f"💾 Saved metadata → {LOCAL_META_FILE}")


def load_contract_metadata() -> Optional[dict]:
    if not LOCAL_META_FILE.exists():
        print("⚠️  contract_meta.json not found.")
        return None
    return json.loads(LOCAL_META_FILE.read_text())


def get_contract_instance(w3: Web3, address: str, abi: dict):
    return w3.eth.contract(address=address, abi=abi)


# ──────────────────────────────────────────────────────────────────────────────
# CONTRACT INTERACTIONS
# ──────────────────────────────────────────────────────────────────────────────
def set_c2_url(contract_instance, w3, new_url: str):
    print(f"🌐 Setting C2 URL → {new_url}")
    tx_hash = contract_instance.functions.setC2Url(new_url).transact({"from": C2_ACCOUNT})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print("✅ C2 URL updated on-chain.")


def get_c2_url(contract_instance) -> str:
    print("🔍 Fetching current C2 URL ...")
    try:
        url = contract_instance.functions.getC2Url().call()
        print(f"Current C2 URL: {url}")
        return url
    except Exception as e:
        print(f"❌ Failed to read C2 URL: {e}")
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ──────────────────────────────────────────────────────────────────────────────
def main():
    try:
        if not CONTRACT_FILE.exists():
            raise FileNotFoundError(f"❌ Missing Solidity file: {CONTRACT_FILE}")

        solidity_code = CONTRACT_FILE.read_text()
        w3 = get_web3()
        contract_interface = compile_contract(solidity_code)
        contract_addr = deploy_contract(w3, contract_interface)
        save_contract_metadata(contract_addr, contract_interface["abi"])
        print("✅ Deployment complete and metadata written.")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()

