import json
import os
from web3 import Web3
from blockchain_utils import get_contract_instance, get_c2_url, DEFAULT_BLOCKCHAIN_URL

def check_contract():
    try:
        http_url = os.getenv("C2_BLOCKCHAIN_URL", DEFAULT_BLOCKCHAIN_URL)
        print(f"Attempting to connect to blockchain at: {http_url}")

        with open('contract_meta.json', 'r') as f:
            contract_meta = json.load(f)

        w3 = Web3(Web3.HTTPProvider(http_url))
        if not w3.is_connected():
            print("Failed to connect to the blockchain.")
            return

        print("Connected. Current block:", w3.eth.block_number)
        contract_instance = get_contract_instance(w3, contract_meta['address'], contract_meta['abi'])
        c2_url = get_c2_url(contract_instance)

        if c2_url:
            print(f"✅ Successfully retrieved C2 URL: {c2_url}")
        else:
            print("⚠️  Contract reachable but C2 URL not yet set.")

    except FileNotFoundError:
        print("❌ contract_meta.json not found — has the contract been deployed?")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    check_contract()

