
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, Optional

import solcx
from solcx import compile_source
from web3 import Web3

try:
    from web3 import EthereumTesterProvider
except ImportError:  # pragma: no cover - optional dependency
    EthereumTesterProvider = None  # type: ignore

solcx.install_solc('0.8.20')
solcx.set_solc_version('0.8.20')

logger = logging.getLogger(__name__)

DEFAULT_BLOCKCHAIN_URL = "http://127.0.0.1:7545"
BLOCKCHAIN_URL_ENV = "C2_BLOCKCHAIN_URL"
LOCAL_STATE_FILE = Path(__file__).resolve().with_name(".local_c2_registry.json")
LOCAL_CONTRACT_ADDRESS = "0xLOCALC2REGISTRY"


class _LocalCall:
    def __init__(self, fn):
        self._fn = fn

    def call(self):
        return self._fn()


class _LocalTransact:
    def __init__(self, fn):
        self._fn = fn

    def transact(self, tx_params=None):
        return self._fn(tx_params)


class _LocalContractFunctions:
    def __init__(self, contract: "LocalContract"):
        self._contract = contract

    def setC2Url(self, new_url: str):
        def _commit(_tx_params=None):
            self._contract.web3._set_state(self._contract.address, "c2_url", new_url)
            tx_hash = f"local-tx-{uuid.uuid4().hex}"
            self._contract.web3._last_tx_receipt = {"contractAddress": self._contract.address, "status": 1}
            return tx_hash
        return _LocalTransact(_commit)

    def getC2Url(self):
        return _LocalCall(lambda: self._contract.web3._get_state(self._contract.address, "c2_url"))


class _LocalContractConstructor:
    def __init__(self, contract: "LocalContract"):
        self._contract = contract

    def transact(self, tx_params=None):
        address = self._contract.web3._register_contract()
        self._contract.address = address
        tx_hash = f"local-deploy-{uuid.uuid4().hex}"
        self._contract.web3._last_tx_receipt = {"contractAddress": address, "status": 1}
        return tx_hash


class LocalContract:
    def __init__(self, web3: "LocalWeb3", address: Optional[str] = None):
        self.web3 = web3
        self.address = address or LOCAL_CONTRACT_ADDRESS
        self.functions = _LocalContractFunctions(self)

    def constructor(self):
        return _LocalContractConstructor(self)


class LocalEth:
    def __init__(self, web3: "LocalWeb3"):
        self.web3 = web3
        self.accounts = ["0xLOCALACCOUNT000000000000000000000000000000"]
        self.default_account = self.accounts[0]

    def contract(self, abi=None, bytecode=None, address=None):
        return LocalContract(self.web3, address=address or LOCAL_CONTRACT_ADDRESS)

    def wait_for_transaction_receipt(self, tx_hash):
        return getattr(self.web3, "_last_tx_receipt", {"status": 1, "transactionHash": tx_hash})


class LocalWeb3:
    def __init__(self, state_path: Path):
        self._state_path = state_path
        self._state: Dict[str, Dict[str, str]] = self._load_state()
        self._last_tx_receipt = None
        self.eth = LocalEth(self)

    def _load_state(self) -> Dict[str, Dict[str, str]]:
        if self._state_path.exists():
            try:
                with self._state_path.open('r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                logger.warning("Failed to load local blockchain state; starting fresh.")
        return {}

    def _persist(self) -> None:
        try:
            with self._state_path.open('w', encoding='utf-8') as fh:
                json.dump(self._state, fh, indent=2)
        except Exception:
            logger.exception("Failed to persist local blockchain state.")

    def _register_contract(self) -> str:
        address = LOCAL_CONTRACT_ADDRESS
        self._state.setdefault(address, {})
        self._persist()
        return address

    def _set_state(self, address: str, key: str, value: str) -> None:
        self._state.setdefault(address, {})[key] = value
        self._persist()

    def _get_state(self, address: str, key: str):
        return self._state.get(address, {}).get(key)


def _local_web3() -> LocalWeb3:
    logger.info("Using local JSON-backed blockchain stub.")
    return LocalWeb3(LOCAL_STATE_FILE)


def _is_connected(w3: Web3) -> bool:
    if hasattr(w3, "is_connected"):
        return w3.is_connected()  # type: ignore[attr-defined]
    return w3.isConnected()


def _prime_default_account(w3: Web3) -> None:
    try:
        accounts = w3.eth.accounts
    except Exception:  # pragma: no cover - provider dependent
        return
    if accounts:
        w3.eth.default_account = accounts[0]


def get_web3(preferred_url: Optional[str] = None) -> Web3:
    """
    Return a Web3 instance, preferring the configured HTTP endpoint and falling
    back to an in-memory Ethereum tester when the endpoint is unavailable.
    """
    http_url = preferred_url or os.environ.get(BLOCKCHAIN_URL_ENV, DEFAULT_BLOCKCHAIN_URL)
    provider = Web3.HTTPProvider(http_url, request_kwargs={"timeout": 5})
    w3 = Web3(provider)

    try:
        if _is_connected(w3):
            logger.debug("Connected to blockchain at %s", http_url)
            _prime_default_account(w3)
            return w3
        logger.warning("Blockchain endpoint %s unreachable; attempting tester fallback.", http_url)
    except Exception as exc:
        logger.warning("Failed connecting to %s (%s); attempting tester fallback.", http_url, exc)

    if EthereumTesterProvider is None:
        return _local_web3()

    try:
        tester_w3 = Web3(EthereumTesterProvider())
    except Exception as exc:  # pragma: no cover - provider dependent
        logger.warning("Failed to initialise Ethereum tester backend (%s); using local stub.", exc)
        return _local_web3()

    logger.info("Using in-memory Ethereum tester backend for blockchain interactions.")
    _prime_default_account(tester_w3)
    return tester_w3


def compile_contract(solidity_source):
    compiled_sol = compile_source(solidity_source)
    contract_id, contract_interface = compiled_sol.popitem()
    return contract_interface


def deploy_contract(w3, contract_interface):
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )
    tx_hash = contract.constructor().transact({'from': w3.eth.accounts[0]})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = getattr(tx_receipt, "contractAddress", None)
    if contract_address is None and isinstance(tx_receipt, dict):
        contract_address = tx_receipt.get("contractAddress")
    if not contract_address:
        raise RuntimeError("Failed to obtain contract address from deployment receipt.")
    return contract_address


def get_contract_instance(w3, contract_address, contract_abi):
    return w3.eth.contract(address=contract_address, abi=contract_abi)


def set_c2_url(contract_instance, w3, new_url):
    tx_hash = contract_instance.functions.setC2Url(new_url).transact({'from': w3.eth.accounts[0]})
    w3.eth.wait_for_transaction_receipt(tx_hash)


def get_c2_url(contract_instance):
    return contract_instance.functions.getC2Url().call()


if __name__ == '__main__':
    with open('C2UrlRegistry.sol', 'r') as f:
        solidity_source = f.read()

    web3_instance = get_web3()
    contract_interface = compile_contract(solidity_source)
    contract_address = deploy_contract(web3_instance, contract_interface)

    print(f"Contract deployed at: {contract_address}")

    with open('contract_meta.json', 'w') as f:
        json.dump({
            'address': contract_address,
            'abi': contract_interface['abi']
        }, f)
