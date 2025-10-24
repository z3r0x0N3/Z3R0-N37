
import json
import logging
import os
from typing import Optional

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
        raise ConnectionError(
            f"Unable to reach blockchain endpoint at {http_url} and ethereum tester backend is unavailable. "
            f"Ensure the service is running or install eth-tester."
        )

    try:
        tester_w3 = Web3(EthereumTesterProvider())
    except Exception as exc:  # pragma: no cover - provider dependent
        raise ConnectionError(
            f"Unable to reach blockchain endpoint at {http_url} and failed to initialise Ethereum tester backend."
        ) from exc

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
    return tx_receipt.contractAddress


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
