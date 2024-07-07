import logging
import requests
import json
from os import environ

from eth_abi_ext import decode_packed
from eth_abi.abi import encode

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

ERC_20_PORTAL_ADDRESS = "0x9C21AEb2093C32DDbC53eEF24B873BDCd1aDa1DB".lower()
TOKEN_ADDRESS = "0x8464135c8F25Da09e49BC8782676a84730C318bC".lower()

balance = {}
current_bid = 0
current_bidder = None

TRANSFER_FUNCTION_SELECTOR = b'\xa9\x05\x9c\xbb'

def hex2str(h):
    return bytes.fromhex(h[2:]).decode("utf-8")

def str2hex(s):
    return "0x" + s.encode("utf-8").hex()

def post(endpoint, json):
    try:
        response = requests.post(f"{rollup_server}/{endpoint}", json=json)
        logger.info(f"Received {endpoint} status {response.status_code} body {response.content}")
    except Exception as e:
        logger.error(f"Error posting to {endpoint}: {e}")

def handle_erc20_deposit(data):
    binary = bytes.fromhex(data["payload"][2:])
    try:
        decoded = decode_packed(['bool', 'address', 'address', 'uint256'], binary)
    except Exception as e:
        logger.error(f"Error decoding ERC20 deposit payload: {e}")
        return "reject"

    success = decoded[0]
    erc20 = decoded[1]
    depositor = decoded[2]
    amount = decoded[3]

    if depositor not in balance:
        balance[depositor] = {}

    if erc20 not in balance[depositor]:
        balance[depositor][erc20] = 0

    balance[depositor][erc20] += amount
    return "accept"

def handle_bid(sender, payload_dict):
    global current_bid, current_bidder

    erc20 = payload_dict["erc20"].lower()
    amount = payload_dict["amount"]

    if amount <= current_bid:
        raise Exception("Bid is not higher than current highest bid")

    if current_bidder:
        balance[current_bidder][erc20] += current_bid  # Refund the previous highest bidder

    if sender not in balance:
        balance[sender] = {}

    if erc20 not in balance[sender]:
        balance[sender][erc20] = 0

    if balance[sender][erc20] < amount:
        raise Exception(f"User {sender} does not have enough {erc20} tokens.")

    balance[sender][erc20] -= amount
    current_bid = amount
    current_bidder = sender

def handle_end_auction():
    global current_bid, current_bidder

    if current_bidder:
        erc20 = TOKEN_ADDRESS
        transfer_payload = TRANSFER_FUNCTION_SELECTOR + encode(['address', 'uint256'], [current_bidder, current_bid])
        voucher = {"destination": erc20, "payload": "0x" + transfer_payload.hex()}
        post("voucher", voucher)

def handle_withdraw(sender, payload_dict):
    erc20 = payload_dict["erc20"].lower()
    amount = payload_dict["amount"]

    if balance[sender][erc20] < amount:
        raise Exception(f"User {sender} does not have enough {erc20} tokens.")

    transfer_payload = TRANSFER_FUNCTION_SELECTOR + encode(['address', 'uint256'], [sender, amount])
    voucher = {"destination": erc20, "payload": "0x" + transfer_payload.hex()}
    post("voucher", voucher)

def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    try:
        if data["metadata"]["msg-sender"].lower() == ERC_20_PORTAL_ADDRESS:
            return handle_erc20_deposit(data)

        payload_dict = json.loads(hex2str(data["payload"]))
        sender = data["metadata"]["msg-sender"].lower()

        if payload_dict["action"] == "bid":
            handle_bid(sender, payload_dict)
        elif payload_dict["action"] == "withdraw":
            handle_withdraw(sender, payload_dict)
        elif payload_dict["action"] == "end_auction":
            handle_end_auction()
            
    except Exception as e:
        post("report", {"payload": str2hex(str(e))})
        return "reject"
    return "accept"

def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    balance_report = json.dumps(balance)
    post("report", {"payload": str2hex(balance_report)})
    return "accept"

handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
