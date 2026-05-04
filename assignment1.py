import asyncio
import hashlib
from hmac import digest
import logging
import struct
from asyncio import run
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import convert_to_payload

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.util import run_forever
from ipv8_service import IPv8
from ipv8.peer import Peer


EMAIL = "ndobrica@tudelft.nl"
GITHUB_URL = "https://github.com/Nicole1408/BlockchainEngineering/"
SERVER_PUBLIC_KEY = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"

@dataclass
class SubmissionMessage:
    email: str
    github_url: str
    nonce: int

@dataclass
class ResponseMessage:
    success: bool
    message: str

convert_to_payload(SubmissionMessage, msg_id=1)
convert_to_payload(ResponseMessage, msg_id=2)

def proof_of_work(email: str, github_url: str) -> int:
    encoded_email = email.encode("utf-8")
    encoded_github_url = github_url.encode("utf-8")
    beginning_pow = encoded_email + b"\n" + encoded_github_url + b"\n"
    nonce = 0
    while True:
        digest = hashlib.sha256(beginning_pow + struct.pack(">q", nonce)).digest()
        if digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16:
            print(f"Found nonce: {nonce}")
            print(f"Hash: {digest.hex()}")
            print(f"Hash in binary: {bin(int(digest.hex(), 16))[2:].zfill(256)}")
            return nonce
        nonce += 1


class MyCommunity(Community):
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponseMessage, self.on_response)
        self._submitted = False
        self.register_task("find_server", self.find_server, interval = 3.0, delay = 3.0)

    async def find_server(self) -> None:
        if self._submitted:
            return
        server = next((p for p in self.get_peers() if p.public_key.key_to_bin() == bytes.fromhex(SERVER_PUBLIC_KEY)), None)
        if server is None:
            logging.info("Server not found.")
            return
        self._submitted = True
        logging.info("Server found! Mining PoW")
        loop = asyncio.get_event_loop()
        nonce = await loop.run_in_executor(None, proof_of_work, EMAIL, GITHUB_URL)
        logging.info("Nonce found: %d", nonce)
        self.ez_send(server, SubmissionMessage(EMAIL, GITHUB_URL, nonce))

    @lazy_wrapper(ResponseMessage)
    def on_response(self, peer: Peer, payload: ResponseMessage) -> None:
        logging.info("Response: success=%s, message=%s", payload.success, payload.message)

async def start_communities() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", "ec1.pem")
    builder.add_overlay("MyCommunity", "my peer", 
                        [WalkerDefinition(Strategy.RandomWalk,
                                              10, {"timeout": 30.0})],
                            default_bootstrap_defs, {}, [])
    await IPv8(builder.finalize(), extra_communities={"MyCommunity": MyCommunity}).start()
    await run_forever()


run(start_communities())