import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import math
import os
import random
import re
import secrets
import time
import uuid
import httpx
from urllib.parse import urlparse, parse_qs, quote
import jwt
import pkce
import websockets

_LOGGER = logging.getLogger(__name__)

from aiokevoplus.const import (
    CLIENT_ID,
    CLIENT_SECRET,
    LOCK_STATE_LOCK,
    LOCK_STATE_UNLOCK,
    TENANT_ID,
    UNIKEY_API_URL_BASE,
    UNIKEY_INVALID_LOGIN_URL,
    UNIKEY_LOGIN_URL_BASE,
    UNIKEY_WS_URL_BASE,
)


class KevoError(Exception):
    pass


class KevoAuthError(KevoError):
    pass


class KevoApi:
    def __init__(self, device_id=None):
        self._expires_at = 0
        self._refresh_token = None
        self._id_token = None
        self._access_token = None
        self._user_id = None
        self._device_id = device_id
        self._websocket_task = None
        self._callbacks = []

        if self._device_id is None:
            self._device_id = uuid.uuid4()

    def __generate_websocket_verification(self, cnonce, snonce):
        """Generate the verification value used to connect to the websocket."""
        snonce_bytes = base64.b64decode(snonce)
        cnonce_bytes = base64.b64decode(cnonce)
        secret_bytes = base64.b64decode(CLIENT_SECRET)

        total_bytes = snonce_bytes
        total_bytes += cnonce_bytes
        sign = hmac.new(secret_bytes, total_bytes, hashlib.sha512).digest()

        return base64.b64encode(sign).decode()

    def __generate_certificate(self):
        """Generate a device certificate."""

        def int_val(byte_val):
            e = []
            r = 0
            while True:
                e.append(255 & byte_val)
                byte_val >>= 8
                r += 1
                if r >= 4:
                    break
            return e

        def short_val(byte_val):
            e = []
            r = 0
            while True:
                e.append(255 & byte_val)
                byte_val >>= 8
                r += 1
                if r >= 2:
                    break
            return e

        def random_bytes(byte_val):
            e = []
            for _ in range(byte_val):
                e.append(math.floor(255 * random.random()))
            return e

        def uuid_to_bytes(guid: str):
            guid_parts = guid.split("-")
            result_list = []

            def map_the_thing(element, index):
                list_of_parts = None
                if index < 3:
                    list_of_parts = list(reversed(re.findall(".{1,2}", element)))
                else:
                    list_of_parts = re.findall(".{1,2}", element)

                [result_list.append(int(element, 16)) for element in list_of_parts]

            [map_the_thing(element, index) for index, element in enumerate(guid_parts)]
            return list(reversed(result_list))

        def length_encoded_bytes(byte_val, byte_array):
            result = [byte_val]
            result.extend(short_val(len(byte_array)))
            result.extend(byte_array)
            return result

        e = int(time.time())
        s = [17, 1, 0, 1, 19, 1, 0, 1, 16, 1, 0, 48]
        s.extend(length_encoded_bytes(18, int_val(1)))
        s.extend(length_encoded_bytes(20, int_val(e)))
        s.extend(length_encoded_bytes(21, int_val(e)))
        s.extend(length_encoded_bytes(22, int_val(e + 86400)))
        s.extend([48, 1, 0, 6])
        s.extend(
            length_encoded_bytes(
                49, uuid_to_bytes("00000000-0000-0000-0000-000000000000")
            )
        )
        s.extend(length_encoded_bytes(50, uuid_to_bytes(str(self._device_id))))
        s.extend(length_encoded_bytes(53, random_bytes(32)))
        s.extend(length_encoded_bytes(54, random_bytes(32)))
        result = base64.b64encode(bytearray(s)).decode()
        return result

    async def __get_server_nonce(self):
        """Retrieve a server nonce."""
        client = httpx.AsyncClient()
        client.headers = {"Content-Type": "application/json"}
        res = await client.post(
            UNIKEY_API_URL_BASE + "/api/v2/nonces",
            json={"headers": {"Accept": "application/json"}},
        )
        res.raise_for_status()

        return res.headers["x-unikey-nonce"]

    def __get_client_nonce(self):
        """Generate a client nonce."""
        return base64.b64encode(secrets.token_bytes(64)).decode()

    async def async_refresh_token(self):
        """Refresh the access token."""
        client = httpx.AsyncClient()
        post_params = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }
        res = await client.post(
            UNIKEY_LOGIN_URL_BASE + "/connect/token", data=post_params
        )
        res.raise_for_status()
        json_response = res.json()
        self._access_token = json_response["access_token"]
        self._id_token = json_response["id_token"]
        self._refresh_token = json_response["refresh_token"]
        self._expires_at = time.time() + json_response["expires_in"]

    async def _api_post(self, url, body):
        """POST to the API."""
        client = httpx.AsyncClient()
        cnonce = self.__get_client_nonce()
        snonce = await self.__get_server_nonce()

        # Reauth if needed
        if self._expires_at < time.time() + 100:
            await self.async_refresh_token()

        headers = {
            "X-unikey-cnonce": cnonce,
            "X-unikey-context": "Web",
            "X-unikey-nonce": snonce,
            "Authorization": "Bearer " + self._access_token,
            "Accept": "application/json",
        }

        res = await client.post(
            UNIKEY_API_URL_BASE + url,
            headers=headers,
            json=body,
        )
        res.raise_for_status()
        return res.json()

    async def get_locks(self):
        """Retrieve the list of available locks."""
        client = httpx.AsyncClient()
        cnonce = self.__get_client_nonce()
        snonce = await self.__get_server_nonce()

        headers = {
            "X-unikey-cnonce": cnonce,
            "X-unikey-context": "Web",
            "X-unikey-nonce": snonce,
            "Authorization": "Bearer " + self._access_token,
            "Accept": "application/json",
        }
        res = await client.get(
            UNIKEY_API_URL_BASE + "/api/v2/users/" + self._user_id + "/locks",
            headers=headers,
        )
        res.raise_for_status()
        json_response = res.json()
        lock_response = json_response["locks"]
        self._devices = []

        for lock in lock_response:
            self._devices.append(
                KevoLock(
                    self,
                    lock["id"],
                    lock["name"],
                    lock["firmwareVersion"],
                    lock["batteryLevel"],
                    lock["boltState"],
                )
            )
        return self._devices

    async def login(self, username, password):
        """Login to the API."""
        client = httpx.AsyncClient()
        code_verifier, code_challenge = pkce.generate_pkce_pair()
        certificate = self.__generate_certificate()
        md5hash = hashlib.md5(os.urandom(32))
        state = md5hash.hexdigest()
        res = await client.get(
            UNIKEY_LOGIN_URL_BASE + "/connect/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": "https://mykevo.com/#/token",
                "response_type": "code",
                "scope": "openid email profile identity.api tumbler.api tumbler.ws offline_access",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "response_mode": "query",
                "acr_values": f"\n    appId:{CLIENT_ID}\n    tenant:{TENANT_ID}\n    tenantCode:KWK\n    tenantClientId:{CLIENT_ID}\n    loginContext:Web\n    deviceType:Browser\n    deviceName:Chrome,(Windows)\n    deviceMake:Chrome,108.0.0.0\n    deviceModel:Windows,10\n    deviceVersion:rp-1.0.2\n    staticDeviceId:{self._device_id}\n    deviceCertificate:{certificate}\n    isDark:false",
            },
        )

        if res.status_code == 302:
            redirect_location = res.headers["Location"]
            client.cookies = res.cookies
            res = await client.get(redirect_location)
            res.raise_for_status()
            body_text = res.text
            request_verification_token = next(
                re.finditer(
                    '<input name="__RequestVerificationToken" .+ value="(.+?)"',
                    body_text,
                )
            ).group(1)
            serialized_client = html.unescape(
                next(
                    re.finditer(
                        '<input .+ name="SerializedClient" value="(.+?)"',
                        body_text,
                    )
                ).group(1)
            )
            client.cookies = res.cookies

            res = await client.post(
                UNIKEY_LOGIN_URL_BASE + "/account/login",
                data={
                    "SerializedClient": serialized_client,
                    "NumFailedAttempts": 0,
                    "Username": username,
                    "Password": password,
                    "login": "",
                    "__RequestVerificationToken": request_verification_token,
                },
            )
            if res.status_code == 302:
                redirect_location = res.headers["Location"]
                # Rather than get an exception when auth fails, we get here.
                if redirect_location == UNIKEY_INVALID_LOGIN_URL:
                    raise KevoAuthError()
                client.cookies = res.cookies
                res = await client.get(UNIKEY_LOGIN_URL_BASE + redirect_location)
                if res.status_code == 302:
                    redirect_location = res.headers["Location"]
                    redirect_url = urlparse(redirect_location)
                    redirect_fragment = redirect_url.fragment
                    redirect_fragment_url = urlparse(redirect_fragment)
                    query_params = parse_qs(redirect_fragment_url.query)
                    client.cookies = res.cookies

                    post_params = {
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "code": query_params["code"],
                        "code_verifier": code_verifier,
                        "grant_type": "authorization_code",
                        "redirect_uri": "https://mykevo.com/#/token",
                    }
                    res = await client.post(
                        UNIKEY_LOGIN_URL_BASE + "/connect/token", data=post_params
                    )
                    res.raise_for_status()
                    json_response = res.json()
                    self._access_token = json_response["access_token"]
                    self._id_token = json_response["id_token"]
                    self._refresh_token = json_response["refresh_token"]
                    self._expires_at = time.time() + json_response["expires_in"]
                    jwt_value = jwt.decode(
                        self._id_token, options={"verify_signature": False}
                    )
                    self._user_id = jwt_value["sub"]
                else:
                    res.raise_for_status()
            else:
                res.raise_for_status()
        else:
            res.raise_for_status()

    def __process_message(self, message):
        """Process a websocket message."""
        try:
            json_body = json.loads(message)
            if json_body["messageType"] == "LockStatus":
                message_body = json_body["messageData"]
                lock_id = message_body["lockId"]

                lock = next((x for x in self._devices if x.lock_id == lock_id))

                if lock is not None:
                    lock.battery_level = message_body["batteryLevel"]
                    boltState = message_body["boltState"]
                    if boltState == LOCK_STATE_LOCK:
                        lock.lock_state = "Locked"
                    elif boltState == LOCK_STATE_UNLOCK:
                        lock.lock_state = "Unlocked"
                    else:
                        _LOGGER.warn("Unknown lock state %s", boltState)
                        lock.lock_state = "Unknown"

                    for callback in self._callbacks:
                        try:
                            callback(lock)
                        except Exception as err:
                            _LOGGER.error("Callback error: %s", err)
        except Exception as ex:
            _LOGGER.error("Exception occurred reading websocket message: %s", ex)

    async def __websocket_connect(self):
        """Connect to the websocket."""
        auth_token = quote(f"Bearer {self._access_token}", safe="!~*'()")
        cnonce = self.__get_client_nonce()
        snonce = await self.__get_server_nonce()
        verification = quote(
            self.__generate_websocket_verification(cnonce, snonce), safe="!~*'()"
        )
        cnonce = quote(cnonce, safe="!~*'()")
        snonce = quote(snonce, safe="!~*'()")
        query_string = f"?Authorization={auth_token}&X-unikey-context=web&X-unikey-cnonce={cnonce}&X-unikey-nonce={snonce}&X-unikey-request-verification={verification}&X-unikey-message-content-type=application%2Fjson&"
        async for websocket in websockets.connect(
            UNIKEY_WS_URL_BASE + "/v3/web/" + self._user_id + query_string,
            ping_interval=None,
            user_agent_header="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        ):
            try:
                async for message in websocket:
                    self.__process_message(message)
            except websockets.ConnectionClosed:
                _LOGGER.error("Lost connection to websocket")
                continue

    async def websocket_connect(self):
        """Connect to the websocket via a task."""
        if self._websocket_task is not None:
            self._websocket_task.cancel()
        self._websocket_task = asyncio.create_task(self.__websocket_connect())
        return self._websocket_task

    def register_callback(self, callback=lambda *args, **kwargs: None):
        """Add a callback to be triggered when an event is received."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback=lambda *args, **kwargs: None):
        """Remove a callback that gets triggered when an event is received."""
        self._callbacks.remove(callback)


class KevoLock:
    def __init__(self, api, lock_id, name, firmware, battery_level, state):
        self._api = api
        self._lock_id = lock_id
        self._name = name
        self._firmware = firmware
        self._battery_level = battery_level
        self._lock_state = state

    @property
    def lock_id(self):
        """Retrieve the lock id."""
        return self._lock_id

    @property
    def name(self):
        """Retrieve the lock name."""
        return self._name

    @property
    def firmware(self):
        """Retrieve the firmware version."""
        return self._firmware

    @firmware.setter
    def firmware(self, value):
        """Update the firmware version."""
        self._firmware = value

    @property
    def battery_level(self):
        """Retrieve the battery level on a scale of 0.0 to 1.0"""
        return self._battery_level

    @battery_level.setter
    def battery_level(self, value):
        """Update the battery level."""
        self._battery_level = value

    @property
    def lock_state(self):
        """Retrieve the lock state."""
        return self._lock_state

    @lock_state.setter
    def lock_state(self, value):
        """Update the lock state."""
        self._lock_state = value

    async def lock(self):
        """Lock the lock."""
        return await self._api._api_post(
            "/api/v2/users/"
            + self._api._user_id
            + "/locks/"
            + self._lock_id
            + "/commands",
            {"command": LOCK_STATE_LOCK},
        )

    async def unlock(self):
        """Unlock the lock."""
        return await self._api._api_post(
            "/api/v2/users/"
            + self._api._user_id
            + "/locks/"
            + self._lock_id
            + "/commands",
            {"command": LOCK_STATE_UNLOCK},
        )
