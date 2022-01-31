import asyncio
from attr import dataclass
import hashlib
from typing import Generic, Optional, TypeVar, TypedDict, Dict, Tuple
from aiohttp.client import ClientSession
import aiohttp
from ruuvi_decoders import get_decoder

STATION_IP = "10.0.0.21"
USERNAME = "username"
PASSWORD = "password"


class SensorPayload(TypedDict):
    rssi: int
    timestamp: str
    data: str


class PayloadData(TypedDict):
    coordinates: any
    timestamp: str
    gw_mac: str
    tags: Dict[str, SensorPayload]


class Payload(TypedDict):
    data: PayloadData


class SensorData(TypedDict):
    data_format: int
    humidity: float
    temperature: float
    pressure: float
    acceleration: float
    acceleration_x: float
    acceleration_y: float
    acceleration_z: float
    battery: int
    tx_power: Optional[int]
    movement_counter:  Optional[int]
    measurement_sequence_number:  Optional[int]
    mac: Optional[str]
    rssi: Optional[int]


ParsedDatas = Dict[str, SensorData]

T = TypeVar('T')


@dataclass
class Result(Generic[T]):
    val: Optional[T] = None
    status: Optional[int] = None
    ok: bool = True


@dataclass
class Ok(Result):
    ok: bool = True


@dataclass
class Err(Result):
    ok: bool = False


def _parse_sensor_payload(mac: str, payload: SensorPayload) -> Tuple[str, SensorData]:
    raw = payload["data"]

    try:
        companyIndex = raw.index("FF9904")
    except ValueError:
        print("Ruuvi company id not found in data")
        return [mac, None]

    rt: SensorData = {}
    rt["rssi"] = payload["rssi"]

    try:
        broadcast_data = raw[companyIndex+6:]
        data_format = broadcast_data[0:2]
        rt = get_decoder(int(data_format)).decode_data(broadcast_data)
    except ValueError:
        print("Valid data format data not found in payload")
        return [mac, None]

    return [mac, rt]


def _parse_received_data(payload: Payload) -> ParsedDatas:
    data = payload["data"]
    sensor_datas = [_parse_sensor_payload(key, value)
                    for key, value in data["tags"].items()]
    return dict(sensor_datas)


def _parse_value_from_header(header: str, key: str) -> str:
    ch_start = header.index(key) + len(key) + 2
    ch_end = header.index("\"", ch_start + 1)
    return header[ch_start:ch_end]


def _parse_password(header: str, username: str, password: str) -> str:
    challenge = _parse_value_from_header(header, "challenge")
    realm = _parse_value_from_header(header, "realm")
    password_md5 = hashlib.md5(
        f'{username}:{realm}:{password}'.encode()).hexdigest()
    password_sha256 = hashlib.sha256(
        f'{challenge}:{password_md5}'.encode()).hexdigest()
    return password_sha256


def _parse_session_cookie(header: str) -> Dict[str, str]:
    session_cookie = _parse_value_from_header(header, "session_cookie")
    session_id = _parse_value_from_header(header, "session_id")
    return {session_cookie: session_id}


async def get_auth_info(session: ClientSession, ip: str, cookies: Dict[str, str] = {}) -> Result[str]:
    async with session.get(f'http://{ip}/auth', cookies=cookies) as response:
        if response.status == 401:
            auth_info = response.headers["WWW-Authenticate"]
            return Ok(auth_info)
        return Err()


async def authorize_user(session: ClientSession, ip: str, cookies, username: str, password_encrypted: str) -> Result:
    auth_payload = '{"login":"' + username + \
        '","password":"' + password_encrypted + '"}'
    async with session.post(f'http://{ip}/auth', data=auth_payload, cookies=cookies) as response:
        return Result(None, response.status, response.status == 200)


async def get_data(session: ClientSession, ip: str, cookies: Dict[str, str] = {}) -> Result[Optional[ParsedDatas]]:
    try:
        async with session.get(f'http://{ip}/history?time=30', cookies=cookies) as response:
            if response.status == 200:
                data = await response.json()
                parsed = _parse_received_data(data)
                return Ok(parsed, 200)
            else:
                return Err(None, response.status)
    except aiohttp.ClientConnectionError as e:
        message = e.args[0]
        if hasattr(message, 'code') and message.code == 302:
            return Err(None, 302)
        return Err(None, 500)


async def get_authenticate_cookies(session: ClientSession, ip: str, username: str, password: str) -> Result[Dict[str, str]]:
    auth_info_result = await get_auth_info(session, ip)
    if not auth_info_result.ok:
        return Err()
    cookies = _parse_session_cookie(auth_info_result.val)
    password_encrypted = _parse_password(
        auth_info_result.val, username, password)
    auth_result = await authorize_user(session, ip, cookies, username, password_encrypted)
    if not auth_result.ok:
        return Err(None, auth_result.status)
    return Ok(cookies)


async def fetch_data(ip: str, username: str, password: str) -> Result[Optional[ParsedDatas]]:
    async with aiohttp.ClientSession() as session:
        get_result = await get_data(session, ip)
        if get_result.ok:
            return Ok(get_result.val)
        if get_result.status != 302:
            return Err(f'Fetch failed - {get_result.status}')

        cookie_result = await get_authenticate_cookies(session, ip, username, password)
        if not cookie_result.ok:
            return Err(f'Authentication failed - {cookie_result.status}')

        get_result = await get_data(session, ip, cookie_result.val)
        if get_result.ok:
            return Ok(get_result.val)
        else:
            return Err(f'Fetch failed after authorization - {get_result.status}')


async def main():
    fetch_result = await fetch_data(STATION_IP, USERNAME, PASSWORD)
    print(
        fetch_result.val if fetch_result.ok else f'Fetch failed: {fetch_result.val}')

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
