"""Utility functions for validation, RCON, and API calls."""

import re
import asyncio
import httpx
import socket
import struct
import logging
from typing import Tuple
from config import RCON_HOST, RCON_PASSWORD, RCON_PORT

logger = logging.getLogger(__name__)


def is_valid_minecraft_username(username: str) -> bool:
    """
    Validates a Minecraft username format.
    Minecraft usernames must be 3-16 characters, containing only letters, numbers, and underscores.
    """
    return bool(re.match(r'^[a-zA-Z0-9_]{3,16}$', username))


async def check_mojang_username(username: str) -> Tuple[bool, str | None, str | None]:
    """
    Check if a Minecraft username exists via Mojang API.
    Returns (exists: bool, uuid: str or None, error: str or None)
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://api.mojang.com/users/profiles/minecraft/{username}")
            if response.status_code == 200:
                data = response.json()
                return (True, data.get('id'), None)
            elif response.status_code == 404:
                return (False, None, "Username does not exist")
            else:
                return (False, None, f"API returned status {response.status_code}")
    except httpx.TimeoutException:
        return (False, None, "Mojang API timeout")
    except Exception as e:
        return (False, None, f"API error: {str(e)}")


def _check_rcon_sync() -> Tuple[bool, str]:
    """
    Synchronous RCON check to run in thread executor.
    Returns (success: bool, message: str)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((RCON_HOST, RCON_PORT))
        sock.close()
        return (True, "Connection successful (basic check)")
    except socket.timeout:
        return (False, "Connection timeout")
    except socket.error as e:
        return (False, f"Socket error: {e}")
    except Exception as e:
        return (False, str(e))


def _rcon_exec_sync(command: str, timeout: float = 5.0) -> str:
    """
    Minimal RCON exec without signals; returns payload string or raises.
    """
    def send_packet(sock, req_id, req_type, payload_str):
        payload = payload_str.encode('utf-8')
        length = 4 + 4 + len(payload) + 2  # id + type + payload + 2 null bytes
        packet = struct.pack('<iii', length, req_id, req_type) + payload + b'\x00\x00'
        sock.sendall(packet)
    
    def recv_packet(sock):
        # read length
        header = sock.recv(4)
        if not header or len(header) < 4:
            raise RuntimeError('RCON: incomplete header')
        (length,) = struct.unpack('<i', header)
        body = b''
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) < 8:
            raise RuntimeError('RCON: incomplete body')
        req_id, req_type = struct.unpack('<ii', body[:8])
        payload = body[8:]
        # strip trailing two nulls if present
        if payload.endswith(b'\x00\x00'):
            payload = payload[:-2]
        return req_id, req_type, payload.decode('utf-8', errors='replace')

    try:
        logger.debug(f"Connecting to RCON at {RCON_HOST}:{RCON_PORT}")
        sock = socket.create_connection((RCON_HOST, RCON_PORT), timeout=timeout)
        sock.settimeout(timeout)
        try:
            # authenticate
            send_packet(sock, 0x1234, 3, RCON_PASSWORD)
            rid, rtype, payload = recv_packet(sock)
            if rid == -1:
                raise RuntimeError('RCON auth failed')
            # exec command
            send_packet(sock, 0x1235, 2, command)
            rid, rtype, payload = recv_packet(sock)
            return payload
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except socket.timeout:
        logger.error(f"RCON connection timeout to {RCON_HOST}:{RCON_PORT} after {timeout}s")
        raise TimeoutError(f"RCON server at {RCON_HOST}:{RCON_PORT} is not responding")
    except ConnectionRefusedError:
        logger.error(f"RCON connection refused by {RCON_HOST}:{RCON_PORT}")
        raise ConnectionError(f"RCON server at {RCON_HOST}:{RCON_PORT} refused connection. Is it running?")
    except Exception as e:
        logger.error(f"RCON error: {e}")
        raise


def _check_whitelist_sync(username: str) -> Tuple[bool, str | None]:
    """
    Check if a player is whitelisted. 
    Returns (is_whitelisted: bool, error: str or None)
    """
    try:
        response = _rcon_exec_sync('whitelist list')
        if not response:
            return (False, None)
        # parse names after colon
        names_part = ''
        if ':' in response:
            names_part = response.split(':', 1)[1]
        names = [n.strip().lower() for n in names_part.split(',') if n.strip()]
        is_white = username.lower() in names
        logger.info(f"Whitelist check for {username}: {'YES' if is_white else 'NO'}")
        return (is_white, None)
    except Exception as e:
        logger.error(f"Error checking whitelist for {username}: {e}")
        return (False, str(e))


async def check_if_whitelisted(username: str, executor) -> Tuple[bool, str | None]:
    """Async wrapper to check if player is whitelisted."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _check_whitelist_sync, username)


def whitelist_add_sync(username: str) -> str:
    """Execute whitelist add command via RCON."""
    return _rcon_exec_sync(f"whitelist add {username}")


async def ping_host(host: str, port: int = 80, timeout: float = 3.0) -> Tuple[bool, float | None, str | None]:
    """
    Ping a host by attempting a TCP connection.
    Returns (success: bool, latency_ms: float or None, error: str or None)
    """
    import time
    try:
        start = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        end = time.perf_counter()
        writer.close()
        await writer.wait_closed()
        latency_ms = (end - start) * 1000
        return (True, latency_ms, None)
    except asyncio.TimeoutError:
        return (False, None, "Connection timeout")
    except Exception as e:
        return (False, None, str(e))


async def ping_rcon() -> Tuple[bool, float | None, str | None]:
    """
    Ping the RCON server.
    Returns (success: bool, latency_ms: float or None, error: str or None)
    """
    return await ping_host(RCON_HOST, RCON_PORT)
