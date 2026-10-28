"""Discover physical neighbor links reported by managed switches through LLDP/SNMP."""

import asyncio
import ipaddress
import os
import re


LLDP_LOCAL_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_REMOTE_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REMOTE_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REMOTE_SYSTEM_NAME = "1.0.8802.1.1.2.1.4.1.1.9"


def _decode(value):
    if hasattr(value, "asOctets"):
        raw = value.asOctets()
        try:
            text = raw.decode("utf-8").strip("\x00 \t\r\n")
            if text and all(char.isprintable() for char in text):
                return text
        except UnicodeDecodeError:
            pass
        return ":".join(f"{byte:02x}" for byte in raw)
    try:
        return value.prettyPrint().strip()
    except AttributeError:
        return str(value).strip()


def _normalize_chassis_id(value):
    value = str(value or "").strip().casefold()
    compact = re.sub(r"[^0-9a-f]", "", value)
    if len(compact) == 12:
        return "-".join(compact[index:index + 2] for index in range(0, 12, 2))
    return value.replace(":", "-")


def _snmp_authentication():
    version = os.environ.get("GEAREYE_SNMP_VERSION", "2c").strip().casefold()
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData

    if version in {"3", "v3"}:
        username = os.environ.get("GEAREYE_SNMP_V3_USER", "").strip()
        auth_key = os.environ.get("GEAREYE_SNMP_V3_AUTH_KEY", "")
        priv_key = os.environ.get("GEAREYE_SNMP_V3_PRIV_KEY", "")
        if not username or not auth_key:
            return None, None, "snmp_credentials_incomplete"
        if not 8 <= len(auth_key.encode("utf-8")) <= 32 or (priv_key and not 8 <= len(priv_key.encode("utf-8")) <= 32):
            return None, None, "snmp_credentials_invalid_length"

        from pysnmp.hlapi.v3arch.asyncio import (
            USM_AUTH_HMAC192_SHA256,
            USM_PRIV_CFB128_AES,
            UsmUserData,
        )

        privacy = {"privKey": priv_key, "privProtocol": USM_PRIV_CFB128_AES} if priv_key else {}
        return UsmUserData(
            username,
            authKey=auth_key,
            authProtocol=USM_AUTH_HMAC192_SHA256,
            **privacy,
        ), ContextData(), None

    if version not in {"1", "v1", "2", "2c", "v2c"}:
        return None, None, "snmp_version_unsupported"
    community = os.environ.get("GEAREYE_SNMP_COMMUNITY", "").strip()
    if not community:
        return None, None, "snmp_not_configured"

    return CommunityData(community, mpModel=0 if version in {"1", "v1"} else 1), ContextData(), None


async def _walk_lldp(ip, authentication):
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        ObjectIdentity,
        ObjectType,
        UdpTransportTarget,
        walk_cmd,
    )

    result = {}
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((ip, 161), timeout=1.2, retries=0)
        for key, root in (
            ("local_ports", LLDP_LOCAL_PORT_ID),
            ("remote_chassis", LLDP_REMOTE_CHASSIS_ID),
            ("remote_ports", LLDP_REMOTE_PORT_ID),
            ("remote_names", LLDP_REMOTE_SYSTEM_NAME),
        ):
            table = {}
            async for indication, status, _index, var_binds in walk_cmd(
                engine,
                authentication[0],
                target,
                authentication[1],
                ObjectType(ObjectIdentity(root)),
                lexicographicMode=False,
                maxRows=2048,
            ):
                if indication or status:
                    break
                for oid, value in var_binds:
                    oid_text = oid.prettyPrint()
                    if oid_text.startswith(root + "."):
                        table[oid_text[len(root) + 1:]] = _decode(value)
            result[key] = table
    finally:
        engine.close_dispatcher()
    return result


def discover_lldp_topology(devices):
    """Return verified LLDP links; physical links are never inferred from ping/ARP."""
    try:
        authentication, context, configuration_error = _snmp_authentication()
    except ImportError:
        return {"enabled": False, "reason": "pysnmp_not_installed", "switches": [], "links": []}
    if configuration_error:
        return {"enabled": False, "reason": configuration_error, "switches": [], "links": []}
    authentication = (authentication, context)

    from Backend.Models.Dispositivo import Dispositivo

    inventory = [device.model_dump() if isinstance(device, Dispositivo) else device for device in devices]
    by_mac = {
        _normalize_chassis_id(device.get("mac")): device
        for device in inventory if device.get("mac")
    }
    by_name = {
        str(device.get("nombre") or "").strip().casefold(): device
        for device in inventory if device.get("nombre")
    }
    by_ip = {str(device.get("ip")): device for device in inventory if device.get("ip")}
    infrastructure_words = (
        "cisco", "ubiquiti", "mikrotik", "juniper", "aruba", "hewlett",
        "tp-link", "tplink", "netgear", "d-link", "huawei", "switch",
    )
    targets = {
        str(device.get("ip")) for device in inventory
        if device.get("estado") == "activo" and (
            device.get("tipo") in {"dispositivo_red", "router"}
            or any(word in " ".join(str(device.get(key) or "") for key in ("fabricante", "fabricante_red", "nombre")).casefold()
                   for word in infrastructure_words)
        )
    }
    for raw_ip in os.environ.get("GEAREYE_SNMP_TARGETS", "").split(","):
        raw_ip = raw_ip.strip()
        if not raw_ip:
            continue
        try:
            targets.add(str(ipaddress.IPv4Address(raw_ip)))
        except ipaddress.AddressValueError:
            continue

    if not targets:
        return {"enabled": True, "reason": "switch_not_found", "switches": [], "links": []}

    async def scan_all():
        semaphore = asyncio.Semaphore(12)

        async def scan(ip):
            async with semaphore:
                try:
                    return ip, await _walk_lldp(ip, authentication)
                except Exception:
                    return ip, None

        return await asyncio.gather(*(scan(ip) for ip in sorted(targets)))

    try:
        results = asyncio.run(scan_all())
    except RuntimeError:
        return {"enabled": True, "reason": "snmp_scan_unavailable", "switches": [], "links": []}

    switches = []
    links = []
    answered = 0
    for switch_ip, tables in results:
        if tables is None:
            continue
        answered += 1
        switch_device = by_ip.get(switch_ip, {})
        switch = {
            "ip": switch_ip,
            "name": switch_device.get("nombre") or switch_device.get("fabricante") or "Switch administrable",
            "links": [],
        }
        indices = set().union(*(set(tables[key]) for key in ("remote_chassis", "remote_ports", "remote_names")))
        for index in sorted(indices):
            parts = index.split(".")
            if len(parts) < 3:
                continue
            local_port_number = parts[-2]
            local_port = tables["local_ports"].get(local_port_number, local_port_number)
            chassis = tables["remote_chassis"].get(index, "")
            remote_port = tables["remote_ports"].get(index, "")
            remote_name = tables["remote_names"].get(index, "")
            remote = by_mac.get(_normalize_chassis_id(chassis)) or by_name.get(remote_name.casefold())
            if not remote:
                try:
                    remote = by_ip.get(str(ipaddress.IPv4Address(chassis)))
                except ipaddress.AddressValueError:
                    pass
            link = {
                "switch_ip": switch_ip,
                "switch_name": switch["name"],
                "local_port": local_port or local_port_number,
                "remote_ip": remote.get("ip") if remote else None,
                "remote_name": (remote.get("nombre") if remote else None) or remote_name or "Vecino LLDP",
                "remote_port": remote_port or None,
                "remote_mac": chassis or None,
                "protocol": "LLDP",
            }
            switch["links"].append(link)
            links.append(link)
        switches.append(switch)

    reason = None if links else "no_lldp_neighbors" if answered else "snmp_unreachable"
    return {
        "enabled": True,
        "reason": reason,
        "targets": len(targets),
        "switches_reachable": answered,
        "switches": switches,
        "links": links,
    }
