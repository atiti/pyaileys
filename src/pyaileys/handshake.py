from __future__ import annotations

import hashlib
from typing import Any

from .constants import KEY_BUNDLE_TYPE
from .exceptions import HandshakeError
from .wabinary.jid import jid_decode


def encode_big_endian(value: int, length: int = 4) -> bytes:
    v = value
    out = bytearray(length)
    for i in range(length - 1, -1, -1):
        out[i] = v & 0xFF
        v >>= 8
    return bytes(out)


def _get_proto() -> Any:
    try:
        from .proto import WAProto_pb2 as proto

        return proto
    except Exception as e:  # pragma: no cover
        raise HandshakeError(f"failed to import WAProto protobufs: {e}") from e


def _get_web_subplatform(
    proto: Any, *, browser_name: str, browser_platform: str, sync_full_history: bool
) -> int:
    # Mirrors Baileys' PLATFORM_MAP heuristic.
    web_subplatform = proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER
    platform_map = {
        "Mac OS": proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
        "Windows": proto.ClientPayload.WebInfo.WebSubPlatform.WIN32,
    }
    if sync_full_history and browser_name in platform_map and browser_platform == "Desktop":
        web_subplatform = platform_map[browser_name]
    return int(web_subplatform)


def build_login_payload(
    *,
    user_jid: str,
    version: tuple[int, int, int],
    browser: tuple[str, str],
    country_code: str,
    sync_full_history: bool,
) -> Any:
    proto = _get_proto()

    decoded = jid_decode(user_jid)
    if not decoded or decoded.device is None:
        raise HandshakeError(f"invalid user jid for login payload: {user_jid}")

    user_agent = proto.ClientPayload.UserAgent(
        appVersion=proto.ClientPayload.UserAgent.AppVersion(
            primary=version[0], secondary=version[1], tertiary=version[2]
        ),
        platform=proto.ClientPayload.UserAgent.Platform.WEB,
        releaseChannel=proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        osVersion="0.1",
        device="Desktop",
        osBuildNumber="0.1",
        localeLanguageIso6391="en",
        mnc="000",
        mcc="000",
        localeCountryIso31661Alpha2=country_code,
    )

    web_info = proto.ClientPayload.WebInfo(
        webSubPlatform=_get_web_subplatform(
            proto,
            browser_name=browser[0],
            browser_platform=browser[1],
            sync_full_history=sync_full_history,
        )
    )

    payload = proto.ClientPayload(
        connectType=proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
        connectReason=proto.ClientPayload.ConnectReason.USER_ACTIVATED,
        userAgent=user_agent,
        webInfo=web_info,
        passive=True,
        pull=True,
        username=int(decoded.user),
        device=int(decoded.device),
        lidDbMigrated=False,
    )
    return payload


def build_registration_payload(
    *,
    registration_id: int,
    signed_identity_public: bytes,
    signed_pre_key_id: int,
    signed_pre_key_public: bytes,
    signed_pre_key_signature: bytes,
    version: tuple[int, int, int],
    browser: tuple[str, str],
    country_code: str,
    sync_full_history: bool,
) -> Any:
    """
    Build the ClientPayload used when linking a new companion device.

    This mirrors Baileys' `generateRegistrationNode` shape.
    """

    proto = _get_proto()

    app_version_md5 = hashlib.md5(".".join(map(str, version)).encode("utf-8")).digest()

    platform_type_name = (browser[1] or "CHROME").upper()
    try:
        platform_type = proto.DeviceProps.PlatformType.Value(platform_type_name)
    except Exception:
        platform_type = int(proto.DeviceProps.PlatformType.CHROME)

    # Keep this intentionally small; WhatsApp may add fields frequently.
    device_props = proto.DeviceProps(
        os=browser[0],
        platformType=platform_type,
        requireFullSync=sync_full_history,
        historySyncConfig=proto.DeviceProps.HistorySyncConfig(
            storageQuotaMb=10240,
            inlineInitialPayloadInE2EeMsg=True,
            supportCallLogHistory=False,
            supportBotUserAgentChatHistory=True,
            supportCagReactionsAndPolls=True,
            supportBizHostedMsg=True,
            supportRecentSyncChunkMessageCountTuning=True,
            supportHostedGroupMsg=True,
            supportFbidBotChatHistory=True,
            supportMessageAssociation=True,
            supportGroupHistory=False,
        ),
        version=proto.DeviceProps.AppVersion(primary=10, secondary=15, tertiary=7),
    )
    device_props_bytes = device_props.SerializeToString()

    user_agent = proto.ClientPayload.UserAgent(
        appVersion=proto.ClientPayload.UserAgent.AppVersion(
            primary=version[0], secondary=version[1], tertiary=version[2]
        ),
        platform=proto.ClientPayload.UserAgent.Platform.WEB,
        releaseChannel=proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        osVersion="0.1",
        device="Desktop",
        osBuildNumber="0.1",
        localeLanguageIso6391="en",
        mnc="000",
        mcc="000",
        localeCountryIso31661Alpha2=country_code,
    )

    web_info = proto.ClientPayload.WebInfo(
        webSubPlatform=_get_web_subplatform(
            proto,
            browser_name=browser[0],
            browser_platform=browser[1],
            sync_full_history=sync_full_history,
        )
    )

    pairing_data = proto.ClientPayload.DevicePairingRegistrationData(
        buildHash=app_version_md5,
        deviceProps=device_props_bytes,
        eRegid=encode_big_endian(registration_id),
        eKeytype=KEY_BUNDLE_TYPE,
        eIdent=signed_identity_public,
        eSkeyId=encode_big_endian(signed_pre_key_id, 3),
        eSkeyVal=signed_pre_key_public,
        eSkeySig=signed_pre_key_signature,
    )

    payload = proto.ClientPayload(
        connectType=proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
        connectReason=proto.ClientPayload.ConnectReason.USER_ACTIVATED,
        userAgent=user_agent,
        webInfo=web_info,
        passive=False,
        pull=False,
        devicePairingData=pairing_data,
    )
    return payload
