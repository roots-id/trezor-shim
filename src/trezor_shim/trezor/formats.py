"""SSH format parsing and formatting tools."""
import hashlib
import logging

import ecdsa
import nacl.signing

from . import util

log = logging.getLogger(__name__)

# Supported ECDSA curves (for SSH and GPG)
CURVE_NIST256 = 'nist256p1'
CURVE_ED25519 = 'ed25519'
SUPPORTED_CURVES = {CURVE_NIST256, CURVE_ED25519}

# Supported ECDH curves (for GPG)
ECDH_NIST256 = 'nist256p1'
ECDH_CURVE25519 = 'curve25519'

# SSH key types
SSH_NIST256_DER_OCTET = b'\x04'
SSH_NIST256_KEY_PREFIX = b'ecdsa-sha2-'
SSH_NIST256_CURVE_NAME = b'nistp256'
SSH_NIST256_KEY_TYPE = SSH_NIST256_KEY_PREFIX + SSH_NIST256_CURVE_NAME
SSH_NIST256_CERT_POSTFIX = b'-cert-v01@openssh.com'
SSH_NIST256_CERT_TYPE = SSH_NIST256_KEY_TYPE + SSH_NIST256_CERT_POSTFIX
SSH_ED25519_KEY_TYPE = b'ssh-ed25519'
SUPPORTED_KEY_TYPES = {SSH_NIST256_KEY_TYPE, SSH_NIST256_CERT_TYPE, SSH_ED25519_KEY_TYPE}

hashfunc = hashlib.sha256

def _decompress_ed25519(pubkey):
    """Load public key from the serialized blob (stripping the prefix byte)."""
    if pubkey[:1] in {b'\x00', b'\x01'}:
        # set by Trezor fsm_msgSignIdentity() and fsm_msgGetPublicKey()
        return nacl.signing.VerifyKey(pubkey[1:], encoder=nacl.encoding.RawEncoder)
    else:
        return None

def _decompress_nist256(pubkey):
    """
    Load public key from the serialized blob.

    The leading byte least-significant bit is used to decide how to recreate
    the y-coordinate from the specified x-coordinate. See bitcoin/main.py#L198
    (from https://github.com/vbuterin/pybitcointools/) for details.
    """
    if pubkey[:1] in {b'\x02', b'\x03'}:  # set by ecdsa_get_public_key33()
        curve = ecdsa.NIST256p
        P = curve.curve.p()
        A = curve.curve.a()
        B = curve.curve.b()
        x = util.bytes2num(pubkey[1:33])
        beta = pow(int(x * x * x + A * x + B), int((P + 1) // 4), int(P))

        p0 = util.bytes2num(pubkey[:1])
        y = (P - beta) if ((beta + p0) % 2) else beta

        point = ecdsa.ellipticcurve.Point(curve.curve, x, y)
        return ecdsa.VerifyingKey.from_public_point(point, curve=curve,
                                                    hashfunc=hashfunc)
    else:
        return None

def decompress_pubkey(pubkey, curve_name):
    """
    Load public key from the serialized blob.

    Raise ValueError on parsing error.
    """
    vk = None
    if len(pubkey) == 33:
        decompress = {
            CURVE_NIST256: _decompress_nist256,
            CURVE_ED25519: _decompress_ed25519,
            ECDH_CURVE25519: _decompress_ed25519,
        }[curve_name]
        vk = decompress(pubkey)

    if not vk:
        msg = 'invalid {!s} public key: {!r}'.format(curve_name, pubkey)
        raise ValueError(msg)

    return vk

def get_ecdh_curve_name(signature_curve_name):
    """Return appropriate curve for ECDH for specified signing curve."""
    return {
        CURVE_NIST256: ECDH_NIST256,
        CURVE_ED25519: ECDH_CURVE25519,
        ECDH_CURVE25519: ECDH_CURVE25519,
    }[signature_curve_name]
