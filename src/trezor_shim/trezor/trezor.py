import binascii
import logging
import semver
import os

import semver
from trezorlib.btc import get_address, get_public_node
from trezorlib.client import PASSPHRASE_TEST_PATH
from trezorlib.client import TrezorClient as Client
from trezorlib.exceptions import PinException, TrezorFailure
from trezorlib.messages import IdentityType
from trezorlib.misc import get_ecdh_session_key, sign_identity
from trezorlib.transport import get_transport

from . import formats
from . import interface

log = logging.getLogger(__name__)

class Trezor():

    required_version = '>=1.4.0'

    ui = None  # can be overridden by device's users
    cached_session_id = None

    def verify_version(self, connection):
        f = connection.features
        log.debug('connected to %s %s', self, f.device_id)
        log.debug('label    : %s', f.label)
        log.debug('vendor   : %s', f.vendor)
        current_version = '{}.{}.{}'.format(f.major_version,
                                            f.minor_version,
                                            f.patch_version)
        log.debug('version  : %s', current_version)
        log.debug('revision : %s', binascii.hexlify(f.revision))
        if not semver.match(current_version, self.required_version):
            fmt = ('Please upgrade your {} firmware to {} version'
                   ' (current: {})')
            raise ValueError(fmt.format(self, self.required_version,
                                        current_version))

    def connect(self):
        transport = self.find_device()
        if not transport:
            raise interface.NotFoundError('{} not connected'.format(self))

        log.debug('using transport: %s', transport)
        for _ in range(5):  # Retry a few times in case of PIN failures
            connection = Client(transport=transport,
                                           ui=self.ui,
                                           session_id=self.__class__.cached_session_id)
            self.verify_version(connection)

            try:
                # unlock PIN and passphrase
                get_address(connection,
                                       "Testnet",
                                       PASSPHRASE_TEST_PATH)
                return connection
            except (PinException, ValueError) as e:
                log.error('Invalid PIN: %s, retrying...', e)
                continue
            except Exception as e:
                log.exception('ping failed: %s', e)
                connection.close()  # so the next HID open() will succeed
                raise
        return None

    def close(self):
        """Close connection."""
        self.__class__.cached_session_id = self.conn.session_id
        super().close()

    def pubkey(self, key_id, ecdh=False):
        """Return public key."""

        identity = self._create_identity(key_id)

        curve_name = identity.get_curve_name(ecdh=ecdh)
        log.debug('"%s" getting public key (%s) from %s',
                  identity.to_string(), curve_name, self)
        addr = identity.get_bip32_address(ecdh=ecdh)
        result = get_public_node(
            self.conn,
            n=addr,
            ecdsa_curve_name=curve_name)
        log.debug('result: %s', result)
        pubkey = bytes(result.node.public_key)
        return bytes(formats.decompress_pubkey(pubkey=pubkey, curve_name=identity.curve_name))

    def _identity_proto(self, identity):
        result = IdentityType()
        for name, value in identity.items():
            setattr(result, name, value)
        return result

    def sign(self, key_id, blob):
        """Sign given blob and return the signature (as bytes)."""
        sig, _ = self.sign_with_pubkey(key_id, blob)
        return sig

    def sign_with_pubkey(self, key_id, blob):
        """Sign given blob and return the signature (as bytes)."""
        identity = self._create_identity(key_id)
        curve_name = identity.get_curve_name(ecdh=False)
        log.debug('"%s" signing %r (%s) on %s',
                  identity.to_string(), blob, curve_name, self)
        try:
            result = sign_identity(
                self.conn,
                identity=self._identity_proto(identity),
                challenge_hidden=blob,
                challenge_visual='',
                ecdsa_curve_name=curve_name)
            log.debug('result: %s', result)
            assert len(result.signature) == 65
            assert result.signature[:1] == b'\x00'
            return bytes(result.signature[1:]), bytes(result.public_key[1:])
        except TrezorFailure as e:
            msg = '{} error: {}'.format(self, e)
            log.debug(msg, exc_info=True)
            raise interface.DeviceError(msg)

    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        session_key, _ = self.ecdh_with_pubkey(identity, pubkey)
        return session_key

    def ecdh_with_pubkey(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman & self public key."""
        curve_name = identity.get_curve_name(ecdh=True)
        log.debug('"%s" shared session key (%s) for %r from %s',
                  identity.to_string(), curve_name, pubkey, self)
        try:
            result = get_ecdh_session_key(
                self.conn,
                identity=self._identity_proto(identity),
                peer_public_key=pubkey,
                ecdsa_curve_name=curve_name)
            log.debug('result: %s', result)
            assert len(result.session_key) in {65, 33}  # NIST256 or Curve25519
            assert result.session_key[:1] == b'\x04'
            self_pubkey = result.public_key
            if self_pubkey:
                self_pubkey = bytes(self_pubkey[1:])

            return bytes(result.session_key), self_pubkey
        except TrezorFailure as e:
            msg = '{} error: {}'.format(self, e)
            log.debug(msg, exc_info=True)
            raise interface.DeviceError(msg)

    def find_device(self):
        """Selects a transport based on `TREZOR_PATH` environment variable.
            If unset, picks first connected device.
        """
        try:
            return get_transport(os.environ.get("TREZOR_PATH"), prefix_search=True)
        except Exception as e:  # pylint: disable=broad-except
            log.debug("Failed to find a Trezor device: %s", e)
            return None
    def _create_identity(self, key_id):
        result = interface.Identity(identity_str='signify://', curve_name='ed25519')
        # result.identity_dict['user'] = key_id
        result.identity_dict['host'] = key_id
        return result
    
    def __enter__(self):
        """Allow usage as context manager."""
        self.conn = self.connect()
        return self
    
    def __init__(self):
        self.conn = None

    def __exit__(self, *args):
        """Close and mark as disconnected."""
        try:
            self.close()
        except Exception as e:  # pylint: disable=broad-except
            log.exception('close failed: %s', e)
        self.conn = None

    
    def close(self):
        """Close connection to device."""
        self.conn.close()

    def __str__(self):
        """Human-readable representation."""
        return '{}'.format(self.__class__.__name__)