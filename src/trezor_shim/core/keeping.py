# -*- encoding: utf-8 -*-
"""
SIGNIFYPY
trezor-shim module

"""
from keri.core import coring
from keri.core.coring import MtrDex, Cigar, IdrDex, Siger
from ..trezor import trezor

from ..trezor import util
from ..trezor import ui

class Module:

    def shim(self, **kwargs):
        return TrezorShim( **kwargs)

class TrezorShim:
    STEM = 'trezor_shim'

    def __init__(self, pidx, kidx=0, transferable=True, stem=None, count=1, ncount=1,
                 dcode=MtrDex.Blake3_256):

        self.icount = count
        self.ncount = ncount
        self.dcode = dcode
        self.pidx = pidx
        self.kidx = kidx
        self.transferable = transferable
        self.stem = stem if stem is not None else self.STEM

        self.device = trezor.Trezor()
        self.device.ui = ui.UI(trezor.Trezor, config=None)
        self.device.ui.cached_passphrase_ack = util.ExpiringCache(seconds=float(60))

    def params(self):
        return dict(
            pidx=self.pidx,
            kidx=self.kidx,
            stem=self.stem,
            icount=self.icount,
            ncount=self.ncount,
            dcode=self.dcode,
            transferable=self.transferable
        )

    def incept(self, transferable=True):

        keys = self._keys( self.icount, self.kidx, transferable)
        nkeys = self._keys(self.ncount, self.kidx + self.icount, True)
        ndigs = [coring.Diger(ser=nkey.encode('utf-8'), code=self.dcode).qb64 for nkey in nkeys]

        return keys, ndigs

    def _keys(self, count, kidx, transferable):
        keys = []
        for idx in range(count):
            key_id = f"{self.stem}-{self.pidx}-{kidx + idx}"
            with self.device:
                verkey = self.device.pubkey(key_id=key_id, ecdh=False)
            verfer = coring.Verfer(raw=verkey,
                                   code=coring.MtrDex.Ed25519 if transferable
                                   else coring.MtrDex.Ed25519N)
            keys.append(verfer.qb64)

        return keys

    def rotate(self, ncount, transferable):
        keys = self._keys(self.ncount, self.kidx + self.icount, transferable)
        self.kidx = self.kidx + self.icount
        self.icount = self.ncount
        self.ncount = ncount
        nkeys = self._keys(self.ncount, self.kidx + self.icount, True)
        ndigs = [coring.Diger(ser=nkey, code=self.dcode).qb64 for nkey in nkeys]

        return keys, ndigs

    def sign(self, ser, indexed=True, indices=None, ondices=None, **_):
        signers = []
        for idx in range(self.icount):
            key_id = f"{self.stem}-{self.pidx}-{self.kidx + idx}"
            with self.device:
                verkey = self.device.pubkey(key_id=key_id, ecdh=False )
            verfer = coring.Verfer(raw=verkey,
                                   code=coring.MtrDex.Ed25519 if self.transferable
                                   else coring.MtrDex.Ed25519N)
            with self.device:
                sig = self.device.sign(blob=ser, key_id=key_id)
            signers.append((sig, verfer))

        return sign(signers, indexed, indices, ondices)

def sign(signers, indexed=False, indices=None, ondices=None):
    if indexed:
        sigers = []
        for j, (sig, verfer) in enumerate(signers):
            if indices:  # not the default get index from indices
                i = indices[j]  # must be whole number
                if not isinstance(i, int) or i < 0:
                    raise ValueError(f"Invalid signing index = {i}, not "
                                     f"whole number.")
            else:  # the default
                i = j  # same index as database

            if ondices:  # not the default get ondex from ondices
                o = ondices[j]  # int means both, None means current only
                if not (o is None or
                        isinstance(o, int) and not isinstance(o, bool) and o >= 0):
                    raise ValueError(f"Invalid other signing index = {o}, not "
                                     f"None or not whole number.")
            else:  # default
                o = i  # must both be same value int
            # .sign assigns .verfer of siger and sets code of siger
            # appropriately for single or dual indexed signatures
            sigers.append(ding(sig, verfer,
                               index=i,
                               only=True if o is None else False,
                               ondex=o))
        return [siger.qb64 for siger in sigers]

    else:
        cigars = []
        for sig, verfer in signers:
            cigars.append(ding(sig, verfer, index=None, only=False, ondex=None))  # assigns .verfer to cigar

        return [cigar.qb64 for cigar in cigars]


def ding(sig, verfer, index, only, ondex):
    if index is None:  # Must be Cigar i.e. non-indexed signature
        return Cigar(raw=sig, code=MtrDex.Ed25519_Sig, verfer=verfer)
    else:  # Must be Siger i.e. indexed signature
        # should add Indexer class method to get ms main index size for given code
        if only:  # only main index ondex not used
            ondex = None
            if index <= 63:  # (64 ** ms - 1) where ms is main index size
                code = IdrDex.Ed25519_Crt_Sig  # use small current only
            else:
                code = IdrDex.Ed25519_Big_Crt_Sig  # use big current only
        else:  # both
            if ondex is None:
                ondex = index  # enable default to be same
            if ondex == index and index <= 63:  # both same and small
                code = IdrDex.Ed25519_Sig  # use  small both same
            else:  # otherwise big or both not same so use big both
                code = IdrDex.Ed25519_Big_Sig  # use use big both

        return Siger(raw=sig,
                     code=code,
                     index=index,
                     ondex=ondex,
                     verfer=verfer)
