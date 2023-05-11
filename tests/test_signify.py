# -*- encoding: utf-8 -*-
"""
SIGNIFY
signify.app.clienting module

Testing clienting with integration tests that require a running KERIA Cloud Agent
"""
from time import sleep

import requests
from keri.app.keeping import Algos
from keri.core import coring
from responses import _recorder

import pytest
from keri import kering
from keri.core.coring import Tiers, Serder, MtrDex

from signify.app.clienting import SignifyClient




def test_trezor():
    url = "http://localhost:3901"
    bran = b'0123456789abcdefghijk'
    tier = None

    client = SignifyClient(url=url, bran=bran, tier=tier,
                           extern_modules=[
                               dict(
                                   type="trezor",
                                   name="trezor_shim",
                                   params=dict()
                               )])

    assert client.controller == "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
    evt, siger = client.ctrl.event()
    res = requests.post(url="http://localhost:3903/boot",
                        json=dict(
                            icp=evt.ked,
                            sig=siger.qb64,
                            stem=client.ctrl.stem,
                            pidx=1,
                            tier=client.ctrl.tier))

    if res.status_code != requests.codes.accepted:
        raise kering.AuthNError(f"unable to initialize cloud agent connection, {res.status_code}, {res.text}")

    client.connect()
    assert client.agent is not None
    assert client.agent.anchor == "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
    assert client.agent.pre == "EJoqUMpQAfqsJhBqv02ehR-9BJYBTCrW8h5JlLdMTWBg"
    assert client.ctrl.ridx == 0

    # Create AID using external HSM module
    stem = "ABO4qF9g9L-e1QzvMXgY-58elMh8L-63ZBnNXhxScO81"
    identifiers = client.identifiers()
    aid = identifiers.create("aidtrezor", algo=Algos.extern, extern_type="trezor", extern=dict(stem=stem))
    icp = Serder(ked=aid)
    print(icp.pretty())




if __name__ == "__main__":
    test_trezor()
