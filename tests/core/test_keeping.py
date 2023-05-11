from keri.core import coring, eventing
from trezor_shim.core import keeping

def test_trezor_module():
    # stem = randomNonce()
    stem = "ABO4qF9g9L-e1QzvMXgY-58elMh8L-63ZBnNXhxScO81"
    mod = keeping.TrezorShim( pidx=0, transferable=True, stem=stem)
    keys, ndigs = mod.incept()
    # assert len(keys) == 1
    # assert keys[0].startswith("1AAB")
    # assert len(keys[0]) == 48

    # assert len(ndigs) == 1
    # assert ndigs[0].startswith("E")
    # assert len(ndigs[0]) == 44
    print(keys)
    print(ndigs)

    params = mod.params()
    # assert params == {'dcode': 'E',
    #                   'icount': 1,
    #                   'kidx': 0,
    #                   'ncount': 1,
    #                   'pidx': 0,
    #                   'stem': 'ABO4qF9g9L-e1QzvMXgY-58elMh8L-63ZBnNXhxScO81',
    #                   'tier': 'low',
    #                   'transferable': True}

    serder = eventing.incept(keys=keys,
                             isith='1',
                             nsith='1',
                             ndigs=ndigs,
                             code=coring.MtrDex.Blake3_256,
                             wits=[],
                             toad='0')

    print()
    sigs = mod.sign(ser=serder.raw, indices=[0])
    print(sigs)
    # assert len(sigs) == 1
    # assert sigs[0].startswith('C')

    # cigs = mod.sign(ser=serder.raw, indexed=False)
    # assert len(cigs) == 1
    # assert cigs[0].startswith('0C')

    # sigers = [coring.Siger(qb64=sig) for sig in sigs]
    # msg = eventing.messagize(serder=serder, sigers=sigers)
    # print(msg)


if __name__ == "__main__":
    test_trezor_module()
