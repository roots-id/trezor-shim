# trezor-shim
Trezor SHIM (Signify Hardware Securoty Module) is an extension module for [signifypy](https://github.com/WebOfTrust/signifypy) that enables Trezor security devices to store KERI private keys and sign KERI transactions.

Keys generated are ED25519 derived from the main seed created on the device. Hierraichal deterministic key derivation is based on [SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) with a URI defines as follows:

`URI: signify://{stem}-{pidx}-{kidx + idx}`

Where:

* `stem`:
* `pidx`:
* `kidx`:
* `idx`:


## Module installation
```
 pip install -e .    
```

## Testing

### Standalone test
```
python ./tests/test_module.py
```

### Signify test
* Install [keria](https://github.com/WebOfTrust/keria) and start a keria agent with `keria start`

* Install [signifipy](https://github.com/WebOfTrust/signifypy)

* Execute the test:
```
python ./tests/test_signify.py   
```

