# BtcTool

Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms
used in bitcoin to create addresses or public keys from private keys,
brainwallets, WIFs, etc.

## Functions

  [BtcTool.privkey_to_wif(privkey, options)](https://hexdocs.pm/btctool/BtcTool.html#privkey_to_wif/2)
  Create WIF private key from raw private key.

  [BtcTool.wif_to_privkey(wif)](https://hexdocs.pm/btctool/BtcTool.html#wif_to_privkey/1)
  Returns the raw private key from a Wallet Import Format (WIF) string.

  [BtcTool.wif_to_pubkey(wif)](https://hexdocs.pm/btctool/BtcTool.html#wif_to_pubkey/1)
  Returns the public key from a Wallet Import Format (WIF) string.

  [BtcTool.wif_to_address(wif, options)](https://hexdocs.pm/btctool/BtcTool.html#wif_to_address/2)
  Generate a bitcoin address from a Wallet Import Format (WIF) string.

  [BtcTool.brainwallet_to_wif(wif, options)](https://hexdocs.pm/btctool/BtcTool.html#brainwallet_to_wif/2)
  Returns Wallet Import Format (WIF) generated from any arbitrary text (passphrase).

## Installation

The package can be installed by adding `btctool` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:btctool, "~> 0.1"}
  ]
end
```

The docs can be found at
[https://hexdocs.pm/btctool](https://hexdocs.pm/btctool).

