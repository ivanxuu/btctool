# BtcTool

Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms
used in bitcoin to create addresses or public keys from private keys,
brainwallets, WIFs, etc.

## Usage examples

    iex> hexprivkey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    iex> binprivkey = hexprivkey |> Base.decode16!()
    <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>

Create WIF private key from raw private key. Use Base58. Compressed by default.

    iex> privkeywifcomp = BtcTool.privkey_to_wif(hexprivkey)
    "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL"
    iex> privkeywifuncomp = BtcTool.privkey_to_wif(binprivkey, compressed: false)
    "5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb"


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

