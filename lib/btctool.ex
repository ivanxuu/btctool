defmodule BtcTool do
  @moduledoc """
  Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms
  used in bitcoin to create addresses or public keys from private keys,
  brainwallets, WIFs, etc.
  """

  alias BtcTool.PrivKey

  @doc """
  Create Wallet Import Format (WIF) private key from raw private key.
  A raw private key can be presented by a binary of 32 bytes or in
  64 hexadecimal characters (0-9a-fA-F)

  It assumes you want the compressed WIF version by default. That way
  you are signalling that the bitcoin address which should be used when
  imported into a wallet will be also compressed.

  ## Options
    - `compressed` - Generate a WIF which signals that a compressed
      public key should be used if `true`. Deafault is `true`.
    - `network` - Specifies the network is this private key intended to
      be used on. Can be `:mainnet` or `:testnet`. Default is `:mainnet`.
    - `case` - Specifies the character case to accept when decoding.
      Valid values are: `:upper`, `:lower`, `:mixed`.
      Only useful when the raw private key is passed in hex format.
      Default is `:mixed`

  ## Examples

      iex> hexprivkey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      iex> binprivkey = hexprivkey |> Base.decode16!()
      <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>
      iex> privkey_to_wif(hexprivkey)
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        compressed: true,
        network: :mainnet
      }}
      iex> privkey_to_wif(binprivkey)
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        compressed: true,
        network: :mainnet
      }}
      iex> privkey_to_wif(binprivkey, compressed: false, network: :testnet)
      {:ok, %{
        wif: "91bRE5Duv5h8kYhhTLhYRXijCiXWSpWwFNX6nndfuntBdPV2idD",
        compressed: false,
        network: :testnet
      }}

  When binary private key has an unexpected length (not 64 bytes for hex
  format or 32 bytes for binary format):

      iex> privkey_to_wif(<<1, 35, 69>>)
      {:error, :incorrect_privkey}
  """
  @default_options [network: :mainnet, compressed: true]
  def privkey_to_wif(hexprivkey, options \\ [])
  def privkey_to_wif(hexprivkey, options) when is_binary(hexprivkey) and bit_size(hexprivkey) === 512 do
    options = Keyword.merge( [case: :mixed], options)
    hexprivkey
    |>Base.decode16!(case: options[:case])
    |>privkey_to_wif(options)
  end
  def privkey_to_wif(binprivkey, options) when is_binary(binprivkey) and bit_size(binprivkey) === 256 do
    options = Keyword.merge(@default_options, options)
    {:ok, PrivKey.to_wif(binprivkey, options[:network], options[:compressed])}
  end
  # If privkey is not binary or have the expected length return error
  def privkey_to_wif(_privkey, _options ) do
    {:error, :incorrect_privkey}
  end

end
