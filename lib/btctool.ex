defmodule BtcTool do
  @moduledoc """
  Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms
  used in bitcoin to create addresses or public keys from private keys,
  brainwallets, WIFs, etc.
  """

  alias BtcTool.PrivKey

  # Min-max value for secp256k1 ECC. More info at:
  # https://bitcoin.stackexchange.com/questions/1389#answer-1715
  @ecc_min "0000000000000000000000000000000000000000000000000000000000000000" |> Base.decode16!()
  @ecc_max "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" |> Base.decode16!()

  @typedoc """
  Wallet Import Format string to be imported in base58check.

  Examples:
    - Uncompressed private key to be imported (51 characters in base58,
    starts with `5`)
    E.g.: `5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb`
    - Compressed private key to be imported (52 characters in base58,
    starts with `K` or `L`)
    E.g.: `KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL`
  """
  @type wif_type :: <<_::408>> | <<_::416>>
  @typedoc """
  Wallet Import Format including the base58check containing the private
  key.

  WIF will be a base58check string of 51 characters (408 bits) if user
  want to use uncompressed public keys in the bitcoin addresses, or 52
  characters (416 bits) if wants to use compressed public keys.

  Metadata like `network` or `compressed` can also be deducted from the
  WIP string, but make them visible anyway here:
   - `network`. Which network (`:mainnet`, or `:testnet`) is intended to
   be used on.
   - `compressed`. States if a compressed public key will be used when
   generating addresses.
  """
  @type wif_result :: %{wif: wif_type, network: :testnet | :mainnet, compressed: boolean }
  @typedoc """
  Returns the raw private key in binary format (512bits) and hexadecimal
  format (characters a-z0-9)

  Also returns extracted available metadata like `network` or
  `compressed` deducted from the WIP string:
   - `network`. Which network (`:mainnet`, or `:testnet`)is intended to
   be used on.
   - `compressed`. States if a compressed public key will be used when
   generating addresses.
  """
  @type privkey_result :: %{privkey_bin: <<_::256>>, privkey_hex: <<_::512>>, network: :testnet | :mainnet, compressed: boolean }

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
  format or 32 bytes for binary format) returns error:

      iex> privkey_to_wif(<<1, 35, 69>>)
      {:error, :incorrect_privkey_length}

  When private key is out of recommended range will return error:

      iex> maxprivkey = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" |> Base.decode16!()
      iex> privkey_to_wif(maxprivkey)
      {:error, :ecc_out_range}
  """
  @default_options [network: :mainnet, compressed: true]
  @spec privkey_to_wif( <<_::512>> | <<_::256>>, [{atom, any}] ) ::
    {:ok, wif_result}
    | {:error, atom }
  def privkey_to_wif(privkey, options \\ [])
  def privkey_to_wif(hexprivkey, options) when is_binary(hexprivkey) and bit_size(hexprivkey) === 512 do
    options = Keyword.merge( [case: :mixed], options)
    hexprivkey
    |>Base.decode16!(case: options[:case])
    |>privkey_to_wif(options)
  end
  # Private key must be inside a recommended range. Otherwise return
  # error. More info at:
  # https://bitcoin.stackexchange.com/questions/1389#answer-1715
  def privkey_to_wif(hexprivkey, _options) when hexprivkey <= @ecc_min or hexprivkey >= @ecc_max do
    {:error, :ecc_out_range}
  end
  def privkey_to_wif(binprivkey, options) when is_binary(binprivkey) and bit_size(binprivkey) === 256 do
    options = Keyword.merge(@default_options, options)
    {:ok, PrivKey.to_wif(binprivkey, options[:network], options[:compressed])}
  end
  # If privkey is not binary or have the expected length return error
  def privkey_to_wif(_privkey, _options ) do
    {:error, :incorrect_privkey_length}
  end

  @doc """
  Returns the raw private key from a Wallet Import Format (WIF) string.
  Including metadata from WIF telling:
    - `compressed`: If when generating the public key, should use
    compressed format or uncompressed.
    - `network`: Where the private key should be used. In mainnet, or
    testnet.

  ## Examples

  Converts from wif to raw private key.

      iex> wif_to_privkey("KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL")
      {:ok, %{
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :mainnet
      }}

  ### Expected errors:

    Error if is base58check is another type other from WIF:

      iex> wif_to_privkey("1CLrrRUwXswyF2EVAtuXyqdk4qb8DSUHCX")
      {:error, :not_wif_version_prefix}

    Error if checksum is not valid:

      iex> wif_to_privkey("KyFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL")
      {:error, :checksum_incorrect}

    Error if using an unvalid base58 character:

      iex> wif_to_privkey("10Ol0Ol0Ol0Ol0Ol0Ol0OOlIIIIIII0OlI")
      {:error, :incorrect_base58}
  """
  @spec wif_to_privkey(wif_type) :: {:ok, privkey_result} | {:error, atom}
  def wif_to_privkey(wif), do: PrivKey.from_wif(wif)

end
