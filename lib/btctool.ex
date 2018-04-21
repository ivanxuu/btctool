defmodule BtcTool do
  @moduledoc """
  Bitcoin utils related to Elliptic curve cryptography (ECC) algorithms
  used in bitcoin to create addresses or public keys from private keys,
  brainwallets, WIFs, etc.
  """

  alias BtcTool.{PrivKey,PubKey}

  # Min-max value for secp256k1 ECC. More info at:
  # https://bitcoin.stackexchange.com/questions/1389#answer-1715
  @ecc_min "0000000000000000000000000000000000000000000000000000000000000000" |> Base.decode16!()
  @ecc_max "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" |> Base.decode16!()

  @typedoc """
  Wallet Import Format string ready to be imported into a wallet. It
  uses base58check characters. The raw private key can be extracted from
  this.

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
  Hash which includes WIF, private key and metadata.

  #### WIF string
  Wallet Import Format string containing the private key. It also
  includes metadata with information extracted from the WIF string.

  WIF will be a base58check string of 51 characters (408 bits) if user
  want to use uncompressed public keys in the bitcoin addresses, or 52
  characters (416 bits) if wants to use compressed public keys.

  #### Raw private key
  Raw private key in binary format (512bits) and hexadecimal
  format (characters a-z0-9).

  #### Available metadata
  Metadata like `network` or `compressed` is deducted from the WIP
  string:
   - `network`. Which network (`:mainnet`, or `:testnet`) is intended to
   be used the private key.
   - `compressed`. States if when using private key to generate an
   address  should use the compressed or uncompressed version of the
   public key. *Note: Nowadays is normal to use the compressed version.*
  """
  @type privkey_result :: %{
    wif: wif_type,
    privkey_bin: <<_::256>>, privkey_hex: <<_::512>>,
    network: :testnet | :mainnet, compressed: boolean }

  @typedoc """
  Public key derived from the private key.

  This key can be compressed or uncompressed. Compressed keys include
  only the x coordinate. Uncompressed public key includes the `x` and
  `y` coordinates. To differentiate between them, an additional byte is
  added to the beginning:

    - Uncompressed key starts with `0x04`
    - Compressed key begins with `0x02` or `0x03` depending on if the
    `y` coordinate is odd or even.
  """
  @type pubkey_type :: <<_::264>> | <<_::520>>

  @doc """
  Create Wallet Import Format (WIF) private key from raw private key.
  A raw private key can be presented by a binary of 32 bytes or in
  64 hexadecimal characters (0-9a-fA-F)

  It assumes you want the **compressed** WIF version by default. That
  way you are signalling that the bitcoin address which should be used
  when imported into a wallet will be also compressed.

  ## Options
    - `compressed` - Generate a WIF which signals that a compressed
      public key should be used if `true`. Default to `true`.
    - `network` - Specifies the network this private key intended to
      be used on. Can be `:mainnet` or `:testnet`. Default is `:mainnet`.
    - `case` - Ensures the character case to accept when decoding.
      Valid values are: `:upper`, `:lower`, `:mixed`.
      Only useful when the raw private key is passed in hex format.
      If case is not satisfied will return an error.
      Default is `:mixed`

  ## Examples

      iex> hexprivkey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      iex> privkey_to_wif(hexprivkey)
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :mainnet
      }}
      iex> binprivkey = hexprivkey |> Base.decode16!()
      <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>
      iex> privkey_to_wif(binprivkey)
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :mainnet
      }}
      iex> privkey_to_wif(binprivkey, compressed: false, network: :testnet)
      {:ok, %{
        wif: "91bRE5Duv5h8kYhhTLhYRXijCiXWSpWwFNX6nndfuntBdPV2idD",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
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

  When private key is hexadecimal and have an unexpected case:

      iex> privkey_to_wif("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", case: :lower)
      {:error, :unexpected_hexadecimal_case}
  """
  @default_options [network: :mainnet, compressed: true]
  @spec privkey_to_wif( <<_::512>> | <<_::256>>, [{atom, any}] ) ::
    {:ok, privkey_result}
    | {:error, atom }
  def privkey_to_wif(privkey, options \\ [])
  # Private key was provided in hexadecimal format
  def privkey_to_wif(hexprivkey, options) when is_binary(hexprivkey) and bit_size(hexprivkey) === 512 do
    options = Keyword.merge( [case: :mixed], options)
    hexprivkey
    |>Base.decode16(case: options[:case])
    |>case do
        {:ok, binprivkey} -> privkey_to_wif(binprivkey, options)
        :error -> {:error, :unexpected_hexadecimal_case}
      end
  end
  # Private key must be inside a recommended range. Otherwise return
  # error. More info at:
  # https://bitcoin.stackexchange.com/questions/1389#answer-1715
  def privkey_to_wif(binprivkey, _options) when binprivkey <= @ecc_min or binprivkey >= @ecc_max do
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

  Converts from a WIF string to raw private key.

      iex> wif_to_privkey("KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL")
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
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

  @doc """
  Generate public key from a Wallet Import Format string (WIF).

  If succesfull, public key is returned in binary and hexadecimal format
  in a map.

  For any private key, its public key can be presented in compressed or
  uncompressed format. The compressed format is usually the most used.
  Which one should be used, can be deducted from the WIF string, so this
  function finds out which one is requested without any user
  intervention.

  Note: If you want to generate a public key directly from the binary
  private key, instead of a WIF string, you can use the function
  `BtcTool.Pubkey.binprivkey_to_binpubkey/2`, documented in the source.

  #### Examples

  With a compressed a WIF string (starts with `K` or `L`):

      iex> wif_to_pubkey("KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL")
      {:ok, %{
        pubkey_bin: <<3, 70, 70, 174, 80, 71, 49, 107, 66, 48, 208, 8, 108, 138, 206, 198, 135, 240, 11, 28, 217, 209, 220, 99, 79, 108, 179, 88, 172, 10, 154, 143, 255>>,
        pubkey_hex: "034646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFF"}
      }

  With a uncompressed WIF string (starts with `5`):

      iex> wif_to_pubkey("5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb")
      {:ok, %{
        pubkey_bin: <<4, 70, 70, 174, 80, 71, 49, 107, 66, 48, 208, 8, 108, 138, 206, 198, 135, 240, 11, 28, 217, 209, 220, 99, 79, 108, 179, 88, 172, 10, 154, 143, 255, 254, 119, 180, 221, 10, 75, 251, 149, 133, 31, 59, 115, 85, 199, 129, 221, 96, 248, 65, 143, 200, 166, 93, 20, 144, 122, 255, 71, 201, 3, 165, 89>>,
        pubkey_hex: "044646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFFFE77B4DD0A4BFB95851F3B7355C781DD60F8418FC8A65D14907AFF47C903A559"}
      }

  Will return an error and atom if any error is present. Some examples
  (among other errors):

      iex> wif_to_pubkey("Not_a_WIF")
      {:error, :incorrect_base58}
      iex> wif_to_pubkey("2dqAyxFfwDYds")
      {:error, :unexpected_length}
  """
  @spec wif_to_pubkey(wif_type) :: {:ok, %{
      pubkey_bin: BtcTool.pubkey_type,
      pubkey_hex: <<_::528>> | <<_::1040>> # E.g.: 33hexchars * 16bits = 528
    }} | {:error, atom}
  def wif_to_pubkey(wif) do
    wif
    |>wif_to_privkey() # To find out privatekey and if need compressed format
    |>case do
        {:ok, %{privkey_bin: binprivkey, compressed: compressed}} ->
          PubKey.binprivkey_to_binpubkey(binprivkey, compressed)
        {:error, reason} -> {:error, reason}
      end
  end

end
