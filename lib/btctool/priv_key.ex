defmodule BtcTool.PrivKey do
  @moduledoc false
  # Functions to convert from a raw private key to other formats.

  @doc """
  Convert a raw private key to Wallet Import Format (WIP).

  Arguments:

  - `binprivkey`. Which is the 32 bytes of the private key in binary
    format.
  - `network`. Can be `:mainnet` (default) or `:testnet`
  - `compress`. Can be `true` (default) or `false`

  ## Examples:

  On mainnet:
      iex> hexprivkey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      iex> binprivkey = hexprivkey |> Base.decode16!()
      <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>
      iex> to_wif(binprivkey, :mainnet, true)
      %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :mainnet
      }
      iex> to_wif(binprivkey, :mainnet, false)
      %{
        wif: "5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: false,
        network: :mainnet
      }
      iex> to_wif(binprivkey, :testnet, true)
      %{
        wif: "cMcuvhdzZHi9DCvdZFwwhGbBGiHexxj8SRyrZ6Qrk1WuuFC5NyCf",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :testnet
      }
      iex> to_wif(binprivkey, :testnet, false)
      %{
        wif: "91bRE5Duv5h8kYhhTLhYRXijCiXWSpWwFNX6nndfuntBdPV2idD",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: false,
        network: :testnet
      }
  """
  @spec to_wif(<<_::256>> | <<_::264>>, :testnet | :mainnet, boolean) ::
    BtcTool.privkey_result
  def to_wif(binprivkey, network, compress)
  def to_wif(binprivkey, :testnet, false) do
    %{encoded: encoded} = Area58check.encode(binprivkey, :testnet_wif)
    %{wif: encoded, network: :testnet, compressed: false}
    |>merge_privkey(binprivkey)
  end
  def to_wif(binprivkey, :mainnet, false) do
    %{encoded: encoded} = Area58check.encode(binprivkey, :wif)
    %{wif: encoded, network: :mainnet, compressed: false}
    |>merge_privkey(binprivkey)
  end
  def to_wif(binprivkey, network, true) when bit_size(binprivkey) === 256 do
    # To signal the compressed WIF, a 0x01 is appended to the end of
    # binary private key, resulting in a WIF of 52 characters. More info
    # https://bitcoin.stackexchange.com/questions/3059#answer-3839
    binprivkey <> <<1>>
    |>to_wif(network, false)
    |>Map.merge(%{ compressed: true }) # Override compression to true
    |>merge_privkey(binprivkey)
  end
  # Merge the raw private key into result (binary and hexadecimal)
  defp merge_privkey(result, binprivkey) do
    Map.merge(result, %{
      privkey_bin: binprivkey,
      privkey_hex: Base.encode16(binprivkey)
    })
  end

  @doc """
  Convert from Wallet Import Format private key to its raw version
  (binary and hexadecimal format).

  #### Example

      iex> from_wif("KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL")
      {:ok, %{
        wif: "KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL",
        privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
        privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        compressed: true,
        network: :mainnet
      }}
  """
  @spec from_wif(BtcTool.wif_type) :: {:ok, BtcTool.privkey_result} | {:error, atom}
  def from_wif(wif) do
    with \
      {:ok, %{decoded: binprivkey, version: version}} <- Area58check.decode(wif),
      # version must be wif, otherwise return error
      true <- (version in [:wif, :testnet_wif]) or {:error, :not_wif_version_prefix},
      # User expects to get the network field as `:testnet` or `:mainnet`
      network <- %{wif: :mainnet, testnet_wif: :testnet}[version],
      {:ok, privkey} <- add_metadata(binprivkey)
    do
      {:ok, %{privkey | network: network, wif: wif}}
    end
  end

  # binary privkey has the expected length of 256 bits. So that signals
  # to use public uncompressed keys
  defp add_metadata(binprivkey) when bit_size(binprivkey) == 256 do
    {:ok, %{
        privkey_bin: binprivkey,
        privkey_hex: Base.encode16(binprivkey),
        compressed: false,
        network: nil, # To be filed later
        wif: nil # To be filed later
      }
    }
  end
  # Binary privkey ending byte is <<1>>, so WIF signals to use compressed
  # public keys. Remove ending <<1>>, and process as uncompressed WIF
  defp add_metadata(binprivkey) when bit_size(binprivkey) == (256 + 8) do
    with \
      trailed_privkey <- String.trim_trailing(binprivkey, <<1>>),
      {:ok, privkey_metadata} <- add_metadata(trailed_privkey) do
      {:ok, %{privkey_metadata | compressed: true}}
    end
  end
  # The private key has a length != 256 or 264. That's weird, so return error.
  defp add_metadata(_binprivkey) do
    {:error, :unexpected_length}
  end

end
