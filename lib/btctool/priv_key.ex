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
  """
  @spec from_wif(BtcTool.wif_type) :: {:ok, BtcTool.privkey_result} | {:error, atom}
  def from_wif(wif) do
    Area58check.decode(wif)
    |>process_base58check_result()
    |>case do
        {:ok, result} -> {:ok, Map.put(result, :wif, wif)}
        {:error, error} -> {:error, error}
      end
  end
  defp process_base58check_result({:ok, %{decoded: decoded, version: version}}) when version in [:wif, :testnet_wif] do
    network = wif_version_to_network(version) #=> :testnet or :mainnet
    process_binary_privkey(decoded)
    |>case do
        {:ok, result} -> {:ok, Map.put(result, :network, network)}
        {:error, error} -> {:error, error}
      end
  end
  # Version is other from :wif, or :wif_testnet
  defp process_base58check_result({:ok, %{decoded: _decoded, version: _version}}) do
    {:error, :not_wif_version_prefix}
  end
  defp process_base58check_result({:error, area58check_error}) do
    {:error, area58check_error}
  end
  defp wif_version_to_network(:wif), do: :mainnet
  defp wif_version_to_network(:testnet_wif), do: :testnet
  # binary privkey has the expected length of 256 bits. So that signals
  # to use public uncompressed keys
  defp process_binary_privkey(binprivkey) when bit_size(binprivkey) == 256 do
    {:ok, %{
      privkey_bin: binprivkey,
      privkey_hex: Base.encode16(binprivkey),
      compressed: false}
    }
  end
  # binary privkey length ending byte is <<1>>, so WIF signals to use
  # compressed public keys
  defp process_binary_privkey(privkey) when bit_size(privkey) == (256 + 8) do
    String.trim_trailing(privkey, <<1>>) # Remove trailing <<1>>
    |>process_binary_privkey() # Process as uncompressed WIF
    |>case do # Update `:compressed` metadata
        {:ok, result} -> {:ok, Map.put(result, :compressed, true)}
        {:error, error} -> {:error, error}
      end
  end
  # The private key has a length != 256. That's weird.
  defp process_binary_privkey(_privkey) do
    {:error, :unexpected_length}
  end

end
