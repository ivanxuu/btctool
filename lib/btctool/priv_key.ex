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
        compressed: true,
        network: :mainnet
      }
      iex> to_wif(binprivkey, :mainnet, false)
      %{
        wif: "5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb",
        compressed: false,
        network: :mainnet
      }
      iex> to_wif(binprivkey, :testnet, true)
      %{
        wif: "cMcuvhdzZHi9DCvdZFwwhGbBGiHexxj8SRyrZ6Qrk1WuuFC5NyCf",
        compressed: true,
        network: :testnet
      }
      iex> to_wif(binprivkey, :testnet, false)
      %{
        wif: "91bRE5Duv5h8kYhhTLhYRXijCiXWSpWwFNX6nndfuntBdPV2idD",
        compressed: false,
        network: :testnet
      }
  """
  def to_wif(binprivkey, network, compress)
  def to_wif(binprivkey, :testnet, false) do
    %{encoded: encoded} = Area58check.encode(binprivkey, :tesnet_wif)
    %{wif: encoded, network: :testnet, compressed: false }
  end
  def to_wif(binprivkey, :mainnet, false) do
    %{encoded: encoded} = Area58check.encode(binprivkey, :wif)
    %{wif: encoded, network: :mainnet, compressed: false}
  end
  def to_wif(binprivkey, network, true) when bit_size(binprivkey) === 256 do
    # To signal the compressed WIF, a 0x01 is appended to the end of
    # binary private key, resulting in a WIF of 52 characters. More info
    # https://bitcoin.stackexchange.com/questions/3059#answer-3839
    binprivkey <> <<1>>
    |>to_wif(network, false)
    |>Map.merge(%{compressed: true}) # Override compression to true
  end
end
