defmodule BtcTool.PubKey do
  @moduledoc false
  # Functions to convert between public key to other formats.

  @doc """
  Convert a binary private key (256 bits) to its public key.

  Public key internally is a a point in the elliptic curve, that is the
  pair {x, y}. We can have two formats:
    - **Uncompressed**: Used until bitcoin client v0.6, where both axis
    x and y are used. To recognize this format is prefixed with 0x04
    - **Compressed**: Used nowadays. Only the x is used. To be
    recognized this format is prefixed with 0x02 or 0x03, depending if
    y is odd (0x02) or even (0x03).

  Returned result will be the public key in both formats (binary and
  hexadecimal), plus if the public key is compressed or uncompressed.

  #### Example

      iex> binary_private_key = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" |> Base.decode16!()
      iex> compressed = true # If we want the compressed format
      iex> binprivkey_to_binpubkey(binary_private_key, compressed)
      {:ok, %{
        pubkey_bin: <<3, 70, 70, 174, 80, 71, 49, 107, 66, 48, 208, 8, 108, 138, 206, 198, 135, 240, 11, 28, 217, 209, 220, 99, 79, 108, 179, 88, 172, 10, 154, 143, 255>>,
        pubkey_hex: "034646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFF",
        compressed: true}}

  """
  @spec binprivkey_to_binpubkey(binary, boolean) ::
    {:ok, %{
      pubkey_bin: BtcTool.pubkey_type,
      pubkey_hex: <<_::528>> | <<_::1040>>, # E.g.: 33hexchars * 16bits = 528
      compressed: boolean
    }} | {:error, atom}
  def binprivkey_to_binpubkey(binprivkey, compressed)
  def binprivkey_to_binpubkey(binprivkey, true) when bit_size(binprivkey) == 256 do
    # When using compressed keys it will only output the coordinate x
    # plus an extra byte at the beginning. That extra byte can be 0x03
    # or 0x02 depending on the value of `y mod 2`.
    {x, <<y::256>>} = ecc_pubkey(binprivkey)
    case Integer.mod(y, 2) do
      0 -> {:ok, present_pubkey(<<0x02>> <> x, %{compressed: true})}
      1 -> {:ok, present_pubkey(<<0x03>> <> x, %{compressed: true})}
    end
  end
  def binprivkey_to_binpubkey(binprivkey, false) when bit_size(binprivkey) == 256  do
    {x, y} = ecc_pubkey(binprivkey)
    # When using uncompressed keys coordinates are prefixed with 0x04
    {:ok, present_pubkey(<<0x04>> <> x <> y, %{compressed: false})}
  end
  def binprivkey_to_binpubkey(_binprivkey, _compressed) do
    # The private key must be 256 bits in length. But this requirement
    # is not fulfilled.
    {:error, :unexpected_binary_privkey_length}
  end
  # Present result. Merge metadata map with extra information
  defp present_pubkey(binpubkey, %{} = metadata \\ %{}) do
    # Return binary and hexadecimal format
    %{pubkey_bin: binpubkey,
      pubkey_hex: Base.encode16(binpubkey) }
    |>Map.merge(metadata)
  end
  # Return public key from ECC
  defp ecc_pubkey(binprivkey) do
    {uncompressed_ecc_pubkey, _priv_key} =
      :crypto.generate_key(:ecdh, :crypto.ec_curve(:secp256k1), binprivkey)
    # Ignore first byte which always is 0x04 for uncompressed pub key
    x = binary_part(uncompressed_ecc_pubkey, 1, 32)
    y = binary_part(uncompressed_ecc_pubkey, 33, 32)
    {x, y}
  end
end
