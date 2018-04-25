defmodule BtcTool.Crypto do
  @moduledoc """
  Some cryptographic functions used internally, but exposed for
  convenience.
  """

  @doc """
  Return public key coordinates in elliptic curve from a binary private
  key.

  Result will be a tuple with `x` and `y` binary coordinates like: `{x,
  y}`

  #### Examples

      iex> binprivkey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" |> Base.decode16!()
      iex> ecc_pubkey_coordinates(binprivkey)
      {<<70, 70, 174, 80, 71, 49, 107, 66, 48, 208, 8, 108, 138, 206, 198, 135, 240, 11, 28, 217, 209, 220, 99, 79, 108, 179, 88, 172, 10, 154, 143, 255>>,
       <<254, 119, 180, 221, 10, 75, 251, 149, 133, 31, 59, 115, 85, 199, 129, 221, 96, 248, 65, 143, 200, 166, 93, 20, 144, 122, 255, 71, 201, 3, 165, 89>>}
  """
  @spec ecc_pubkey_coordinates(binary) :: {<<_::256>>, <<_::256>>}
  def ecc_pubkey_coordinates(binprivkey) do
    {uncompressed_ecc_pubkey, _priv_key} =
      :crypto.generate_key(:ecdh, :crypto.ec_curve(:secp256k1), binprivkey)
    # Ignore first byte which always is 0x04 for uncompressed pub key
    x = binary_part(uncompressed_ecc_pubkey, 1, 32)
    y = binary_part(uncompressed_ecc_pubkey, 33, 32)
    {x, y}
  end

  @doc """
  Generate a hash using SHA256 from a provided seed that can be any
  string.

  Returned result will be a binary hash of 256 bits.

  #### Examples
      iex> sha256("any string")
      <<30, 87, 164, 82, 160, 148, 114, 140, 41, 27, 196, 43, 242, 188, 126, 184, 217, 253, 136, 68, 209, 54, 157, 162, 191, 114, 133, 136, 180, 108, 78, 117>>
  """
  @spec sha256(binary) :: <<_::256>>
  def sha256(seed) do
    :crypto.hash(:sha256, seed)
  end

  @doc """
  Generate a hash using RIPEMD160 from a provided seed that can be any
  string.

  Returned result will be a binary hash of 160 bits.

  #### Examples
      iex> ripemd160("any string")
      <<139, 29, 138, 146, 56, 239, 32, 33, 226, 92, 115, 96, 183, 154, 46, 97, 240, 65, 200, 180>>
  """
  @spec ripemd160(binary) :: <<_::160>>
  def ripemd160(seed) do
    :crypto.hash(:ripemd160, seed)
  end

end
