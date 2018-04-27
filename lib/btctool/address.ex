defmodule BtcTool.Address do
  @moduledoc false

  alias BtcTool.Crypto

  @doc """
  Generate bitcoin address from the public key in the requested
  `address_type`.

  #### Examples

      iex> {:ok, %{pubkey_bin: binpubkey}} = BtcTool.wif_to_pubkey "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
      iex> from_pubkey(binpubkey, :p2pkh)
      {:ok, %{address: "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T", type: :p2pkh}}
  """
  @spec from_pubkey(BtcTool.pubkey_type, BtcTool.address_type) ::
    {:ok, %{address: binary, type: BtcTool.address_type}} | {:error, atom}
  def from_pubkey(pubkey, address_type)
  def from_pubkey(pubkey, :p2pkh) do
    pubkey
    |>Crypto.sha256()
    |>Crypto.ripemd160()
    |>Area58check.encode(:p2pkh)
    |>case do
        %Area58check{encoded: encoded} ->
          {:ok, %{address: encoded, type: :p2pkh}}
        {:error, error} -> {:error, error}
      end
  end
  def from_pubkey(_pubkey, _address_type), do: {:error, :unknown_address_type}
end
