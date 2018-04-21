defmodule BtcToolTest.PubKey do
  use ExUnit.Case
  doctest BtcTool.PubKey, import: true
  alias BtcTool.PubKey

  @binprivkey "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" |> Base.decode16!()
  describe "binprivkey_to_binpubkey" do
    test "to compressed format" do
      assert PubKey.binprivkey_to_binpubkey(@binprivkey, true) ==
        {:ok, %{
          pubkey_bin: Base.decode16!("034646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFF"),
          pubkey_hex: "034646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFF" }
        }
    end
    test "to uncompressed format" do
      assert PubKey.binprivkey_to_binpubkey(@binprivkey, false) ==
        {:ok, %{
          pubkey_bin: Base.decode16!("044646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFFFE77B4DD0A4BFB95851F3B7355C781DD60F8418FC8A65D14907AFF47C903A559"),
          pubkey_hex: "044646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFFFE77B4DD0A4BFB95851F3B7355C781DD60F8418FC8A65D14907AFF47C903A559" }
        }
    end
    test "Error if unexpected privkey length" do
      assert PubKey.binprivkey_to_binpubkey(<<1,2,3>>, true) ==
        {:error, :unexpected_binary_privkey_length}
    end
  end

end
