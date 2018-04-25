defmodule BtcToolTest do
  use ExUnit.Case
  doctest BtcTool, import: true

  describe "privkey_to_wif" do
    @min_priv_key "0000000000000000000000000000000000000000000000000000000000000000" |> Base.decode16!()
    test "returns error if privkey less or equal than ECC recommended values" do
      assert BtcTool.privkey_to_wif(@min_priv_key) ==
        {:error, :ecc_out_range}
    end
    @max_priv_key "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140" |> Base.decode16!()
    test "returns error if privkey greater or equal than ECC recommended values" do
      assert BtcTool.privkey_to_wif(@max_priv_key) ==
        {:error, :ecc_out_range}
    end
  end

  describe "brainwallet_to_wif" do
    test "accept options" do
      {:ok, %{wif: "935ZTXVqEatu6BaEX6CHrzpXquDKurpVXD7q1FQ1K3pt8VwmG2L"}}
        = BtcTool.brainwallet_to_wif(
            "correct horse battery staple",
            network: :testnet, compressed: false)
    end
  end

end
