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

end
