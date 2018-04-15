defmodule BtcToolTest.PrivKey do
  use ExUnit.Case
  doctest BtcTool.PrivKey, import: true
  alias BtcTool.PrivKey

  describe "to_wif" do
    test "read compressed WIF in mainnet" do
      assert PrivKey.from_wif("KwFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL") ==
        {:ok, %{
          privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
          privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
          compressed: true,
          network: :mainnet}}
    end
    test "read uncompressed WIF in mainnet" do
      assert PrivKey.from_wif("5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb") ==
        {:ok, %{
          privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
          privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
          compressed: false,
          network: :mainnet}}
    end
    test "read compressed WIF in testnet" do
      assert PrivKey.from_wif("cMcuvhdzZHi9DCvdZFwwhGbBGiHexxj8SRyrZ6Qrk1WuuFC5NyCf") ==
        {:ok, %{
          privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
          privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
          compressed: true,
          network: :testnet}}
    end
    test "read uncompressed WIF in testnet" do
      assert PrivKey.from_wif("91bRE5Duv5h8kYhhTLhYRXijCiXWSpWwFNX6nndfuntBdPV2idD") ==
        {:ok, %{
          privkey_bin: <<1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239>>,
          privkey_hex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
          compressed: false,
          network: :testnet}}
    end
    test "Error if is base58check is another type other from WIF" do
      assert PrivKey.from_wif("1CLrrRUwXswyF2EVAtuXyqdk4qb8DSUHCX") ==
        {:error, :not_wif_version_prefix}
    end
    test "Error if checksum is not valid" do
      assert PrivKey.from_wif("KyFvTne98E1t3mTNAr8pKx67eUzFJWdSNPqPSfxMEtrueW7PcQzL") ==
        {:error, :checksum_incorrect}
    end
    test "Error if using an unvalid base58 character" do
      assert PrivKey.from_wif("10Ol0Ol0Ol0Ol0Ol0Ol0OOlIIIIIII0OlI") ==
        {:error, :incorrect_base58}
    end
  end

end
