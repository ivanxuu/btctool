defmodule BtcToolTest do
  use ExUnit.Case
  doctest BtcTool

  test "greets the world" do
    assert BtcTool.hello() == :world
  end
end
