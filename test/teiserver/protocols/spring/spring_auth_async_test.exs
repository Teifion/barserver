defmodule Barserver.SpringAuthAsyncTest do
  use Barserver.ServerCase, async: true
  alias Barserver.Client
  alias Barserver.Protocols.Spring

  import Barserver.BarserverTestLib,
    only: [
      async_auth_setup: 1,
      _send_lines: 2,
      _recv_lines: 0,
      _recv_lines: 1
    ]

  setup do
    %{user: user, state: state} = async_auth_setup(Spring)
    on_exit(fn -> teardown(user) end)
    {:ok, state: state, user: user}
  end

  defp teardown(user) do
    Client.disconnect(user.id)
  end

  test "PING", %{state: state} do
    _send_lines(state, "#4 PING\n")
    reply = _recv_lines()
    assert reply == "#4 PONG\n"
  end

  test "GETUSERINFO", %{state: state, user: user} do
    _send_lines(state, "GETUSERINFO\n")
    reply = _recv_lines(3)
    assert reply =~ "SERVERMSG Registration date: "
    assert reply =~ "SERVERMSG Email address: #{user.email}"
    assert reply =~ "SERVERMSG Ingame time: "
  end
end
