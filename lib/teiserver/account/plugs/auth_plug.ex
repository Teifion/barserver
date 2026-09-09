defmodule Teiserver.Account.AuthPlug do
  @moduledoc false

  alias ExULID.ULID
  alias Phoenix.Controller
  alias Phoenix.LiveView
  alias Phoenix.LiveView.Utils
  alias Teiserver.Account
  alias Teiserver.Account.Guardian
  alias Teiserver.Account.Guardian.Plug, as: GuardianPlug
  alias Teiserver.Account.TOTPLib

  use TeiserverWeb, :verified_routes

  import Plug.Conn

  def init(_opts) do
    # Keyword.fetch!(opts, :repo)
  end

  def call(conn, _opts) do
    user =
      case Guardian.resource_from_token(conn.cookies["guardian_default_token"]) do
        {:ok, user, _claims} -> Account.get_user!(user.id)
        _error -> nil
      end

    user_token =
      if user do
        GuardianPlug.current_token(conn)
      else
        ""
      end

    if user != nil do
      Logger.metadata([user_id: user.id] ++ Logger.metadata())
    end

    totp_status =
      case user do
        nil -> nil
        _user -> TOTPLib.get_user_totp_status(user.id)
      end

    conn =
      conn
      |> assign(:user_token, user_token)
      |> assign(:current_user, user)
      |> assign(:totp_status, totp_status)

    if banned_user?(conn) do
      conn
      |> assign(:current_user, nil)
      |> assign(:user_token, nil)
      |> assign(:totp_status, nil)
      |> Controller.put_flash(:danger, "You are banned")
      |> GuardianPlug.sign_out(clear_remember_me: true)
      |> Controller.redirect(to: ~p"/logout")
    else
      conn
    end
  end

  def live_call(socket, session) do
    user =
      case Guardian.resource_from_token(session["guardian_default_token"]) do
        {:ok, user, _claims} -> Account.get_user!(user.id)
        _error -> nil
      end

    if user != nil do
      request_id = ULID.generate()
      Logger.metadata([request_id: request_id, user_id: user.id] ++ Logger.metadata())
    end

    socket =
      socket
      |> Utils.assign(:current_user, user)

    if banned_user?(socket) do
      socket
      |> Utils.assign(:current_user, nil)
      |> Utils.assign(:user_token, nil)
      |> LiveView.redirect(to: ~p"/logout")
    else
      socket
    end
  end

  defp banned_user?(%{assigns: %{current_user: nil}}), do: false

  defp banned_user?(%{assigns: %{current_user: current_user}} = _conn_or_socket) do
    cond do
      Account.restricted?(current_user.id, ["Login"]) ->
        true

      current_user.smurf_of_id != nil ->
        true

      true ->
        false
    end
  end
end
