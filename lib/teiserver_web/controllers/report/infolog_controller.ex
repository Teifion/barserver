defmodule TeiserverWeb.Report.InfologController do
  use CentralWeb, :controller
  alias Teiserver.Telemetry

  plug(AssignPlug,
    site_menu_active: "teiserver_report",
    sub_menu_active: "infolog"
  )

  plug Bodyguard.Plug.Authorize,
    policy: Teiserver.Telemetry.Infolog,
    action: {Phoenix.Controller, :action_name},
    user: {Central.Account.AuthLib, :current_user}

  plug(:add_breadcrumb, name: 'Teiserver', url: '/teiserver')
  plug(:add_breadcrumb, name: 'Reports', url: '/teiserver/reports')
  plug(:add_breadcrumb, name: 'Infologs', url: '/teiserver/reports/infolog')

  @spec index(Plug.Conn.t(), map) :: Plug.Conn.t()
  def index(conn, params) do
    infologs =
      Telemetry.list_infologs(
        search: [],
        preload: [:user],
        select: ~w(id user_hash user_id log_type timestamp metadata size)a,
        order_by: "Newest first"
      )

    conn
    |> assign(:infologs, infologs)
    |> assign(:params, params)
    |> render("index.html")
  end

  @spec search(Plug.Conn.t(), map) :: Plug.Conn.t()
  def search(conn, %{"search" => params}) do
    infologs =
      Telemetry.list_infologs(
        search: [
          log_type: params["type"],
          engine: params["engine"],
          game: params["game"]
        ],
        preload: [:user],
        select: ~w(id user_hash user_id log_type timestamp metadata size)a,
        order_by: params["order"]
      )

    conn
    |> assign(:params, params)
    |> assign(:infologs, infologs)
    |> render("index.html")
  end

  @spec show(Plug.Conn.t(), map) :: Plug.Conn.t()
  def show(conn, %{"id" => id}) do
    infolog = Telemetry.get_infolog(id, preload: [:user])

    conn
    |> assign(:infolog, infolog)
    |> render("show.html")
  end

  @spec download(Plug.Conn.t(), map) :: Plug.Conn.t()
  def download(conn, %{"id" => id}) do
    infolog = Telemetry.get_infolog(id)

    conn
    |> put_resp_content_type("text/plain")
    |> put_resp_header(
      "content-disposition",
      "attachment; filename=\"infolog_#{infolog.id}.log\""
    )
    |> send_resp(200, infolog.contents)
  end

  @spec delete(Plug.Conn.t(), map) :: Plug.Conn.t()
  def delete(conn, %{"id" => id}) do
    infolog = Telemetry.get_infolog(id)

    {:ok, _clan} = Telemetry.delete_infolog(infolog)

    conn
    |> put_flash(:info, "Infolog deleted successfully.")
    |> redirect(to: Routes.ts_reports_infolog_path(conn, :index))
  end
end
