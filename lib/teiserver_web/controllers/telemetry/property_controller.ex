defmodule TeiserverWeb.Telemetry.PropertyController do
  use CentralWeb, :controller
  alias Teiserver.Telemetry
  alias Teiserver.Telemetry.ExportPropertiesTask
  require Logger

  plug(AssignPlug,
    site_menu_active: "telemetry",
    sub_menu_active: "client_event"
  )

  plug Bodyguard.Plug.Authorize,
    policy: Teiserver.Auth.Server,
    action: {Phoenix.Controller, :action_name},
    user: {Teiserver.Account.AuthLib, :current_user}

  plug(:add_breadcrumb, name: 'Telemetry', url: '/telemetry')
  plug(:add_breadcrumb, name: 'Client events', url: '/teiserver/telemetry/client_events/summary')

  @spec summary(Plug.Conn.t(), map) :: Plug.Conn.t()
  def summary(conn, params) do
    timeframe = Map.get(params, "timeframe", "week")

    between =
      case timeframe do
        "day" -> {Timex.now() |> Timex.shift(days: -1), Timex.now()}
        "week" -> {Timex.now() |> Timex.shift(days: -7), Timex.now()}
      end

    args = [
      between: between
    ]

    client_properties = Telemetry.get_client_properties_summary(args)
    unauth_properties = Telemetry.get_unauth_properties_summary(args)

    property_types =
      (Map.keys(client_properties) ++ Map.keys(unauth_properties))
      |> Enum.uniq()
      |> Enum.sort()

    conn
    |> assign(:timeframe, timeframe)
    |> assign(:property_types, property_types)
    |> assign(:client_properties, client_properties)
    |> assign(:unauth_properties, unauth_properties)
    |> render("summary.html")
  end

  @spec detail(Plug.Conn.t(), map) :: Plug.Conn.t()
  def detail(conn, %{"property_name" => property_name} = _params) do
    property_type_id = Telemetry.get_or_add_property_type(property_name)

    client_counts =
      Telemetry.list_client_properties(search: [property_type_id: property_type_id])
      |> Enum.group_by(fn p -> p.value end)
      |> Map.new(fn {value, items} -> {value, Enum.count(items)} end)

    unauth_counts =
      Telemetry.list_unauth_properties(search: [property_type_id: property_type_id])
      |> Enum.group_by(fn p -> p.value end)
      |> Map.new(fn {value, items} -> {value, Enum.count(items)} end)

    combined_values =
      (Map.keys(client_counts) ++ Map.keys(unauth_counts))
      |> Enum.uniq()
      |> Enum.sort()

    conn
    |> assign(:property_name, property_name)
    |> assign(:client_counts, client_counts)
    |> assign(:unauth_counts, unauth_counts)
    |> assign(:combined_values, combined_values)
    |> render("detail.html")
  end

  @spec export_form(Plug.Conn.t(), map) :: Plug.Conn.t()
  def export_form(conn, _params) do
    conn
    |> assign(:event_types, Telemetry.list_client_event_types(order_by: "Name (A-Z)"))
    |> assign(:property_types, Telemetry.list_property_types())
    |> render("export_form.html")
  end

  @spec export_post(Plug.Conn.t(), map) :: Plug.Conn.t()
  def export_post(conn, params) do
    start_time = System.system_time(:millisecond)

    data = ExportPropertiesTask.perform(params)

    time_taken = System.system_time(:millisecond) - start_time

    Logger.info(
      "ComplexClientEventController property export of #{Kernel.inspect(params)}, took #{time_taken}ms"
    )

    conn
    |> put_resp_content_type("text/csv")
    |> put_resp_header("content-disposition", "attachment; filename=\"properties.csv\"")
    |> send_resp(200, data)
  end
end
