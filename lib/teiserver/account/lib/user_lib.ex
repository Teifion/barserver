defmodule Teiserver.Account.UserLib do
  use CentralWeb, :library
  alias Central.Account.UserQueries
  require Logger
  alias Teiserver.Data.Types, as: T

  # Functions
  @spec icon :: String.t()
  def icon, do: "fa-regular fa-user-robot"

  @spec colours :: atom
  def colours, do: :success

  @spec colour :: atom
  def colour, do: :success

  @spec make_favourite(Central.Account.User.t()) :: Map.t()
  def make_favourite(user) do
    %{
      type_colour: StylingHelper.colours(colours()) |> elem(0),
      type_icon: icon(),
      item_id: user.id,
      item_type: "teiserver_user",
      item_colour: user.colour,
      item_icon: user.icon,
      item_label: "#{user.name}",
      url: "/teiserver/admin/user/#{user.id}"
    }
  end

  # Queries
  @spec get_user() :: Ecto.Query.t()
  def get_user, do: UserQueries.get_users()

  @spec search(Ecto.Query.t(), map | nil) :: Ecto.Query.t()
  def search(query, nil), do: query

  def search(query, params) do
    params
    |> Enum.reduce(query, fn {key, value}, query_acc ->
      _search(query_acc, key, value)
    end)
  end

  @spec _search(Ecto.Query.t(), atom, any) :: Ecto.Query.t()
  def _search(query, _, ""), do: query
  def _search(query, _, nil), do: query
  def _search(query, _, "Any"), do: query

  def _search(query, :data_equal, {field, value}) do
    from users in query,
      where: fragment("? ->> ? = ?", users.data, ^field, ^value)
  end

  def _search(query, :data_greater_than, {field, value}) do
    from users in query,
      where: fragment("? ->> ? > ?", users.data, ^field, ^value)
  end

  def _search(query, :data_less_than, {field, value}) do
    from users in query,
      where: fragment("? ->> ? < ?", users.data, ^field, ^value)
  end

  def _search(query, :data_not, {field, value}) do
    from users in query,
      where: fragment("? ->> ? != ?", users.data, ^field, ^value)
  end

  # https://www.postgresql.org/docs/current/functions-json.html - Unable to find a function for this :(
  def _search(query, :data_contains, {field, value}) do
    from users in query,
      where: fragment("? ->> ? @> ?", users.data, ^field, ^value)
  end

  def _search(query, :data_contains_key, field) do
    from users in query,
      where: fragment("? @> ?", users.data, ^field)
  end

  # E.g. [data_contains_number: {"ignored", 9265}]
  def _search(query, :data_contains_number, {field, value}) when is_number(value) do
    from users in query,
      where: fragment("(? ->> ?)::jsonb @> ?::jsonb", users.data, ^field, ^value)
  end

  def _search(query, :bot, "Person") do
    Logger.error("user.data['bot'] is being queried, this property is due to be depreciated")

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "bot", "false")
  end

  def _search(query, :bot, "Robot") do
    Logger.error("user.data['bot'] is being queried, this property is due to be depreciated")

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "bot", "true")
  end

  def _search(query, :moderator, "User") do
    Logger.error(
      "user.data['moderator'] is being queried, this property is due to be depreciated"
    )

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "moderator", "false")
  end

  def _search(query, :moderator, "Moderator") do
    Logger.error(
      "user.data['moderator'] is being queried, this property is due to be depreciated"
    )

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "moderator", "true")
  end

  def _search(query, :verified, "Unverified") do
    Logger.error("user.data['verified'] is being queried, this property is due to be depreciated")

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "verified", "false")
  end

  def _search(query, :verified, "Verified") do
    Logger.error("user.data['verified'] is being queried, this property is due to be depreciated")

    from users in query,
      where: fragment("? ->> ? = ?", users.data, "verified", "true")
  end

  def _search(query, :mod_action, "Banned") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "restrictions", "\"Login\"")
  end

  def _search(query, :mod_action, "Not banned") do
    from users in query,
      where: not fragment("? -> ? @> ?", users.data, "restrictions", "\"Login\"")
  end

  def _search(query, :mod_action, "Muted") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "restrictions", "\"All chat\"")
  end

  def _search(query, :mod_action, "Shadowbanned") do
    from users in query,
      where: fragment("? ->> ? = ?", users.data, "shadowbanned", "true")
  end

  def _search(query, :mod_action, "Warned") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "restrictions", "\"Warning reminder\"")
  end

  def _search(query, :mod_action, "Any action") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "restrictions", "\"Warning reminder\"")
  end

  def _search(query, :mod_action, "Any user") do
    query
  end

  def _search(query, :tester, "Trusted") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Trusted\"")
  end

  def _search(query, :tester, "Tester") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Tester\"")
  end

  def _search(query, :tester, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Tester\"")
  end

  def _search(query, :streamer, "Streamer") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Streamer\"")
  end

  def _search(query, :streamer, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Streamer\"")
  end

  def _search(query, :donor, "Donor") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Donor\"")
  end

  def _search(query, :donor, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Donor\"")
  end

  def _search(query, :gdt_member, "GDT") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"GDT\"")
  end

  def _search(query, :gdt_member, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"GDT\"")
  end

  def _search(query, :contributor, "Contributor") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Contributor\"")
  end

  def _search(query, :contributor, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Contributor\"")
  end

  def _search(query, :developer, "Developer") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Developer\"")
  end

  def _search(query, :developer, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Developer\"")
  end

  def _search(query, :caster, "Caster") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Caster\"")
  end

  def _search(query, :caster, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Caster\"")
  end

  def _search(query, :tournament_player, "Player") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"Tournament player\"")
  end

  def _search(query, :tournament_player, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"Tournament player\"")
  end

  def _search(query, :vip, "VIP") do
    from users in query,
      where: fragment("? -> ? @> ?", users.data, "roles", "\"VIP\"")
  end

  def _search(query, :vip, "Normal") do
    from users in query,
      where: fragment("not ? -> ? @> ?", users.data, "roles", "\"VIP\"")
  end

  def _search(query, :lobby_client, lobby_client) do
    from users in query,
      where: fragment("? ->> ? = ?", users.data, "lobby_client", ^lobby_client)
  end

  def _search(query, :previous_names, name) do
    uname = "%" <> name <> "%"

    from users in query,
      where: ilike(users.name, ^uname)
  end

  def _search(query, key, value) do
    UserQueries._search(query, key, value)
  end

  @spec order_by(Ecto.Query.t(), tuple() | String.t() | nil) :: Ecto.Query.t()
  def order_by(query, nil), do: query

  def order_by(query, {:data, field, :asc}) do
    from users in query,
      order_by: [asc: fragment("? -> ?", users.data, ^field)]
  end

  def order_by(query, {:data, field, :desc}) do
    from users in query,
      order_by: [desc: fragment("? -> ?", users.data, ^field)]
  end

  def order_by(query, key), do: UserQueries.order(query, key)

  @spec preload(Ecto.Query.t(), list() | nil) :: Ecto.Query.t()
  def preload(query, nil), do: query

  def preload(query, preloads) do
    query = UserQueries.preload(query, preloads)

    query = if :user_stat in preloads, do: _preload_user_stat(query), else: query

    query
  end

  @spec _preload_user_stat(Ecto.Query.t()) :: Ecto.Query.t()
  def _preload_user_stat(query) do
    from user in query,
      left_join: user_stats in assoc(user, :user_stat),
      preload: [user_stat: user_stats]
  end

  @spec global_roles :: [String.t()]
  def global_roles() do
    ~w(Default Armada Cortex Raptor Scavenger)
  end

  @spec role_def(String.t()) :: nil | {String.t(), String.t()}
  def role_def("Default"), do: {"#666666", "fa-solid fa-user"}
  def role_def("Armada"), do: {"#000066", "fa-solid fa-a"}
  def role_def("Cortex"), do: {"#660000", "fa-solid fa-c"}
  def role_def("Legion"), do: {"#006600", "fa-solid fa-l"}
  def role_def("Raptor"), do: {"#AA6600", "fa-solid fa-drumstick"}
  def role_def("Scavenger"), do: {"#660066", "fa-solid fa-user-robot"}

  def role_def("Admin"), do: {"#CE5C00", "fa-duotone fa-user-circle"}
  def role_def("Moderator"), do: {"#FFAA00", "fa-duotone fa-gavel"}
  def role_def("Reviewer"), do: {"#AA7700", "fa-duotone fa-user-magnifying-glass"}
  def role_def("Overwatch"), do: {"#AA7733", "fa-duotone fa-clipboard-list-check"}
  def role_def("Core team"), do: {"#008800", "fa-duotone fa-code-branch"}
  def role_def("GDT"), do: {"#AA0000", "fa-duotone fa-pen-ruler"}
  def role_def("VIP"), do: {"#AA8833", "fa-duotone fa-sparkles"}
  def role_def("Contributor"), do: {"#00AA66", "fa-duotone fa-code-commit"}
  def role_def("Tournament player"), do: {"#0000AA", "fa-duotone fa-trophy"}

  def role_def("Caster"), do: {"#660066", "fa-duotone fa-microphone-lines"}
  def role_def("Donor"), do: {"#0066AA", "fa-duotone fa-euro"}
  def role_def("Streamer"), do: {"#0066AA", "fa-brands fa-twitch"}

  def role_def(_), do: nil

  @spec generate_user_icons(T.user()) :: map()
  def generate_user_icons(user) do
    role_icons =
      user.roles
      |> Enum.filter(fn r -> role_def(r) != nil end)
      |> Map.new(fn r -> {r, 1} end)

    %{
      "play_time_rank" => user.rank
    }
    |> Map.merge(role_icons)
  end

  @spec make_bot_password() :: String.t()
  def make_bot_password() do
    :crypto.strong_rand_bytes(64) |> Base.encode64(padding: false) |> binary_part(0, 64)
  end
end
