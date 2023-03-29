defmodule TeiserverWeb.Account.PreferencesController do
  use CentralWeb, :controller

  alias Central.Config
  alias Central.Config.UserConfig

  plug(:add_breadcrumb, name: 'Teiserver', url: '/teiserver')
  plug(:add_breadcrumb, name: 'Account', url: '/teiserver/account')
  plug(:add_breadcrumb, name: 'Preferences', url: '/teiserver/account/preferences')

  plug(AssignPlug,
    site_menu_active: "teiserver_account",
    sub_menu_active: "preferences"
  )

  def index(conn, _params) do
    config_values =
      conn.user_id
      |> Config.get_user_configs!()

    config_types = Config.get_grouped_user_configs()

    conn
    |> assign(:config_types, config_types)
    |> assign(:config_values, config_values)
    |> render("index.html")
  end

  def new(conn, %{"key" => key}) do
    config_info = Config.get_user_config_type(key)
    changeset = UserConfig.creation_changeset(%UserConfig{}, config_info)

    user_config = %{
      value: config_info.default
    }

    conn
    |> assign(:user_config, user_config)
    |> assign(:changeset, changeset)
    |> assign(:config_info, config_info)
    |> assign(:method, "POST")
    |> render("new.html")
  end

  def create(conn, %{"user_config" => user_config_params}) do
    value = Map.get(user_config_params, "value", "false")

    user_config_params =
      Map.merge(user_config_params, %{
        "user_id" => conn.user_id,
        "value" => value
      })

    case Config.create_user_config(user_config_params) do
      {:ok, _user_config} ->
        conn
        |> put_flash(:info, "Your preferences have been updated.")
        |> redirect(to: Routes.ts_account_preferences_path(conn, :index))

      {:error, %Ecto.Changeset{} = _changeset} ->
        conn
        |> put_flash(:info, "Your preferences have been updated.")
        |> redirect(to: Routes.ts_account_preferences_path(conn, :index))
    end
  end

  def show(conn, %{"id" => id}) do
    user_config = Config.get_user_config!(id)
    render(conn, "show.html", user_config: user_config)
  end

  def edit(conn, %{"id" => key}) do
    config_info = Config.get_user_config_type(key)
    user_config = Config.get_user_config!(conn.user_id, key)

    changeset = Config.change_user_config(user_config)

    conn
    |> assign(:user_config, user_config)
    |> assign(:changeset, changeset)
    |> assign(:config_info, config_info)
    |> assign(:method, "PUT")
    |> render("edit.html")
  end

  def update(conn, %{"id" => id, "user_config" => user_config_params}) do
    user_config = Config.get_user_config!(id)

    value = Map.get(user_config_params, "value", "false")

    user_config_params =
      Map.merge(user_config_params, %{
        "user_id" => conn.user_id,
        "value" => value
      })

    case Config.update_user_config(user_config, user_config_params) do
      {:ok, _user_config} ->
        conn
        |> put_flash(:info, "Your preferences have been updated.")
        |> redirect(to: Routes.ts_account_preferences_path(conn, :index))

      # If there's an error then it's because they have removed the value, we just delete the config
      {:error, %Ecto.Changeset{} = _changeset} ->
        {:ok, _user_config} = Config.delete_user_config(user_config)
        Central.cache_delete(:config_user_cache, user_config.user_id)

        conn
        |> put_flash(:info, "Your preferences have been updated.")
        |> redirect(to: Routes.ts_account_preferences_path(conn, :index))
    end
  end
end
