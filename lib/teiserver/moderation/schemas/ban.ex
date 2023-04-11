defmodule Teiserver.Moderation.Ban do
  @moduledoc false
  use CentralWeb, :schema

  schema "moderation_bans" do
    belongs_to :source, Central.Account.User
    belongs_to :added_by, Central.Account.User

    field :key_values, {:array, :string}
    field :enabled, :boolean
    field :reason, :string

    timestamps()
  end

  @spec changeset(Map.t(), Map.t()) :: Ecto.Changeset.t()
  def changeset(struct, params \\ %{}) do
    params =
      params
      |> trim_strings(~w(reason)a)

    struct
    |> cast(params, ~w(source_id added_by_id key_values enabled reason)a)
    |> validate_required(~w(source_id added_by_id key_values enabled reason)a)
  end

  @spec authorize(Atom.t(), Plug.Conn.t(), Map.t()) :: Boolean.t()
  def authorize(:index, conn, _), do: allow?(conn, "teiserver.staff.overwatch")
  def authorize(:show, conn, _), do: allow?(conn, "teiserver.staff.reviewer")
  def authorize(_, conn, _), do: allow?(conn, "teiserver.staff.moderator")
end
