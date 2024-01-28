defmodule Barserver.Moderation.Report do
  @moduledoc false
  use BarserverWeb, :schema

  schema "moderation_reports" do
    belongs_to :reporter, Barserver.Account.User
    belongs_to :target, Barserver.Account.User

    field :type, :string
    field :sub_type, :string
    field :extra_text, :string
    field :closed, :boolean, default: false

    belongs_to :match, Barserver.Battle.Match
    field :relationship, :string
    belongs_to :result, Barserver.Moderation.Action
    belongs_to :report_group, Barserver.Moderation.ReportGroup

    has_many :responses, Barserver.Moderation.Response

    timestamps()
  end

  @spec changeset(Map.t(), Map.t()) :: Ecto.Changeset.t()
  def changeset(struct, params \\ %{}) do
    params =
      params
      |> trim_strings(~w(name)a)

    struct
    |> cast(
      params,
      ~w(reporter_id target_id type sub_type extra_text match_id relationship result_id closed report_group_id)a
    )
    |> validate_required(~w(reporter_id target_id type sub_type closed)a)
  end

  @spec authorize(Atom.t(), Plug.Conn.t(), Map.t()) :: Boolean.t()
  def authorize(:index, conn, _), do: allow?(conn, "Overwatch")
  def authorize(:search, conn, _), do: allow?(conn, "Overwatch")
  def authorize(:show, conn, _), do: allow?(conn, "Overwatch")
  def authorize(:user, conn, _), do: allow?(conn, "Overwatch")
  def authorize(:respond, conn, _), do: allow?(conn, "Overwatch")
  def authorize(_, conn, _), do: allow?(conn, "Moderator")
end
