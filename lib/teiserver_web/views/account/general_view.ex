defmodule BarserverWeb.Account.GeneralView do
  use BarserverWeb, :view

  @spec view_colour :: atom
  def view_colour(), do: :success

  @spec icon() :: String.t()
  def icon(), do: "fa-solid fa-user"

  @spec view_colour(String.t()) :: atom
  def view_colour("profile"), do: :primary
  def view_colour("relationships"), do: :info
  def view_colour("customisation"), do: Barserver.Config.UserConfigLib.colours()
  def view_colour("preferences"), do: Barserver.Config.UserConfigLib.colours()
  def view_colour("clans"), do: Barserver.Clans.ClanLib.colours()
  def view_colour("achievements"), do: Barserver.Game.AchievementTypeLib.colour()

  def view_colour("details"), do: :primary
  def view_colour("security"), do: :danger
end
