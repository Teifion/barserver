defmodule Teiserver.TeiserverQuickActions do
  alias Central.General.QuickAction

  @spec teiserver_quick_actions :: any
  def teiserver_quick_actions do
    QuickAction.add_items([
      # Global page
      %{
        label: "Live lobbies",
        icons: [Teiserver.Battle.LobbyLib.icon()],
        url: "/teiserver/battle/lobbies",
        permissions: "teiserver"
      },

      # Profile/Account
      %{
        label: "My profile",
        icons: ["fa-solid fa-user-circle"],
        url: "/teiserver/profile",
        permissions: "teiserver"
      },
      %{
        label: "Friends/Mutes/Invites",
        icons: [Teiserver.icon(:relationship)],
        url: "/teiserver/account/relationships",
        permissions: "teiserver"
      },
      %{
        label: "Profile appearance",
        icons: ["fa-solid fa-icons"],
        url: "/teiserver/account/customisation_form",
        permissions: "teiserver"
      },
      %{
        label: "Teiserver preferences",
        icons: [Central.Config.UserConfigLib.icon()],
        url: "/teiserver/account/preferences",
        permissions: "teiserver"
      },

      # Your stuff but not part of profile/account
      %{
        label: "My match history",
        icons: [Teiserver.Battle.LobbyLib.icon(), :list],
        url: "/teiserver/battle/matches",
        permissions: "teiserver"
      },
      %{
        label: "Matchmaking",
        icons: [Teiserver.Game.QueueLib.icon()],
        url: "/teiserver/games/queues",
        permissions: "teiserver.player.verified"
      },

      # Moderator pages
      %{
        label: "Live clients",
        icons: [Teiserver.Account.ClientLib.icon(), :list],
        url: "/teiserver/admin/client",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Teiserver users",
        icons: [Teiserver.Account.ClientLib.icon(), :list],
        input: "s",
        method: "get",
        placeholder: "Search username",
        url: "/teiserver/admin/users/search",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Chat logs",
        icons: [Central.Communication.CommentLib.icon(), :list],
        url: "/teiserver/admin/chat",
        permissions: "teiserver.staff.moderator"
      },
      # %{
      #   label: "Clan admin",
      #   icons: [Teiserver.Clans.ClanLib.icon(), :list],
      #   url: "/teiserver/admin/clans",
      #   permissions: "teiserver.staff.moderator"
      # },

      # Admin pages
      %{
        label: "Teiserver dashboard",
        icons: ["fa-regular fa-tachometer-alt", :list],
        url: "/logging/live/dashboard/metrics?nav=teiserver",
        permissions: "logging.live.show"
      },
      %{
        label: "Client events",
        icons: ["fa-regular #{Teiserver.Telemetry.ClientEventLib.icon()}", :list],
        url: "/teiserver/reports/client_events/summary",
        permissions: "teiserver.admin"
      },
      %{
        label: "Infologs",
        icons: ["fa-regular #{Teiserver.Telemetry.InfologLib.icon()}", :list],
        url: "/teiserver/reports/client_events/summary",
        permissions: "teiserver.staff.telemetry"
      },
      %{
        label: "Match list",
        icons: [Teiserver.Battle.MatchLib.icon(), :list],
        url: "/teiserver/admin/matches?search=true",
        permissions: "teiserver.staff.moderator"
      },

      # Specific report
      %{
        label: "Active",
        icons: ["fa-regular #{Teiserver.Account.ActiveReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/active"
      },
      %{
        label: "Time spent",
        icons: ["fa-regular #{Teiserver.Account.TimeSpentReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/time_spent"
      },
      %{
        label: "Ranks",
        icons: ["fa-regular #{Teiserver.Account.RanksReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/ranks"
      },
      %{
        label: "Verified",
        icons: ["fa-regular #{Teiserver.Account.VerifiedReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/verified"
      },
      %{
        label: "Retention",
        icons: ["fa-regular #{Teiserver.Account.RetentionReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/retention"
      },
      %{
        label: "Population",
        icons: ["fa-regular #{Teiserver.Account.PopulationReport.icon()}"],
        permissions: Teiserver.Account.PopulationReport.permissions(),
        url: "/teiserver/reports/show/population"
      },
      %{
        label: "New user funnel",
        icons: ["fa-regular #{Teiserver.Account.NewUserFunnelReport.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/new_user_funnel"
      },
      %{
        label: "Accolades",
        icons: ["fa-regular #{Teiserver.Account.AccoladeLib.icon()}"],
        permissions: "teiserver.staff.moderator",
        url: "/teiserver/reports/show/accolades"
      },
      %{
        label: "Mutes",
        icons: ["fa-regular #{Teiserver.Account.MuteReport.icon()}"],
        permissions: Teiserver.Account.MuteReport.permissions(),
        url: "/teiserver/reports/show/mutes"
      },
      %{
        label: "Review",
        icons: ["fa-regular #{Teiserver.Account.ReviewReport.icon()}"],
        permissions: Teiserver.Account.ReviewReport.permissions(),
        url: "/teiserver/reports/show/review"
      },
      %{
        label: "Growth",
        icons: ["fa-regular #{Teiserver.Account.GrowthReport.icon()}"],
        permissions: Teiserver.Account.GrowthReport.permissions(),
        url: "/teiserver/reports/show/growth"
      },

      %{
        label: "Teiserver infologs",
        icons: ["fa-regular #{Teiserver.Telemetry.InfologLib.icon()}", :list],
        url: "/teiserver/reports/infolog",
        permissions: "teiserver.staff.telemetry"
      },

      # Server metrics
      %{
        label: "Server metrics - Daily",
        icons: ["fa-regular #{Teiserver.Telemetry.ServerDayLogLib.icon()}", :day],
        url: "/teiserver/reports/server/day_metrics",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Server metrics - Monthly",
        icons: ["fa-regular #{Teiserver.Telemetry.ServerDayLogLib.icon()}", :month],
        url: "/teiserver/reports/server/month_metrics",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Server metrics - Now report",
        icons: ["fa-regular #{Teiserver.Telemetry.ServerDayLogLib.icon()}", "fa-regular fa-clock"],
        url: "/teiserver/reports/server/day_metrics/now",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Server metrics - Load report",
        icons: ["fa-regular #{Teiserver.Telemetry.ServerDayLogLib.icon()}", "fa-regular fa-server"],
        url: "/teiserver/reports/server/day_metrics/load",
        permissions: "teiserver.staff.moderator"
      },

      # Match metrics
      %{
        label: "Match metrics - Daily",
        icons: ["fa-regular #{Teiserver.Battle.MatchLib.icon()}", :day],
        url: "/teiserver/reports/match/day_metrics",
        permissions: "teiserver.staff.moderator"
      },
      %{
        label: "Match metrics - Monthly",
        icons: ["fa-regular #{Teiserver.Battle.MatchLib.icon()}", :month],
        url: "/teiserver/reports/match/month_metrics",
        permissions: "teiserver.staff.moderator"
      },

      # Dev/Admin
      %{
        label: "Teiserver live metrics",
        icons: ["fa-regular fa-tachometer-alt", :list],
        url: "/teiserver/admin/metrics",
        permissions: "logging.live"
      }
    ])
  end
end
