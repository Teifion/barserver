defmodule Barserver.Tachyon.Handlers.Account.WhoamiRequest do
  @moduledoc """

  """
  alias Barserver.Data.Types, as: T
  alias Barserver.Tachyon.Responses.Account.WhoamiResponse
  alias Barserver.Account

  @spec dispatch_handlers :: map()
  def dispatch_handlers() do
    %{
      "account/whoAmI/request" => &execute/3
    }
  end

  @spec execute(T.tachyon_conn(), T.tachyon_object(), map) ::
          {T.tachyon_response(), T.tachyon_conn()}
  def execute(conn, _object, _meta) do
    user = Account.get_user_by_id(conn.userid)
    client = Account.get_client_by_id(conn.userid)

    response = WhoamiResponse.generate(user, client)

    {response, conn}
  end
end
