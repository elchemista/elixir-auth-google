defmodule ElixirAuthGoogle do
  @moduledoc """
  Minimalist Google OAuth Authentication for Elixir Apps.
  Extensively tested, documented, maintained and in active use in production.
  """

  @google_auth_url "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
  @google_token_url "https://oauth2.googleapis.com/token"
  @google_user_profile "https://www.googleapis.com/oauth2/v3/userinfo"
  @default_scope "profile email"
  @default_callback_path "/auth/google/callback"

  @httpoison (Application.compile_env(:elixir_auth_google, :httpoison_mock) &&
                ElixirAuthGoogle.HTTPoisonMock) || HTTPoison

  @type conn :: map()
  @type url :: String.t()

  @doc """
  `inject_poison/0` injects a TestDouble of HTTPoison in Test
  so that we don't have duplicate mocks in consuming apps.

  see: github.com/dwyl/elixir-auth-google/issues/35
  """
  def inject_poison, do: @httpoison

  @doc """
  `get_baseurl_from_conn/1` derives the base URL from the conn struct.

  If `:scheme` exists, we use that. If `:port` exists and isn't the default
  for HTTP/HTTPS, it's appended.

  If no scheme is present in the conn, **default to `"https"`.**
  """
  @spec get_baseurl_from_conn(conn) :: String.t()
  def get_baseurl_from_conn(%{scheme: scheme, host: host, port: port})
      when is_atom(scheme) and is_binary(host) and is_integer(port) do
    scheme_str = Atom.to_string(scheme)
    port_str = port_part(port, scheme)

    "#{scheme_str}://#{host}#{port_str}"
  end

  def get_baseurl_from_conn(%{scheme: scheme, host: host})
      when is_atom(scheme) and is_binary(host) do
    "#{Atom.to_string(scheme)}://#{host}"
  end

  def get_baseurl_from_conn(%{host: host}) when is_binary(host) do
    # If no scheme is found, default to https
    "https://#{host}"
  end

  @doc """
  `generate_redirect_uri/1` returns the **full** redirect URI used for Google OAuth:

  1. If `GOOGLE_CALLBACK_PATH` is set, it's used **as-is** and returned in full.
  2. Otherwise, builds `<base_url> + <callback_path>`.
     - For a `conn`, we derive `<base_url>` using `get_baseurl_from_conn/1`.
     - For a `url` string, we prepend `https://` unless the string already
       contains `'https'` or a port definition.
  """
  @spec generate_redirect_uri(url) :: String.t()
  def generate_redirect_uri(url) when is_binary(url) do
    cond do
      # If there's a custom env var set, treat it as the full callback URL
      full_env_callback?() ->
        get_app_callback_url()

      true ->
        scheme_prefix = determine_scheme_prefix(url)
        scheme_prefix <> url <> default_or_config_callback_path()
    end
  end

  @spec generate_redirect_uri(conn) :: String.t()
  def generate_redirect_uri(conn) when is_map(conn) do
    cond do
      # If there's a custom env var set, treat it as the full callback URL
      full_env_callback?() ->
        get_app_callback_url()

      true ->
        get_baseurl_from_conn(conn) <> default_or_config_callback_path()
    end
  end

  @doc """
  `generate_oauth_url/1` creates the Google OAuth2 URL with `client_id`, `scope` and
  `redirect_uri`, which is where Google will redirect on successful auth.
  This is the URL you use for your "Login with Google" button.
  """
  @spec generate_oauth_url(String.t()) :: String.t()
  def generate_oauth_url(url) when is_binary(url) do
    build_oauth_url(generate_redirect_uri(url))
  end

  @spec generate_oauth_url(conn) :: String.t()
  def generate_oauth_url(conn) when is_map(conn) do
    build_oauth_url(generate_redirect_uri(conn))
  end

  @doc """
  Similar to `generate_oauth_url/1` but accepts a `state` string or a `map` of extra
  query parameters to include in the final OAuth URL.
  """
  @spec generate_oauth_url(conn, String.t() | map) :: String.t()
  def generate_oauth_url(conn, state) when is_binary(state) do
    generate_oauth_url(conn) <> "&#{URI.encode_query(%{state: state}, :rfc3986)}"
  end

  def generate_oauth_url(conn, query) when is_map(query) do
    generate_oauth_url(conn) <> "&#{URI.encode_query(query, :rfc3986)}"
  end

  @doc """
  `get_token/2` exchanges the authorization code returned by Google
  for a token. Accepts either a Plug.Conn map or a base URL string.

  **TODO**: we still need to handle various failure conditions >> issues/16
  """
  @spec get_token(String.t(), conn) :: {:ok, map} | {:error, any}
  def get_token(code, conn) when is_map(conn) do
    do_get_token(code, generate_redirect_uri(conn))
  end

  @spec get_token(String.t(), url) :: {:ok, map} | {:error, any}
  def get_token(code, url) when is_binary(url) do
    do_get_token(code, generate_redirect_uri(url))
  end

  @doc """
  `get_user_profile/1` requests the Google user's profile data using
  the `access_token`. Invokes `parse_body_response/1` to decode the JSON.

  **TODO**: we still need to handle various failure conditions >> issues/16
  """
  @spec get_user_profile(String.t()) :: {:ok, map} | {:error, any}
  def get_user_profile(access_token) when is_binary(access_token) do
    params = URI.encode_query(%{access_token: access_token}, :rfc3986)

    "#{@google_user_profile}?#{params}"
    |> inject_poison().get()
    |> parse_body_response()
  end

  @doc """
  `parse_body_response/1` parses the response from Google
  so your app can use the resulting JSON map with atom keys.
  """
  @spec parse_body_response({atom, any}) :: {:ok, map} | {:error, any}
  def parse_body_response({:error, error}), do: {:error, error}

  def parse_body_response({:ok, %{body: nil}}), do: {:error, :no_body}

  def parse_body_response({:ok, %{body: body}}) do
    with {:ok, string_key_map} <- Jason.decode(body) do
      atom_key_map =
        for {key, value} <- string_key_map, into: %{} do
          {String.to_atom(key), value}
        end

      {:ok, atom_key_map}
    end
  end

  def google_client_id do
    System.get_env("GOOGLE_CLIENT_ID") ||
      Application.get_env(:elixir_auth_google, :client_id)
  end

  defp google_client_secret do
    System.get_env("GOOGLE_CLIENT_SECRET") ||
      Application.get_env(:elixir_auth_google, :client_secret)
  end

  defp google_scope do
    System.get_env("GOOGLE_SCOPE") ||
      Application.get_env(:elixir_auth_google, :google_scope) ||
      @default_scope
  end

  # Checks if there's a valid GOOGLE_CALLBACK_PATH in the environment.
  # If it exists and is non-empty, we'll treat it as the full callback URL.
  defp full_env_callback? do
    case System.get_env("GOOGLE_CALLBACK_PATH") do
      nil -> false
      "" -> false
      _non_empty -> true
    end
  end

  # Returns the callback path used if there's NO `GOOGLE_CALLBACK_PATH`.
  defp default_or_config_callback_path do
    Application.get_env(:elixir_auth_google, :callback_path) ||
      @default_callback_path
  end

  # If the env var is present and non-empty, that's our complete callback path.
  # Otherwise, we fall back to the config or default.
  defp get_app_callback_url do
    System.get_env("GOOGLE_CALLBACK_PATH") ||
      default_or_config_callback_path()
  end

  # Builds the Google OAuth2 URL with `client_id`, `scope` and `redirect_uri`.
  defp build_oauth_url(redirect_uri) do
    query = %{
      client_id: google_client_id(),
      scope: google_scope(),
      redirect_uri: redirect_uri
    }

    encoded = URI.encode_query(query, :rfc3986)
    "#{@google_auth_url}&#{encoded}"
  end

  # Internal function to fetch the token from Google given a code & redirect_uri.
  defp do_get_token(code, redirect_uri) do
    code
    |> req_body(redirect_uri)
    |> post_for_token()
    |> parse_body_response()
  end

  # Construct the JSON body for requesting the token.
  defp req_body(code, redirect_uri) do
    Jason.encode!(%{
      client_id: google_client_id(),
      client_secret: google_client_secret(),
      redirect_uri: redirect_uri,
      grant_type: "authorization_code",
      code: code
    })
  end

  # Posts the token request to Google.
  defp post_for_token(body) do
    inject_poison().post(@google_token_url, body)
  end

  # Determines whether to prepend "https://" or not for a raw URL.
  defp determine_scheme_prefix(url) do
    cond do
      # If the URL already has https
      String.contains?(url, "https") ->
        ""

      # If the URL includes a colon (e.g., localhost:4000)
      String.contains?(url, ":") ->
        ""

      # Otherwise default to "https://"
      true ->
        "https://"
    end
  end

  # Appends port if it is neither 80 nor 443.
  defp port_part(80, _scheme), do: ""
  defp port_part(443, _scheme), do: ""
  defp port_part(port, _scheme), do: ":#{port}"
end
