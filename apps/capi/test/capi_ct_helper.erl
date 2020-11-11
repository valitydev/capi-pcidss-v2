-module(capi_ct_helper).

-include_lib("common_test/include/ct.hrl").
-include_lib("capi_dummy_data.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").

-export([init_suite/2]).
-export([init_suite/3]).
-export([start_app/1]).
-export([start_app/2]).
-export([start_capi/1]).
-export([start_capi/2]).
-export([issue_token/2]).
-export([issue_token/3]).
-export([issue_token/4]).
-export([get_context/1]).
-export([get_context/2]).
-export([get_keysource/2]).
-export([start_mocked_service_sup/1]).
-export([stop_mocked_service_sup/1]).
-export([mock_services/2]).
-export([mock_services_/2]).
-export([get_lifetime/0]).
-export([get_unique_id/0]).

-define(CAPI_IP, "::").
-define(CAPI_PORT, 8080).
-define(CAPI_HOST_NAME, "localhost").
-define(CAPI_URL, ?CAPI_HOST_NAME ++ ":" ++ integer_to_list(?CAPI_PORT)).

%%
-type config() :: [{atom(), any()}].
-type app_name() :: atom().

-spec init_suite(module(), config()) -> config().
init_suite(Module, Config) ->
    init_suite(Module, Config, []).

-spec init_suite(module(), config(), any()) -> config().
init_suite(Module, Config, CapiEnv) ->
    SupPid = start_mocked_service_sup(Module),
    Apps1 =
        start_app(woody) ++
            start_app(scoper),
    Apps2 =
        start_capi(Config, CapiEnv),
    [{apps, lists:reverse(Apps2 ++ Apps1)}, {suite_test_sup, SupPid} | Config].

-spec start_app(app_name()) -> [app_name()].
start_app(woody = AppName) ->
    start_app(AppName, [
        {acceptors_pool_size, 4}
    ]);
start_app(scoper = AppName) ->
    start_app(AppName, [
        {storage, scoper_storage_logger}
    ]);
start_app(AppName) ->
    genlib_app:start_application(AppName).

-spec start_app(app_name(), list()) -> [app_name()].
start_app(AppName, Env) ->
    genlib_app:start_application_with(AppName, Env).

-spec start_capi(config()) -> [app_name()].
start_capi(Config) ->
    start_capi(Config, []).

-spec start_capi(config(), list()) -> [app_name()].
start_capi(Config, ExtraEnv) ->
    JwkPublSource = {json, {file, get_keysource("keys/local/jwk.publ.json", Config)}},
    JwkPrivSource = {json, {file, get_keysource("keys/local/jwk.priv.json", Config)}},
    CapiEnv =
        ExtraEnv ++
            [
                {ip, ?CAPI_IP},
                {port, ?CAPI_PORT},
                {service_type, real},
                {access_conf, #{
                    jwt => #{
                        keyset => #{
                            capi_pcidss => {pem_file, get_keysource("keys/local/private.pem", Config)}
                        }
                    }
                }},
                {lechiffre_opts, #{
                    encryption_source => JwkPublSource,
                    decryption_sources => [JwkPrivSource]
                }},
                {validation, #{
                    now => {{2020, 3, 1}, {0, 0, 0}}
                }},
                {payment_tool_token_lifetime, <<"1024s">>}
            ],
    start_app(capi_pcidss, CapiEnv).

-spec get_keysource(_, config()) -> _.
get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

-spec issue_token(_, _) -> binary() | no_return().
issue_token(ACL, LifeTime) ->
    issue_token(?STRING, ACL, LifeTime, #{}).

-spec issue_token(_, _, _) -> binary() | no_return().
issue_token(PartyID, ACL, LifeTime) ->
    issue_token(PartyID, ACL, LifeTime, #{}).

-spec issue_token(_, _, _, _) -> binary() | no_return().
issue_token(PartyID, ACL, LifeTime, ExtraProperties) ->
    Claims = maps:merge(
        #{
            ?STRING => ?STRING,
            <<"exp">> => LifeTime,
            <<"resource_access">> => #{
                <<"common-api">> => uac_acl:from_list(ACL)
            }
        },
        ExtraProperties
    ),
    UniqueId = get_unique_id(),
    genlib:unwrap(
        uac_authorizer_jwt:issue(
            UniqueId,
            PartyID,
            Claims,
            capi_pcidss
        )
    ).

-spec get_unique_id() -> binary().
get_unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

-spec get_context(binary()) -> capi_client_lib:context().
get_context(Token) ->
    get_context(Token, #{}).

-spec get_context(binary(), map()) -> capi_client_lib:context().
get_context(Token, ExtraProperties) ->
    capi_client_lib:get_context(?CAPI_URL, Token, 10000, ipv4, ExtraProperties).

% TODO move it to `capi_dummy_service`, looks more appropriate

-spec start_mocked_service_sup(module()) -> pid().
start_mocked_service_sup(Module) ->
    {ok, SupPid} = supervisor:start_link(Module, []),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) -> _.
stop_mocked_service_sup(SupPid) ->
    exit(SupPid, shutdown).

-spec mock_services(_, _) -> _.
mock_services(Services, SupOrConfig) ->
    start_woody_client(mock_services_(Services, SupOrConfig)).

start_woody_client(ServiceURLs) ->
    start_app(capi_woody_client, [{services, ServiceURLs}]).

-spec mock_services_(_, _) -> _.
% TODO need a better name
mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));
mock_services_(Services, SupPid) when is_pid(SupPid) ->
    Name = lists:map(fun get_service_name/1, Services),
    Port = get_random_port(),
    {ok, IP} = inet:parse_address(?CAPI_IP),
    ChildSpec = woody_server:child_spec(
        {dummy, Name},
        #{
            ip => IP,
            port => Port,
            event_handler => {scoper_woody_event_handler, #{}},
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            Acc#{ServiceName => make_url(ServiceName, Port)}
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, capi_woody_client:get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {capi_dummy_service, #{function => Fun}}}}.

% TODO not so failproof, ideally we need to bind socket first and then give to a ranch listener
get_random_port() ->
    rand:uniform(32768) + 32767.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?CAPI_HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).

-spec get_lifetime() -> map().
get_lifetime() ->
    get_lifetime(0, 0, 7).

get_lifetime(YY, MM, DD) ->
    #{
        <<"years">> => YY,
        <<"months">> => MM,
        <<"days">> => DD
    }.
