-module(capi_ct_helper).

-include_lib("common_test/include/ct.hrl").
-include_lib("capi_dummy_data.hrl").
-include_lib("capi_token_keeper_data.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").

-export([init_suite/2]).
-export([init_suite/3]).
-export([start_app/1]).
-export([start_app/2]).
-export([start_capi/1]).
-export([start_capi/2]).
-export([issue_token/1]).
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
-define(PAYMENT_SYSTEM_REF(ID), {payment_system, #domain_PaymentSystemRef{id = ID}}).
-define(PAYMENT_SYSTEM_OBJ(ID, Rules),
    {payment_system, #domain_PaymentSystemObject{
        ref = #domain_PaymentSystemRef{id = ID},
        data = #domain_PaymentSystem{
            name = ID,
            validation_rules = Rules
        }
    }}
).

-define(PAYMENT_SERVICE_REF(ID), {payment_service, #domain_PaymentServiceRef{id = ID}}).
-define(PAYMENT_SERVICE_OBJ(ID),
    {payment_system, #domain_PaymentServiceObject{
        ref = #domain_PaymentServiceRef{id = ID},
        data = #domain_PaymentService{
            name = ID
        }
    }}
).

%%
-type config() :: [{atom(), any()}].
-type app_name() :: atom().

-spec init_suite(module(), config()) -> config().
init_suite(Module, Config) ->
    init_suite(Module, Config, []).

-spec init_suite(module(), config(), any()) -> config().
init_suite(Module, Config, CapiEnv) ->
    SupPid = start_mocked_service_sup(Module),
    WoodyApp = start_app(woody),
    ScoperApp = start_app(scoper),
    ServiceURLs = mock_services_(
        [
            {
                'Repository',
                {dmsl_domain_config_thrift, 'Repository'},
                fun('Checkout', _) ->
                    {ok, #'Snapshot'{
                        version = 1,
                        domain = #{
                            ?PAYMENT_SYSTEM_REF(<<"VISA">>) =>
                                ?PAYMENT_SYSTEM_OBJ(
                                    <<"VISA">>,
                                    bankcard_validator_legacy:get_payment_system_ruleset(<<"VISA">>)
                                ),
                            ?PAYMENT_SYSTEM_REF(<<"MASTERCARD">>) =>
                                ?PAYMENT_SYSTEM_OBJ(
                                    <<"MASTERCARD">>,
                                    bankcard_validator_legacy:get_payment_system_ruleset(<<"MASTERCARD">>)
                                ),
                            ?PAYMENT_SERVICE_REF(<<"qiwi">>) =>
                                ?PAYMENT_SERVICE_OBJ(
                                    <<"qiwi">>
                                ),
                            ?PAYMENT_SERVICE_REF(<<"euroset">>) =>
                                ?PAYMENT_SERVICE_OBJ(
                                    <<"euroset">>
                                )
                        }
                    }}
                end
            }
        ],
        SupPid
    ),
    DmtClient =
        start_app(dmt_client, [
            {max_cache_size, #{}},
            {service_urls, ServiceURLs},
            {cache_update_interval, 50000}
        ]),
    Capi = start_capi(Config, CapiEnv),
    TokenKeeperApp = start_token_keeper(SupPid, Config),
    BouncerApp = capi_ct_helper_bouncer:mock_client(SupPid),
    Apps = lists:reverse(Capi ++ DmtClient ++ WoodyApp ++ ScoperApp ++ BouncerApp ++ TokenKeeperApp),
    [{apps, Apps}, {suite_test_sup, SupPid} | Config].

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

-spec start_token_keeper(pid(), config()) -> [app_name()].
start_token_keeper(SupPid, Config) ->
    ok = capi_ct_helper_token_keeper:configure_uac(Config),
    capi_ct_helper_token_keeper:mock_client(capi_ct_helper_token_keeper:user_session_handler(), SupPid).

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
                {bouncer_ruleset_id, ?TEST_RULESET_ID},
                {lechiffre_opts, #{
                    encryption_source => JwkPublSource,
                    decryption_sources => [JwkPrivSource]
                }},
                {validation, #{
                    now => {{2020, 3, 1}, {0, 0, 0}}
                }},
                {payment_tool_token_lifetime, <<"1024s">>},
                {auth_config, #{
                    metadata_mappings => #{
                        party_id => ?TK_META_PARTY_ID,
                        token_consumer => ?TK_META_TOKEN_CONSUMER,
                        user_id => ?TK_META_USER_ID,
                        user_email => ?TK_META_USER_EMAIL
                    }
                }},
                {bank_card_token_service_mapping, #{
                    googlepay => <<"GOOGLE PAY">>,
                    applepay => <<"APPLE PAY">>,
                    samsungpay => <<"SAMSUNG PAY">>,
                    yandexpay => <<"YANDEX PAY">>
                }}
            ],
    start_app(capi_pcidss, CapiEnv).

-spec get_keysource(_, config()) -> _.
get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

-spec issue_token(_) -> binary() | no_return().
issue_token(unlimited) ->
    <<
        "eyJhbGciOiJQUzI1NiIsImtpZCI6Il90a1hzNWlBYXNIckhpb21tMlNaaGtvR2tMdmZXcllaMkZ0bnZ2VDhFSnMiLCJ0eXAi"
        "OiJKV1QifQ.eyJURVNUIjoiVEVTVCIsImVtYWlsIjoiYmxhQGJsYS5ydSIsImV4cCI6MCwianRpIjoiVEVTVCIsInJlc291c"
        "mNlX2FjY2VzcyI6eyJjb21tb24tYXBpIjp7InJvbGVzIjpbInBheW1lbnRfcmVzb3VyY2VzOndyaXRlIl19fSwic3ViIjoiV"
        "EVTVCJ9.I0RPu_ESO3HQJsWjhuVEpvpOZat9Vz6K_NzNzjAss5RNQVd-uf4Opc493rGfxtfsIMUdZtb0Pu-6Fz_SH-YuzA"
    >>;
issue_token(_LifeTime) ->
    <<
        "eyJhbGciOiJQUzI1NiIsImtpZCI6Il90a1hzNWlBYXNIckhpb21tMlNaaGtvR2tMdmZXcllaMkZ0bnZ2VDhFSnMiLCJ0eXAiO"
        "iJKV1QifQ.eyJURVNUIjoiVEVTVCIsImVtYWlsIjoiYmxhQGJsYS5ydSIsImV4cCI6NDEwMjQ0NDgwMCwianRpIjoiVEVTVCI"
        "sInJlc291cmNlX2FjY2VzcyI6eyJjb21tb24tYXBpIjp7InJvbGVzIjpbInBheW1lbnRfcmVzb3VyY2VzOndyaXRlIl19fSwi"
        "c3ViIjoiVEVTVCJ9.FNuU3vsMLC_Y2HjXVP-tCBYrU2o_3alqlvijHOOGO7tqR5N5BlbKL96C5erufDv1wVxlB7istvg8X4iRShFkEw"
    >>.

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
    {ok, IP} = inet:parse_address(?CAPI_IP),
    ServerID = {dummy, Name},
    WoodyOpts = #{
        ip => IP,
        port => 0,
        event_handler => {scoper_woody_event_handler, #{}},
        handlers => lists:map(fun mock_service_handler/1, Services)
    },
    ChildSpec = woody_server:child_spec(ServerID, WoodyOpts),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {_IP, Port} = woody_server:get_addr(ServerID, WoodyOpts),
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
