-module(capi_self_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").
-include_lib("capi_dummy_data.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([
    oops_body_test/1
]).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

-behaviour(supervisor).

-define(OOPS_BODY, filename:join(?config(data_dir, Config), "securest_cat_alive")).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, stream_handler_tests}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {stream_handler_tests, [], [
            oops_body_test
        ]}
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    capi_ct_helper:init_suite(?MODULE, Config, [
        {oops_bodies, #{
            500 => ?OOPS_BODY
        }}
    ]).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    _ = capi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    _ = [application:stop(App) || App <- proplists:get_value(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(stream_handler_tests, Config) ->
    Token = capi_ct_helper:issue_token(unlimited),
    Context = capi_ct_helper:get_context(Token),
    [{context, Context} | Config];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, C) ->
    _ = capi_utils:maybe(?config(group_test_sup, C), fun capi_ct_helper:stop_mocked_service_sup/1),
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, capi_ct_helper:start_mocked_service_sup(?MODULE)} | C].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    capi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    proplists:delete(test_sup, C).

%%% Tests

-spec oops_body_test(config()) -> _.
oops_body_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, <<"whoa">>}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, <<"totally legit bank card">>} end}
        ],
        Config
    ),
    _ = capi_ct_helper_token_keeper:mock_user_session_token(Config),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_allowed(), Config),
    Context = ?config(context, Config),
    Token = maps:get(token, Context),
    {ok, 500, _, OopsBody} = hackney:request(
        post,
        "localhost:8080/v2/processing/payment-resources",
        [
            {<<"Authorization">>, <<<<"Bearer ">>/binary, Token/binary>>},
            {<<"Content-Type">>, <<"application/json; charset=UTF-8">>},
            {<<"X-Request-ID">>, list_to_binary(integer_to_list(rand:uniform(100000)))}
        ],
        <<
            "{"
            " \"paymentTool\":\n"
            "   {\"paymentToolType\":\"CardData\","
            "   \"cardNumber\":\"4242424242424242\","
            "   \"expDate\":\"12/20\""
            "   },\n"
            " \"clientInfo\": {\"fingerprint\":\"test\"}"
            "}"
        >>,
        [
            with_body
        ]
    ),
    {ok, OopsBody} = file:read_file(?OOPS_BODY).
