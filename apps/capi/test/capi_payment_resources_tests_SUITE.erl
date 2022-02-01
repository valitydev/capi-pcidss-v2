-module(capi_payment_resources_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_restriction_thrift.hrl").
-include_lib("binbase_proto/include/binbase_binbase_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").
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
    expiration_date_fail_test/1,
    create_visa_payment_resource_ok_test/1,
    % FIXME Made obsolete by client validation
    % create_payment_resource_with_client_url_fail_test/1,
    create_payment_resource_invalid_cardholder_test/1,
    create_visa_with_empty_cvc_ok_test/1,
    create_visa_with_wrong_cvc_test/1,
    create_visa_with_wrong_cardnumber_test/1,
    create_visa_payment_resource_idemp_ok_test/1,
    create_visa_payment_resource_idemp_fail_test/1,
    create_nspkmir_payment_resource_ok_test/1,
    create_euroset_payment_resource_ok_test/1,
    create_mobile_payment_resource_ok_test/1,
    create_qw_payment_resource_ok_test/1,
    create_qw_payment_resource_with_access_token_generates_different_payment_token/1,
    create_qw_payment_resource_with_access_token_depends_on_external_id/1,
    create_crypto_payment_resource_ok_test/1,
    create_applepay_tokenized_payment_resource_ok_test/1,
    create_googlepay_tokenized_payment_resource_ok_test/1,
    create_googlepay_plain_payment_resource_ok_test/1,
    create_yandexpay_tokenized_payment_resource_ok_test/1,
    ip_replacement_allowed_test/1,
    ip_replacement_restricted_test/1,

    authorization_positive_lifetime_ok_test/1,
    authorization_unlimited_lifetime_ok_test/1,
    authorization_far_future_deadline_ok_test/1,
    authorization_error_no_header_test/1,
    authorization_bad_token_error_test/1,
    authorization_error_no_permission_test/1,

    payment_token_prev_test/1,
    payment_token_valid_until_test/1
]).

%% 01/01/2100 @ 12:00am (UTC)
-define(DISTANT_TIMESTAMP, 4102444800).

-define(IDEMPOTENT_KEY, <<"capi/CreatePaymentResource/TEST/ext_id">>).

-define(TEST_PAYMENT_TOOL_ARGS, #{
    <<"paymentTool">> => #{
        <<"paymentToolType">> => <<"CardData">>,
        <<"cardNumber">> => <<"4111111111111111">>,
        <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
        <<"expDate">> => <<"08/27">>,
        <<"cvv">> => <<"232">>
    },
    <<"clientInfo">> => #{<<"fingerprint">> => <<"test fingerprint">>}
}).

-define(badresp(Code), {error, {Code, #{}}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

-behaviour(supervisor).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, payment_resources}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {payment_resources, [], [
            expiration_date_fail_test,
            create_visa_payment_resource_ok_test,
            % FIXME Made obsolete by client validation
            %create_payment_resource_with_client_url_fail_test,
            create_payment_resource_invalid_cardholder_test,
            create_visa_with_empty_cvc_ok_test,
            create_visa_with_wrong_cvc_test,
            create_visa_with_wrong_cardnumber_test,
            create_visa_payment_resource_idemp_ok_test,
            create_visa_payment_resource_idemp_fail_test,
            create_nspkmir_payment_resource_ok_test,
            create_euroset_payment_resource_ok_test,
            create_mobile_payment_resource_ok_test,
            create_qw_payment_resource_ok_test,
            create_qw_payment_resource_with_access_token_generates_different_payment_token,
            create_qw_payment_resource_with_access_token_depends_on_external_id,
            create_crypto_payment_resource_ok_test,
            create_applepay_tokenized_payment_resource_ok_test,
            create_googlepay_tokenized_payment_resource_ok_test,
            create_googlepay_plain_payment_resource_ok_test,
            create_yandexpay_tokenized_payment_resource_ok_test,
            ip_replacement_allowed_test,
            ip_replacement_restricted_test,

            authorization_positive_lifetime_ok_test,
            authorization_unlimited_lifetime_ok_test,
            authorization_far_future_deadline_ok_test,
            authorization_error_no_header_test,
            authorization_bad_token_error_test,
            authorization_error_no_permission_test,

            payment_token_prev_test,
            payment_token_valid_until_test
        ]}
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    % _ = dbg:tracer(),
    % _ = dbg:p(all, c),
    % _ = dbg:tpl({'capi_payment_resources_tests_SUITE', 'p', '_'}, x),
    % _ = dbg:tpl({'capi_handler_tokens', 'p', '_'}, x),
    capi_ct_helper:init_suite(?MODULE, C).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    _ = capi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    _ = [application:stop(App) || App <- proplists:get_value(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(_Group, C) ->
    Token = capi_ct_helper:issue_token(unlimited),
    Context = capi_ct_helper:get_context(Token),
    [{context, Context} | C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, C) ->
    _ = capi_utils:maybe(?config(group_test_sup, C), fun capi_ct_helper:stop_mocked_service_sup/1),
    ok.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(authorization_bad_token_error_test, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_invalid_token(SupPid),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_allowed(), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(authorization_error_no_permission_test, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_user_session_token(SupPid),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_forbidden(), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(ip_replacement_restricted_test, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_user_session_token(SupPid),
    Restriction = #brstn_Restrictions{capi = #brstn_RestrictionsCommonAPI{ip_replacement_forbidden = true}},
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_restricted(Restriction), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(_Name, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_user_session_token(SupPid),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_allowed(), SupPid),
    [{test_sup, SupPid} | C].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    capi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    proplists:delete(test_sup, C).

%%% Tests

-spec create_visa_payment_resource_ok_test(_) -> _.
create_visa_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{
        <<"fingerprint">> => <<"test fingerprint">>,
        <<"url">> => <<"http://www.shop.com">>
    },
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
            <<"paymentSystem">> := <<"visa">>,
            <<"last4">> := <<"1111">>,
            <<"first6">> := <<"411111">>,
            <<"cardNumberMask">> := <<"411111******1111">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"03/20">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

% FIXME Made obsolete by client validation
% -spec create_payment_resource_with_client_url_fail_test(_) -> _.
% create_payment_resource_with_client_url_fail_test(Config) ->
%     ClientInfo = #{
%         <<"fingerprint">> => <<"test fingerprint">>,
%         <<"url">> => <<"123://www.shop.com">>
%     },
%     {error,
%         {400, #{
%             <<"code">> := <<"invalidRequest">>,
%             <<"message">> := <<"Client info url is invalid">>
%         }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
%         <<"paymentTool">> => #{
%             <<"paymentToolType">> => <<"CardData">>,
%             <<"cardNumber">> => <<"4111111111111111">>,
%             <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
%             <<"expDate">> => <<"03/20">>,
%             <<"cvv">> => <<"232">>
%         },
%         <<"clientInfo">> => ClientInfo
%     }).

-spec expiration_date_fail_test(_) -> _.
expiration_date_fail_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #'cds_PutCardData'{pan = <<"411111", _:6/binary, Mask:4/binary>>}
                    }
                ) ->
                    {ok, #'cds_PutCardResult'{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    CardHolder = <<"Alexander Weinerschnitzel">>,
    {error,
        {400, #{
            <<"code">> := <<"invalidRequest">>,
            <<"message">> := <<"Invalid expiration date">>
        }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => CardHolder,
            <<"expDate">> => <<"02/20">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_payment_resource_invalid_cardholder_test(_) -> _.
create_payment_resource_invalid_cardholder_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentTool = #{
        <<"paymentToolType">> => <<"CardData">>,
        <<"cardNumber">> => <<"4111111111111111">>,
        <<"expDate">> => <<"08/27">>,
        <<"cvv">> => <<"232">>
    },
    {ok, _} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася Иванов"/utf8>>},
            <<"clientInfo">> => ClientInfo
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"4111111111111111">>},
            <<"clientInfo">> => ClientInfo
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася123"/utf8>>},
            <<"clientInfo">> => ClientInfo
        }
    ).

-spec create_visa_with_empty_cvc_ok_test(_) -> _.
create_visa_with_empty_cvc_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
            <<"paymentSystem">> := <<"visa">>,
            <<"last4">> := <<"1111">>,
            <<"first6">> := <<"411111">>,
            <<"cardNumberMask">> := <<"411111******1111">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_visa_with_wrong_cvc_test(_) -> _.
create_visa_with_wrong_cvc_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {error,
        {400, #{
            <<"code">> := <<"invalidRequest">>,
            <<"message">> := <<"Invalid cvv length">>
        }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"CardData">>,
                <<"cardNumber">> => <<"4111111111111111">>,
                <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
                <<"expDate">> => <<"08/27">>,
                <<"cvv">> => <<"2020">>
            },
            <<"clientInfo">> => ClientInfo
        }).

-spec create_visa_with_wrong_cardnumber_test(_) -> _.
create_visa_with_wrong_cardnumber_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {error,
        {400, #{
            <<"code">> := <<"invalidRequest">>,
            <<"message">> := <<"Invalid cardNumber checksum">>
        }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"CardData">>,
                <<"cardNumber">> => <<"4111111211111111">>,
                <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
                <<"expDate">> => <<"08/27">>,
                <<"cvv">> => <<"202">>
            },
            <<"clientInfo">> => ClientInfo
        }).

-spec create_visa_payment_resource_idemp_ok_test(_) -> _.
create_visa_payment_resource_idemp_ok_test(Config) ->
    ExternalID = <<"Degusi :P">>,
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    Params = #{
        <<"externalID">> => ExternalID,
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    },
    PaymentToolDetails = #{
        <<"detailsType">> => <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> => <<"visa">>,
        <<"last4">> => <<"1111">>,
        <<"first6">> => <<"411111">>,
        <<"cardNumberMask">> => <<"411111******1111">>
    },
    {ok, #{
        <<"paymentToolToken">> := PT1,
        <<"paymentSession">> := ToolSession,
        <<"paymentToolDetails">> := PaymentToolDetails
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), Params),
    {ok, #{
        <<"paymentToolToken">> := PT2,
        <<"paymentSession">> := ToolSession,
        <<"paymentToolDetails">> := PaymentToolDetails
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), Params),
    PaymentTool1 = decrypt_payment_tool(PT1),
    PaymentTool2 = decrypt_payment_tool(PT2),
    ?assertEqual(PaymentTool1, PaymentTool2).

-spec create_visa_payment_resource_idemp_fail_test(_) -> _.
create_visa_payment_resource_idemp_fail_test(Config) ->
    ExternalID = <<"Degusi :P">>,
    BenderKey = <<"bender key">>,
    Token1 = <<"TOKEN1">>,
    Token2 = <<"TOKEN2">>,
    Ctx = capi_msgp_marshalling:marshal(#{<<"params_hash">> => erlang:phash2(Token1)}),
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"532130", _:6/binary, LastDigits:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = Token2,
                            bin = <<"532130">>,
                            last_digits = LastDigits
                        }
                    }};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"411111", _:6/binary, LastDigits:4/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = Token1,
                            bin = <<"411111">>,
                            last_digits = LastDigits
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(BenderKey, Ctx)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentTool = #{
        <<"paymentToolType">> => <<"CardData">>,
        <<"cardNumber">> => <<"4111111111111111">>,
        <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
        <<"expDate">> => <<"08/27">>,
        <<"cvv">> => <<"232">>
    },
    Params = #{
        <<"externalID">> => ExternalID,
        <<"paymentTool">> => PaymentTool,
        <<"clientInfo">> => ClientInfo
    },
    Params2 = #{
        <<"externalID">> => ExternalID,
        <<"paymentTool">> => PaymentTool#{<<"cardNumber">> => <<"5321301234567892">>},
        <<"clientInfo">> => ClientInfo
    },
    {ok, _} = capi_client_tokens:create_payment_resource(?config(context, Config), Params),
    {error,
        {409, #{
            <<"externalID">> := ExternalID,
            <<"message">> := <<"This 'externalID' has been used by another request">>
        }}} = capi_client_tokens:create_payment_resource(?config(context, Config), Params2).

-spec create_nspkmir_payment_resource_ok_test(_) -> _.
create_nspkmir_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                (
                    'PutCard',
                    {
                        #cds_PutCardData{pan = <<"22022002", _:6/binary, LastDigits:2/binary>>}
                    }
                ) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"22022002">>,
                            last_digits = LastDigits
                        }
                    }}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"NSPK MIR">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
            <<"paymentSystem">> := <<"nspkmir">>,
            <<"cardNumberMask">> := <<"220220******8454">>,
            <<"last4">> := <<"8454">>,
            <<"first6">> := <<"220220">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"2202200223948454">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_euroset_payment_resource_ok_test(_) -> _.
create_euroset_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsPaymentTerminal">>,
            <<"provider">> := <<"euroset">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"PaymentTerminalData">>,
            <<"provider">> => <<"euroset">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_mobile_payment_resource_ok_test(_) -> _.
create_mobile_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {moneypenny, fun('Lookup', _) -> {ok, capi_ct_mnp_helper:get_result()} end}
        ],
        Config
    ),
    MobilePhone = #{<<"cc">> => <<"7">>, <<"ctn">> => <<"9210001122">>},
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, Res} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"MobileCommerceData">>,
            <<"mobilePhone">> => MobilePhone
        },
        <<"clientInfo">> => ClientInfo
    }),
    ?assertEqual(
        #{
            <<"detailsType">> => <<"PaymentToolDetailsMobileCommerce">>,
            <<"phoneNumber">> => <<"+7******1122">>
        },
        maps:get(<<"paymentToolDetails">>, Res)
    ),
    PaymentToolToken = maps:get(<<"paymentToolToken">>, Res),
    {mobile_commerce, MobileCommerce} = decrypt_payment_tool(PaymentToolToken),

    ?assertEqual(
        #domain_MobileCommerce{
            phone = #domain_MobilePhone{
                cc = <<"7">>,
                ctn = <<"9210001122">>
            },
            operator_deprecated = megafone
        },
        MobileCommerce
    ).

-spec create_qw_payment_resource_ok_test(_) -> _.
create_qw_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsDigitalWallet">>,
            <<"digitalWalletDetailsType">> := <<"DigitalWalletDetailsQIWI">>,
            <<"phoneNumberMask">> := <<"+7******3210">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_qw_payment_resource_with_access_token_generates_different_payment_token(_) -> _.
create_qw_payment_resource_with_access_token_generates_different_payment_token(Config) ->
    BenderResult = capi_ct_helper_bender:get_result(<<"benderkey">>),
    _ = capi_ct_helper:mock_services(
        [
            {bender, fun('GenerateID', _) -> {ok, BenderResult} end},
            {tds_storage, fun('PutToken', _) -> {ok, ok} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentParams0 = #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    },
    PaymentParams1 = #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>,
            <<"accessToken">> => <<"some_token">>
        },
        <<"clientInfo">> => ClientInfo
    },
    Result0 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParams0),
    Result1 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParams1),
    {ok, #{<<"paymentToolToken">> := Token0}} = Result0,
    {ok, #{<<"paymentToolToken">> := Token1}} = Result1,
    ?assertNotEqual(Token0, Token1).

-spec create_qw_payment_resource_with_access_token_depends_on_external_id(_) -> _.
create_qw_payment_resource_with_access_token_depends_on_external_id(Config) ->
    BenderResultExtID = capi_ct_helper_bender:get_result(<<"benderkey0">>),
    BenderResultNoExtId = capi_ct_helper_bender:get_result(<<"benderkey1">>),
    _ = capi_ct_helper:mock_services(
        [
            {bender, fun
                ('GenerateID', {?IDEMPOTENT_KEY, _, _}) -> {ok, BenderResultExtID};
                ('GenerateID', _Args) -> {ok, BenderResultNoExtId}
            end},
            {tds_storage, fun('PutToken', _) -> {ok, ok} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentParamsNoExtId = #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>,
            <<"accessToken">> => <<"some_token">>
        },
        <<"clientInfo">> => ClientInfo
    },
    PaymentParamsExtId = PaymentParamsNoExtId#{<<"externalID">> => <<"ext_id">>},
    ResultExtId0 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsExtId),
    ResultExtId1 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsExtId),
    ResultNoExtId = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsNoExtId),
    {ok, #{<<"paymentToolToken">> := TokenExtId0}} = ResultExtId0,
    {ok, #{<<"paymentToolToken">> := TokenExtId1}} = ResultExtId1,
    {ok, #{<<"paymentToolToken">> := TokenNoExtId}} = ResultNoExtId,
    PaymentTool1 = decrypt_payment_tool(TokenExtId0),
    PaymentTool2 = decrypt_payment_tool(TokenExtId1),
    PaymentTool3 = decrypt_payment_tool(TokenNoExtId),
    ?assertEqual(PaymentTool1, PaymentTool2),
    ?assertNotEqual(PaymentTool1, PaymentTool3).

-spec create_crypto_payment_resource_ok_test(_) -> _.
create_crypto_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsCryptoWallet">>,
            <<"cryptoCurrency">> := <<"bitcoinCash">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CryptoWalletData">>,
            <<"cryptoCurrency">> => <<"bitcoinCash">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_applepay_tokenized_payment_resource_ok_test(_) -> _.
create_applepay_tokenized_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {payment_tool_provider_apple_pay, fun('Unwrap', _) ->
                {ok, ?UNWRAPPED_PAYMENT_TOOL(?APPLE_PAY_DETAILS)}
            end},
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"mastercard">>,
            <<"cardNumberMask">> := <<"************7892">>,
            <<"last4">> := <<"7892">>
        }
    }} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"ApplePay">>,
                <<"merchantID">> => gateway_merchant_id(),
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    false = maps:is_key(<<"first6">>, Details),
    {bank_card, BankCard} = decrypt_payment_tool(PaymentToolToken),
    ?assertMatch(
        #domain_BankCard{
            tokenization_method = dpan,
            token_provider_deprecated = applepay
        },
        BankCard
    ).

-spec create_googlepay_tokenized_payment_resource_ok_test(_) -> _.
create_googlepay_tokenized_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {payment_tool_provider_google_pay, fun('Unwrap', _) ->
                {ok, ?UNWRAPPED_PAYMENT_TOOL(?GOOGLE_PAY_DETAILS)}
            end},
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"mastercard">>,
            <<"tokenProvider">> := <<"googlepay">>,
            <<"cardNumberMask">> := <<"************7892">>,
            <<"last4">> := <<"7892">>
        }
    }} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => gateway_merchant_id(),
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    ?assertEqual(error, maps:find(<<"first6">>, Details)),
    {bank_card, BankCard} = decrypt_payment_tool(PaymentToolToken),
    ?assertMatch(
        #domain_BankCard{
            tokenization_method = dpan
        },
        BankCard
    ).

-spec create_googlepay_plain_payment_resource_ok_test(_) -> _.
create_googlepay_plain_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {payment_tool_provider_google_pay, fun('Unwrap', _) ->
                {ok,
                    ?UNWRAPPED_PAYMENT_TOOL(
                        ?GOOGLE_PAY_DETAILS,
                        {card, #paytoolprv_Card{
                            pan = <<"5321301234567892">>,
                            exp_date = #paytoolprv_ExpDate{month = 10, year = 2028}
                        }}
                    )}
            end},
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := #{
            <<"tokenProvider">> := <<"googlepay">>,
            <<"paymentSystem">> := <<"mastercard">>,
            <<"cardNumberMask">> := <<"532130******7892">>,
            <<"first6">> := <<"532130">>,
            <<"last4">> := <<"7892">>
        }
    }} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => gateway_merchant_id(),
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    %% is_cvv_empty = true for GooglePay tokenized plain bank card
    %% see capi_handler_tokens:set_is_empty_cvv/2 for more info
    {bank_card, BankCard} = decrypt_payment_tool(PaymentToolToken),
    ?assertMatch(
        #domain_BankCard{
            payment_system_deprecated = mastercard,
            last_digits = <<"7892">>,
            is_cvv_empty = true,
            tokenization_method = none
        },
        BankCard
    ).

-spec create_yandexpay_tokenized_payment_resource_ok_test(_) -> _.
create_yandexpay_tokenized_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {payment_tool_provider_yandex_pay, fun('Unwrap', _) ->
                {ok, ?UNWRAPPED_PAYMENT_TOOL(?YANDEX_PAY_DETAILS)}
            end},
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := EncryptedToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"mastercard">>,
            <<"tokenProvider">> := <<"yandexpay">>,
            <<"cardNumberMask">> := <<"************7892">>,
            <<"last4">> := <<"7892">>
        }
    }} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"YandexPay">>,
                <<"gatewayMerchantID">> => gateway_merchant_id(),
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    ?assertEqual(error, maps:find(<<"first6">>, Details)),
    PaymentTool = decrypt_payment_tool(EncryptedToken),
    ?assertMatch(
        {bank_card, #domain_BankCard{
            tokenization_method = dpan,
            metadata = #{
                <<"com.rbkmoney.payment-tool-provider">> :=
                    {obj, #{
                        {str, <<"details">>} :=
                            {obj, #{
                                {str, <<"message_id">>} := {str, ?MESSAGE_ID}
                            }}
                    }}
            }
        }},
        PaymentTool
    ).

%%

-spec ip_replacement_allowed_test(_) -> _.
ip_replacement_allowed_test(Config) ->
    ClientIP = <<"::ffff:42.42.42.42">>,
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>, <<"ip">> => ClientIP},
    {ok, Res} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    }),
    ?assertEqual(ClientIP, maps:get(<<"ip">>, maps:get(<<"clientInfo">>, Res))).

-spec ip_replacement_restricted_test(_) -> _.
ip_replacement_restricted_test(Config) ->
    ClientIP = <<"::ffff:42.42.42.42">>,
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>, <<"ip">> => ClientIP},
    {ok, Res} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    }),
    case maps:get(<<"ip">>, maps:get(<<"clientInfo">>, Res)) of
        ClientIP ->
            error("unathorized ip replacement");
        _ ->
            ok
    end.
%%

-spec authorization_positive_lifetime_ok_test(config()) -> _.
authorization_positive_lifetime_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    Token = capi_ct_helper:issue_token(?DISTANT_TIMESTAMP),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_unlimited_lifetime_ok_test(config()) -> _.
authorization_unlimited_lifetime_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    Token = capi_ct_helper:issue_token(unlimited),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_far_future_deadline_ok_test(config()) -> _.
authorization_far_future_deadline_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    % 01/01/2100 @ 12:00am (UTC)
    Token = capi_ct_helper:issue_token(?DISTANT_TIMESTAMP),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_header_test(config()) -> _.
authorization_error_no_header_test(_Config) ->
    Token = <<>>,
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_bad_token_error_test(config()) -> _.
authorization_bad_token_error_test(Config) ->
    Token = issue_dummy_token(Config),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_permission_test(config()) -> _.
authorization_error_no_permission_test(_Config) ->
    Token = capi_ct_helper:issue_token(?DISTANT_TIMESTAMP),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec payment_token_prev_test(config()) -> _.
payment_token_prev_test(_Config) ->
    PaymentToolToken = <<
        "v2.eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJhbGciOiJFQ0RILUVTIiwiY3J2IjoiUC0yNTYiLCJrdHkiOi"
        "JFQyIsInVzZSI6ImVuYyIsIngiOiJ1ODNOVXpSWGtPU2VoRlcwdktLeEk3TlU1OGhZdUhqTFNtazJ2bldPQzIwIiwieSI6IjltRjhhamc"
        "tYXVaMUp4RlZSdHhWQTlqYU83WWppMnBZT0I2M0RYWFVUcG8ifSwia2lkIjoia3hkRDBvclZQR29BeFdycUFNVGVRMFU1TVJvSzQ3dVp4"
        "V2lTSmRnbzB0MCJ9..9O0gWgWCFJqL3rLJ.mGgBOAPCW56d1BrpCiQCcuNU6b0ej42NGtPmwIFv-Le38-HumdAuAn56nR9xhGEmTCLWyW"
        "thrM3N7oSkXdAVJrn0eSHQq-YxvBCqH8J-D48.SKNeKddaTRF9UKvTTbWoWw"
    >>,
    {ok, TokenData} = capi_crypto:decode_token(PaymentToolToken),
    #{payment_tool := PaymentTool} = TokenData,
    #{valid_until := ValidUntil} = TokenData,
    ?assertEqual(
        {mobile_commerce, #domain_MobileCommerce{
            phone = #domain_MobilePhone{
                cc = <<"7">>,
                ctn = <<"9210001122">>
            },
            operator_deprecated = megafone
        }},
        PaymentTool
    ),
    ?assertEqual(<<"2021-08-02T11:21:15.082Z">>, capi_utils:deadline_to_binary(ValidUntil)).

-spec payment_token_valid_until_test(_) -> _.

payment_token_valid_until_test(Config) ->
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"validUntil">> := ValidUntil
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CryptoWalletData">>,
            <<"cryptoCurrency">> => <<"bitcoinCash">>
        },
        <<"clientInfo">> => #{
            <<"fingerprint">> =>
                <<"test fingerprint">>
        }
    }),
    {ok, #{valid_until := DeadlineToken}} = capi_crypto:decode_token(PaymentToolToken),
    Deadline = capi_utils:deadline_from_binary(ValidUntil),
    ?assertEqual(Deadline, DeadlineToken).

%%

issue_dummy_token(Config) ->
    Claims = #{
        <<"jti">> => capi_ct_helper:get_unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

decrypt_payment_tool(PaymentToolToken) ->
    {ok, #{payment_tool := PaymentTool}} = capi_crypto:decode_token(PaymentToolToken),
    PaymentTool.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

gateway_merchant_id() ->
    % MerchantID сгенерированный в capi методом
    % capi_merchant_id:encode(live, <<"party-a4ef-4d03-b666-bdec4b26c5f7">>, <<"shop-a4ef-4d03-b666-bdec4b26c5f7">>)
    <<
        "CwABAAAAIXBhcnR5LWE0ZWYtNGQwMy1iNjY2LWJkZWM0YjI2YzVmNwsAAgAAAC"
        "BzaG9wLWE0ZWYtNGQwMy1iNjY2LWJkZWM0YjI2YzVmNwgAAwAAAAEA"
    >>.
