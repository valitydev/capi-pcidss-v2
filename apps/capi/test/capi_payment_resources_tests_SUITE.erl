-module(capi_payment_resources_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_paytool_provider_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_rstn_thrift.hrl").
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
    create_payment_resource_invalid_card_test/1,
    create_payment_resource_unsupported_card_test/1,
    create_payment_resource_invalid_cardholder_test/1,
    create_visa_with_empty_cvc_ok_test/1,
    create_visa_with_wrong_cvc_test/1,
    create_visa_with_wrong_cardnumber_test/1,
    create_nspkmir_payment_resource_ok_test/1,
    create_euroset_payment_resource_ok_test/1,
    create_euroset_no_metadata_payment_resource_ok_test/1,
    create_mobile_payment_resource_ok_test/1,
    create_qw_payment_resource_ok_test/1,
    create_qw_payment_resource_with_access_token_generates_different_payment_token/1,
    create_crypto_payment_resource_ok_test/1,
    create_nonexistent_provider_payment_resource_fails_test/1,
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
    authorization_error_wrong_token_type_test/1,

    payment_token_valid_until_test/1
]).

%% 01/01/2100 @ 12:00am (UTC)
-define(DISTANT_TIMESTAMP, 4102444800).

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

-define(badresp(Status), {error, {Status, #{}}}).
-define(badresp(Status, Code), {error, {Status, #{<<"code">> := Code}}}).

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
            create_payment_resource_invalid_card_test,
            create_payment_resource_unsupported_card_test,
            create_payment_resource_invalid_cardholder_test,
            create_visa_with_empty_cvc_ok_test,
            create_visa_with_wrong_cvc_test,
            create_visa_with_wrong_cardnumber_test,
            create_nspkmir_payment_resource_ok_test,
            create_euroset_payment_resource_ok_test,
            create_euroset_no_metadata_payment_resource_ok_test,
            create_mobile_payment_resource_ok_test,
            create_qw_payment_resource_ok_test,
            create_qw_payment_resource_with_access_token_generates_different_payment_token,
            create_nonexistent_provider_payment_resource_fails_test,
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
            authorization_error_wrong_token_type_test,

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
    _ = capi_ct_helper_token_keeper:mock_invoice_access_token(SupPid),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_forbidden(), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(authorization_error_wrong_token_type_test, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_user_session_token(SupPid),
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_forbidden(), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(ip_replacement_restricted_test, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_invoice_access_token(SupPid),
    Restriction = #rstn_Restrictions{capi = #rstn_RestrictionsCommonAPI{ip_replacement_forbidden = true}},
    _ = capi_ct_helper_bouncer:mock_arbiter(capi_ct_helper_bouncer:judge_always_restricted(Restriction), SupPid),
    [{test_sup, SupPid} | C];
init_per_testcase(_Name, C) ->
    SupPid = capi_ct_helper:start_mocked_service_sup(?MODULE),
    _ = capi_ct_helper_token_keeper:mock_invoice_access_token(SupPid),
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
                ('PutCard', {#cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}}) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
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
            <<"paymentSystem">> := <<"VISA">>,
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
                ('PutCard', {#'cds_PutCardData'{pan = <<"411111", _:6/binary, Mask:4/binary>>}}) ->
                    {ok, #'cds_PutCardResult'{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
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
        <<"clientInfo">> => ?SWAG_CLIENT_INFO
    }).

-spec create_payment_resource_unsupported_card_test(_) -> _.
create_payment_resource_unsupported_card_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {binbase, fun('Lookup', _) -> {throwing, #binbase_BinNotFound{}} end}
        ],
        Config
    ),
    ?assertEqual(
        {error,
            {400, #{
                <<"code">> => <<"invalidRequest">>,
                <<"message">> => <<"Unsupported card">>
            }}},
        capi_client_tokens:create_payment_resource(
            ?config(context, Config),
            #{
                <<"paymentTool">> => ?SWAG_BANK_CARD(?PAN),
                <<"clientInfo">> => ?SWAG_CLIENT_INFO
            }
        )
    ).

-spec create_payment_resource_invalid_card_test(_) -> _.
create_payment_resource_invalid_card_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ?assertEqual(
        {error,
            {400, #{
                <<"code">> => <<"invalidRequest">>,
                <<"message">> => <<"Invalid cardNumber checksum">>
            }}},
        capi_client_tokens:create_payment_resource(
            ?config(context, Config),
            #{
                <<"paymentTool">> => ?SWAG_BANK_CARD(<<"4111111111111112">>),
                <<"clientInfo">> => ?SWAG_CLIENT_INFO
            }
        )
    ),
    ?assertEqual(
        {error,
            {400, #{
                <<"code">> => <<"invalidRequest">>,
                <<"message">> => <<"Invalid cardNumber length">>
            }}},
        capi_client_tokens:create_payment_resource(
            ?config(context, Config),
            #{
                <<"paymentTool">> => ?SWAG_BANK_CARD(<<"41111111111114">>),
                <<"clientInfo">> => ?SWAG_CLIENT_INFO
            }
        )
    ).

-spec create_payment_resource_invalid_cardholder_test(_) -> _.
create_payment_resource_invalid_cardholder_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                ('PutCard', {#cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}}) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    PaymentTool = ?SWAG_BANK_CARD(<<"4111111111111111">>),
    {ok, _} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася Иванов"/utf8>>},
            <<"clientInfo">> => ?SWAG_CLIENT_INFO
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"4111111111111111">>},
            <<"clientInfo">> => ?SWAG_CLIENT_INFO
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(
        ?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася123"/utf8>>},
            <<"clientInfo">> => ?SWAG_CLIENT_INFO
        }
    ).

-spec create_visa_with_empty_cvc_ok_test(_) -> _.
create_visa_with_empty_cvc_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                ('PutCard', {#cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}}) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"411111">>,
                            last_digits = Mask
                        }
                    }}
            end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
            <<"paymentSystem">> := <<"VISA">>,
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

-spec create_nspkmir_payment_resource_ok_test(_) -> _.
create_nspkmir_payment_resource_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) ->
                    {ok, ok};
                ('PutCard', {#cds_PutCardData{pan = <<"22022002", _:6/binary, LastDigits:2/binary>>}}) ->
                    {ok, #cds_PutCardResult{
                        bank_card = #cds_BankCard{
                            token = ?STRING,
                            bin = <<"22022002">>,
                            last_digits = LastDigits
                        }
                    }}
            end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"NSPK MIR">>)} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
            <<"paymentSystem">> := <<"NSPK MIR">>,
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
            <<"provider">> => <<"euroset">>,
            <<"metadata">> => #{
                <<"branch">> => <<"БИРЮЛЁВО"/utf8>>,
                <<"nonsense">> => 31.337
            }
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_euroset_no_metadata_payment_resource_ok_test(_) -> _.
create_euroset_no_metadata_payment_resource_ok_test(Config) ->
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
            operator = #domain_MobileOperatorRef{id = <<"MEGAFON">>}
        },
        MobileCommerce
    ).

-spec create_qw_payment_resource_ok_test(_) -> _.
create_qw_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolDetails">> := #{
            <<"detailsType">> := <<"PaymentToolDetailsDigitalWallet">>,
            <<"provider">> := <<"qiwi">>
        }
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"id">> => <<"+79876543210">>,
            <<"provider">> => <<"qiwi">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_qw_payment_resource_with_access_token_generates_different_payment_token(_) -> _.
create_qw_payment_resource_with_access_token_generates_different_payment_token(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {tds_storage, fun('PutToken', _) -> {ok, ok} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentParams0 = #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"id">> => <<"+79876543210">>,
            <<"provider">> => <<"qiwi">>
        },
        <<"clientInfo">> => ClientInfo
    },
    PaymentParams1 = #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"id">> => <<"+79876543210">>,
            <<"provider">> => <<"qiwi">>,
            <<"token">> => <<"some_token">>
        },
        <<"clientInfo">> => ClientInfo
    },
    Result0 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParams0),
    Result1 = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParams1),
    {ok, #{<<"paymentToolToken">> := Token0}} = Result0,
    {ok, #{<<"paymentToolToken">> := Token1}} = Result1,
    ?assertNotEqual(Token0, Token1).

-spec create_nonexistent_provider_payment_resource_fails_test(_) -> _.
create_nonexistent_provider_payment_resource_fails_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"fingerprint">>},
    Provider = <<"✨NOPE✨"/utf8>>,
    ?badresp(400, <<"invalidRequest">>) =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"DigitalWalletData">>,
                <<"id">> => <<"42">>,
                <<"provider">> => Provider
            },
            <<"clientInfo">> => ClientInfo
        }).

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
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"MASTERCARD">>,
            <<"tokenProvider">> := <<"APPLE PAY">>,
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
            payment_token = #domain_BankCardTokenServiceRef{id = <<"APPLE PAY">>}
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
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"MASTERCARD">>,
            <<"tokenProvider">> := <<"GOOGLE PAY">>,
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
                        {card, #paytool_provider_Card{
                            pan = <<"5321301234567892">>,
                            exp_date = #paytool_provider_ExpDate{month = 10, year = 2028}
                        }}
                    )}
            end},
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := #{
            <<"tokenProvider">> := <<"GOOGLE PAY">>,
            <<"paymentSystem">> := <<"MASTERCARD">>,
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
            payment_system = #domain_PaymentSystemRef{id = <<"MASTERCARD">>},
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
            {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
        ],
        Config
    ),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := EncryptedToken,
        <<"paymentToolDetails">> := Details = #{
            <<"paymentSystem">> := <<"MASTERCARD">>,
            <<"tokenProvider">> := <<"YANDEX PAY">>,
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
            <<"id">> => <<"+79876543210">>,
            <<"provider">> => <<"qiwi">>
        },
        <<"clientInfo">> => ClientInfo
    }),
    ?assertEqual(ClientIP, maps:get(<<"ip">>, maps:get(<<"clientInfo">>, Res))),
    ?assertEqual(ClientIP, maps:get(<<"user_ip">>, maps:get(<<"clientInfo">>, Res))).

-spec ip_replacement_restricted_test(_) -> _.
ip_replacement_restricted_test(Config) ->
    ClientIP = <<"::ffff:42.42.42.42">>,
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>, <<"ip">> => ClientIP},
    {ok, Res} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"id">> => <<"+79876543210">>,
            <<"provider">> => <<"qiwi">>
        },
        <<"clientInfo">> => ClientInfo
    }),
    PeerIP = maps:get(<<"peer_ip">>, maps:get(<<"clientInfo">>, Res)),
    ?assertEqual(PeerIP, maps:get(<<"ip">>, maps:get(<<"clientInfo">>, Res))).
%%

-spec authorization_positive_lifetime_ok_test(config()) -> _.
authorization_positive_lifetime_ok_test(Config) ->
    _ = capi_ct_helper:mock_services(
        [
            {cds_storage, fun
                ('PutSession', _) -> {ok, ok};
                ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
            end},
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

-spec authorization_error_wrong_token_type_test(config()) -> _.
authorization_error_wrong_token_type_test(_Config) ->
    Token = capi_ct_helper:issue_token(unlimited),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

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
