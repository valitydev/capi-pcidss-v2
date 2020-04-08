-module(capi_payment_resources_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_errors_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_token_thrift.hrl").
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
    create_visa_payment_resource_ok_test/1,
    create_payment_resource_invalid_cardholder_test/1,
    create_visa_with_empty_cvv_ok_test/1,
    create_visa_with_wrong_cvv_test/1,
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
    ip_replacement_not_allowed_test/1,
    ip_replacement_allowed_test/1,

    authorization_positive_lifetime_ok_test/1,
    authorization_unlimited_lifetime_ok_test/1,
    authorization_far_future_deadline_ok_test/1,
    authorization_error_no_header_test/1,
    authorization_error_no_permission_test/1,
    authorization_bad_token_error_test/1
]).

-define(CAPI_PORT                   , 8080).
-define(CAPI_HOST_NAME              , "localhost").
-define(CAPI_URL                    , ?CAPI_HOST_NAME ++ ":" ++ integer_to_list(?CAPI_PORT)).

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

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].
-type group_name()      :: atom().

-behaviour(supervisor).

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() ->
    [test_case_name()].
all() ->
    [
        {group, payment_resources},
        {group, ip_replacement_allowed}
    ].

-spec groups() ->
    [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {payment_resources, [],
            [
                create_visa_payment_resource_ok_test,
                create_payment_resource_invalid_cardholder_test,
                create_visa_with_empty_cvv_ok_test,
                create_visa_with_wrong_cvv_test,
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
                ip_replacement_not_allowed_test,

                authorization_positive_lifetime_ok_test,
                authorization_unlimited_lifetime_ok_test,
                authorization_far_future_deadline_ok_test,
                authorization_error_no_header_test,
                authorization_error_no_permission_test,
                authorization_bad_token_error_test
            ]
        },
        {ip_replacement_allowed, [],
            [
                ip_replacement_allowed_test
            ]
        }
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    _ = dbg:tracer(),
    _ = dbg:p(all, c),
    _ = dbg:tpl({'capi_payment_resources_tests_SUITE', 'p', '_'}, x),
    _ = dbg:tpl({'capi_handler_tokens', 'p', '_'}, x),
   capi_ct_helper:init_suite(?MODULE, Config).

-spec end_per_suite(config()) ->
    _.
end_per_suite(C) ->
    _ = capi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    [application:stop(App) || App <- proplists:get_value(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) ->
    config().

init_per_group(payment_resources, Config) ->
    Token = capi_ct_helper:issue_token([{[payment_resources], write}], unlimited),
    [{context, capi_ct_helper:get_context(Token)} | Config];

init_per_group(ip_replacement_allowed, Config) ->
    ExtraProperties = #{<<"ip_replacement_allowed">> => true},
    Token = capi_ct_helper:issue_token(?STRING, [{[payment_resources], write}], unlimited, ExtraProperties),
    [{context, capi_ct_helper:get_context(Token)} | Config].

-spec end_per_group(group_name(), config()) ->
    _.
end_per_group(_Group, C) ->
    proplists:delete(context, C),
    ok.

-spec init_per_testcase(test_case_name(), config()) ->
    config().
init_per_testcase(_Name, C) ->
    [{test_sup, capi_ct_helper:start_mocked_service_sup(?MODULE)} | C].

-spec end_per_testcase(test_case_name(), config()) ->
    config().
end_per_testcase(_Name, C) ->
    capi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec create_visa_payment_resource_ok_test(_) ->
    _.
create_visa_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
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
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"visa">>,
        <<"last4">> := <<"1111">>,
        <<"first6">> := <<"411111">>,
        <<"cardNumberMask">> := <<"411111******1111">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_payment_resource_invalid_cardholder_test(_) ->
    _.
create_payment_resource_invalid_cardholder_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
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
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentTool = #{
        <<"paymentToolType">> => <<"CardData">>,
        <<"cardNumber">> => <<"4111111111111111">>,
        <<"expDate">> => <<"08/27">>,
        <<"cvv">> => <<"232">>
    },
    {ok, _ } = capi_client_tokens:create_payment_resource(?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася Иванов"/utf8>>},
            <<"clientInfo">> => ClientInfo
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"4111111111111111">>},
            <<"clientInfo">> => ClientInfo
        }
    ),
    {error, {request_validation_failed, _}} = capi_client_tokens:create_payment_resource(?config(context, Config),
        #{
            <<"paymentTool">> => PaymentTool#{<<"cardHolder">> => <<"Вася123"/utf8>>},
            <<"clientInfo">> => ClientInfo
        }
    ).

-spec create_visa_with_empty_cvv_ok_test(_) ->
    _.
create_visa_with_empty_cvv_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
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
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"visa">>,
        <<"last4">>  := <<"1111">>,
        <<"first6">> := <<"411111">>,
        <<"cardNumberMask">> := <<"411111******1111">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_visa_with_wrong_cvv_test(_) ->
    _.
create_visa_with_wrong_cvv_test(Config) ->
    capi_ct_helper:mock_services([
        {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {error,
        {400,
            #{<<"code">> := <<"invalidRequest">>,
              <<"message">> := <<"Invalid cvv length">>}}}
        = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"2020">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_visa_with_wrong_cardnumber_test(_) ->
    _.
create_visa_with_wrong_cardnumber_test(Config) ->
    capi_ct_helper:mock_services([
        {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {error,
        {400,
            #{<<"code">> := <<"invalidRequest">>,
              <<"message">> := <<"Invalid cardNumber checksum">>}}}
        = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111211111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"202">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_visa_payment_resource_idemp_ok_test(_) ->
    _.
create_visa_payment_resource_idemp_ok_test(Config) ->
    ExternalID = <<"Degusi :P">>,
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
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
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    Params = #{
        <<"externalID">> => ExternalID,
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">>      => <<"4111111111111111">>,
            <<"cardHolder">>      => <<"Alexander Weinerschnitzel">>,
            <<"expDate">>         => <<"08/27">>,
            <<"cvv">>             => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    },
    PaymentToolDetails = #{
        <<"detailsType">>    => <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">>  => <<"visa">>,
        <<"last4">>          => <<"1111">>,
        <<"first6">>         => <<"411111">>,
        <<"cardNumberMask">> => <<"411111******1111">>
    },
    {ok, #{
        <<"paymentToolToken">>   := ToolToken,
        <<"paymentSession">>     := ToolSession,
        <<"paymentToolDetails">> := PaymentToolDetails
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), Params),
    {ok, #{
        <<"paymentToolToken">> := ToolToken,
        <<"paymentSession">>   := ToolSession,
        <<"paymentToolDetails">> := PaymentToolDetails
    }} = capi_client_tokens:create_payment_resource(?config(context, Config), Params).

-spec create_visa_payment_resource_idemp_fail_test(_) ->
    _.
create_visa_payment_resource_idemp_fail_test(Config) ->
    ExternalID = <<"Degusi :P">>,
    BenderKey = <<"bender key">>,
    Token1 = <<"TOKEN1">>,
    Token2 = <<"TOKEN2">>,
    Ctx = capi_msgp_marshalling:marshal(#{<<"params_hash">> => erlang:phash2(Token1)}),
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"532130", _:6/binary, LastDigits:4/binary>>}
            ]) ->
                {ok, #cds_PutCardResult{
                    bank_card = #cds_BankCard{
                        token = Token2,
                        bin = <<"532130">>,
                        last_digits = LastDigits
                    }
                }};
            ('PutCard', [
                #cds_CardData{pan = <<"411111", _:6/binary, LastDigits:4/binary>>}
            ]) ->
                {ok, #cds_PutCardResult{
                    bank_card = #cds_BankCard{
                        token = Token1,
                        bin = <<"411111">>,
                        last_digits = LastDigits
                    }
                }}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(BenderKey, Ctx)} end},
        {binbase, fun('Lookup', _)     -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    PaymentTool = #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">>      => <<"4111111111111111">>,
            <<"cardHolder">>      => <<"Alexander Weinerschnitzel">>,
            <<"expDate">>         => <<"08/27">>,
            <<"cvv">>             => <<"232">>
        },
    Params = #{
        <<"externalID">>  => ExternalID,
        <<"paymentTool">> => PaymentTool,
        <<"clientInfo">>  => ClientInfo
    },
    Params2 = #{
        <<"externalID">>  => ExternalID,
        <<"paymentTool">> => PaymentTool#{<<"cardNumber">> => <<"5321301234567892">>},
        <<"clientInfo">>  => ClientInfo
    },
    {ok, _} = capi_client_tokens:create_payment_resource(?config(context, Config), Params),
    {error, {409, #{
        <<"externalID">> := ExternalID,
        <<"message">>    := <<"This 'externalID' has been used by another request">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), Params2).

-spec create_nspkmir_payment_resource_ok_test(_) ->
    _.
create_nspkmir_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_CardData{pan = <<"22022002", _:6/binary, LastDigits:2/binary>>}
            ]) ->
                {ok, #cds_PutCardResult{
                    bank_card = #cds_BankCard{
                        token = ?STRING,
                        bin = <<"22022002">>,
                        last_digits = LastDigits
                    }
                }}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"NSPK MIR">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"nspkmir">>,
        <<"cardNumberMask">> := <<"220220******8454">>,
        <<"last4">> := <<"8454">>,
        <<"first6">> := <<"220220">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"2202200223948454">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_euroset_payment_resource_ok_test(_) ->
    _.
create_euroset_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsPaymentTerminal">>,
        <<"provider">> := <<"euroset">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"PaymentTerminalData">>,
            <<"provider">> => <<"euroset">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_mobile_payment_resource_ok_test(_) ->
    _.
create_mobile_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {moneypenny, fun('Lookup', _) -> {ok, capi_ct_mnp_helper:get_result()} end}
    ], Config),
    MobilePhone = #{<<"cc">> => <<"7">>, <<"ctn">> => <<"9210001122">>},
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, Res} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"MobileCommerceData">>,
            <<"mobilePhone">> => MobilePhone
        },
        <<"clientInfo">> => ClientInfo
    }),
    ?assertEqual(#{
        <<"detailsType">> => <<"PaymentToolDetailsMobileCommerce">>,
        <<"phoneNumber">> => <<"+7******1122">>
    }, maps:get(<<"paymentToolDetails">>, Res)),
    PaymentToolToken = maps:get(<<"paymentToolToken">>, Res),
    {ok, {mobile_commerce_payload, #ptt_MobileCommercePayload{
        mobile_commerce = MobileCommerce
    }}} = capi_crypto:decrypt_payment_tool_token(PaymentToolToken),

    ?assertEqual(#domain_MobileCommerce{
        phone =  #domain_MobilePhone{
            cc = <<"7">>,
            ctn = <<"9210001122">>
        },
        operator = megafone
    }, MobileCommerce).


-spec create_qw_payment_resource_ok_test(_) ->
    _.
create_qw_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsDigitalWallet">>,
        <<"digitalWalletDetailsType">> := <<"DigitalWalletDetailsQIWI">>,
        <<"phoneNumberMask">> := <<"+7******3210">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_qw_payment_resource_with_access_token_generates_different_payment_token(_) ->
    _.
create_qw_payment_resource_with_access_token_generates_different_payment_token(Config) ->
    BenderResult = capi_ct_helper_bender:get_result(<<"benderkey">>),
    capi_ct_helper:mock_services([
        {bender,      fun ('GenerateID', _) -> {ok, BenderResult} end},
        {tds_storage, fun ('PutToken', _)   -> {ok, ok} end}
    ], Config),
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

-spec create_qw_payment_resource_with_access_token_depends_on_external_id(_) ->
    _.
create_qw_payment_resource_with_access_token_depends_on_external_id(Config) ->
    BenderResultExtID   = capi_ct_helper_bender:get_result(<<"benderkey0">>),
    BenderResultNoExtId = capi_ct_helper_bender:get_result(<<"benderkey1">>),
    capi_ct_helper:mock_services([
        {bender,      fun ('GenerateID', [?IDEMPOTENT_KEY | _]) -> {ok, BenderResultExtID};
                          ('GenerateID', _Args)                 -> {ok, BenderResultNoExtId}
                      end},
        {tds_storage, fun ('PutToken', _) -> {ok, ok} end}
    ], Config),
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
    PaymentParamsExtId = PaymentParamsNoExtId#{ <<"externalID">> => <<"ext_id">> },
    ResultExtId0  = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsExtId),
    ResultExtId1  = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsExtId),
    ResultNoExtId = capi_client_tokens:create_payment_resource(?config(context, Config), PaymentParamsNoExtId),
    {ok, #{<<"paymentToolToken">> := TokenExtId0}}  = ResultExtId0,
    {ok, #{<<"paymentToolToken">> := TokenExtId1}}  = ResultExtId1,
    {ok, #{<<"paymentToolToken">> := TokenNoExtId}} = ResultNoExtId,
    ?assertEqual(TokenExtId0, TokenExtId1),
    ?assertNotEqual(TokenExtId0, TokenNoExtId).

-spec create_crypto_payment_resource_ok_test(_) ->
    _.
create_crypto_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsCryptoWallet">>,
        <<"cryptoCurrency">> := <<"bitcoinCash">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CryptoWalletData">>,
            <<"cryptoCurrency">> => <<"bitcoinCash">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_applepay_tokenized_payment_resource_ok_test(_) ->
    _.
create_applepay_tokenized_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_apple_pay, fun('Unwrap', _) -> {ok, ?UNWRAPPED_PAYMENT_TOOL(?APPLE_PAY_DETAILS)} end},
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _)    -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := Details = #{
        <<"paymentSystem">> := <<"mastercard">>,
        <<"cardNumberMask">> := <<"************7892">>,
        <<"last4">> := <<"7892">>
    }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"ApplePay">>,
                <<"merchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    false = maps:is_key(<<"first6">>, Details).

-spec create_googlepay_tokenized_payment_resource_ok_test(_) ->
    _.
create_googlepay_tokenized_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_google_pay, fun('Unwrap', _) -> {ok, ?UNWRAPPED_PAYMENT_TOOL(?GOOGLE_PAY_DETAILS)} end},
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _)    -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := Details = #{
        <<"paymentSystem">> := <<"mastercard">>,
        <<"tokenProvider">> := <<"googlepay">>,
        <<"cardNumberMask">> := <<"************7892">>,
        <<"last4">> := <<"7892">>
    }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    false = maps:is_key(<<"first6">>, Details).

-spec create_googlepay_plain_payment_resource_ok_test(_) ->
    _.
create_googlepay_plain_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_google_pay,
            fun('Unwrap', _) ->
                {ok, ?UNWRAPPED_PAYMENT_TOOL(
                    ?GOOGLE_PAY_DETAILS,
                    {card, #paytoolprv_Card{
                        pan = <<"5321301234567892">>,
                        exp_date = #paytoolprv_ExpDate{month = 10, year = 2028}
                    }}
                )}
            end
        },
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _)    -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase,
            fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end
        }
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{
        <<"paymentToolToken">> := PaymentToolToken,
        <<"paymentToolDetails">> := Details = #{
        <<"paymentSystem">> := <<"mastercard">>,
        <<"cardNumberMask">> := <<"532130******7892">>,
        <<"first6">> := <<"532130">>,
        <<"last4">> := <<"7892">>
    }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    false = maps:is_key(<<"tokenProvider">>, Details),
    %% is_cvv_empty = true for GooglePay tokenized plain bank card
    %% see capi_handler_tokens:set_is_empty_cvv/2 for more info
    {ok, {bank_card_payload, #ptt_BankCardPayload{
        bank_card = #domain_BankCard{is_cvv_empty = true}
    }}}
        = capi_crypto:decrypt_payment_tool_token(PaymentToolToken).

%%

-spec ip_replacement_not_allowed_test(_) ->
    _.

ip_replacement_not_allowed_test(Config) ->
    % In this case we have no ip_replacement_allowed field, perhaps we could also test token with this field set to false
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

-spec ip_replacement_allowed_test(_) ->
    _.

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
   ClientIP = maps:get(<<"ip">>, maps:get(<<"clientInfo">>, Res)).

%%

-spec authorization_positive_lifetime_ok_test(config()) ->
    _.
authorization_positive_lifetime_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    Token = capi_ct_helper:issue_token([{[payment_resources], write}], {lifetime, 10}),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_unlimited_lifetime_ok_test(config()) ->
    _.
authorization_unlimited_lifetime_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    Token = capi_ct_helper:issue_token([{[payment_resources], write}], unlimited),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_far_future_deadline_ok_test(config()) ->
    _.
authorization_far_future_deadline_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', _) -> {ok, ?PUT_CARD_RESULT}
        end},
        {bender,  fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    Token = capi_ct_helper:issue_token([{[payment_resources], write}], {deadline, 4102444800}), % 01/01/2100 @ 12:00am (UTC)
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_header_test(config()) ->
    _.
authorization_error_no_header_test(_Config) ->
    Token = <<>>,
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_permission_test(config()) ->
    _.
authorization_error_no_permission_test(_Config) ->
    Token = capi_ct_helper:issue_token([{[payment_resources], read}], {lifetime, 10}),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_bad_token_error_test(config()) ->
    _.
authorization_bad_token_error_test(Config) ->
    Token = issue_dummy_token([{[payment_resources], write}], Config),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

%%

issue_dummy_token(ACL, Config) ->
    Claims = #{
        <<"jti">> => capi_ct_helper:get_unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0,
        <<"resource_access">> => #{
            <<"common-api">> => #{
                <<"roles">> => uac_acl:encode(uac_acl:from_list(ACL))
            }
        }
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).
