-module(capi_handler_tokens).

-type token_provider() :: yandexpay | applepay | googlepay | samsungpay.

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").
-include_lib("tds_proto/include/tds_proto_storage_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("moneypenny/include/moneypenny_mnp_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_restriction_thrift.hrl").

-behaviour(capi_handler).

-export([prepare/3]).
-export([get_token_providers/0]).

-import(capi_handler_utils, [logic_error/2, validation_error/1]).

-define(DEFAULT_PAYMENT_TOOL_TOKEN_LIFETIME, <<"64m">>).

-spec prepare(
    OperationID :: capi_handler:operation_id(),
    Req :: capi_handler:request_data(),
    Context :: capi_handler:processing_context()
) -> {ok, capi_handler:request_state()} | {error, noimpl}.
prepare('CreatePaymentResource' = OperationID, Req, Context) ->
    PartyID = capi_handler_utils:get_party_id(Context),

    Params = maps:get('PaymentResourceParams', Req),
    ReplacementIP = prepare_replacement_ip(Params),

    Authorize = fun() ->
        Prototypes = [
            {operation, #{id => OperationID, party => PartyID, client_info => #{ip => ReplacementIP}}},
            {payment_tool, prepare_payment_tool_prototype(Params)}
        ],
        {ok, capi_auth:authorize_operation(Prototypes, Context, Req)}
    end,
    Process = fun(Resolution) ->
        process_request(OperationID, Req, Context, Resolution)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(_OperationID, _Req, _Context) ->
    {error, noimpl}.

prepare_payment_tool_prototype(#{<<"paymentTool">> := Data}) ->
    prepare_provider_scope(Data).

prepare_provider_scope(#{<<"paymentToolType">> := <<"TokenizedCardData">>} = Data) ->
    Provider = get_token_provider(Data),
    EncodedID = get_token_provider_merchant_id(Data),
    MerchantID = unwrap_merchant_id(Provider, EncodedID),
    #{
        party => maps:get(party, MerchantID, undefined),
        shop => maps:get(shop, MerchantID, undefined),
        expiration => maps:get(expiration, MerchantID, undefined)
    };
prepare_provider_scope(_Data) ->
    #{}.

prepare_replacement_ip(#{<<"clientInfo">> := ClientInfo}) ->
    get_replacement_ip(ClientInfo);
prepare_replacement_ip(_) ->
    undefined.

-spec process_request(
    OperationID :: capi_handler:operation_id(),
    Req :: capi_handler:request_data(),
    Context :: capi_handler:processing_context(),
    Resolution :: capi_auth:resolution()
) -> {ok | error, capi_handler:response() | noimpl}.
process_request('CreatePaymentResource' = OperationID, Req, Context, Resolution) ->
    Params = maps:get('PaymentResourceParams', Req),
    ClientInfo0 = maps:get(<<"clientInfo">>, Params),
    ClientIP =
        case flatten_resolution_decision(Resolution) of
            {restricted, ip_replacement_forbidden} ->
                prepare_requester_ip(Context);
            allowed ->
                case get_replacement_ip(ClientInfo0) of
                    undefined -> prepare_requester_ip(Context);
                    IP -> IP
                end
        end,

    ClientInfo1 = maps:put(<<"ip">>, ClientIP, ClientInfo0),
    try
        ClientUrl = get_client_url(ClientInfo1),
        ClientInfo = maps:put(<<"url">>, ClientUrl, ClientInfo1),
        Data = maps:get(<<"paymentTool">>, Params),
        PartyID = capi_handler_utils:get_party_id(Context),
        ExternalID = maps:get(<<"externalID">>, Params, undefined),
        IdempotentKey = capi_bender:get_idempotent_key(OperationID, PartyID, ExternalID),
        IdempotentParams = {ExternalID, IdempotentKey},
        {PaymentTool, PaymentSessionID, PaymentToolDeadline} =
            case Data of
                #{<<"paymentToolType">> := <<"CardData">>} ->
                    erlang:append_element(process_card_data(Data, IdempotentParams, Context), undefined);
                #{<<"paymentToolType">> := <<"PaymentTerminalData">>} ->
                    {process_payment_terminal_data(Data), <<>>, undefined};
                #{<<"paymentToolType">> := <<"DigitalWalletData">>} ->
                    {process_digital_wallet_data(Data, IdempotentParams, Context), <<>>, undefined};
                #{<<"paymentToolType">> := <<"TokenizedCardData">>} ->
                    process_tokenized_card_data(Data, IdempotentParams, Context);
                #{<<"paymentToolType">> := <<"CryptoWalletData">>} ->
                    {process_crypto_wallet_data(Data), <<>>, undefined};
                #{<<"paymentToolType">> := <<"MobileCommerceData">>} ->
                    {process_mobile_commerce_data(Data, Context), <<>>, undefined}
            end,
        TokenData = #{
            payment_tool => PaymentTool,
            valid_until => make_payment_token_deadline(PaymentToolDeadline)
        },
        PaymentResource = #domain_DisposablePaymentResource{
            payment_tool = PaymentTool,
            payment_session_id = PaymentSessionID,
            client_info = capi_handler_encoder:encode_client_info(ClientInfo)
        },
        {ok,
            {201, #{},
                capi_handler_decoder:decode_disposable_payment_resource(
                    PaymentResource,
                    capi_crypto:encode_token(TokenData),
                    maps:get(valid_until, TokenData)
                )}}
    catch
        Result -> Result
    end.

%%

flatten_resolution_decision(allowed) ->
    allowed;
flatten_resolution_decision({restricted, #brstn_Restrictions{capi = CAPI}}) ->
    case CAPI of
        #brstn_RestrictionsCommonAPI{
            ip_replacement_forbidden = true
        } ->
            {restricted, ip_replacement_forbidden};
        _ ->
            allowed
    end.

prepare_requester_ip(Context) ->
    #{ip_address := IP} = get_peer_info(Context),
    genlib:to_binary(inet:ntoa(IP)).

get_peer_info(#{swagger_context := #{peer := Peer}}) ->
    Peer.

get_replacement_ip(ClientInfo) ->
    maps:get(<<"ip">>, ClientInfo, undefined).

get_client_url(ClientInfo) ->
    case maps:get(<<"url">>, ClientInfo, undefined) of
        undefined ->
            undefined;
        Url ->
            delete_query_params(Url)
    end.

delete_query_params(Url) ->
    case capi_utils:delete_url_query_params(Url) of
        {ok, UrlWithoutParams} ->
            UrlWithoutParams;
        {error, Error, Description} ->
            _ = logger:notice("Unexpected client info url reason: ~p ~p", [Error, Description]),
            throw({ok, logic_error(invalidRequest, <<"Client info url is invalid">>)})
    end.

%%

-spec payment_token_deadline() -> capi_utils:deadline().
payment_token_deadline() ->
    Lifetime = genlib_app:env(capi_pcidss, payment_tool_token_lifetime, ?DEFAULT_PAYMENT_TOOL_TOKEN_LIFETIME),
    lifetime_to_deadline(Lifetime).

% Ограничиваем время жизни платежного токена временем жизни платежного инструмента.
% Если время жизни платежного инструмента не задано, то интервалом заданным в настройках.
-spec make_payment_token_deadline(capi_utils:deadline()) -> capi_utils:deadline().
make_payment_token_deadline(undefined) ->
    payment_token_deadline();
make_payment_token_deadline(PaymentToolDeadline) ->
    erlang:min(PaymentToolDeadline, payment_token_deadline()).

%%

process_card_data(Data, IdempotentParams, #{woody_context := WoodyCtx} = Context) ->
    SessionData = encode_session_data(Data),
    {CardData, ExtraCardData} = encode_card_data(Data),
    BankInfo = get_bank_info(CardData#'cds_PutCardData'.pan, Context),
    PaymentSystem = capi_bankcard:payment_system(BankInfo),
    ValidationEnv = capi_bankcard:validation_env(),
    BankCardData = capi_bankcard:merge_data(CardData, ExtraCardData, SessionData),
    case bankcard_validator:validate(BankCardData, PaymentSystem, ValidationEnv, WoodyCtx) of
        ok ->
            Result = put_card_data_to_cds(CardData, SessionData, IdempotentParams, BankInfo, Context),
            process_card_data_result(Result, CardData, ExtraCardData);
        {error, Error} ->
            throw({ok, validation_error(Error)})
    end.

process_card_data_result(
    {{bank_card, BankCard}, SessionID},
    #cds_PutCardData{
        pan = CardNumber
    },
    ExtraCardData
) ->
    {
        {bank_card, BankCard#domain_BankCard{
            bin = get_first6(CardNumber),
            last_digits = get_last4(CardNumber),
            exp_date = encode_exp_date(genlib_map:get(exp_date, ExtraCardData)),
            cardholder_name = genlib_map:get(cardholder, ExtraCardData)
        }},
        SessionID
    }.

encode_exp_date(undefined) ->
    undefined;
encode_exp_date({Month, Year}) ->
    #domain_BankCardExpDate{
        year = Year,
        month = Month
    }.

encode_session_data(CardData) ->
    #cds_SessionData{
        auth_data =
            {card_security_code, #cds_CardSecurityCode{
                % dirty hack for cds support empty cvv bank cards
                value = maps:get(<<"cvv">>, CardData, <<"">>)
            }}
    }.

encode_card_data(CardData) ->
    CardNumber = genlib:to_binary(genlib_map:get(<<"cardNumber">>, CardData)),
    ExpDate = parse_exp_date(genlib_map:get(<<"expDate">>, CardData)),
    Cardholder = genlib_map:get(<<"cardHolder">>, CardData),
    {
        #cds_PutCardData{
            pan = CardNumber
        },
        genlib_map:compact(#{
            cardholder => Cardholder,
            exp_date => ExpDate
        })
    }.

parse_exp_date(undefined) ->
    undefined;
parse_exp_date(ExpDate) when is_binary(ExpDate) ->
    [Month, Year0] = binary:split(ExpDate, <<"/">>),
    Year =
        case genlib:to_int(Year0) of
            Y when Y < 100 ->
                2000 + Y;
            Y ->
                Y
        end,
    {genlib:to_int(Month), Year}.

put_card_data_to_cds(CardData, SessionData, {ExternalID, IdempotentKey}, BankInfo, Context) ->
    #{woody_context := WoodyCtx} = Context,
    BankCard = put_card_to_cds(CardData, SessionData, BankInfo, Context),
    {bank_card, #domain_BankCard{token = Token}} = BankCard,
    RandomID = gen_random_id(),
    Hash = erlang:phash2(Token),
    case capi_bender:gen_by_constant(IdempotentKey, RandomID, Hash, WoodyCtx) of
        {ok, SessionID} ->
            ok = put_session_to_cds(SessionID, SessionData, Context),
            {BankCard, SessionID};
        {error, {external_id_conflict, _}} ->
            throw({ok, logic_error(externalIDConflict, ExternalID)})
    end.

put_card_to_cds(CardData, SessionData, BankInfo, Context) ->
    Call = {cds_storage, 'PutCard', {CardData}},
    case capi_handler_utils:service_call(Call, Context) of
        {ok, #cds_PutCardResult{bank_card = BankCard}} ->
            {bank_card, expand_card_info(BankCard, BankInfo, undef_cvv(SessionData))};
        {exception, #cds_InvalidCardData{}} ->
            throw({ok, logic_error(invalidRequest, <<"Card data is invalid">>)})
    end.

expand_card_info(
    BankCard,
    #{
        payment_system := PaymentSystem,
        payment_system_deprecated := LegacyPaymentSystem,
        bank_name := BankName,
        issuer_country := IssuerCountry,
        category := Category,
        metadata := {NS, Metadata}
    },
    HaveCVV
) ->
    BankCard1 = #domain_BankCard{
        token = BankCard#cds_BankCard.token,
        bin = BankCard#cds_BankCard.bin,
        last_digits = BankCard#cds_BankCard.last_digits,
        payment_system = #domain_PaymentSystemRef{id = PaymentSystem},
        payment_system_deprecated = LegacyPaymentSystem,
        issuer_country = IssuerCountry,
        category = Category,
        bank_name = BankName,
        is_cvv_empty = HaveCVV
    },
    add_metadata(NS, Metadata, BankCard1).

%% Seems to fit within PCIDSS requirments for all PAN lengths
get_first6(CardNumber) ->
    binary:part(CardNumber, {0, 6}).

get_last4(CardNumber) ->
    binary:part(CardNumber, {byte_size(CardNumber), -4}).

undef_cvv(#cds_SessionData{
    auth_data =
        {card_security_code, #cds_CardSecurityCode{
            value = Value
        }}
}) ->
    Value == <<>>;
undef_cvv(#cds_SessionData{}) ->
    undefined.

gen_random_id() ->
    Random = crypto:strong_rand_bytes(16),
    genlib_format:format_int_base(binary:decode_unsigned(Random), 62).

put_session_to_cds(SessionID, SessionData, Context) ->
    Call = {cds_storage, 'PutSession', {SessionID, SessionData}},
    {ok, ok} = capi_handler_utils:service_call(Call, Context),
    ok.

-spec unwrap_merchant_id(atom(), binary()) -> map().
unwrap_merchant_id(Provider, EncodedID) ->
    case unwrap_merchant_id_fallback(Provider, EncodedID) of
        #{} = Map ->
            Map;
        _ ->
            case capi_merchant_id:decode(EncodedID) of
                Data when Data =/= undefined ->
                    #{
                        realm => capi_merchant_id:realm(Data),
                        party => capi_merchant_id:party_id(Data),
                        shop => capi_merchant_id:shop_id(Data)
                    };
                _ ->
                    _ = logger:warning("invalid merchant id: ~p ~p", [Provider, EncodedID]),
                    capi_handler:respond(logic_error(invalidRequest, <<"Invalid merchant ID">>))
            end
    end.

unwrap_merchant_id_fallback(Provider, EncodedID) ->
    FallbackMap = genlib_app:env(capi_pcidss, fallback_merchant_map, #{}),
    case maps:get({Provider, EncodedID}, FallbackMap, undefined) of
        Map when is_map(Map) ->
            genlib_map:compact(
                maps:map(
                    fun
                        (realm, V) -> V;
                        (party, V) -> V;
                        (shop, V) -> V;
                        (expiration, {_Y, _M, _D} = V) -> capi_utils:deadline_to_binary({{V, {0, 0, 0}}, 0});
                        (_Other, _V) -> undefined
                    end,
                    Map
                )
            );
        _Other ->
            undefined
    end.

lifetime_to_deadline(Lifetime) when is_integer(Lifetime) ->
    capi_utils:deadline_from_timeout(Lifetime);
lifetime_to_deadline(Lifetime) ->
    case capi_utils:parse_lifetime(Lifetime) of
        {ok, V} ->
            capi_utils:deadline_from_timeout(V);
        Error ->
            erlang:error(Error, [Lifetime])
    end.

%%

process_payment_terminal_data(Data) ->
    Ref = encode_payment_service_ref(maps:get(<<"provider">>, Data)),
    case validate_payment_service_ref(Ref) of
        {ok, _} ->
            PaymentTerminal = #domain_PaymentTerminal{payment_service = Ref},
            {payment_terminal, PaymentTerminal};
        {error, object_not_found} ->
            throw({ok, logic_error(invalidRequest, <<"Terminal provider is invalid">>)})
    end.

process_digital_wallet_data(Data, IdempotentParams, Context) ->
    Ref = encode_payment_service_ref(maps:get(<<"provider">>, Data)),
    case validate_payment_service_ref(Ref) of
        {ok, _} ->
            DigitalWallet = #domain_DigitalWallet{
                id = maps:get(<<"id">>, Data),
                payment_service = encode_payment_service_ref(maps:get(<<"provider">>, Data)),
                token = maybe_store_token_in_tds(maps:get(<<"token">>, Data, undefined), IdempotentParams, Context)
            },
            {digital_wallet, DigitalWallet};
        {error, object_not_found} ->
            throw({ok, logic_error(invalidRequest, <<"Digital wallet provider is invalid">>)})
    end.

maybe_store_token_in_tds(TokenContent, IdempotentParams, Context) when
    TokenContent =/= undefined
->
    #{woody_context := WoodyCtx} = Context,
    {_ExternalID, IdempotentKey} = IdempotentParams,
    Token = #tds_Token{content = TokenContent},
    RandomID = gen_random_id(),
    Hash = undefined,
    {ok, TokenID} = capi_bender:gen_by_constant(IdempotentKey, RandomID, Hash, WoodyCtx),
    Call = {tds_storage, 'PutToken', {TokenID, Token}},
    {ok, ok} = capi_handler_utils:service_call(Call, Context),
    TokenID;
maybe_store_token_in_tds(_, _IdempotentParams, _Context) ->
    undefined.

process_tokenized_card_data(Data, IdempotentParams, #{woody_context := WoodyCtx} = Context) ->
    Call = {get_token_provider_service_name(Data), 'Unwrap', {encode_wrapped_payment_tool(Data)}},
    UnwrappedPaymentTool =
        case capi_handler_utils:service_call(Call, Context) of
            {ok, Tool} ->
                Tool;
            {exception, #'InvalidRequest'{}} ->
                throw({ok, logic_error(invalidRequest, <<"Tokenized card data is invalid">>)})
        end,
    {CardData, ExtraCardData} = encode_tokenized_card_data(UnwrappedPaymentTool),
    SessionData = encode_tokenized_session_data(UnwrappedPaymentTool),
    BankInfo = get_bank_info(CardData#cds_PutCardData.pan, Context),
    PaymentSystem = capi_bankcard:payment_system(BankInfo),
    ValidationEnv = capi_bankcard:validation_env(),
    BankCardData = capi_bankcard:merge_data(CardData, ExtraCardData, SessionData),
    case bankcard_validator:validate(BankCardData, PaymentSystem, ValidationEnv, WoodyCtx) of
        ok ->
            Result = put_card_data_to_cds(CardData, SessionData, IdempotentParams, BankInfo, Context),
            process_tokenized_card_data_result(Result, ExtraCardData, UnwrappedPaymentTool);
        {error, Error} ->
            throw({ok, validation_error(Error)})
    end.

get_token_provider_service_name(Data) ->
    case Data of
        #{<<"provider">> := <<"ApplePay">>} ->
            payment_tool_provider_apple_pay;
        #{<<"provider">> := <<"GooglePay">>} ->
            payment_tool_provider_google_pay;
        #{<<"provider">> := <<"SamsungPay">>} ->
            payment_tool_provider_samsung_pay;
        #{<<"provider">> := <<"YandexPay">>} ->
            payment_tool_provider_yandex_pay
    end.

get_token_provider(#{<<"provider">> := <<"ApplePay">>}) ->
    applepay;
get_token_provider(#{<<"provider">> := <<"GooglePay">>}) ->
    googlepay;
get_token_provider(#{<<"provider">> := <<"SamsungPay">>}) ->
    samsungpay;
get_token_provider(#{<<"provider">> := <<"YandexPay">>}) ->
    yandexpay.

get_token_provider_merchant_id(#{<<"provider">> := <<"ApplePay">>} = Data) ->
    maps:get(<<"merchantID">>, Data);
get_token_provider_merchant_id(#{<<"provider">> := <<"GooglePay">>} = Data) ->
    maps:get(<<"gatewayMerchantID">>, Data);
get_token_provider_merchant_id(#{<<"provider">> := <<"SamsungPay">>} = Data) ->
    % TODO #123 пока serviceID поскольку merchant.reference отсутствует
    % https://pay.samsung.com/developers/resource/guide
    maps:get(<<"serviceID">>, Data);
get_token_provider_merchant_id(#{<<"provider">> := <<"YandexPay">>} = Data) ->
    maps:get(<<"gatewayMerchantID">>, Data).

encode_wrapped_payment_tool(Data) ->
    Provider = get_token_provider(Data),
    EncodedID = get_token_provider_merchant_id(Data),
    MerchantID = unwrap_merchant_id(Provider, EncodedID),
    RealmMode = maps:get(realm, MerchantID, undefined),
    #paytoolprv_WrappedPaymentTool{
        request = encode_payment_request(Data),
        realm = RealmMode
    }.

encode_payment_request(#{<<"provider">> := <<"ApplePay">>} = Data) ->
    {apple, #paytoolprv_ApplePayRequest{
        merchant_id = maps:get(<<"merchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider">> := <<"GooglePay">>} = Data) ->
    {google, #paytoolprv_GooglePayRequest{
        gateway_merchant_id = maps:get(<<"gatewayMerchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider">> := <<"SamsungPay">>} = Data) ->
    {samsung, #paytoolprv_SamsungPayRequest{
        service_id = genlib_map:get(<<"serviceID">>, Data),
        reference_id = genlib_map:get(<<"referenceID">>, Data)
    }};
encode_payment_request(#{<<"provider">> := <<"YandexPay">>} = Data) ->
    {yandex, #paytoolprv_YandexPayRequest{
        gateway_merchant_id = maps:get(<<"gatewayMerchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }}.

process_tokenized_card_data_result(
    {{bank_card, BankCard}, SessionID},
    ExtraCardData,
    #paytoolprv_UnwrappedPaymentTool{
        card_info = #paytoolprv_CardInfo{
            last_4_digits = Last4
        },
        payment_data = PaymentData,
        details = PaymentDetails,
        valid_until = ValidUntil
    }
) ->
    TokenProvider = get_payment_token_provider(PaymentDetails),
    TokenServiceID = get_token_service_id(TokenProvider),
    TokenizationMethod = get_tokenization_method(PaymentData),
    {NS, ProviderMetadata} = extract_payment_tool_provider_metadata(PaymentDetails),
    BankCard1 = BankCard#domain_BankCard{
        bin = get_tokenized_bin(PaymentData),
        last_digits = get_tokenized_pan(Last4, PaymentData),
        payment_token = #domain_BankCardTokenServiceRef{id = TokenServiceID},
        token_provider_deprecated = TokenProvider,
        is_cvv_empty = set_is_empty_cvv(TokenizationMethod, BankCard),
        exp_date = encode_exp_date(genlib_map:get(exp_date, ExtraCardData)),
        cardholder_name = genlib_map:get(cardholder, ExtraCardData),
        tokenization_method = TokenizationMethod
    },
    BankCard2 = add_metadata(NS, ProviderMetadata, BankCard1),
    Deadline = capi_utils:deadline_from_binary(ValidUntil),
    {{bank_card, BankCard2}, SessionID, Deadline}.

get_tokenized_bin({card, #paytoolprv_Card{pan = PAN}}) ->
    get_first6(PAN);
get_tokenized_bin({tokenized_card, _}) ->
    <<>>.

% Prefer to get last4 from the PAN itself rather than using the one from the adapter
% On the other hand, getting a DPAN and no last4 from the adapter is unsupported
get_tokenized_pan(_Last4, {card, #paytoolprv_Card{pan = PAN}}) ->
    get_last4(PAN);
get_tokenized_pan(Last4, _PaymentData) when Last4 =/= undefined ->
    Last4.

get_tokenization_method({card, _}) ->
    none;
get_tokenization_method({tokenized_card, _}) ->
    dpan.

% Do not drop is_cvv_empty flag for tokenized bank cards which looks like
% simple bank card. This prevent wrong routing decisions in hellgate
% when cvv is empty, but is_cvv_empty = undefined, which forces routing to bypass
% restrictions and crash adapter.
set_is_empty_cvv(none, BankCard) ->
    BankCard#domain_BankCard.is_cvv_empty;
set_is_empty_cvv(_, _) ->
    undefined.

get_payment_token_provider({yandex, _}) ->
    yandexpay;
get_payment_token_provider({apple, _}) ->
    applepay;
get_payment_token_provider({google, _}) ->
    googlepay;
get_payment_token_provider({samsung, _}) ->
    samsungpay.

-spec get_token_providers() -> [token_provider()].
get_token_providers() ->
    [yandexpay, applepay, googlepay, samsungpay].

get_token_service_id(TokenProvider) ->
    TokenServices = genlib_app:env(capi_pcidss, bank_card_token_service_mapping),
    maps:get(TokenProvider, TokenServices).

%% TODO
%% All this stuff deserves its own module I believe. These super-long names are quite strong hints.
-define(PAYMENT_TOOL_PROVIDER_META_NS, <<"com.rbkmoney.payment-tool-provider">>).

extract_payment_tool_provider_metadata({_Provider, Details}) ->
    {?PAYMENT_TOOL_PROVIDER_META_NS, #{
        <<"details">> => extract_payment_details_metadata(Details)
    }}.

extract_payment_details_metadata(#paytoolprv_ApplePayDetails{
    transaction_id = TransactionID,
    device_id = DeviceID
}) ->
    #{
        <<"transaction_id">> => TransactionID,
        <<"device_id">> => DeviceID
    };
extract_payment_details_metadata(#paytoolprv_SamsungPayDetails{
    device_id = DeviceID
}) ->
    #{
        <<"device_id">> => DeviceID
    };
extract_payment_details_metadata(#paytoolprv_GooglePayDetails{
    message_id = MessageID
}) ->
    #{
        <<"message_id">> => MessageID
    };
extract_payment_details_metadata(#paytoolprv_YandexPayDetails{
    message_id = MessageID
}) ->
    #{
        <<"message_id">> => MessageID
    }.

%%

encode_tokenized_card_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data =
        {tokenized_card, #paytoolprv_TokenizedCard{
            dpan = DPAN,
            exp_date = #paytoolprv_ExpDate{
                month = Month,
                year = Year
            }
        }},
    card_info = #paytoolprv_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    ExpDate = {Month, Year},
    {
        #cds_PutCardData{
            pan = DPAN
        },
        genlib_map:compact(#{
            cardholder => CardholderName,
            exp_date => ExpDate
        })
    };
encode_tokenized_card_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data =
        {card, #paytoolprv_Card{
            pan = PAN,
            exp_date = #paytoolprv_ExpDate{
                month = Month,
                year = Year
            }
        }},
    card_info = #paytoolprv_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    ExpDate = {Month, Year},
    {
        #cds_PutCardData{
            pan = PAN
        },
        genlib_map:compact(#{
            cardholder => CardholderName,
            exp_date => ExpDate
        })
    }.

encode_tokenized_session_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data =
        {tokenized_card, #paytoolprv_TokenizedCard{
            auth_data =
                {auth_3ds, #paytoolprv_Auth3DS{
                    cryptogram = Cryptogram,
                    eci = ECI
                }}
        }}
}) ->
    #cds_SessionData{
        auth_data =
            {auth_3ds, #cds_Auth3DS{
                cryptogram = Cryptogram,
                eci = ECI
            }}
    };
encode_tokenized_session_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data = {card, #paytoolprv_Card{}}
}) ->
    #cds_SessionData{
        auth_data =
            {card_security_code, #cds_CardSecurityCode{
                %% TODO dirty hack for test GooglePay card data
                value = <<"">>
            }}
    }.

%%

process_crypto_wallet_data(Data) ->
    #{<<"cryptoCurrency">> := CryptoCurrency} = Data,
    {crypto_currency_deprecated, capi_handler_decoder:convert_crypto_currency_from_swag(CryptoCurrency)}.

%%

process_mobile_commerce_data(Data, Context) ->
    MobilePhone = maps:get(<<"mobilePhone">>, Data),
    {ok, Operator} = get_mobile_operator(MobilePhone, Context),
    MobileCommerce = encode_mobile_commerce(MobilePhone, Operator),
    {mobile_commerce, MobileCommerce}.

get_mobile_operator(MobilePhone, Context) ->
    PhoneNumber = encode_request_params(MobilePhone),
    Call = {moneypenny, 'Lookup', {PhoneNumber}},
    case capi_handler_utils:service_call(Call, Context) of
        {ok, #mnp_ResponseData{operator = Operator}} ->
            {ok, Operator};
        {exception, #mnp_BadPhoneFormat{}} ->
            throw({ok, logic_error(invalidRequest, <<"Bad phone format.">>)});
        {exception, #mnp_OperatorNotFound{}} ->
            throw({ok, logic_error(invalidRequest, <<"Operator not found.">>)})
    end.

encode_request_params(#{<<"cc">> := Cc, <<"ctn">> := Ctn}) ->
    #mnp_RequestParams{
        phone = #mnp_PhoneNumber{
            cc = Cc,
            ctn = Ctn
        }
    }.

encode_mobile_commerce(MobilePhone, Operator) ->
    #{<<"cc">> := Cc, <<"ctn">> := Ctn} = MobilePhone,
    #domain_MobileCommerce{
        operator_deprecated = Operator,
        phone = #domain_MobilePhone{cc = Cc, ctn = Ctn}
    }.

get_bank_info(CardDataPan, Context) ->
    case capi_bankcard:lookup_bank_info(CardDataPan, Context) of
        {ok, BankInfo} ->
            BankInfo;
        {error, _Reason} ->
            throw({ok, logic_error(invalidRequest, <<"Unsupported card">>)})
    end.

add_metadata(NS, Metadata, BankCard = #domain_BankCard{metadata = Acc = #{}}) ->
    undefined = maps:get(NS, Acc, undefined),
    BankCard#domain_BankCard{
        metadata = Acc#{NS => capi_msgp_marshalling:marshal(Metadata)}
    };
add_metadata(NS, Metadata, BankCard = #domain_BankCard{metadata = undefined}) ->
    add_metadata(NS, Metadata, BankCard#domain_BankCard{metadata = #{}}).

encode_payment_service_ref(Provider) ->
    #domain_PaymentServiceRef{id = Provider}.

validate_payment_service_ref(Ref = #domain_PaymentServiceRef{})->
    dmt_client:try_checkout_data({payment_service, Ref}).