-module(capi_handler_tokens).

-type token_provider() :: yandexpay | applepay | googlepay | samsungpay.
-type mobile_operator() :: mts | beeline | megafone | tele2 | yota.

-include_lib("damsel/include/dmsl_base_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").
-include_lib("tds_proto/include/tds_storage_thrift.hrl").
-include_lib("damsel/include/dmsl_paytool_provider_thrift.hrl").
-include_lib("moneypenny/include/mnp_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_rstn_thrift.hrl").

-behaviour(capi_handler).

-export([prepare/3]).
-export([get_token_providers/0]).
-export([get_mobile_operators/0]).

-define(APP, capi_pcidss).

-define(DEFAULT_PAYMENT_TOOL_TOKEN_LIFETIME, <<"64m">>).
-define(DEFAULT_RESOURCE_METADATA_NAMESPACE, <<"dev.vality.paymentResource">>).

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
        {ok, capi_auth:authorize_operation(Prototypes, Context)}
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
process_request('CreatePaymentResource', Req, Context, Resolution) ->
    Params = maps:get('PaymentResourceParams', Req),
    ClientInfo0 = maps:get(<<"clientInfo">>, Params),
    PeerIP = prepare_requester_ip(Context),
    {ClientIP, UserIP} =
        case flatten_resolution_decision(Resolution) of
            {restricted, ip_replacement_forbidden} ->
                {PeerIP, undefined};
            allowed ->
                case get_replacement_ip(ClientInfo0) of
                    undefined -> {PeerIP, undefined};
                    IP -> {IP, IP}
                end
        end,

    ClientInfo1 = ClientInfo0#{
        <<"ip">> => ClientIP,
        <<"peer_ip">> => PeerIP,
        <<"user_ip">> => UserIP
    },

    try
        ClientUrl = get_client_url(ClientInfo1),
        ClientInfo = maps:put(<<"url">>, ClientUrl, ClientInfo1),
        Data = maps:get(<<"paymentTool">>, Params),
        {Token, PaymentTool, PaymentSessionID, PaymentToolDeadline} =
            case Data of
                #{<<"paymentToolType">> := <<"CardData">>} ->
                    {T, PT, S} = process_card_data(Data, Context),
                    {T, PT, S, undefined};
                #{<<"paymentToolType">> := <<"PaymentTerminalData">>} ->
                    TD = process_payment_terminal_data(Data),
                    {undefined, TD, <<>>, undefined};
                #{<<"paymentToolType">> := <<"DigitalWalletData">>} ->
                    {T, DW} = process_digital_wallet_data(Data, Context),
                    {T, DW, <<>>, undefined};
                #{<<"paymentToolType">> := <<"TokenizedCardData">>} ->
                    process_tokenized_card_data(Data, Context);
                #{<<"paymentToolType">> := <<"CryptoWalletData">>} ->
                    WD = process_crypto_wallet_data(Data),
                    {undefined, WD, <<>>, undefined};
                #{<<"paymentToolType">> := <<"MobileCommerceData">>} ->
                    MCD = process_mobile_commerce_data(Data, Context),
                    {undefined, MCD, <<>>, undefined}
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
                    Token,
                    capi_crypto:encode_token(TokenData),
                    maps:get(valid_until, TokenData)
                )}}
    catch
        Result -> Result
    end.

%%

flatten_resolution_decision(allowed) ->
    allowed;
flatten_resolution_decision({restricted, #rstn_Restrictions{capi = CAPI}}) ->
    case CAPI of
        #rstn_RestrictionsCommonAPI{
            ip_replacement_forbidden = true
        } ->
            {restricted, ip_replacement_forbidden};
        _ ->
            allowed
    end.

prepare_requester_ip(Context) ->
    #{ip_address := IP} = get_peer_info(Context),
    genlib:to_binary(inet:ntoa(IP)).

get_peer_info(#{swagger_context := #{cowboy_req := Req}}) ->
    case capi_handler_utils:determine_peer(Req) of
        {ok, IP} ->
            IP;
        _ ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Malformed 'x-forwarded-for' header">>)})
    end.

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
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Client info url is invalid">>)})
    end.

%%

-spec payment_token_deadline() -> capi_utils:deadline().
payment_token_deadline() ->
    Lifetime = genlib_app:env(?APP, payment_tool_token_lifetime, ?DEFAULT_PAYMENT_TOOL_TOKEN_LIFETIME),
    lifetime_to_deadline(Lifetime).

% Ограничиваем время жизни платежного токена временем жизни платежного инструмента.
% Если время жизни платежного инструмента не задано, то интервалом заданным в настройках.
-spec make_payment_token_deadline(capi_utils:deadline()) -> capi_utils:deadline().
make_payment_token_deadline(undefined) ->
    payment_token_deadline();
make_payment_token_deadline(PaymentToolDeadline) ->
    erlang:min(PaymentToolDeadline, payment_token_deadline()).

%%

process_card_data(Data, Context) ->
    CardData = encode_card_data(Data),
    SessionData = encode_session_data(Data),
    BankInfo = get_bank_info(maps:get(pan, CardData), Context),
    case capi_bankcard:validate(CardData, SessionData, BankInfo, Context) of
        ok ->
            {Token, SessionID} = put_card_data_to_cds(CardData, SessionData, Context),
            BankCard = construct_bank_card(Token, CardData, SessionData),
            {Token, {bank_card, enrich_bank_card(BankCard, BankInfo)}, SessionID};
        {error, Error} ->
            throw({ok, capi_handler_utils:validation_error(Error)})
    end.

construct_bank_card(Token, CardData, SessionData) ->
    CardNumber = maps:get(pan, CardData),
    #domain_BankCard{
        token = Token,
        bin = get_first6(CardNumber),
        last_digits = get_last4(CardNumber),
        exp_date = encode_exp_date(maps:get(exp_date, CardData)),
        cardholder_name = maps:get(cardholder, CardData, undefined),
        is_cvv_empty = undef_cvv(SessionData)
    }.

enrich_bank_card(
    BankCard,
    #{
        payment_system := PaymentSystem,
        bank_name := BankName,
        issuer_country := IssuerCountry,
        category := Category,
        metadata := {NS, Metadata}
    }
) ->
    add_metadata(NS, Metadata, BankCard#domain_BankCard{
        payment_system = #domain_PaymentSystemRef{id = PaymentSystem},
        issuer_country = IssuerCountry,
        category = Category,
        bank_name = BankName
    }).

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
    genlib_map:compact(#{
        pan => maps:get(<<"cardNumber">>, CardData),
        cardholder => maps:get(<<"cardHolder">>, CardData, undefined),
        exp_date => parse_exp_date(maps:get(<<"expDate">>, CardData))
    }).

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

put_card_data_to_cds(CardData, SessionData, Context) ->
    Token = put_card_to_cds(CardData, Context),
    SessionID = gen_random_id(),
    ok = put_session_to_cds(SessionID, SessionData, Context),
    {Token, SessionID}.

put_card_to_cds(CardData, Context) ->
    Arg = #cds_PutCardData{pan = maps:get(pan, CardData)},
    Call = {cds_storage, 'PutCard', {Arg}},
    case capi_handler_utils:service_call(Call, Context) of
        {ok, #cds_PutCardResult{bank_card = #cds_BankCard{token = Token}}} ->
            Token;
        {exception, #cds_InvalidCardData{}} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Card data is invalid">>)})
    end.

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
                    capi_handler:respond(capi_handler_utils:logic_error(invalidRequest, <<"Invalid merchant ID">>))
            end
    end.

unwrap_merchant_id_fallback(Provider, EncodedID) ->
    FallbackMap = genlib_app:env(?APP, fallback_merchant_map, #{}),
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
            Metadata = maps:get(<<"metadata">>, Data, undefined),
            PaymentTerminal = #domain_PaymentTerminal{
                payment_service = Ref,
                metadata = capi_utils:'maybe'(Metadata, fun encode_resource_metadata/1)
            },
            {payment_terminal, PaymentTerminal};
        {error, object_not_found} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Terminal provider is invalid">>)})
    end.

process_digital_wallet_data(Data, Context) ->
    Ref = encode_payment_service_ref(maps:get(<<"provider">>, Data)),
    case validate_payment_service_ref(Ref) of
        {ok, _} ->
            Token0 = maps:get(<<"token">>, Data, undefined),
            Token1 = capi_utils:'maybe'(Token0, fun(T) -> store_token_in_tds(T, Context) end),
            DigitalWallet = #domain_DigitalWallet{
                id = maps:get(<<"id">>, Data),
                payment_service = encode_payment_service_ref(maps:get(<<"provider">>, Data)),
                token = Token1
            },
            {Token1, {digital_wallet, DigitalWallet}};
        {error, object_not_found} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Digital wallet provider is invalid">>)})
    end.

store_token_in_tds(TokenContent, Context) ->
    Token = #tds_Token{content = TokenContent},
    TokenID = gen_random_id(),
    {ok, ok} = capi_handler_utils:service_call({tds_storage, 'PutToken', {TokenID, Token}}, Context),
    TokenID.

process_tokenized_card_data(Data, Context) ->
    UnwrappedPaymentTool = unwrap_card_data_token(Data, Context),
    CardData = encode_tokenized_card_data(UnwrappedPaymentTool),
    SessionData = encode_tokenized_session_data(UnwrappedPaymentTool),
    BankInfo = get_bank_info(maps:get(pan, CardData), Context),
    case capi_bankcard:validate(CardData, SessionData, BankInfo, Context) of
        ok ->
            {Token, SessionID} = put_card_data_to_cds(CardData, SessionData, Context),
            {BankCard, Deadline} = construct_tokenized_bank_card(Token, CardData, SessionData, UnwrappedPaymentTool),
            {Token, {bank_card, enrich_bank_card(BankCard, BankInfo)}, SessionID, Deadline};
        {error, Error} ->
            throw({ok, capi_handler_utils:validation_error(Error)})
    end.

unwrap_card_data_token(Data, Context) ->
    Call = {get_token_provider_service_name(Data), 'Unwrap', {encode_wrapped_payment_tool(Data)}},
    case capi_handler_utils:service_call(Call, Context) of
        {ok, Tool} ->
            Tool;
        {exception, #base_InvalidRequest{}} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Tokenized card data is invalid">>)})
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
    #paytool_provider_WrappedPaymentTool{
        request = encode_payment_request(Data),
        realm = RealmMode
    }.

encode_payment_request(#{<<"provider">> := <<"ApplePay">>} = Data) ->
    {apple, #paytool_provider_ApplePayRequest{
        merchant_id = maps:get(<<"merchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider">> := <<"GooglePay">>} = Data) ->
    {google, #paytool_provider_GooglePayRequest{
        gateway_merchant_id = maps:get(<<"gatewayMerchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider">> := <<"SamsungPay">>} = Data) ->
    {samsung, #paytool_provider_SamsungPayRequest{
        service_id = genlib_map:get(<<"serviceID">>, Data),
        reference_id = genlib_map:get(<<"referenceID">>, Data)
    }};
encode_payment_request(#{<<"provider">> := <<"YandexPay">>} = Data) ->
    {yandex, #paytool_provider_YandexPayRequest{
        gateway_merchant_id = maps:get(<<"gatewayMerchantID">>, Data),
        payment_token = capi_handler_encoder:encode_content(json, maps:get(<<"paymentToken">>, Data))
    }}.

construct_tokenized_bank_card(
    Token,
    CardData,
    SessionData,
    #paytool_provider_UnwrappedPaymentTool{
        card_info = #paytool_provider_CardInfo{
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
    BankCard1 = #domain_BankCard{
        token = Token,
        bin = get_tokenized_bin(PaymentData),
        last_digits = get_tokenized_pan(Last4, PaymentData),
        payment_token = #domain_BankCardTokenServiceRef{id = TokenServiceID},
        is_cvv_empty = set_is_empty_cvv(TokenizationMethod, undef_cvv(SessionData)),
        exp_date = encode_exp_date(maps:get(exp_date, CardData)),
        cardholder_name = maps:get(cardholder, CardData, undefined),
        tokenization_method = TokenizationMethod
    },
    BankCard2 = add_metadata(NS, ProviderMetadata, BankCard1),
    Deadline = capi_utils:deadline_from_binary(ValidUntil),
    {BankCard2, Deadline}.

get_tokenized_bin({card, #paytool_provider_Card{pan = PAN}}) ->
    get_first6(PAN);
get_tokenized_bin({tokenized_card, _}) ->
    <<>>.

% Prefer to get last4 from the PAN itself rather than using the one from the adapter
% On the other hand, getting a DPAN and no last4 from the adapter is unsupported
get_tokenized_pan(_Last4, {card, #paytool_provider_Card{pan = PAN}}) ->
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
set_is_empty_cvv(none, IsEmpty) ->
    IsEmpty;
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
    TokenServices = genlib_app:env(?APP, bank_card_token_service_mapping),
    maps:get(TokenProvider, TokenServices).

%% TODO
%% All this stuff deserves its own module I believe. These super-long names are quite strong hints.
-define(PAYMENT_TOOL_PROVIDER_META_NS, <<"com.rbkmoney.payment-tool-provider">>).

extract_payment_tool_provider_metadata({_Provider, Details}) ->
    {?PAYMENT_TOOL_PROVIDER_META_NS, #{
        <<"details">> => extract_payment_details_metadata(Details)
    }}.

extract_payment_details_metadata(#paytool_provider_ApplePayDetails{
    transaction_id = TransactionID,
    device_id = DeviceID
}) ->
    #{
        <<"transaction_id">> => TransactionID,
        <<"device_id">> => DeviceID
    };
extract_payment_details_metadata(#paytool_provider_SamsungPayDetails{
    device_id = DeviceID
}) ->
    #{
        <<"device_id">> => DeviceID
    };
extract_payment_details_metadata(#paytool_provider_GooglePayDetails{
    message_id = MessageID
}) ->
    #{
        <<"message_id">> => MessageID
    };
extract_payment_details_metadata(#paytool_provider_YandexPayDetails{
    message_id = MessageID
}) ->
    #{
        <<"message_id">> => MessageID
    }.

%%

encode_tokenized_card_data(#paytool_provider_UnwrappedPaymentTool{
    payment_data =
        {tokenized_card, #paytool_provider_TokenizedCard{
            dpan = DPAN,
            exp_date = #paytool_provider_ExpDate{
                month = Month,
                year = Year
            }
        }},
    card_info = #paytool_provider_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    ExpDate = {Month, Year},
    genlib_map:compact(#{
        pan => DPAN,
        cardholder => CardholderName,
        exp_date => ExpDate
    });
encode_tokenized_card_data(#paytool_provider_UnwrappedPaymentTool{
    payment_data =
        {card, #paytool_provider_Card{
            pan = PAN,
            exp_date = #paytool_provider_ExpDate{
                month = Month,
                year = Year
            }
        }},
    card_info = #paytool_provider_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    ExpDate = {Month, Year},
    genlib_map:compact(#{
        pan => PAN,
        cardholder => CardholderName,
        exp_date => ExpDate
    }).

encode_tokenized_session_data(#paytool_provider_UnwrappedPaymentTool{
    payment_data =
        {tokenized_card, #paytool_provider_TokenizedCard{
            auth_data =
                {auth_3ds, #paytool_provider_Auth3DS{
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
encode_tokenized_session_data(#paytool_provider_UnwrappedPaymentTool{
    payment_data = {card, #paytool_provider_Card{}}
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
    {crypto_currency, capi_handler_encoder:encode_crypto_currency(CryptoCurrency)}.

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
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Bad phone format.">>)});
        {exception, #mnp_OperatorNotFound{}} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Operator not found.">>)})
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
        operator = encode_mobile_commerce_operator(Operator),
        phone = #domain_MobilePhone{cc = Cc, ctn = Ctn}
    }.

%%

encode_resource_metadata(Metadata) ->
    Namespace = genlib_app:env(?APP, payment_resource_metadata_namespace, ?DEFAULT_RESOURCE_METADATA_NAMESPACE),
    #{genlib:to_binary(Namespace) => capi_json_marshalling:marshal(Metadata)}.

encode_mobile_commerce_operator(Operator) ->
    OperatorID = maps:get(Operator, genlib_app:env(?APP, mobile_commerce_mapping, #{})),
    #domain_MobileOperatorRef{id = OperatorID}.

-spec get_mobile_operators() -> [mobile_operator()].
get_mobile_operators() ->
    [mts, beeline, megafone, tele2, yota].

%%

get_bank_info(CardDataPan, Context) ->
    case capi_bankcard:lookup_bank_info(CardDataPan, Context) of
        {ok, BankInfo} ->
            BankInfo;
        {error, _Reason} ->
            throw({ok, capi_handler_utils:logic_error(invalidRequest, <<"Unsupported card">>)})
    end.

add_metadata(NS, Metadata, #domain_BankCard{metadata = Acc = #{}} = BankCard) ->
    undefined = maps:get(NS, Acc, undefined),
    BankCard#domain_BankCard{
        metadata = Acc#{NS => capi_msgp_marshalling:marshal(Metadata)}
    };
add_metadata(NS, Metadata, #domain_BankCard{metadata = undefined} = BankCard) ->
    add_metadata(NS, Metadata, BankCard#domain_BankCard{metadata = #{}}).

encode_payment_service_ref(Provider) ->
    #domain_PaymentServiceRef{id = Provider}.

validate_payment_service_ref(#domain_PaymentServiceRef{} = Ref) ->
    dmt_client:try_checkout_data({payment_service, Ref}).
