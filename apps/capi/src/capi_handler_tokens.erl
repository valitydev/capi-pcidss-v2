-module(capi_handler_tokens).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").
-include_lib("tds_proto/include/tds_proto_storage_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("moneypenny/include/moneypenny_mnp_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_restriction_thrift.hrl").

-behaviour(capi_handler).

-export([prepare/3]).

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
    ClientInfo = maps:get(<<"clientInfo">>, Params),

    ReplacementIP = get_replacement_ip(ClientInfo),

    Authorize = fun() ->
        Prototypes = [
            {operation, #{id => OperationID, party => PartyID}},
            {tokens, #{replacement_ip => ReplacementIP}}
        ],

        IpReplacementAllowedOld = ip_replacement_allowed_legacy(Context),

        BouncerResult = capi_auth:authorize_operation(Prototypes, Context, Req),

        Result =
            case handle_auth_result(BouncerResult) of
                allowed when ReplacementIP /= undefined, not IpReplacementAllowedOld ->
                    logger:warning(
                        "Request fully allowed, yet IP replacement was forbidden " ++
                            "in old version: restricting replacement"
                    ),
                    {restricted, #brstn_Restrictions{
                        capi = #brstn_RestrictionsCommonAPI{
                            ip_replacement_forbidden = true
                        }
                    }};
                {restricted, ip_replacement_forbidden} when ReplacementIP /= undefined, IpReplacementAllowedOld ->
                    logger:warning(
                        "Request was restricted with IP replacement, yet it " ++
                            " was allowed in old version: allowing request and replacement"
                    ),
                    allowed;
                _ ->
                    BouncerResult
            end,

        {ok, Result}
    end,
    Process = fun(Resolution) ->
        process_request(OperationID, Req, Context, Resolution)
    end,
    {ok, #{authorize => Authorize, process => Process}};
prepare(_OperationID, _Req, _Context) ->
    {error, noimpl}.

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
        case handle_auth_result(Resolution) of
            {restricted, ip_replacement_forbidden} ->
                prepare_requester_ip(Context);
            allowed ->
                case get_replacement_ip(ClientInfo0) of
                    undefined -> prepare_requester_ip(Context);
                    IP -> IP
                end
        end,

    ClientInfo = maps:put(<<"ip">>, ClientIP, ClientInfo0),
    try
        ClientUrl = get_client_url(ClientInfo),
        ok = validate_url(ClientUrl),
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
        PaymentResource = #domain_DisposablePaymentResource{
            payment_tool = PaymentTool,
            payment_session_id = PaymentSessionID,
            client_info = capi_handler_encoder:encode_client_info(ClientInfo)
        },
        % Ограничиваем время жизни платежного токена временем жизни платежного инструмента.
        % Если время жизни платежного инструмента не задано, то интервалом заданным в настройках.
        TokenDeadline =
            case {PaymentToolDeadline, payment_tool_token_deadline()} of
                {ToolDeadline, DefaultDeadline} when is_atom(ToolDeadline) -> DefaultDeadline;
                {ToolDeadline, DefaultDeadline} when ToolDeadline < DefaultDeadline -> ToolDeadline;
                {_, DefaultDeadline} -> DefaultDeadline
            end,
        EncryptedToken = capi_crypto:create_encrypted_payment_tool_token(PaymentTool, TokenDeadline),
        {ok,
            {201, #{},
                capi_handler_decoder:decode_disposable_payment_resource(
                    PaymentResource,
                    EncryptedToken,
                    TokenDeadline
                )}}
    catch
        Result -> Result
    end.

%%

-spec payment_tool_token_deadline() -> capi_utils:deadline().
payment_tool_token_deadline() ->
    TokenLifetime =
        case genlib_app:env(capi_pcidss, payment_tool_token_lifetime, ?DEFAULT_PAYMENT_TOOL_TOKEN_LIFETIME) of
            Value when is_integer(Value) ->
                Value;
            Value ->
                case capi_utils:parse_lifetime(Value) of
                    {ok, Lifetime} ->
                        Lifetime;
                    Error ->
                        erlang:error(Error, [Value])
                end
        end,
    capi_utils:deadline_from_timeout(TokenLifetime).

%%

ip_replacement_allowed_legacy(Context) ->
    LegacyContext = capi_auth:get_legacy_context(capi_auth:extract_auth_context(Context)),

    case uac_authorizer_jwt:get_claim(<<"ip_replacement_allowed">>, LegacyContext, false) of
        NonBull when not is_boolean(NonBull) ->
            _ = logger:notice("Unexpected ip_replacement_allowed value: ~p", [NonBull]),
            NonBull;
        Bool ->
            Bool
    end.

handle_auth_result(allowed) ->
    allowed;
handle_auth_result(forbidden) ->
    forbidden;
handle_auth_result({forbidden, _Reason} = Forbidden) ->
    Forbidden;
handle_auth_result({restricted, #brstn_Restrictions{capi = CAPI}}) ->
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
    maps:get(<<"url">>, ClientInfo, undefined).

validate_url(undefined) ->
    ok;
validate_url(Url) ->
    case capi_utils:validate_url(Url) of
        ok ->
            ok;
        {error, Error, Description} ->
            _ = logger:notice("Unexpected client info url reason: ~p ~p", [Error, Description]),
            throw({ok, logic_error(invalidRequest, <<"Client info url is invalid">>)})
    end.

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

%%

process_payment_terminal_data(Data) ->
    PaymentTerminal = #domain_PaymentTerminal{
        terminal_type_deprecated = binary_to_existing_atom(genlib_map:get(<<"provider">>, Data), utf8)
    },
    {payment_terminal, PaymentTerminal}.

process_digital_wallet_data(Data, IdempotentParams, Context) ->
    TokenID = maybe_store_token_in_tds(Data, IdempotentParams, Context),
    DigitalWallet =
        case Data of
            #{<<"digitalWalletType">> := <<"DigitalWalletQIWI">>} ->
                #domain_DigitalWallet{
                    provider_deprecated = qiwi,
                    id = maps:get(<<"phoneNumber">>, Data),
                    token = TokenID
                }
        end,
    {digital_wallet, DigitalWallet}.

maybe_store_token_in_tds(#{<<"accessToken">> := TokenContent}, IdempotentParams, Context) ->
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

encode_wrapped_payment_tool(Data) ->
    #paytoolprv_WrappedPaymentTool{
        request = encode_payment_request(Data)
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
            payment_system_deprecated = PaymentSystem,
            last_4_digits = Last4
        },
        payment_data = PaymentData,
        details = PaymentDetails,
        valid_until = ValidUntil
    }
) ->
    TokenProvider = get_payment_token_provider(PaymentDetails, PaymentData),
    {NS, ProviderMetadata} = extract_payment_tool_provider_metadata(PaymentDetails),
    BankCard1 = BankCard#domain_BankCard{
        bin = get_tokenized_bin(PaymentData),
        payment_system_deprecated = PaymentSystem,
        last_digits = get_tokenized_pan(Last4, PaymentData),
        token_provider_deprecated = TokenProvider,
        is_cvv_empty = set_is_empty_cvv(TokenProvider, BankCard),
        exp_date = encode_exp_date(genlib_map:get(exp_date, ExtraCardData)),
        cardholder_name = genlib_map:get(cardholder, ExtraCardData)
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

% Do not drop is_cvv_empty flag for tokenized bank cards which looks like
% simple bank card. This prevent wrong routing decisions in hellgate
% when cvv is empty, but is_cvv_empty = undefined, which forces routing to bypass
% restrictions and crash adapter. This situation is
% only applicable for GooglePay with tokenized bank card via browser.
set_is_empty_cvv(undefined, BankCard) ->
    BankCard#domain_BankCard.is_cvv_empty;
set_is_empty_cvv(_, _) ->
    undefined.

get_payment_token_provider({yandex, _}, _) ->
    % TODO
    % Infamous Yandex.Pay is exempt from the following consideration, because we need that. And because
    % dropping following reclassification is too dangerous because of domain config complexity. I really
    % hope this hyperkludge won't live long.
    yandexpay;
get_payment_token_provider(_PaymentDetails, {card, _}) ->
    % TODO
    % We deliberately hide the fact that we've got that payment tool from the likes of Google Chrome browser
    % in order to make our internal services think of it as if it was good ol' plain bank card. Without a
    % CVV though. A better solution would be to distinguish between a _token provider_ and an _origin_.
    undefined;
get_payment_token_provider({apple, _}, _PaymentData) ->
    applepay;
get_payment_token_provider({google, _}, _PaymentData) ->
    googlepay;
get_payment_token_provider({samsung, _}, _PaymentData) ->
    samsungpay.

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
    {crypto_currency, capi_handler_decoder:convert_crypto_currency_from_swag(CryptoCurrency)}.

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
