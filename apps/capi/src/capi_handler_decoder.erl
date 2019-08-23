-module(capi_handler_decoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([decode_disposable_payment_resource/1]).

-export([decode_last_digits/1]).
-export([decode_masked_pan/2]).

-export([convert_crypto_currency_to_swag/1]).
-export([convert_crypto_currency_from_swag/1]).

-export_type([decode_data/0]).

-type decode_data() :: #{binary() => term()}.

decode_payment_tool_token({bank_card, BankCard}) ->
    decode_bank_card(BankCard);
decode_payment_tool_token({payment_terminal, PaymentTerminal}) ->
    decode_payment_terminal(PaymentTerminal);
decode_payment_tool_token({digital_wallet, DigitalWallet}) ->
    decode_digital_wallet(DigitalWallet);
decode_payment_tool_token({crypto_currency, CryptoCurrency}) ->
    decode_crypto_wallet(CryptoCurrency);
decode_payment_tool_token({mobile_commerce, MobileCommerce}) ->
    decode_mobile_commerce(MobileCommerce).

decode_bank_card(#domain_BankCard{
    'token'          = Token,
    'payment_system' = PaymentSystem,
    'bin'            = Bin,
    'masked_pan'     = MaskedPan,
    'token_provider' = TokenProvider,
    'issuer_country' = IssuerCountry,
    'bank_name'      = BankName,
    'metadata'       = Metadata,
    'is_cvv_empty'   = IsCVVEmpty
}) ->
    capi_utils:map_to_base64url(genlib_map:compact(#{
        <<"type"          >> => <<"bank_card">>,
        <<"token"         >> => Token,
        <<"payment_system">> => PaymentSystem,
        <<"bin"           >> => Bin,
        <<"masked_pan"    >> => MaskedPan,
        <<"token_provider">> => TokenProvider,
        <<"issuer_country">> => IssuerCountry,
        <<"bank_name"     >> => BankName,
        <<"metadata"      >> => decode_bank_card_metadata(Metadata),
        <<"is_cvv_empty"  >> => decode_bank_card_cvv_flag(IsCVVEmpty)
    })).

decode_bank_card_cvv_flag(undefined) ->
    undefined;
decode_bank_card_cvv_flag(CVVFlag) when is_atom(CVVFlag) ->
    erlang:atom_to_binary(CVVFlag, utf8).

decode_bank_card_metadata(undefined) ->
    undefined;
decode_bank_card_metadata(Meta) ->
    maps:map(fun(_, Data) -> capi_msgp_marshalling:unmarshal(Data) end, Meta).

decode_payment_terminal(#domain_PaymentTerminal{
    terminal_type = Type
}) ->
    capi_utils:map_to_base64url(#{
        <<"type"         >> => <<"payment_terminal">>,
        <<"terminal_type">> => Type
    }).

decode_digital_wallet(#domain_DigitalWallet{
    provider = Provider,
    id = ID,
    token = undefined
}) ->
    capi_utils:map_to_base64url(#{
        <<"type"    >> => <<"digital_wallet">>,
        <<"provider">> => atom_to_binary(Provider, utf8),
        <<"id"      >> => ID
    });
decode_digital_wallet(#domain_DigitalWallet{
    provider = Provider,
    id = ID,
    token = Token
}) ->
    capi_utils:map_to_base64url(#{
        <<"type"    >> => <<"digital_wallet">>,
        <<"provider">> => atom_to_binary(Provider, utf8),
        <<"id"      >> => ID,
        <<"token"   >> => Token
    }).

decode_crypto_wallet(CryptoCurrency) ->
    capi_utils:map_to_base64url(#{
        <<"type"           >> => <<"crypto_wallet">>,
        <<"crypto_currency">> => convert_crypto_currency_to_swag(CryptoCurrency)
    }).

decode_mobile_commerce(MobileCommerce) ->
    #domain_MobileCommerce{
        operator = Operator,
        phone = Phone
    } = MobileCommerce,
    capi_utils:map_to_base64url(#{
        <<"type"       >> => <<"mobile_commerce">>,
        <<"phoneNumber">> => decode_mobile_phone(Phone),
        <<"operator">>    => Operator
    }).

decode_payment_tool_details({bank_card, V}) ->
    decode_bank_card_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsBankCard">>});
decode_payment_tool_details({payment_terminal, V}) ->
    decode_payment_terminal_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsPaymentTerminal">>});
decode_payment_tool_details({digital_wallet, V}) ->
    decode_digital_wallet_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsDigitalWallet">>});
decode_payment_tool_details({crypto_currency, CryptoCurrency}) ->
    #{
        <<"detailsType">> => <<"PaymentToolDetailsCryptoWallet">>,
        <<"cryptoCurrency">> => convert_crypto_currency_to_swag(CryptoCurrency)
    };
decode_payment_tool_details({mobile_commerce, MobileCommerce}) ->
    #domain_MobileCommerce{
        phone = Phone
    } = MobileCommerce,
    PhoneNumber = gen_phone_number(decode_mobile_phone(Phone)),
    #{
        <<"detailsType">> => <<"PaymentToolDetailsMobileCommerce">>,
        <<"phoneNumber">> => mask_phone_number(PhoneNumber)
    }.

decode_bank_card_details(BankCard, V) ->
    LastDigits = decode_last_digits(BankCard#domain_BankCard.masked_pan),
    Bin = BankCard#domain_BankCard.bin,
    capi_handler_utils:merge_and_compact(V, #{
        <<"last4">>          => LastDigits,
        <<"first6">>         => Bin,
        <<"cardNumberMask">> => decode_masked_pan(Bin, LastDigits),
        <<"paymentSystem" >> => genlib:to_binary(BankCard#domain_BankCard.payment_system),
        <<"tokenProvider" >> => decode_token_provider(BankCard#domain_BankCard.token_provider)
    }).

decode_token_provider(Provider) when Provider /= undefined ->
    genlib:to_binary(Provider);
decode_token_provider(undefined) ->
    undefined.

decode_payment_terminal_details(#domain_PaymentTerminal{terminal_type = Type}, V) ->
    V#{
        <<"provider">> => genlib:to_binary(Type)
    }.

decode_digital_wallet_details(#domain_DigitalWallet{provider = qiwi, id = ID}, V) ->
    V#{
        <<"digitalWalletDetailsType">> => <<"DigitalWalletDetailsQIWI">>,
        <<"phoneNumberMask"         >> => mask_phone_number(ID)
    }.

mask_phone_number(PhoneNumber) ->
    genlib_string:redact(PhoneNumber, <<"^\\+\\d(\\d{1,10}?)\\d{2,4}$">>).

-spec decode_disposable_payment_resource(capi_handler_encoder:encode_data()) ->
    decode_data().

decode_disposable_payment_resource(Resource) ->
    #domain_DisposablePaymentResource{payment_tool = PaymentTool, payment_session_id = SessionID} = Resource,
    ClientInfo = decode_client_info(Resource#domain_DisposablePaymentResource.client_info),
    #{
        <<"paymentToolToken"  >> => decode_payment_tool_token(PaymentTool),
        <<"paymentSession"    >> => capi_handler_utils:wrap_payment_session(ClientInfo, SessionID),
        <<"paymentToolDetails">> => decode_payment_tool_details(PaymentTool),
        <<"clientInfo"        >> => ClientInfo
    }.

decode_client_info(undefined) ->
    undefined;
decode_client_info(ClientInfo) ->
    #{
        <<"fingerprint">> => ClientInfo#domain_ClientInfo.fingerprint,
        <<"ip"         >> => ClientInfo#domain_ClientInfo.ip_address
    }.

%%

-define(PAN_LENGTH, 16).

-spec decode_masked_pan(binary() | undefined, binary()) ->
    binary().

decode_masked_pan(undefined, LastDigits) ->
    decode_masked_pan(<<>>, LastDigits);
decode_masked_pan(Bin, LastDigits) ->
    Mask = binary:copy(<<"*">>, ?PAN_LENGTH - byte_size(Bin) - byte_size(LastDigits)),
    <<Bin/binary, Mask/binary, LastDigits/binary>>.

-define(MASKED_PAN_MAX_LENGTH, 4).

-spec decode_last_digits(binary()) ->
    binary().

decode_last_digits(MaskedPan) when byte_size(MaskedPan) > ?MASKED_PAN_MAX_LENGTH ->
    binary:part(MaskedPan, {byte_size(MaskedPan), -?MASKED_PAN_MAX_LENGTH});
decode_last_digits(MaskedPan) ->
    MaskedPan.

-spec convert_crypto_currency_from_swag(binary()) -> atom().

convert_crypto_currency_from_swag(<<"bitcoinCash">>) ->
    bitcoin_cash;
convert_crypto_currency_from_swag(CryptoCurrency) when is_binary(CryptoCurrency) ->
    binary_to_existing_atom(CryptoCurrency, utf8).

-spec convert_crypto_currency_to_swag(atom()) -> binary().

convert_crypto_currency_to_swag(bitcoin_cash) ->
    <<"bitcoinCash">>;
convert_crypto_currency_to_swag(CryptoCurrency) when is_atom(CryptoCurrency) ->
    atom_to_binary(CryptoCurrency, utf8).

decode_mobile_phone(#domain_MobilePhone{cc = Cc, ctn = Ctn}) ->
    #{<<"cc">> => Cc, <<"ctn">> => Ctn}.

gen_phone_number(#{<<"cc">> := Cc, <<"ctn">> := Ctn}) ->
    <<"+", Cc/binary, Ctn/binary>>.
