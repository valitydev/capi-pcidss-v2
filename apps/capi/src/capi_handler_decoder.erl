-module(capi_handler_decoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([decode_disposable_payment_resource/3]).

-export([decode_last_digits/1]).
-export([decode_masked_pan/2]).

-export([convert_crypto_currency_to_swag/1]).
-export([convert_crypto_currency_from_swag/1]).

-export_type([decode_data/0]).

-type encrypted_token() :: capi_crypto:encrypted_token().
-type decode_data() :: #{binary() => term()}.

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
    LastDigits = decode_last_digits(BankCard#domain_BankCard.last_digits),
    Bin = get_bank_card_bin(BankCard#domain_BankCard.bin),
    capi_handler_utils:merge_and_compact(V, #{
        <<"last4">> => LastDigits,
        <<"first6">> => Bin,
        <<"cardNumberMask">> => decode_masked_pan(Bin, LastDigits),
        <<"paymentSystem">> => genlib:to_binary(BankCard#domain_BankCard.payment_system_deprecated),
        <<"tokenProvider">> => decode_token_provider(BankCard#domain_BankCard.token_provider_deprecated)
    }).

get_bank_card_bin(<<>>) ->
    undefined;
get_bank_card_bin(Bin) ->
    Bin.

decode_token_provider(Provider) when Provider /= undefined ->
    genlib:to_binary(Provider);
decode_token_provider(undefined) ->
    undefined.

decode_payment_terminal_details(#domain_PaymentTerminal{terminal_type_deprecated = Type}, V) ->
    V#{
        <<"provider">> => genlib:to_binary(Type)
    }.

decode_digital_wallet_details(#domain_DigitalWallet{provider_deprecated = qiwi, id = ID}, V) ->
    V#{
        <<"digitalWalletDetailsType">> => <<"DigitalWalletDetailsQIWI">>,
        <<"phoneNumberMask">> => mask_phone_number(ID)
    }.

mask_phone_number(PhoneNumber) ->
    genlib_string:redact(PhoneNumber, <<"^\\+\\d(\\d{1,10}?)\\d{2,4}$">>).

-spec decode_disposable_payment_resource(
    capi_handler_encoder:encode_data(),
    encrypted_token(),
    capi_utils:deadline()
) -> decode_data().
decode_disposable_payment_resource(Resource, EncryptedToken, TokenValidUntil) ->
    #domain_DisposablePaymentResource{payment_tool = PaymentTool, payment_session_id = SessionID} = Resource,
    ClientInfo = decode_client_info(Resource#domain_DisposablePaymentResource.client_info),
    genlib_map:compact(#{
        <<"paymentToolToken">> => EncryptedToken,
        <<"paymentSession">> => capi_handler_utils:wrap_payment_session(ClientInfo, SessionID),
        <<"paymentToolDetails">> => decode_payment_tool_details(PaymentTool),
        <<"clientInfo">> => ClientInfo,
        <<"validUntil">> => decode_deadline(TokenValidUntil)
    }).

decode_deadline(undefined) ->
    undefined;
decode_deadline(Deadline) ->
    capi_utils:deadline_to_binary(Deadline).

decode_client_info(undefined) ->
    undefined;
decode_client_info(ClientInfo) ->
    #{
        <<"fingerprint">> => ClientInfo#domain_ClientInfo.fingerprint,
        <<"ip">> => ClientInfo#domain_ClientInfo.ip_address
    }.

%%

-define(PAN_LENGTH, 16).

-spec decode_masked_pan(binary() | undefined, binary()) -> binary().
decode_masked_pan(undefined, LastDigits) ->
    decode_masked_pan(<<>>, LastDigits);
decode_masked_pan(Bin, LastDigits) ->
    Mask = binary:copy(<<"*">>, ?PAN_LENGTH - byte_size(Bin) - byte_size(LastDigits)),
    <<Bin/binary, Mask/binary, LastDigits/binary>>.

-define(MASKED_PAN_MAX_LENGTH, 4).

-spec decode_last_digits(binary()) -> binary().
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
