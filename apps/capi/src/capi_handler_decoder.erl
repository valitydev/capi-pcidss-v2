-module(capi_handler_decoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([decode_disposable_payment_resource/3]).

-export([decode_last_digits/1]).
-export([decode_masked_pan/2]).

-export_type([decode_data/0]).

-type encrypted_token() :: capi_crypto:token().
-type decode_data() :: #{binary() => term()}.

decode_payment_tool_details({bank_card, V}) ->
    decode_bank_card_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsBankCard">>});
decode_payment_tool_details({payment_terminal, V}) ->
    decode_payment_terminal_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsPaymentTerminal">>});
decode_payment_tool_details({digital_wallet, V}) ->
    decode_digital_wallet_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsDigitalWallet">>});
decode_payment_tool_details({crypto_currency, V}) ->
    decode_crypto_currency_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsCryptoWallet">>});
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
        <<"paymentSystem">> => decode_payment_system_ref(BankCard#domain_BankCard.payment_system),
        <<"tokenProvider">> => decode_bank_card_service_token_ref(BankCard#domain_BankCard.payment_token)
    }).

get_bank_card_bin(<<>>) ->
    undefined;
get_bank_card_bin(Bin) ->
    Bin.

decode_payment_terminal_details(#domain_PaymentTerminal{payment_service = PaymentService}, V) ->
    V#{
        <<"provider">> => decode_payment_service_ref(PaymentService)
    }.

decode_digital_wallet_details(#domain_DigitalWallet{payment_service = PaymentService}, V) ->
    V#{
        <<"provider">> => decode_payment_service_ref(PaymentService)
    }.

decode_crypto_currency_details(#domain_CryptoCurrencyRef{id = ID}, V) ->
    V#{
        <<"cryptoCurrency">> => ID
    }.

decode_payment_service_ref(#domain_PaymentServiceRef{id = Provider}) ->
    Provider.

decode_payment_system_ref(#domain_PaymentSystemRef{id = ID}) ->
    ID.

decode_bank_card_service_token_ref(undefined) ->
    undefined;
decode_bank_card_service_token_ref(#domain_BankCardTokenServiceRef{id = ID}) ->
    ID.

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
    genlib_map:compact(#{
        <<"fingerprint">> => ClientInfo#domain_ClientInfo.fingerprint,
        <<"ip">> => ClientInfo#domain_ClientInfo.ip_address,
        <<"peer_ip">> => ClientInfo#domain_ClientInfo.peer_ip_address,
        <<"user_ip">> => ClientInfo#domain_ClientInfo.user_ip_address,
        <<"url">> => ClientInfo#domain_ClientInfo.url
    }).

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

decode_mobile_phone(#domain_MobilePhone{cc = Cc, ctn = Ctn}) ->
    #{<<"cc">> => Cc, <<"ctn">> => Ctn}.

gen_phone_number(#{<<"cc">> := Cc, <<"ctn">> := Ctn}) ->
    <<"+", Cc/binary, Ctn/binary>>.
