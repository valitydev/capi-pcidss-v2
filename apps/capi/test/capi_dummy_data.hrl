-define(STRING, <<"TEST">>).
-define(INTEGER, 10000).
-define(TIMESTAMP, <<"2016-03-22T06:12:27Z">>).

-define(BANK_CARD, #domain_BankCard{
    token = ?STRING,
    payment_system = visa,
    bin = <<"411111">>,
    masked_pan = <<"411111******1111">>
}).

-define(BINBASE_LOOKUP_RESULT, ?BINBASE_LOOKUP_RESULT(<<"MASTERCARD">>)).
-define(BINBASE_LOOKUP_RESULT(PaymentSystem), #'binbase_ResponseData'{
    bin_data = #'binbase_BinData' {
        payment_system = PaymentSystem,
        bank_name = ?STRING,
        iso_country_code = <<"KAZ">>,
        card_type = debit
    },
    version = ?INTEGER
}).

-define(PUT_CARD_RESULT, #'PutCardResult'{
    bank_card = ?BANK_CARD
}).

-define(UNWRAPPED_PAYMENT_TOOL(Details),
    ?UNWRAPPED_PAYMENT_TOOL(
        Details,
        {tokenized_card, #paytoolprv_TokenizedCard{
            dpan = ?STRING,
            exp_date = #paytoolprv_ExpDate{
                month = 10,
                year = 2018
            },
            auth_data = {auth_3ds, #paytoolprv_Auth3DS{
                cryptogram = ?STRING,
                eci = ?STRING
            }}
        }}
    )
).
-define(UNWRAPPED_PAYMENT_TOOL(Details, PaymentData), #paytoolprv_UnwrappedPaymentTool{
    payment_data = PaymentData,
    card_info = #paytoolprv_CardInfo{
        display_name = <<"Visa 1234">>,
        cardholder_name = ?STRING,
        last_4_digits = <<"1234">>,
        card_class = debit,
        payment_system = mastercard
    },
    details = Details
}).

-define(PUT_CARD_DATA_RESULT, #'PutCardResult'{
    bank_card = ?BANK_CARD,
    session_id = ?STRING
}).

-define(APPLE_PAY_DETAILS, {apple, #paytoolprv_ApplePayDetails{
    transaction_id = ?STRING,
    amount = ?INTEGER,
    currency_numeric_code = 643,
    device_id = ?STRING
}}).

-define(GOOGLE_PAY_DETAILS, {google, #paytoolprv_GooglePayDetails{
    message_id = ?STRING,
    message_expiration = ?TIMESTAMP
}}).
