%%%
%%% Copyright 2019 RBKmoney
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
-module(capi_bankcard).

-include_lib("binbase_proto/include/binbase_binbase_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").

-define(META_NS, <<"com.rbkmoney.binbase">>).

-export([lookup_bank_info/2]).
-export([merge_data/3]).
-export([payment_system/1]).
-export([validation_env/0]).

-type bank_info() :: #{
    payment_system := payment_system(),
    payment_system_deprecated := dmsl_domain_thrift:'LegacyBankCardPaymentSystem'(),
    bank_name := binary(),
    issuer_country := dmsl_domain_thrift:'CountryCode'() | undefined,
    category := binary() | undefined,
    metadata := {_MetaNS :: binary(), map()}
}.

-type lookup_error() ::
    notfound
    | {invalid,
        payment_system
        | issuer_country}.

-type card_data() :: cds_proto_storage_thrift:'PutCardData'().
-type extra_card_data() :: #{
    cardholder => binary() | undefined,
    exp_data => {integer(), integer()}
}.

-type session_data() :: cds_proto_storage_thrift:'SessionData'().
-type payment_system() :: bankcard_validator:payment_system().
-type reason() :: bankcard_validator:reason().

-type validation_env() :: bankcard_validator:validation_env().

-export_type([session_data/0]).
-export_type([payment_system/0]).
-export_type([reason/0]).
-export_type([validation_env/0]).

-spec validation_env() -> validation_env().
validation_env() ->
    DefaultEnv = #{now => calendar:universal_time()},
    Env = genlib_app:env(capi_pcidss, validation, #{}),
    maps:merge(DefaultEnv, Env).

-spec lookup_bank_info(_PAN :: binary(), capi_handler:processing_context()) ->
    {ok, bank_info()} | {error, lookup_error()}.
lookup_bank_info(PAN, Context) ->
    Call = {binbase, 'Lookup', {PAN, {'last', #binbase_Last{}}}},
    case capi_handler_utils:service_call(Call, Context) of
        {ok, BinData} ->
            decode_bank_info(BinData);
        {exception, #'binbase_BinNotFound'{}} ->
            {error, notfound}
    end.

decode_bank_info(#'binbase_ResponseData'{bin_data = BinData, version = Version}) ->
    try
        {ok, #{
            payment_system => BinData#binbase_BinData.payment_system,
            payment_system_deprecated => decode_payment_system(BinData#binbase_BinData.payment_system),
            bank_name => BinData#binbase_BinData.bank_name,
            issuer_country => decode_issuer_country(BinData#binbase_BinData.iso_country_code),
            category => BinData#binbase_BinData.category,
            metadata => {?META_NS, #{<<"version">> => Version}}
        }}
    catch
        {invalid, What} ->
            {error, {invalid, What}}
    end.

-define(invalid(What), erlang:throw({invalid, What})).

%% Payment system mapping
%%
%% List of known payment systems as of https://github.com/rbkmoney/binbase-data/commit/dcfabb1e.
%% Please keep in sorted order.
-spec decode_payment_system(binary()) -> dmsl_domain_thrift:'LegacyBankCardPaymentSystem'().
decode_payment_system(<<"AMERICAN EXPRESS">>) ->
    amex;
decode_payment_system(<<"AMERICAN EXPRESS COMPANY">>) ->
    amex;
decode_payment_system(<<"ATM CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"ATOS PRIVATE LABEL">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"AURA">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"BANKCARD(INACTIVE)">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"BP FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"CABAL">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"CARNET">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"CHINA UNION PAY">>) ->
    unionpay;
decode_payment_system(<<"CHJONES FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"CIRRUS">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"COMPROCARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"DANKORT">>) ->
    dankort;
decode_payment_system(<<"DFS/DCI">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"DINACARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"DINERS CLUB INTERNATIONAL">>) ->
    dinersclub;
decode_payment_system(<<"DISCOVER">>) ->
    discover;
decode_payment_system(<<"DUET">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"EBT">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"EFTPOS">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"ELO">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"ELO/DISCOVER">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"EUROSHELL FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"GE CAPITAL">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"GLOBAL BC">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"HIPERCARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"HRG STORE CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"JCB">>) ->
    jcb;
decode_payment_system(<<"LOCAL BRAND">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"LOCAL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"LOYALTY CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"LUKOIL FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"MAESTRO">>) ->
    maestro;
decode_payment_system(<<"MASTERCARD">>) ->
    mastercard;
decode_payment_system(<<"NEWDAY">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"NSPK MIR">>) ->
    nspkmir;
decode_payment_system(<<"OUROCARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"PAYPAL">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"PHH FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"PRIVATE LABEL">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"PRIVATE LABEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"PROSTIR">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"RBS GIFT CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"RED FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"RED LIQUID FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"RUPAY">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"SBERCARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"SODEXO">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"STAR REWARDS">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"TROY">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"UATP">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"UK FUEL CARD">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"UNIONPAY">>) ->
    unionpay;
decode_payment_system(<<"VISA">>) ->
    visa;
decode_payment_system(<<"DUMMY">>) ->
    dummy;
% supposedly 🤔
decode_payment_system(<<"VISA/DANKORT">>) ->
    visa;
decode_payment_system(<<"VPAY">>) ->
    ?invalid(payment_system);
decode_payment_system(<<"UZCARD">>) ->
    uzcard;
decode_payment_system(PaymentSystem) ->
    _ = logger:warning("unknown payment system encountered: ~s", [PaymentSystem]),
    ?invalid(payment_system).

%% Residence mapping
%%
-spec decode_issuer_country(binary() | undefined) -> dmsl_domain_thrift:'CountryCode'() | undefined.
decode_issuer_country(CountryCode) when is_binary(CountryCode) ->
    try
        {enum, Variants} = dmsl_domain_thrift:enum_info('CountryCode'),
        Variant = erlang:list_to_existing_atom(string:to_lower(erlang:binary_to_list(CountryCode))),
        element(1, lists:keyfind(Variant, 1, Variants))
    catch
        error:badarg ->
            _ = logger:warning("unknown residence encountered: ~s", [CountryCode]),
            ?invalid(issuer_country)
    end;
decode_issuer_country(undefined) ->
    undefined.

-spec payment_system(bank_info()) -> payment_system().
payment_system(BankInfo) ->
    maps:get(payment_system, BankInfo).

-spec merge_data(card_data(), extra_card_data(), session_data() | undefined) -> bankcard_validator:bankcard_data().
merge_data(CardData, ExtraCardData, undefined) ->
    maps:merge(convert_card_data(CardData), ExtraCardData);
merge_data(CardData, ExtraCardData, #cds_SessionData{auth_data = AuthData}) ->
    CVC = get_cvc_from_session_data(AuthData),
    CardDataMap0 = convert_card_data(CardData),
    CardDataMap1 = maps:merge(CardDataMap0, ExtraCardData),
    CardDataMap1#{cvc => maybe_undefined(CVC)}.

get_cvc_from_session_data({card_security_code, AuthData}) ->
    AuthData#cds_CardSecurityCode.value;
get_cvc_from_session_data(_) ->
    undefined.

%%

convert_card_data(CardData) ->
    #cds_PutCardData{
        pan = PAN
    } = CardData,
    #{
        card_number => PAN
    }.

maybe_undefined(<<>>) ->
    undefined;
maybe_undefined(CVC) ->
    CVC.
