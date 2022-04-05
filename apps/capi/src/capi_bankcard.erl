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
