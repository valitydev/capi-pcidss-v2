-module(capi_handler_utils).

-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([logic_error/2]).
-export([validation_error/1]).
-export([server_error/1]).

-export([service_call/2]).

-export([get_auth_context/1]).
-export([get_extra_properties/1]).

-export([get_party_id/1]).

-export([merge_and_compact/2]).

-export([wrap_payment_session/2]).

-type processing_context() :: capi_handler:processing_context().
-type response() :: capi_handler:response().

-spec logic_error
    (term(), io_lib:chars() | binary()) -> response();
    (term(), {binary(), binary() | undefined}) -> response().
logic_error(externalIDConflict, {ID, undefined}) ->
    logic_error(externalIDConflict, {ID, <<"undefined">>});
logic_error(externalIDConflict, {ID, ExternalID}) ->
    Data = #{
        <<"externalID">> => ExternalID,
        <<"id">> => ID,
        <<"message">> => <<"This 'externalID' has been used by another request">>
    },
    create_error_resp(409, Data);
logic_error(externalIDConflict, ExternalID) ->
    Data = #{
        <<"externalID">> => ExternalID,
        <<"message">> => <<"This 'externalID' has been used by another request">>
    },
    create_error_resp(409, Data);
logic_error(Code, Message) ->
    Data = #{<<"code">> => genlib:to_binary(Code), <<"message">> => genlib:to_binary(Message)},
    create_error_resp(400, Data).

-spec validation_error(capi_bankcard:reason()) -> response().
validation_error(unrecognized) ->
    Data = #{
        <<"code">> => <<"invalidRequest">>,
        <<"message">> => <<"Unrecognized bank card issuer">>
    },
    create_error_resp(400, Data);
validation_error({invalid, K, C}) ->
    Data = #{
        <<"code">> => <<"invalidRequest">>,
        <<"message">> => validation_msg(C, K)
    },
    create_error_resp(400, Data).

validation_msg(expiration, _Key) ->
    <<"Invalid expiration date">>;
validation_msg(luhn, Key) ->
    <<"Invalid ", (key_to_binary(Key))/binary, " checksum">>;
validation_msg({length, _}, Key) ->
    <<"Invalid ", (key_to_binary(Key))/binary, " length">>.

key_to_binary(cardnumber) ->
    <<"cardNumber">>;
key_to_binary(exp_date) ->
    <<"expDate">>;
key_to_binary(cardholder) ->
    <<"cardHolder">>;
key_to_binary(cvv) ->
    <<"cvv">>.

create_error_resp(Code, Data) ->
    create_error_resp(Code, #{}, Data).

create_error_resp(Code, Headers, Data) ->
    {Code, Headers, Data}.

-spec server_error(integer()) -> {integer(), #{}, <<>>}.
server_error(Code) when Code >= 500 andalso Code < 600 ->
    {Code, #{}, <<>>}.

-spec get_party_id(processing_context()) -> binary().
get_party_id(Context) ->
    uac_authorizer_jwt:get_subject_id(get_auth_context(Context)).

%%%

-spec service_call({atom(), atom(), tuple()}, processing_context()) -> woody:result().
service_call({ServiceName, Function, Args}, #{woody_context := WoodyContext}) ->
    capi_woody_client:call_service(ServiceName, Function, Args, WoodyContext).

-spec get_auth_context(processing_context()) -> any().
get_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

-spec get_extra_properties(processing_context()) -> map().
get_extra_properties(Context) ->
    uac_authorizer_jwt:get_claims(get_auth_context(Context)).

%% Utils

-spec merge_and_compact(map(), map()) -> map().
merge_and_compact(M1, M2) ->
    genlib_map:compact(maps:merge(M1, M2)).

-spec wrap_payment_session(map(), binary()) -> binary().
wrap_payment_session(ClientInfo, PaymentSession) ->
    capi_utils:map_to_base64url(#{
        <<"clientInfo">> => ClientInfo,
        <<"paymentSession">> => PaymentSession
    }).
