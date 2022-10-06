-module(capi_handler_utils).

-export([logic_error/2]).
-export([validation_error/1]).
-export([server_error/1]).

-export([service_call/2]).

-export([get_auth_context/1]).

-export([get_party_id/1]).

-export([merge_and_compact/2]).

-export([wrap_payment_session/2]).

-export([determine_peer/1]).
-export([determine_peer_from_header/2]).

-type processing_context() :: capi_handler:processing_context().
-type response() :: capi_handler:response().

-spec logic_error
    (term(), io_lib:chars() | binary()) -> response();
    (term(), {binary(), binary() | undefined}) -> response().
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
validation_msg({length, _, _}, Key) ->
    <<"Invalid ", (key_to_binary(Key))/binary, " length">>;
validation_msg({ranges, _}, Key) ->
    <<"Invalid ", (key_to_binary(Key))/binary, " length">>.

key_to_binary(card_number) ->
    <<"cardNumber">>;
key_to_binary(exp_date) ->
    <<"expDate">>;
key_to_binary(cardholder) ->
    <<"cardHolder">>;
key_to_binary(cvc) ->
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
    capi_auth:get_subject_id(get_auth_context(Context)).

%%%

-spec service_call({atom(), atom(), tuple()}, processing_context()) -> woody:result().
service_call({ServiceName, Function, Args}, #{woody_context := WoodyContext}) ->
    capi_woody_client:call_service(ServiceName, Function, Args, WoodyContext).

-spec get_auth_context(processing_context()) -> any().
get_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

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

-spec determine_peer(cowboy_req:req()) ->
    {ok, #{ip_address := inet:ip_address(), port_number => inet:port_number()}}
    | {error, einval | malformed}.

determine_peer(Req) ->
    Peer = cowboy_req:peer(Req),
    Value = cowboy_req:header(<<"x-forwarded-for">>, Req),
    determine_peer_from_header(Value, Peer).

-spec determine_peer_from_header(undefined | binary(), {inet:ip_address(), inet:port_number()}) ->
    {ok, #{ip_address := inet:ip_address(), port_number => inet:port_number()}}
    | {error, einval | malformed}.
determine_peer_from_header(undefined, {IP, Port}) ->
    % undefined, assuming no proxies were involved
    {ok, #{ip_address => IP, port_number => Port}};
determine_peer_from_header(Value, _Peer) when is_binary(Value) ->
    ClientPeer = string:strip(binary_to_list(Value)),
    case string:lexemes(ClientPeer, ",") of
        [ClientIP | _Proxies] ->
            case inet:parse_strict_address(ClientIP) of
                {ok, IP} ->
                    % ok
                    {ok, #{ip_address => IP}};
                Error ->
                    % unparseable ip address
                    Error
            end;
        _ ->
            % empty or malformed value
            {error, malformed}
    end.

%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec determine_peer_test_() -> [_TestGen].
determine_peer_test_() ->
    [
        ?_assertEqual(
            {ok, #{ip_address => {10, 10, 10, 10}}},
            determine_peer_from_header(<<"10.10.10.10">>, {{1, 1, 1, 1}, 1})
        ),
        ?_assertEqual(
            {error, malformed},
            determine_peer_from_header(<<",,,,">>, {{1, 1, 1, 1}, 1})
        ),
        ?_assertEqual(
            {ok, #{ip_address => {1, 1, 1, 1}}},
            determine_peer_from_header(<<"1.1.1.1,,, ,,,">>, {{1, 1, 1, 1}, 1})
        ),
        ?_assertEqual(
            {error, einval},
            determine_peer_from_header(<<"1.,1.,1.1,">>, {{1, 1, 1, 1}, 1})
        ),
        ?_assertEqual(
            {ok, #{ip_address => {17, 71, 0, 1}}},
            determine_peer_from_header(<<"17.71.0.1">>, {{1, 1, 1, 1}, 1})
        )
    ].

-endif.
