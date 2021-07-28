-module(capi_utils).

-type deadline() :: woody:deadline().

-export_type([deadline/0]).

-export([deadline_to_binary/1]).
-export([deadline_from_binary/1]).
-export([deadline_from_timeout/1]).
-export([deadline_is_reached/1]).

-export([base64url_to_map/1]).
-export([map_to_base64url/1]).

-export([parse_deadline/1]).
-export([parse_lifetime/1]).

-export([to_universal_time/1]).

-export([maybe/2]).

% 1 min
-define(MAX_REQUEST_DEADLINE_TIME, timer:minutes(1)).

-spec deadline_to_binary(deadline()) -> binary() | undefined.
deadline_to_binary(undefined) ->
    undefined;
deadline_to_binary(Deadline) ->
    woody_deadline:to_binary(Deadline).

-spec deadline_from_binary(binary()) -> deadline() | undefined.
deadline_from_binary(undefined) ->
    undefined;
deadline_from_binary(Binary) ->
    woody_deadline:from_binary(Binary).

-spec deadline_from_timeout(timeout()) -> deadline().
deadline_from_timeout(Timeout) ->
    woody_deadline:from_timeout(Timeout).

-spec deadline_is_reached(deadline()) -> boolean().
deadline_is_reached(Deadline) ->
    woody_deadline:is_reached(Deadline).

-spec base64url_to_map(binary()) -> map() | no_return().
base64url_to_map(Base64) when is_binary(Base64) ->
    {ok, Json} = jose_base64url:decode(Base64),
    jsx:decode(Json, [return_maps]).

-spec map_to_base64url(map()) -> binary() | no_return().
map_to_base64url(Map) when is_map(Map) ->
    jose_base64url:encode(jsx:encode(Map)).

-spec to_universal_time(Timestamp :: binary()) -> TimestampUTC :: binary().
to_universal_time(Timestamp) ->
    Micros = genlib_rfc3339:parse(Timestamp, microsecond),
    genlib_rfc3339:format_relaxed(Micros, microsecond).

-spec parse_deadline
    (binary()) -> {ok, woody:deadline()} | {error, bad_deadline};
    (undefined) -> {ok, undefined}.
parse_deadline(undefined) ->
    {ok, undefined};
parse_deadline(DeadlineStr) ->
    Parsers = [
        fun try_parse_woody_default/1,
        fun try_parse_relative/1
    ],
    try_parse_deadline(DeadlineStr, Parsers).

-spec parse_lifetime
    (binary()) -> {ok, timeout()} | {error, bad_lifetime};
    (undefined) -> {error, bad_lifetime}.
parse_lifetime(undefined) ->
    {error, bad_lifetime};
parse_lifetime(Bin) ->
    %% lifetime string like '1ms', '30s', '2.6m' etc
    %% default unit - millisecond
    case re:split(Bin, <<"^(\\d+\\.\\d+|\\d+)([a-z]*)$">>) of
        [<<>>, NumberStr, <<>>, <<>>] ->
            {ok, genlib:to_int(NumberStr)};
        [<<>>, NumberStr, Unit, <<>>] ->
            Number = genlib:to_float(NumberStr),
            case unit_factor(Unit) of
                {ok, Factor} ->
                    {ok, erlang:round(Number * Factor)};
                {error, _Reason} ->
                    {error, bad_lifetime}
            end;
        _Other ->
            {error, bad_lifetime}
    end.

%%
%% Internals
%%
try_parse_deadline(_DeadlineStr, []) ->
    {error, bad_deadline};
try_parse_deadline(DeadlineStr, [P | Parsers]) ->
    case P(DeadlineStr) of
        {ok, _Deadline} = Result ->
            Result;
        {error, bad_deadline} ->
            try_parse_deadline(DeadlineStr, Parsers)
    end.

try_parse_woody_default(DeadlineStr) ->
    try
        Deadline = woody_deadline:from_binary(to_universal_time(DeadlineStr)),
        NewDeadline = clamp_max_request_deadline(woody_deadline:to_timeout(Deadline)),
        {ok, woody_deadline:from_timeout(NewDeadline)}
    catch
        error:{bad_deadline, _Reason} ->
            {error, bad_deadline};
        error:{badmatch, _} ->
            %% Catch badmatch from calendar:rfc3339_to_system_time/2
            {error, bad_deadline};
        error:deadline_reached ->
            {error, bad_deadline}
    end.

try_parse_relative(DeadlineStr) ->
    %% deadline string like '1ms', '30s', '2.6m' etc
    case re:split(DeadlineStr, <<"^(\\d+\\.\\d+|\\d+)([a-z]+)$">>) of
        [<<>>, NumberStr, Unit, <<>>] ->
            Number = genlib:to_float(NumberStr),
            try_parse_relative(Number, Unit);
        _Other ->
            {error, bad_deadline}
    end.

try_parse_relative(Number, Unit) ->
    case unit_factor(Unit) of
        {ok, Factor} ->
            Timeout = erlang:round(Number * Factor),
            {ok, woody_deadline:from_timeout(clamp_max_request_deadline(Timeout))};
        {error, _Reason} ->
            {error, bad_deadline}
    end.

unit_factor(<<"ms">>) ->
    {ok, 1};
unit_factor(<<"s">>) ->
    {ok, 1000};
unit_factor(<<"m">>) ->
    {ok, 1000 * 60};
unit_factor(_Other) ->
    {error, unknown_unit}.

clamp_max_request_deadline(Value) when is_integer(Value) ->
    MaxDeadline = genlib_app:env(capi_pcidss, max_request_deadline, ?MAX_REQUEST_DEADLINE_TIME),
    case Value > MaxDeadline of
        true ->
            MaxDeadline;
        false ->
            Value
    end.

-spec maybe(T | undefined, fun((T) -> R)) -> R | undefined.
maybe(undefined, _Fun) ->
    undefined;
maybe(V, Fun) ->
    Fun(V).

%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec to_universal_time_test() -> _.

to_universal_time_test() ->
    ?assertEqual(<<"2017-04-19T13:56:07Z">>, to_universal_time(<<"2017-04-19T13:56:07Z">>)),
    ?assertEqual(<<"2017-04-19T13:56:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53Z">>)),
    ?assertEqual(<<"2017-04-19T10:36:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53+03:20">>)),
    ?assertEqual(<<"2017-04-19T17:16:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53-03:20">>)).

-spec parse_deadline_test() -> _.
parse_deadline_test() ->
    Deadline = woody_deadline:from_timeout(3000),
    BinDeadline = woody_deadline:to_binary(Deadline),
    {ok, {_, _}} = parse_deadline(BinDeadline),
    ?assertEqual({error, bad_deadline}, parse_deadline(<<"2017-04-19T13:56:07.53Z">>)),
    {ok, {_, _}} = parse_deadline(<<"15s">>),
    {ok, {_, _}} = parse_deadline(<<"15m">>),
    {error, bad_deadline} = parse_deadline(<<"15h">>).

-spec parse_lifetime_test() -> _.
parse_lifetime_test() ->
    {ok, 16 * 1000} = parse_lifetime(<<"16s">>),
    {ok, 32 * 60 * 1000} = parse_lifetime(<<"32m">>),
    {error, bad_lifetime} = parse_lifetime(undefined),
    {error, bad_lifetime} = parse_lifetime(<<"64h">>).

-endif.
