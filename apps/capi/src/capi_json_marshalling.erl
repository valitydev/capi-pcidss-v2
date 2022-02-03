-module(capi_json_marshalling).

-include_lib("damsel/include/dmsl_json_thrift.hrl").

%% API
-export([marshal/1]).
-export([unmarshal/1]).

%%

-type value() :: term().

-spec marshal(value()) -> dmsl_json_thrift:'Value'() | no_return().
marshal(undefined) ->
    {nl, #json_Null{}};
marshal(Boolean) when is_boolean(Boolean) ->
    {b, Boolean};
marshal(Integer) when is_integer(Integer) ->
    {i, Integer};
marshal(Float) when is_float(Float) ->
    {flt, Float};
marshal(String) when is_binary(String) ->
    {str, String};
marshal(Object) when is_map(Object) ->
    {obj,
        maps:fold(
            fun(K, V, Acc) when is_binary(K) ->
                maps:put(K, marshal(V), Acc)
            end,
            #{},
            Object
        )};
marshal(Array) when is_list(Array) ->
    {arr, lists:map(fun marshal/1, Array)}.

-spec unmarshal(dmsl_json_thrift:'Value'()) -> value().
unmarshal({nl, #json_Null{}}) ->
    undefined;
unmarshal({b, Boolean}) ->
    Boolean;
unmarshal({i, Integer}) ->
    Integer;
unmarshal({flt, Float}) ->
    Float;
unmarshal({str, String}) ->
    String;
unmarshal({obj, Object}) ->
    maps:fold(fun(K, V, Acc) -> maps:put(K, unmarshal(V), Acc) end, #{}, Object);
unmarshal({arr, Array}) ->
    lists:map(fun unmarshal/1, Array).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-define(INSTANCES, [
    {undefined, {nl, #json_Null{}}},
    {42, {i, 42}},
    {false, {b, false}},
    {
        #{
            <<"leet">> => 1.337,
            <<"there">> => [<<"be">>, <<"🐲"/utf8>>, <<"dragons">>],
            <<"this">> => #{<<"is">> => true}
        },
        {obj, #{
            <<"leet">> => {flt, 1.337},
            <<"there">> => {arr, [{str, <<"be">>}, {str, <<"🐲"/utf8>>}, {str, <<"dragons">>}]},
            <<"this">> => {obj, #{<<"is">> => {b, true}}}
        }}
    }
]).

-spec marshalling_test_() -> _.
marshalling_test_() ->
    [?_assertEqual(marshal(Instance), Marshalled) || {Instance, Marshalled} <- ?INSTANCES].

-spec unmarshalling_test_() -> _.
unmarshalling_test_() ->
    [?_assertEqual(Instance, unmarshal(Marshalled)) || {Instance, Marshalled} <- ?INSTANCES].

-spec symmetric_marshalling_test_() -> _.
symmetric_marshalling_test_() ->
    [?_assertEqual(Instance, unmarshal(marshal(Instance))) || {Instance, _} <- ?INSTANCES].

-spec symmetric_unmarshalling_test_() -> _.
symmetric_unmarshalling_test_() ->
    [?_assertEqual(Marshalled, marshal(unmarshal(Marshalled))) || {_, Marshalled} <- ?INSTANCES].

-spec thrift_serialize_test_() -> _.
thrift_serialize_test_() ->
    [?_test(serialize_thrift(marshal(Instance))) || {Instance, _} <- ?INSTANCES].

serialize_thrift(Term) ->
    C1 = thrift_strict_binary_codec:new(),
    C2 = thrift_strict_binary_codec:write(C1, {struct, union, {dmsl_json_thrift, 'Value'}}, Term),
    thrift_strict_binary_codec:close(C2).

-endif.
