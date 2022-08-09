-module(capi_msgp_marshalling).

-include_lib("damsel/include/dmsl_msgpack_thrift.hrl").

%% API
-export([marshal/1]).
-export([unmarshal/1]).

%%

-type value() :: term().

-spec marshal(value()) -> dmsl_msgpack_thrift:'Value'() | no_return().
marshal(undefined) ->
    {nl, #msgpack_Nil{}};
marshal(Boolean) when is_boolean(Boolean) ->
    {b, Boolean};
marshal(Integer) when is_integer(Integer) ->
    {i, Integer};
marshal(Float) when is_float(Float) ->
    {flt, Float};
marshal(String) when is_binary(String) ->
    {str, String};
marshal({bin, Binary}) ->
    {bin, Binary};
marshal(Object) when is_map(Object) ->
    {obj,
        maps:fold(
            fun(K, V, Acc) ->
                maps:put(marshal(K), marshal(V), Acc)
            end,
            #{},
            Object
        )};
marshal(Array) when is_list(Array) ->
    {arr, lists:map(fun marshal/1, Array)}.

-spec unmarshal(dmsl_msgpack_thrift:'Value'()) -> value().
unmarshal({nl, #msgpack_Nil{}}) ->
    undefined;
unmarshal({b, Boolean}) ->
    Boolean;
unmarshal({i, Integer}) ->
    Integer;
unmarshal({flt, Float}) ->
    Float;
unmarshal({str, String}) ->
    String;
unmarshal({bin, Binary}) ->
    {bin, Binary};
unmarshal({obj, Object}) ->
    maps:fold(fun(K, V, Acc) -> maps:put(unmarshal(K), unmarshal(V), Acc) end, #{}, Object);
unmarshal({arr, Array}) ->
    lists:map(fun unmarshal/1, Array).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-define(INSTANCES, [
    {undefined, {nl, #msgpack_Nil{}}},
    {42, {i, 42}},
    {false, {b, false}},
    {
        #{
            3.1415 => 1.337,
            <<"there">> => [<<"be">>, {bin, <<"🐲"/utf8>>}, <<"dragons">>],
            false => #{<<"is">> => true}
        },
        {obj, #{
            {flt, 3.1415} => {flt, 1.337},
            {str, <<"there">>} => {arr, [{str, <<"be">>}, {bin, <<"🐲"/utf8>>}, {str, <<"dragons">>}]},
            {b, false} => {obj, #{{str, <<"is">>} => {b, true}}}
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
    {ok, C2} = thrift_strict_binary_codec:write(C1, {struct, union, {dmsl_msgpack_thrift, 'Value'}}, Term),
    thrift_strict_binary_codec:close(C2).

-endif.
