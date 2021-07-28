-module(capi_bouncer_context).

-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_payout_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_webhooker_thrift.hrl").

-type fragment() :: bouncer_client:context_fragment().
-type acc() :: bouncer_context_helpers:context_fragment().

-type fragments() :: {acc(), _ExternalFragments :: #{_ID => fragment()}}.

-export_type([fragment/0]).
-export_type([acc/0]).
-export_type([fragments/0]).

-type prototypes() :: [
    {operation, prototype_operation()}
    | {tokens, prototype_tokens()}
].

-type prototype_operation() :: #{
    id => swag_server:operation_id(),
    party => entity_id()
}.

-type prototype_tokens() :: #{
    replacement_ip => ip()
}.

-type entity_id() :: binary().

-type ip() :: dmsl_domain_thrift:'IPAddress'().

-export_type([prototypes/0]).
-export_type([prototype_operation/0]).
-export_type([prototype_tokens/0]).

-export([new/0]).
-export([build/3]).

%%

-spec new() -> fragments().
new() ->
    {mk_base_fragment(), #{}}.

mk_base_fragment() ->
    bouncer_context_helpers:make_env_fragment(#{
        now => genlib_rfc3339:format(genlib_time:unow(), second),
        deployment => #{id => genlib_app:env(capi_pcidss, deployment, undefined)}
    }).

-spec build(prototypes(), fragments(), woody_context:ctx()) -> fragments().
build(Prototypes, {Acc0, External}, WoodyCtx) ->
    Acc1 = lists:foldl(fun({T, Params}, Acc) -> build(T, Params, Acc, WoodyCtx) end, Acc0, Prototypes),
    {Acc1, External}.

build(operation, Params = #{id := OperationID}, Acc, _WoodyCtx) ->
    Acc#bctx_v1_ContextFragment{
        capi = #bctx_v1_ContextCommonAPI{
            op = #bctx_v1_CommonAPIOperation{
                id = operation_id_to_binary(OperationID),
                party = maybe_entity(party, Params)
            }
        }
    };
build(tokens, Params, Acc, _WoodyCtx) ->
    Acc#bctx_v1_ContextFragment{
        tokens = #bctx_v1_ContextTokens{
            replacement_ip = maybe_with(replacement_ip, Params, fun maybe_marshal_ip/1)
        }
    }.

maybe_with(Name, Params, Then) ->
    capi_utils:maybe(maps:get(Name, Params, undefined), Then).

operation_id_to_binary(V) ->
    erlang:atom_to_binary(V, utf8).

maybe_entity(Name, Params) ->
    maybe_with(Name, Params, fun build_entity/1).

build_entity(ID) when is_binary(ID) ->
    #bctx_v1_Entity{id = ID};
build_entity(ID) when is_integer(ID) ->
    #bctx_v1_Entity{id = integer_to_binary(ID)}.

%% NOTE: from bouncer_client/bouncer_context_helpers.erl
maybe_marshal_ip(IP) when is_tuple(IP) ->
    list_to_binary(inet:ntoa(IP));
maybe_marshal_ip(IP) when is_binary(IP) ->
    IP;
maybe_marshal_ip(IP) when is_list(IP) ->
    list_to_binary(IP).
