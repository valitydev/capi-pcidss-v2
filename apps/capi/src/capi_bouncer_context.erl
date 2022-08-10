-module(capi_bouncer_context).

-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").

-type fragment() :: bouncer_client:context_fragment().
-type acc() :: bouncer_context_helpers:context_fragment().

-type fragments() :: {acc(), _ExternalFragments :: #{_ID => fragment()}}.

-export_type([fragment/0]).
-export_type([acc/0]).
-export_type([fragments/0]).

-type prototypes() :: [
    {operation, prototype_operation()}
    | {payment_tool, prototype_payment_tool()}
].

-type prototype_operation() :: #{
    id => swag_server:operation_id(),
    party => entity_id(),
    client_info => #{ip => ip()}
}.

-type prototype_payment_tool() :: #{
    party => entity_id(),
    shop => entity_id(),
    expiration => timestamp()
}.

-type entity_id() :: bouncer_base_thrift:'EntityID'().
-type timestamp() :: bouncer_base_thrift:'Timestamp'().

-type ip() :: dmsl_domain_thrift:'IPAddress'().

-export_type([prototypes/0]).
-export_type([prototype_operation/0]).
-export_type([prototype_payment_tool/0]).

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
    Acc#ctx_v1_ContextFragment{
        capi = #ctx_v1_ContextCommonAPI{
            op = #ctx_v1_CommonAPIOperation{
                id = operation_id_to_binary(OperationID),
                party = maybe_entity(party, Params),
                client_info = maybe_with(client_info, Params, fun(ClientInfo) ->
                    #ctx_v1_ClientInfo{
                        ip = maybe_marshal_ip(maps:get(ip, ClientInfo, undefined))
                    }
                end)
            }
        }
    };
build(payment_tool, Params, Acc, _WoodyCtx) ->
    Acc#ctx_v1_ContextFragment{
        payment_tool = #ctx_v1_ContextPaymentTool{
            %% #ED-124 для валидации провайдерского токена требуются party&shop
            scope = #ctx_v1_AuthScope{
                party = maybe_entity(party, Params),
                shop = maybe_entity(shop, Params)
            },
            %% Синтетический срок действия legacy токенов capi_handler_tokens:decode_merchant_id_fallback
            expiration = maps:get(expiration, Params, undefined)
        }
    }.

maybe_with(Name, Params, Then) ->
    capi_utils:maybe(maps:get(Name, Params, undefined), Then).

operation_id_to_binary(V) ->
    erlang:atom_to_binary(V, utf8).

maybe_entity(Name, Params) ->
    maybe_with(Name, Params, fun build_entity/1).

build_entity(ID) when is_binary(ID) ->
    #base_Entity{id = ID};
build_entity(ID) when is_integer(ID) ->
    #base_Entity{id = integer_to_binary(ID)}.

%% NOTE: from bouncer_client/bouncer_context_helpers.erl
maybe_marshal_ip(IP) when is_tuple(IP) ->
    list_to_binary(inet:ntoa(IP));
maybe_marshal_ip(IP) when is_binary(IP) ->
    IP;
maybe_marshal_ip(IP) when is_list(IP) ->
    list_to_binary(IP);
maybe_marshal_ip(undefined) ->
    undefined.
