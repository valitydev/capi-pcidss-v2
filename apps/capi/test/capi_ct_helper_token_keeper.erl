-module(capi_ct_helper_token_keeper).

-include_lib("capi_dummy_data.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("capi_token_keeper_data.hrl").

-define(PARTY_ID, ?STRING).
-define(CONSUMER, <<"client">>).
-define(TOKEN_LIFETIME, 259200).

-type sup_or_config() :: capi_ct_helper:sup_or_config().
-type app_name() :: capi_ct_helper:app_name().
-type token_handler() :: fun(('Authenticate' | 'Create', tuple()) -> term() | no_return()).

-export([mock_token/2]).
-export([mock_invalid_token/1]).
-export([mock_invoice_access_token/1]).

-spec mock_token(token_handler(), sup_or_config()) -> list(app_name()).
mock_token(HandlerFun, SupOrConfig) ->
    start_client(
        capi_ct_helper:mock_services_(
            [
                {
                    token_authenticator,
                    {tk_token_keeper_thrift, 'TokenAuthenticator'},
                    HandlerFun
                }
            ],
            SupOrConfig
        )
    ).

start_client(ServiceURLs) ->
    capi_ct_helper:start_app(token_keeper_client, [
        {service_clients, #{
            authenticator => #{
                url => maps:get(token_authenticator, ServiceURLs)
            },
            authorities => #{
                ephemeral => #{},
                offline => #{}
            }
        }}
    ]).

%%

-spec mock_invalid_token(sup_or_config()) -> list(app_name()).
mock_invalid_token(SupOrConfig) ->
    mock_token(fun('Authenticate', {_, _}) -> {throwing, #token_keeper_InvalidToken{}} end, SupOrConfig).

-spec mock_invoice_access_token(sup_or_config()) -> list(app_name()).
mock_invoice_access_token(SupOrConfig) ->
    Handler = make_authenticator_handler(fun() ->
        AuthParams = #{
            method => <<"InvoiceAccessToken">>,
            expiration => posix_to_rfc3339(lifetime_to_expiration(?TOKEN_LIFETIME)),
            token => #{id => ?STRING}
        },
        {?TK_AUTHORITY_API, create_bouncer_context(AuthParams), invoice_access_metadata()}
    end),
    mock_token(Handler, SupOrConfig).

%%

-spec make_authenticator_handler(function()) -> token_handler().
make_authenticator_handler(Handler) ->
    fun('Authenticate', {Token, _}) ->
        {Authority, ContextFragment, Metadata} = Handler(),
        AuthData = #token_keeper_AuthData{
            token = Token,
            status = active,
            context = ContextFragment,
            authority = Authority,
            metadata = Metadata
        },
        {ok, AuthData}
    end.

%%

invoice_access_metadata() ->
    genlib_map:compact(#{
        ?TK_META_PARTY_ID => ?PARTY_ID,
        ?TK_META_TOKEN_CONSUMER => ?CONSUMER
    }).

%%

create_bouncer_context(AuthParams) ->
    Fragment0 = bouncer_context_helpers:make_auth_fragment(AuthParams),
    encode_context(Fragment0).
%%

encode_context(Context) ->
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_content(Context)
    }.

encode_context_content(Context) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, Context) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

%%

lifetime_to_expiration(Lt) when is_integer(Lt) ->
    genlib_time:unow() + Lt.

posix_to_rfc3339(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second).
