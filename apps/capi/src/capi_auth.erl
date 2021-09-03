-module(capi_auth).

-export([get_subject_id/1]).
-export([get_subject_data/1]).
-export([get_subject_email/1]).

-export([preauthorize_api_key/1]).
-export([authorize_api_key/3]).
-export([extract_auth_context/1]).

-export([authorize_operation/3]).

-export_type([resolution/0]).
-export_type([preauth_context/0]).
-export_type([auth_context/0]).

-type token_type() :: bearer.
-type preauth_context() :: {unauthorized, {token_type(), token_keeper_client:token()}}.
-type auth_context() ::
    {authorized, #{
        auth_data => token_keeper_auth_data:auth_data()
    }}.

-type resolution() :: bouncer_client:judgement() | undefined.

-define(authorized(Ctx), {authorized, Ctx}).
-define(unauthorized(Ctx), {unauthorized, Ctx}).

-define(APP, capi_pcidss).

-spec get_subject_id(auth_context()) -> binary() | undefined.
get_subject_id(?authorized(#{auth_data := AuthData})) ->
    case get_party_id(AuthData) of
        PartyId when is_binary(PartyId) ->
            PartyId;
        undefined ->
            get_user_id(AuthData)
    end.

-spec get_subject_data(auth_context()) -> #{atom() => binary()}.
get_subject_data(?authorized(#{auth_data := AuthData})) ->
    genlib_map:compact(#{
        user_id => get_user_id(AuthData),
        party_id => get_party_id(AuthData)
    }).

-spec get_subject_email(auth_context()) -> binary() | undefined.
get_subject_email(?authorized(#{auth_data := AuthData})) ->
    get_user_email(AuthData).

-spec preauthorize_api_key(swag_server:api_key()) -> {ok, preauth_context()} | {error, _Reason}.
preauthorize_api_key(ApiKey) ->
    case parse_api_key(ApiKey) of
        {ok, Token} ->
            {ok, ?unauthorized(Token)};
        {error, Error} ->
            {error, Error}
    end.

parse_api_key(<<"Bearer ", Token/binary>>) ->
    {ok, {bearer, Token}};
parse_api_key(_) ->
    {error, unsupported_auth_scheme}.

-spec authorize_api_key(preauth_context(), token_keeper_client:source_context(), woody_context:ctx()) ->
    {ok, auth_context()} | {error, _Reason}.
authorize_api_key(?unauthorized({TokenType, Token}), TokenContext, WoodyContext) ->
    authorize_token_by_type(TokenType, Token, TokenContext, WoodyContext).

authorize_token_by_type(bearer = _TokenType, Token, TokenContext, WoodyContext) ->
    case token_keeper_client:get_by_token(Token, TokenContext, WoodyContext) of
        {ok, AuthData} ->
            {ok, {authorized, #{auth_data => AuthData}}};
        {error, _} = TokenKeeperError ->
            TokenKeeperError
    end.

-spec extract_auth_context(capi_handler:processing_context()) -> auth_context().
extract_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

get_auth_data(?authorized(AuthContext)) ->
    maps:get(auth_data, AuthContext, undefined).

-spec authorize_operation(
    Prototypes :: capi_bouncer_context:prototypes(),
    Context :: capi_handler:processing_context(),
    Req :: capi_handler:request_data()
) -> resolution() | no_return().
authorize_operation(
    Prototypes,
    ProcessingContext,
    _Req
) ->
    AuthContext = extract_auth_context(ProcessingContext),
    do_authorize_operation(Prototypes, get_auth_data(AuthContext), ProcessingContext).

do_authorize_operation(_, undefined, _) ->
    undefined;
do_authorize_operation(Prototypes, AuthData, #{swagger_context := ReqCtx, woody_context := WoodyCtx}) ->
    FragmentsAcc = capi_bouncer:gather_context_fragments(
        get_token_keeper_fragment(AuthData),
        get_user_id(AuthData),
        ReqCtx,
        WoodyCtx
    ),
    Fragments = capi_bouncer_context:build(Prototypes, FragmentsAcc, WoodyCtx),
    try
        capi_bouncer:judge(Fragments, WoodyCtx)
    catch
        error:{woody_error, _Error} ->
            % TODO
            % This is temporary safeguard around bouncer integration put here so that
            % external requests would remain undisturbed by bouncer intermittent failures.
            % We need to remove it as soon as these two points come true:
            % * bouncer proves to be stable enough,
            % * capi starts depending on bouncer exclusively for authz decisions.
            undefined
    end.

get_token_keeper_fragment(AuthData) ->
    token_keeper_auth_data:get_context_fragment(AuthData).

%%

get_party_id(AuthData) ->
    get_metadata(get_metadata_mapped_key(party_id), token_keeper_auth_data:get_metadata(AuthData)).

get_user_id(AuthData) ->
    get_metadata(get_metadata_mapped_key(user_id), token_keeper_auth_data:get_metadata(AuthData)).

get_user_email(AuthData) ->
    get_metadata(get_metadata_mapped_key(user_email), token_keeper_auth_data:get_metadata(AuthData)).

get_metadata(Key, Metadata) ->
    maps:get(Key, Metadata, undefined).

get_metadata_mapped_key(Key) ->
    maps:get(Key, get_meta_mappings()).

get_meta_mappings() ->
    AuthConfig = genlib_app:env(?APP, auth_config),
    maps:get(metadata_mappings, AuthConfig).
