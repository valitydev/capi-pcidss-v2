-module(capi_auth).

-export([get_consumer/1]).
-export([get_subject_id/1]).
-export([get_subject_data/1]).
-export([get_subject_email/1]).
-export([get_subject_name/1]).

-export([preauthorize_api_key/1]).
-export([authorize_api_key/3]).
-export([get_legacy_context/1]).
-export([extract_auth_context/1]).

-export([authorize_operation/3]).

-export_type([resolution/0]).
-export_type([preauth_context/0]).
-export_type([auth_context/0]).

-type consumer() :: client | merchant | provider.

-type token_type() :: bearer.
-type preauth_context() :: {unauthorized, {token_type(), token_keeper_client:token()}}.
-type auth_context() ::
    {authorized, #{
        legacy := capi_auth_legacy:context(),
        auth_data => tk_auth_data:auth_data()
    }}.

-type resolution() ::
    allowed
    | forbidden
    | {forbidden, _Reason}
    | {restricted, bouncer_restriction_thrift:'Restrictions'()}.

-define(authorized(Ctx), {authorized, Ctx}).
-define(unauthorized(Ctx), {unauthorized, Ctx}).

-spec get_subject_id(auth_context()) -> binary() | undefined.
get_subject_id(?authorized(#{auth_data := AuthData})) ->
    case tk_auth_data:get_party_id(AuthData) of
        PartyId when is_binary(PartyId) ->
            PartyId;
        undefined ->
            tk_auth_data:get_user_id(AuthData)
    end;
get_subject_id(?authorized(#{legacy := Context})) ->
    capi_auth_legacy:get_subject_id(Context).

-spec get_subject_data(auth_context()) -> #{atom() => binary()}.
get_subject_data(?authorized(#{auth_data := AuthData})) ->
    genlib_map:compact(#{
        user_id => tk_auth_data:get_user_id(AuthData),
        party_id => tk_auth_data:get_party_id(AuthData)
    }).

-spec get_subject_email(auth_context()) -> binary() | undefined.
get_subject_email(?authorized(#{auth_data := AuthData})) ->
    tk_auth_data:get_user_email(AuthData);
get_subject_email(?authorized(#{legacy := Context})) ->
    capi_auth_legacy:get_subject_email(Context).

-spec get_subject_name(auth_context()) -> binary() | undefined.
get_subject_name(?authorized(#{auth_data := _AuthData})) ->
    %% Subject names are no longer a thing for auth_data contexts
    undefined;
get_subject_name(?authorized(#{legacy := Context})) ->
    capi_auth_legacy:get_subject_name(Context).

-spec get_consumer(uac:claims()) -> consumer().
get_consumer(Claims) ->
    case maps:get(<<"cons">>, Claims, <<"merchant">>) of
        <<"merchant">> -> merchant;
        <<"client">> -> client;
        <<"provider">> -> provider
    end.

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

restore_api_key(bearer, Token) ->
    %% Kind of a hack since legacy auth expects the full api key string, but
    %% token-keeper does not and we got rid of it at preauth stage
    <<"Bearer ", Token/binary>>.

-spec authorize_api_key(preauth_context(), token_keeper_client:source_context(), woody_context:ctx()) ->
    {ok, auth_context()} | {error, _Reason}.
authorize_api_key(?unauthorized({TokenType, Token}), TokenContext, WoodyContext) ->
    authorize_token_by_type(TokenType, Token, TokenContext, WoodyContext).

authorize_token_by_type(bearer = TokenType, Token, TokenContext, WoodyContext) ->
    %% NONE: For now legacy auth still takes precedence over
    %% bouncer-based auth, so we MUST have a legacy context
    case capi_auth_legacy:authorize_api_key(restore_api_key(TokenType, Token)) of
        {ok, LegacyContext} ->
            case token_keeper_client:get_by_token(Token, TokenContext, WoodyContext) of
                {ok, AuthData} ->
                    {ok, {authorized, make_context(AuthData, LegacyContext)}};
                {error, TokenKeeperError} ->
                    _ = logger:warning("Token keeper authorization failed: ~p", [TokenKeeperError]),
                    {ok, {authorized, make_context(undefined, LegacyContext)}}
            end;
        {error, LegacyError} ->
            {error, {legacy_auth_failed, LegacyError}}
    end.

-spec extract_auth_context(capi_handler:processing_context()) -> auth_context().
extract_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

-spec get_legacy_context(auth_context()) -> capi_auth_legacy:context().
get_legacy_context(?authorized(#{legacy := LegacyContext})) ->
    LegacyContext.

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
    Req
) ->
    AuthContext = extract_auth_context(ProcessingContext),
    OldAuthResult = capi_auth_legacy:authorize_operation(get_legacy_context(AuthContext), ProcessingContext, Req),
    AuthResult = do_authorize_operation(Prototypes, get_auth_data(AuthContext), ProcessingContext),
    handle_auth_result(OldAuthResult, AuthResult).

make_context(AuthData, LegacyContext) ->
    genlib_map:compact(#{
        legacy => LegacyContext,
        auth_data => AuthData
    }).

handle_auth_result(allowed, allowed) ->
    allowed;
handle_auth_result(Res = {forbidden, _Reason}, forbidden) ->
    Res;
handle_auth_result(Res, undefined) ->
    Res;
handle_auth_result(allowed, {restricted, _} = Res) ->
    Res;
handle_auth_result(OldRes, NewRes) ->
    _ = logger:warning("New auth ~p differ from old ~p", [NewRes, OldRes]),
    OldRes.

do_authorize_operation(_, undefined, _) ->
    undefined;
do_authorize_operation(Prototypes, AuthData, #{swagger_context := ReqCtx, woody_context := WoodyCtx}) ->
    FragmentsAcc = capi_bouncer:gather_context_fragments(AuthData, ReqCtx, WoodyCtx),
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
