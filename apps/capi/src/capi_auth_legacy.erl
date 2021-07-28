-module(capi_auth_legacy).

-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([get_subject_name/1]).
-export([get_claims/1]).

-export([get_operation_access/2]).
-export([get_access_config/0]).
-export([authorize_api_key/1]).
-export([authorize_operation/3]).

-export_type([resolution/0]).
-export_type([context/0]).

-type context() :: uac:context().
-type claims() :: uac:claims().
-type request_data() :: #{atom() | binary() => term()}.
-type resolution() ::
    allowed
    | forbidden
    | {forbidden, _Reason}.

-spec get_subject_id(context()) -> binary() | undefined.
get_subject_id(Context) ->
    uac_authorizer_jwt:get_subject_id(Context).

-spec get_subject_email(context()) -> binary() | undefined.
get_subject_email(Context) ->
    uac_authorizer_jwt:get_claim(<<"email">>, Context, undefined).

-spec get_subject_name(context()) -> binary() | undefined.
get_subject_name(Context) ->
    uac_authorizer_jwt:get_claim(<<"name">>, Context, undefined).

-spec get_claims(context()) -> claims().
get_claims(Context) ->
    uac_authorizer_jwt:get_claims(Context).

-spec get_operation_access(swag_server:operation_id(), request_data()) -> [{uac_acl:scope(), uac_acl:permission()}].
get_operation_access('CreatePaymentResource', _) ->
    [{[payment_resources], write}].

-spec get_resource_hierarchy() -> uac_conf:resource_hierarchy().
get_resource_hierarchy() ->
    #{
        payment_resources => #{}
    }.

-spec get_access_config() -> uac_conf:options().
get_access_config() ->
    #{
        domain_name => <<"common-api">>,
        resource_hierarchy => get_resource_hierarchy()
    }.

-spec authorize_api_key(ApiKey :: binary()) ->
    {ok, context()} | {error, {authorize_api_key_failed | blacklisted_token, _Reason}}.
authorize_api_key(ApiKey) ->
    case uac:authorize_api_key(ApiKey, #{}) of
        {ok, _Context} = Ok ->
            Ok;
        {error, Error} ->
            {error, {authorize_api_key_failed, Error}}
    end.

-spec authorize_operation(
    AuthContext :: context(),
    ProcessingContext :: capi_handler:processing_context(),
    Req :: capi_handler:request_data()
) -> resolution().
authorize_operation(AuthContext, #{operation_id := OperationID}, Req) ->
    OperationACL = get_operation_access(OperationID, Req),
    case uac:authorize_operation(OperationACL, AuthContext) of
        ok ->
            allowed;
        {error, Reason} ->
            {forbidden, Reason}
    end.
