-module(capi_auth).

-export([get_subject_id/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).
-export([get_consumer/1]).
-export([get_operation_access/2]).

-type consumer() :: client | merchant | provider.

-spec get_subject_id(uac:context()) -> binary().

get_subject_id({_Id, {SubjectID, _ACL}, _Claims}) ->
    SubjectID.

-spec get_claims(uac:context()) -> uac:claims().

get_claims({_Id, _Subject, Claims}) ->
    Claims.

-spec get_claim(binary(), uac:context()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), uac:context(), term()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}, Default) ->
    maps:get(ClaimName, Claims, Default).

%%

-spec get_operation_access(swag_server:operation_id(), swag_server:request_data()) ->
    [{uac_acl:scope(), uac_acl:permission()}].

get_operation_access('CreatePaymentResource'     , _) ->
    [{[payment_resources], write}].

-spec get_consumer(uac:claims()) ->
    consumer().
get_consumer(Claims) ->
    case maps:get(<<"cons">>, Claims, <<"merchant">>) of
        <<"merchant">> -> merchant;
        <<"client"  >> -> client;
        <<"provider">> -> provider
    end.
