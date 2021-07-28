-ifndef(capi_bouncer_data_included__).
-define(capi_bouncer_data_included__, ok).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-define(JUDGEMENT(Resolution), #bdcs_Judgement{resolution = Resolution}).
-define(ALLOWED, {allowed, #bdcs_ResolutionAllowed{}}).
-define(FORBIDDEN, {forbidden, #bdcs_ResolutionForbidden{}}).
-define(RESTRICTED(R), {restricted, #bdcs_ResolutionRestricted{restrictions = R}}).

-define(CTX_ENTITY(ID), #bctx_v1_Entity{id = ID}).

-define(CTX_CAPI(Op), #bctx_v1_ContextCommonAPI{op = Op}).

-define(CTX_CAPI_OP(ID), #bctx_v1_CommonAPIOperation{id = ID}).

-define(CTX_PARTY_OP(ID, PartyID), #bctx_v1_CommonAPIOperation{
    id = ID,
    party = ?CTX_ENTITY(PartyID)
}).

-define(assertContextMatches(Expect), fun(Context) ->
    try
        ?assertMatch(Expect, Context),
        {ok, ?JUDGEMENT(?ALLOWED)}
    catch
        error:AssertMatchError:Stacktrace ->
            logger:error("failed ~p at ~p", [AssertMatchError, Stacktrace]),
            {throwing, #bdcs_InvalidContext{}}
    end
end).

-endif.
