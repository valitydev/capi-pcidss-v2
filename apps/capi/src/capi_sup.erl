%% @doc Top level supervisor.
%% @end

-module(capi_sup).

-behaviour(supervisor).

-define(APP, capi_pcidss).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%%

-spec start_link() -> {ok, pid()} | {error, {already_started, pid()}}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    validate_token_services(),
    LechiffreOpts = genlib_app:env(capi_pcidss, lechiffre_opts),
    LechiffreSpec = lechiffre:child_spec(lechiffre, LechiffreOpts),
    {LogicHandler, LogicHandlerSpecs} = get_logic_handler_info(),
    AdditionalRoutes = [
        {'_', [
            % get_prometheus_route(),
            erl_health_handle:get_route(genlib_app:env(capi_pcidss, health_check, #{}))
        ]}
    ],
    SwaggerHandlerOpts = genlib_app:env(?APP, swagger_handler_opts, #{}),
    SwaggerSpec = capi_swagger_server:child_spec({AdditionalRoutes, LogicHandler, SwaggerHandlerOpts}),
    {ok, {
        {one_for_all, 0, 1},
        [LechiffreSpec] ++ LogicHandlerSpecs ++ [SwaggerSpec]
    }}.

% -spec get_prometheus_route() -> {iodata(), module(), _Opts :: any()}.
% get_prometheus_route() ->
%     {"/metrics/[:registry]", prometheus_cowboy2_handler, []}.

-spec get_logic_handler_info() -> {Handler :: atom(), [Spec :: supervisor:child_spec()] | []}.
get_logic_handler_info() ->
    case genlib_app:env(capi_pcidss, service_type) of
        real ->
            {capi_handler, []};
        undefined ->
            exit(undefined_service_type)
    end.

validate_token_services() ->
    TokenServices = genlib_app:env(capi_pcidss, bank_card_token_service_mapping),
    lists:foreach(
        fun(TokenProvider) ->
            case maps:find(TokenProvider, TokenServices) of
                error ->
                    exit({invalid, bank_card_token_service_mapping, {missed_token_provider, TokenProvider}});
                {ok, _} ->
                    ok
            end
        end,
        capi_handler_tokens:get_token_providers()
    ).
