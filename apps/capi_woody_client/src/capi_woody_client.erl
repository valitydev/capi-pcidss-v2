-module(capi_woody_client).

-export([call_service/4]).

-export([get_service_modname/1]).

%%

-type service_name() :: atom().
-type client_opts() :: #{
    url            := woody:url(),
    %% See hackney:request/5 for available transport options.
    transport_opts => woody_client_thrift_http_transport:transport_options()
}.

-spec call_service(service_name(), woody:func(), [term()], woody_context:ctx()) ->
    woody:result().

call_service(ServiceName, Function, Args, Context0) ->
    Deadline = get_service_deadline(ServiceName),
    Context1 = set_deadline(Deadline, Context0),
    Retry = get_service_retry(ServiceName, Function),
    EventHandlerOpts = genlib_app:env(capi_pcidss, scoper_event_handler_options, #{}),
    EventHandler = {scoper_woody_event_handler, EventHandlerOpts},
    call_service(ServiceName, Function, Args, Context1, EventHandler, Retry).

call_service(ServiceName, Function, Args, Context, EventHandler, Retry) ->
    Options = get_service_options(ServiceName),
    Service = get_service_modname(ServiceName),
    Request = {Service, Function, Args},
    try
        woody_client:call(
            Request,
            Options#{event_handler => EventHandler},
            Context
        )
    catch
        error:{woody_error, {_Source, Class, _Details}} = Error
        when Class =:= resource_unavailable orelse Class =:= result_unknown
        ->
            NextRetry = apply_retry_strategy(Retry, Error, Context),
            call_service(ServiceName, Function, Args, Context, EventHandler, NextRetry)
    end.

apply_retry_strategy(Retry, Error, Context) ->
    apply_retry_step(genlib_retry:next_step(Retry), woody_context:get_deadline(Context), Error).

apply_retry_step(finish, _, Error) ->
    erlang:error(Error);
apply_retry_step({wait, Timeout, Retry}, undefined, _) ->
    ok = timer:sleep(Timeout),
    Retry;
apply_retry_step({wait, Timeout, Retry}, Deadline0, Error) ->
    Deadline1 = woody_deadline:from_unixtime_ms(
        woody_deadline:to_unixtime_ms(Deadline0) - Timeout
    ),
    case woody_deadline:is_reached(Deadline1) of
        true ->
            % no more time for retries
            erlang:error(Error);
        false ->
            ok = timer:sleep(Timeout),
            Retry
    end.

-spec get_service_options(service_name()) ->
    client_opts().

get_service_options(ServiceName) ->
    construct_opts(maps:get(ServiceName, genlib_app:env(?MODULE, services))).

construct_opts(Opts = #{url := Url}) ->
    Opts#{url := genlib:to_binary(Url)};
construct_opts(Url) ->
    #{url => genlib:to_binary(Url)}.

-spec get_service_modname(service_name()) -> woody:service().

get_service_modname(cds_storage) ->
    {cds_proto_storage_thrift, 'Storage'};
get_service_modname(tds_storage) ->
    {tds_proto_storage_thrift, 'TokenStorage'};
get_service_modname(payment_tool_provider_apple_pay) ->
    {dmsl_payment_tool_provider_thrift, 'PaymentToolProvider'};
get_service_modname(payment_tool_provider_google_pay) ->
    {dmsl_payment_tool_provider_thrift, 'PaymentToolProvider'};
get_service_modname(payment_tool_provider_samsung_pay) ->
    {dmsl_payment_tool_provider_thrift, 'PaymentToolProvider'};
get_service_modname(binbase) ->
    {binbase_binbase_thrift, 'Binbase'};
get_service_modname(bender) ->
    {bender_thrift, 'Bender'};
get_service_modname(moneypenny) ->
    {moneypenny_mnp_thrift, 'Mnp'}.

get_service_deadline(ServiceName) ->
    ServiceDeadlines = genlib_app:env(?MODULE, service_deadlines, #{}),
    case maps:get(ServiceName, ServiceDeadlines, undefined) of
        Timeout when is_integer(Timeout) andalso Timeout >= 0 ->
            woody_deadline:from_timeout(Timeout);
        undefined ->
            undefined
    end.

set_deadline(Deadline, Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            woody_context:set_deadline(Deadline, Context);
        _AlreadySet ->
            Context
    end.

get_service_retry(ServiceName, Function) ->
    ServiceRetries = genlib_app:env(?MODULE, service_retries, #{}),
    FunctionReties = maps:get(ServiceName, ServiceRetries, #{}),
    DefaultRetry = maps:get('_', FunctionReties, finish),
    maps:get(Function, FunctionReties, DefaultRetry).
