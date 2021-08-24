-module(capi_handler_encoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([encode_client_info/1]).
-export([encode_content/2]).

-export_type([encode_data/0]).

-type request_data() :: capi_handler:request_data().
-type encode_data() :: tuple().

-spec encode_client_info(request_data()) -> encode_data().
encode_client_info(ClientInfo) ->
    #domain_ClientInfo{
        fingerprint = maps:get(<<"fingerprint">>, ClientInfo),
        ip_address = maps:get(<<"ip">>, ClientInfo),
        url = maps:get(<<"url">>, ClientInfo, undefined)
    }.

-spec encode_content(json, term()) -> encode_data().
encode_content(json, Data) ->
    #'Content'{
        type = <<"application/json">>,
        data = jsx:encode(Data)
    }.
