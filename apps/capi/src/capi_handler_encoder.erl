-module(capi_handler_encoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([encode_client_info/1]).
-export([encode_residence/1]).
-export([encode_content/2]).

-export_type([encode_data/0]).

-type request_data() :: capi_handler:request_data().
-type encode_data()  :: tuple().

-spec encode_client_info(request_data()) ->
    encode_data().
encode_client_info(ClientInfo) ->
    #domain_ClientInfo{
        fingerprint = maps:get(<<"fingerprint">>, ClientInfo),
        ip_address  = maps:get(<<"ip"         >>, ClientInfo)
    }.

-spec encode_residence(binary() | undefined) ->
    atom().

encode_residence(undefined) ->
    undefined;
encode_residence(Residence) when is_binary(Residence) ->
    try
        list_to_existing_atom(string:to_lower(binary_to_list(Residence)))
    catch
        error:badarg ->
            throw({encode_residence, invalid_residence})
    end.

-spec encode_content(json, term()) ->
    encode_data().

encode_content(json, Data) ->
    #'Content'{
        type = <<"application/json">>,
        data = jsx:encode(Data)
    }.
