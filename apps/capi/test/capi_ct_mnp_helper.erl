-module(capi_ct_mnp_helper).

-include_lib("moneypenny_proto/include/moneypenny_mnp_thrift.hrl").

-export([
    get_result/0
]).

-spec get_result() -> _.
get_result() ->
    #mnp_ResponseData{
        operator = megafone
    }.
