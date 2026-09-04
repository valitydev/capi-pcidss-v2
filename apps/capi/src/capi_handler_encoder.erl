-module(capi_handler_encoder).

-include_lib("damsel/include/dmsl_base_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_thrift.hrl").

-export([encode_client_info/1]).
-export([encode_content/2]).
-export([encode_crypto_currency/1]).

-export_type([encode_data/0]).

-type request_data() :: capi_handler:request_data().
-type encode_data() :: tuple().

-spec encode_client_info(request_data()) -> encode_data().
encode_client_info(ClientInfo) ->
    #domain_ClientInfo{
        fingerprint = maps:get(<<"fingerprint">>, ClientInfo),
        ip_address = maps:get(<<"ip">>, ClientInfo),
        peer_ip_address = maps:get(<<"peer_ip">>, ClientInfo),
        user_ip_address = maps:get(<<"user_ip">>, ClientInfo),
        url = maps:get(<<"url">>, ClientInfo, undefined),
        browser_info = encode_browser_info(maps:get(<<"browserInfo">>, ClientInfo, undefined)),
        device_info = encode_device_info(maps:get(<<"deviceInfo">>, ClientInfo, undefined)),
        peer_user_agent = maps:get(<<"peer_user_agent">>, ClientInfo, undefined),
        peer_accept_header = maps:get(<<"peer_accept_header">>, ClientInfo, undefined)
    }.

-spec encode_content(json, term()) -> encode_data().
encode_content(json, Data) ->
    #base_Content{
        type = <<"application/json">>,
        data = jsx:encode(Data)
    }.

-spec encode_crypto_currency(binary()) -> encode_data().
encode_crypto_currency(CryptoCurrency) ->
    #domain_CryptoCurrencyRef{id = CryptoCurrency}.

%% Internals

encode_browser_info(undefined) ->
    undefined;
encode_browser_info(BrowserInfo) ->
    #domain_BrowserInfo{
        accept_header = maps:get(<<"browserAcceptHeader">>, BrowserInfo, undefined),
        user_agent = maps:get(<<"browserUserAgent">>, BrowserInfo, undefined),
        language = maps:get(<<"browserLanguage">>, BrowserInfo, undefined),
        color_depth = maps:get(<<"browserColorDepth">>, BrowserInfo, undefined),
        screen_width = maps:get(<<"browserScreenWidth">>, BrowserInfo, undefined),
        screen_height = maps:get(<<"browserScreenHeight">>, BrowserInfo, undefined),
        tz_offset = maps:get(<<"browserTZ">>, BrowserInfo, undefined)
    }.

encode_device_info(undefined) ->
    undefined;
encode_device_info(DeviceInfo) ->
    #domain_DeviceInfo{
        device_type = encode_device_type(maps:get(<<"deviceType">>, DeviceInfo, undefined)),
        os_name = maps:get(<<"osName">>, DeviceInfo, undefined),
        os_version = maps:get(<<"osVersion">>, DeviceInfo, undefined),
        device_model = maps:get(<<"deviceModel">>, DeviceInfo, undefined),
        browser_name = maps:get(<<"browserName">>, DeviceInfo, undefined),
        browser_version = maps:get(<<"browserVersion">>, DeviceInfo, undefined),
        time_zone = maps:get(<<"timeZone">>, DeviceInfo, undefined),
        languages = maps:get(<<"languages">>, DeviceInfo, undefined),
        screen_pixel_ratio = maps:get(<<"screenPixelRatio">>, DeviceInfo, undefined),
        web_view = maps:get(<<"webView">>, DeviceInfo, undefined),
        user_agent_brands = encode_brands(maps:get(<<"userAgentBrands">>, DeviceInfo, undefined))
    }.

encode_device_type(undefined) ->
    undefined;
encode_device_type(<<"desktop">>) ->
    {desktop, #domain_DeviceTypeDesktop{}};
encode_device_type(<<"mobile">>) ->
    {mobile, #domain_DeviceTypeMobile{}};
encode_device_type(<<"tablet">>) ->
    {tablet, #domain_DeviceTypeTablet{}};
encode_device_type(<<"unknown">>) ->
    {unknown, #domain_DeviceTypeUnknown{}}.

encode_brands(undefined) ->
    undefined;
encode_brands(UserAgentBrands) ->
    lists:map(
        fun(Brand) -> encode_brand(Brand) end,
        UserAgentBrands
    ).

encode_brand(Brand) ->
    #domain_UserAgentBrand{
        brand = maps:get(<<"brand">>, Brand, undefined),
        version = maps:get(<<"version">>, Brand, undefined)
    }.
