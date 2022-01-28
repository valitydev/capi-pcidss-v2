FROM ghcr.io/rbkmoney/build-erlang:785d48cbfa7e7f355300c08ba9edc6f0e78810cb AS builder
RUN mkdir /build
COPY . /build/
WORKDIR /build
RUN rebar3 compile
RUN rebar3 as prod release

# Keep in sync with Erlang/OTP version in build image
FROM erlang:24.1.3.0-slim
ENV SERVICE=capi_pcidss
ENV CHARSET=UTF-8
ENV LANG=C.UTF-8
COPY --from=builder /build/_build/prod/rel/${SERVICE} /opt/${SERVICE}
WORKDIR /opt/${SERVICE}
ENTRYPOINT []
CMD /opt/${SERVICE}/bin/${SERVICE} foreground
EXPOSE 8080
