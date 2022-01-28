# HINT
# Use this file to override variables here.
# For example, to run with podman put `DOCKER=podman` there.
-include Makefile.env

# NOTE
# Variables specified in `.env` file are used to pick and setup specific
# component versions, both when building a development image and when running
# CI workflows on GH Actions. This ensures that tasks run with `wc-` prefix
# (like `wc-dialyze`) are reproducible between local machine and CI runners.
DOTENV := $(shell grep -v '^\#' .env)

DOCKER ?= docker
DOCKERCOMPOSE ?= docker-compose
REBAR ?= rebar3
TEST_CONTAINER_NAME ?= testrunner

all: compile

# Development images

DEV_IMAGE_TAG = $(TEST_CONTAINER_NAME)-dev
DEV_IMAGE_ID = $(file < .image.dev)

# Enable buildkit extensions in compose
DOCKER_COMPOSE_BUILD_ENV = COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1

.PHONY: dev-image clean-dev-image wc-shell test

dev-image: .image.dev

.image.dev: Dockerfile.dev .env
	env $(DOTENV) DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKER_COMPOSE_BUILD_ENV) $(DOCKERCOMPOSE) build $(TEST_CONTAINER_NAME)
	$(DOCKER) image ls -q -f "reference=$(DEV_IMAGE_ID)" | head -n1 > $@

clean-dev-image:
ifneq ($(DEV_IMAGE_ID),)
	$(DOCKER) image rm -f $(DEV_IMAGE_TAG)
	rm .image.dev
endif

DOCKER_WC_OPTIONS := -v $(PWD):$(PWD) --workdir $(PWD)
DOCKER_WC_EXTRA_OPTIONS ?= --rm
DOCKER_RUN = $(DOCKER) run -t $(DOCKER_WC_OPTIONS) $(DOCKER_WC_EXTRA_OPTIONS)

DOCKERCOMPOSE_RUN = DEV_IMAGE_TAG=$(DEV_IMAGE_TAG) $(DOCKERCOMPOSE) run --name $(TEST_CONTAINER_NAME) --rm $(DOCKER_WC_OPTIONS)

wc-shell: dev-image
	$(DOCKER_RUN) --interactive --tty $(DEV_IMAGE_TAG)

wc-%: dev-image
	$(DOCKER_RUN) $(DEV_IMAGE_TAG) make $*

#  TODO docker compose down doesn't work yet
wdeps-shell: dev-image
	$(DOCKERCOMPOSE_RUN) $(TEST_CONTAINER_NAME) su

wdeps-%: dev-image
	$(DOCKERCOMPOSE_RUN) $(TEST_CONTAINER_NAME) make $*

# CI-required tasks

compile:
	$(REBAR) compile

xref:
	$(REBAR) xref

lint:
	$(REBAR) lint

check-format:
	$(REBAR) fmt -c

dialyze:
	$(REBAR) as test dialyzer

release:
	$(REBAR) as prod release

eunit:
	$(REBAR) eunit --cover

common-test:
	$(REBAR) ct --cover

cover:
	$(REBAR) covertool generate

# Helper tasks

format:
	$(REBAR) fmt -w

clean:
	$(REBAR) clean

distclean: clean-build-image
	rm -rf _build

test: eunit common-test cover

cover-report:
	$(REBAR) cover
