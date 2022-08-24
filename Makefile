export PATH := $(GOPATH)/bin:$(PATH)

V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

GO = GOGC=off go

VersionPath = rttys/version

GitCommit 		:= $(shell git log --pretty=format:"%h" -1)
BuildTime 		:= $(shell date +%FT%T%z)

LDFLAGS 		:= -s -w -X "$(VersionPath).gitCommit=$(GitCommit)" -X "$(VersionPath).buildTime=$(BuildTime)"
OS_ARCHS		:=darwin:amd64 darwin:arm64 linux:amd64 linux:arm64


## build: Build
.PHONY: build
build: | ; $(info $(M) building…)
	$(shell mkdir -p release)
	$(shell cp -r -n rttys.conf release/rttys.conf)
	$Q CGO_ENABLED=1 $(GO) build -ldflags '$(LDFLAGS)' -o ./release/rttys

## build-all: Build all
.PHONY: build-all
build-all: | ; $(info $(M) building all…)
	$(shell mkdir -p release)
	$(shell cp -r -n rttys.conf release/rttys.conf)
	@$(foreach n, $(OS_ARCHS),\
		os=$(shell echo "$(n)" | cut -d : -f 1);\
		arch=$(shell echo "$(n)" | cut -d : -f 2);\
		gomips=$(shell echo "$(n)" | cut -d : -f 3);\
		target_suffix=$${os}_$${arch};\
		env CGO_ENABLED=1 GOOS=$${os} GOARCH=$${arch} GOMIPS=$${gomips} go build -trimpath -ldflags "$(LDFLAGS)" -o ./release/rttys_$${target_suffix};\
	)

## help: Show this help
.PHONY: help
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' |  sed -e 's/^/ /' | sort
