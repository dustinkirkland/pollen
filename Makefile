GO_BUILD=go build
GO_TEST=go test
GO_CLEAN=go clean

all: pollen

pollen: pollen.go
	$(GO_BUILD) -o $@ $<

test: pollen.go pollen_test.go
	$(GO_TEST)

clean:
	$(RM) pollen

.PHONY: all clean test
