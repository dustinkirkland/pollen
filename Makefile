
all: pollen

pollen: pollen.go
	go build -o $@ $<

test: pollen.go pollen_test.go
	go test

clean:
	go clean

.PHONY: all clean
