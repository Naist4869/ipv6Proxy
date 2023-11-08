# Makefile for building a Go project

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=myapp
BINARY_UNIX=$(BINARY_NAME)_unix

# Build the project
all: test build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

# Test the project
test:
	$(GOTEST) -v ./...

# Clean up the project
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Cross-compile for Linux
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v

# Fetch dependencies
deps:
	$(GOGET) -v ./...
