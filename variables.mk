PROJECT_ROOT := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
SRC_DIR := $(PROJECT_ROOT)src/evesrp
STATIC_DIR := $(SRC_DIR)/static
NODE_MODULES := $(shell npm root)
NODE_BIN := $(shell npm bin)
