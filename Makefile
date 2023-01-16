#
# Build, install, and run the demonstrator
#
#     $ make
#     $ make install
#
# The user should setup an environment variable KEYSTONE_BUILD_DIR. The
# environment variable should refer to Keystone subdirectory 'build'.
#
KEYSTONE_BUILD_DIR ?= $(error Set KEYSTONE_BUILD_DIR enviromnment)
HAPP_TARGET = target/riscv64gc-unknown-linux-gnu/release
EAPP_TARGET = target/riscv64gc-unknown-none-elf/release

all:
	@echo "========== BUILD schannel-lib =========="
	(cd schannel-lib; cargo build --release)
	@echo "========== BUILD wasm-client =========="
	(cd wasm-client; cargo build --release)
	@echo "========== BUILD wasm-host =========="
	(cd wasm-host; cargo build --release)
	@echo "========== BUILD wasm-rt =========="
	(cd wasm-rt; cargo build --release)

init:
	git submodule update --init --recursive --depth 1

install:
	@echo "Keystone build directory is $(KEYSTONE_BUILD_DIR)"
	cp $(HAPP_TARGET)/wasm-client $(KEYSTONE_BUILD_DIR)/overlay/root
	cp $(HAPP_TARGET)/wasm-host $(KEYSTONE_BUILD_DIR)/overlay/root
	cp $(EAPP_TARGET)/wasm-rt $(KEYSTONE_BUILD_DIR)/overlay/root

clean:
	(cd schannel-lib; cargo clean)
	(cd wasm-client; cargo clean)
	(cd wasm-host; cargo clean)
	(cd wasm-rt; cargo clean)
