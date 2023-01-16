# Confidential WebAssembly runtime for Keystone enclave #

This project is a proof-of-concept implementation demonstrating the
use of a confidential WebAssembly-based execution environment for
RISC-V, leveraging Keystone Enclaves. A remote client can securely
transmit WebAssembly bytecode to a runtime executing inside a Keystone
Enclave over an encrypted channel. The same secure channel also
supports sending input data to the runtime and receiving computation
results, ensuring confidentiality and integrity throughout the
process.

Software is organized as the following components:

* **wasm-client** - Secure channel client that is used to connect to
  the service.

* **wasm-rt** - Enclave application. This is an interface code to
  WebAssembly bytecode interpreter tinyWASM.

* **wasm-host** - A host application that serves connecting clients
  (e.g., wasm-client) and passes requests to the enclave application
  (wasm-rt).

* **schannel-lib** - Shared code between wasm-client and wasm-host.
   This is using a Rust-based implementation of setting up a secure
   channel between two end points using Diffie-Hellman key exchange and
   AES encryption.

These components form the foundation of a demonstrator built on a
Rust-based Keystone Enclave runtime environment. The demonstrator
first establishes a secure connection between the remote client and
the enclave application, after which it transmits a WebAssembly
program to the enclave for execution.

## Building ##

### Pre-conditions ###

Rust software development tools must be installed

* rustc - Rust compiler
* cargo - Rusts's package manager

Because software is utilizing Cargo workspace feature that is still
only available in Rust toolchain nightly builds, Rust should be
configured to use the nightly version.

Keystone must be installed and built. The environment variable
*KEYSTONE_BUILD_DIR* should point to the build directory (e.g.,
build-generic64 for qemu builds) of the Keystone installation.

A Rust SDK and a library static-dh-ecdh are needed. Those are
available as submodules. Fetch the submodules by giving a command:

      git submodule update --init --recursive --depth 1

This is also packaged to a Makefile and can be invoked with:

      make init

### Compilation ###

The project includes a makefile and compilation is triggered by using
a command:

      make

This command builds all subdirectories and installs executables to the
target subdirectory. It is possible to remove compiled files using a
command:

      make clean

The makefile is using cargo tool for building.

### Installation ###

Compiled files should be installed into qemu-based Keystone
demonstrator. This can be done using a command:

      make install

The executables and installed into root file system and new image is
built.

## Running the demo ##

The demo is similar to the original keystone-demo. Server and client
programs are started and a secure channel is established between these
processes. The client is writing a text line that is then transferred
to the server via the secure channel. The server uses the line as an
input and returns the result to the client also via the secure
channel. The result is then displayed to the user. The demonstrator is
now implementing a calculator and input parameter specifies
calculation operation and parameters.

The server is waiting for connections and spawns a thread for each
secure channel. The client is running in a loop and can pass more text
lines to be word counted to the server. The client is terminated by
writing a message "q" in a console.  The quit message is also passed
to the server that terminates the thread bound to the secure channel.

The demonstrator system running in qemu can be started using the
command:

      make run

This is starting a qemu-based Linux system with Keystone. It is
possible to login from a console using default credentials mentioned
in Keystone documentation (root/sifive). Note that the boot log also
mentions a port that is used by sshd to listen incoming
connections. After login Keystone kernel module should be loaded using
a command:

      modprobe keystone-driver

The server should be started by using a command:

      ./wasm-host ./wasm-rt ./eyrie-rt ./loader

Note that components 'eyrie-rt' and 'loader' must be copied from
Keystone build tree. These are not availabale in this repository.
If wasm-demo is compiled with vector-keystone then this is packaged
using makeself and can be invoked with a command:

      ./wasm-demo.ke

This is starting a server. The server is by default bound to a
port 3333. Use another shell in the host computer to connect to the
qemu using ssh comnection. The port number is listed in the beginning
of the boot log. Check the similar text as the following in th
ebeginning of the boot log:

      **** Running QEMU SSH on port 3000 ****

Use again the default credentials (root/sifive):

      ssh -l root -p <see boot log> localhost

After logging in connect to the server using a command:

      ./wasm-client -c localhost:3333 -p calculator.wasm

The enclave WebAssembly code (calculator.wasm - available in another
repository) implements a simple calculator with four basic operations:
addition, subtraction, multiplication, and division. The client
can send a Web Assembly function name that is matching to an operation
with two parameters. The request is then passed to the enclave code
using the secure channel and the result is returned back using the
same channel. Examples:

      input> add 1 1
	  output> 2
	  input> sub 5 2
	  output> 3
	  input> mul 7 7
	  output> 49
	  input> div 5 2
	  output> 2

Note that the return value is always integer value even in division.
There is no error handling. The client can terminate the connection
by sending a one letter text line 'q'. The server supports multiple
concurret clients.

The server can be terminated using CTRL-C from the shell or with the
kill command. The qemu instance can be terminated using the halt
command.

## Known issues ##

Only small WebAssembly code fragments created using WebAssembly text
notation has been tested.

The code is only meant to demonstrate the use of the Rust SDK
and integration of tinyWASM interpreter.

The current interface with a WASM code is very limited. There are
two integer input parameters and one integer output parameter.

WASM examples are in a different repository called wasm-examples.

The secure channel is vulnerable to man-in-the-middle
attacks. Certificates should be used to mitigate these threats.

The current secure channel implementation is very limited and cannot
be used to transfer large number of data, because of constrained
message size.

There is no true randomness source.

There is a placeholder for remote attestation and there is also
attestation request and reply but the attestation evidence is not
verified.

Modified static-dh-ecdh must be used to get things compiled in no_std
environment for the enclave.

Remember to load the Keystone kernel module before trying this demo
using the modprobe command (see above).

Each qemu invocation will create a different ssh key for the sshd
server. The client connection will report that the remote host
identification has changed. You can remove the entry using the
command (assuming ssh port mapping for port 9821):

      ssh-keygen -f $HOME/.ssh/known_hosts -R "[localhost]:9821"

The code contains also quite a lot debug output.

The demonstrator requires 'eyrie-rt' and 'loader' components from
Keystone code. Those are not available in this repository. However,
these are packed to a self-extracting makeself script if this
repository is built with vector-keystone repository.

# Acknowledgment

This work is partly supported by the European Union’s Horizon Europe
research and innovation programme in the scope of the the
[CONFIDENTIAL6G](https://confidential6g.eu/) project under Grant
Agreement 101096435.
