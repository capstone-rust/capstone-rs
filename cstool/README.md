# cstool

Disassembles machine code.


## Usage

~~~
cstool [FLAGS] [OPTIONS] --arch <arch> --mode <mode> <--file <file>|--stdin|--code <code>>

FLAGS:
    -d, --detail     Print details about instructions
    -h, --help       Prints help information
    -x, --hex        Treat input has hex; only select characters that are [a-fA-F0-9]
    -s, --stdin      read binary instructions from stdin
    -V, --version    Prints version information
    -v               Sets the level of verbosity

OPTIONS:
    -r, --addr <address>      address of code
    -a, --arch <arch>         Architecture [possible values: arm, arm64, mips, x86, ppc, sparc, sysz, xcore, m68k,
                              tms320c64x, m680x, evm]
    -c, --code <code>         instruction bytes (implies --hex)
    -n, --endian <endian>     Endianness [possible values: little, big]
    -e, --extra <extra>...    Extra Mode [possible values: mclass, v8, micro]
    -f, --file <file>         input file with binary instructions
    -m, --mode <mode>         mode [possible values: arm, mode16, mode32, mode64, thumb, mips2, mips3, mips32r6, mips32,
                              mips64, v9, qpx, m68k000, m68k010, m68k020, m68k030, m68k040, m680x6301, m680x6309,
                              m680x6800, m680x6801, m680x6805, m680x6808, m680x6809, m680x6811, m680xcpu12, m680xhcs08,
                              default]
~~~

## Example

~~~
# Disassemble 32-bit X86 (non-hex characters are ignored)
cstool --arch x86 --mode mode32 --code "90 42 e812345678"
      1000:  90                                  nop
      1001:  42                                  inc     edx
      1002:  e8 12 34 56 78                      call    0x78564419
~~~

## Build

**Requirements:**

- Rust language toolchain (such as from [rustup](https://rustup.rs/))
- C compiler (such as `clang`, `gcc`, `msvc`)

**Run with cargo:**

~~~
cargo run -- [arguments]
~~~

### Build for WASI

[WebAssembly System Interface (WASI)][wasi] provides APIs to run [WebAssembly][wasm] in various contexts, not just the web.

[wasi]: https://github.com/CraneStation/wasmtime/blob/master/docs/WASI-overview.md
[wasm]: https://webassembly.org/

**Requirements:**
- `clang-8` (available at https://apt.llvm.org/)
- WASI sysroot from https://github.com/CraneStation/wasi-libc
    - Assumed to be installed at `$WASI_SYSROOT`
- `wasm-wasi` target rust toolchain (tested with Rust 1.36.0):
    ~~~
    rustup target add wasm32-wasi
    ~~~
- WASI runner to run WASI executable, such as:
    - [wasmtime](https://github.com/CraneStation/wasmtime)
    - [wasmer](https://wasmer.io/)

**Build `cstool`:**

Tell `cc` crate to use our WASI sysroot and clang-8 compiler:

~~~sh
cd cstool  # go to path with cstool dir
CFLAGS_wasm32_wasi="--sysroot="$WASI_SYSROOT" \
    CC=clang-8 \
    cargo +nightly build --target=wasm32-wasi
~~~

**Run `cstool`:**

~~~
cd cstool  # go to path with cstool dir
~~~

Run with `wasmer`:

~~~
wasmer run ../target/wasm32-wasi/debug/cstool.wasm -- --arch x86 --mode mode32 --code "90 42 e812345678"
~~~

Run with `wasmtime`:
~~~
wasmtime ../target/wasm32-wasi/debug/cstool.wasm -- --arch x86 --mode mode32 --code "90 42 e812345678"
~~~

Should give output:
~~~
      1000:  90                                  nop
      1001:  42                                  inc     edx
      1002:  e8 12 34 56 78                      call    0x78564419
~~~
