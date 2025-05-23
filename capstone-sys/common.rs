// Contains code common to the build script and main crate
//
// Needs to be included with include! macro

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// Information specific to architecture
pub struct CapstoneArchInfo<'a> {
    /// name of C header
    header_name: &'a str,

    /// name used within capstone C library
    cs_name: &'a str,
}

impl CapstoneArchInfo<'_> {
    /// Get the name of the C header
    pub fn header_name(&self) -> &str {
        self.header_name
    }

    /// Get the arch name used in Capstone types
    pub fn cs_name(&self) -> &str {
        self.cs_name
    }
}

pub static ARCH_INCLUDES: &[CapstoneArchInfo<'static>] = &[
    CapstoneArchInfo {
        header_name: "aarch64.h",
        cs_name: "aarch64",
    },
    CapstoneArchInfo {
        header_name: "arm.h",
        cs_name: "arm",
    },
    CapstoneArchInfo {
        header_name: "evm.h",
        cs_name: "evm",
    },
    CapstoneArchInfo {
        header_name: "m680x.h",
        cs_name: "m680x",
    },
    CapstoneArchInfo {
        header_name: "m68k.h",
        cs_name: "m68k",
    },
    CapstoneArchInfo {
        header_name: "mips.h",
        cs_name: "mips",
    },
    CapstoneArchInfo {
        header_name: "mos65xx.h",
        cs_name: "mos65xx",
    },
    CapstoneArchInfo {
        header_name: "ppc.h",
        cs_name: "ppc",
    },
    CapstoneArchInfo {
        header_name: "riscv.h",
        cs_name: "riscv",
    },
    CapstoneArchInfo {
        header_name: "sh.h",
        cs_name: "sh",
    },
    CapstoneArchInfo {
        header_name: "sparc.h",
        cs_name: "sparc",
    },
    CapstoneArchInfo {
        header_name: "systemz.h",
        cs_name: "systemz",
    },
    CapstoneArchInfo {
        header_name: "tms320c64x.h",
        cs_name: "tms320c64x",
    },
    CapstoneArchInfo {
        header_name: "tricore.h",
        cs_name: "tricore",
    },
    CapstoneArchInfo {
        header_name: "x86.h",
        cs_name: "x86",
    },
    CapstoneArchInfo {
        header_name: "xcore.h",
        cs_name: "xcore",
    },
    CapstoneArchInfo {
        header_name: "bpf.h",
        cs_name: "bpf"
    }
];

pub static BINDINGS_FILE: &str = "capstone.rs";
pub static BINDINGS_IMPL_FILE: &str = "capstone_archs_impl.rs";
