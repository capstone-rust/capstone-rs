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

pub static ARCH_INCLUDES: &'static [CapstoneArchInfo<'static>] = &[
    CapstoneArchInfo {
        header_name: "arm.h",
        cs_name: "arm",
    },
    CapstoneArchInfo {
        header_name: "arm64.h",
        cs_name: "arm64",
    },
    CapstoneArchInfo {
        header_name: "mips.h",
        cs_name: "mips",
    },
    CapstoneArchInfo {
        header_name: "ppc.h",
        cs_name: "ppc",
    },
    CapstoneArchInfo {
        header_name: "sparc.h",
        cs_name: "sparc",
    },
    CapstoneArchInfo {
        header_name: "systemz.h",
        cs_name: "sysz",
    },
    CapstoneArchInfo {
        header_name: "x86.h",
        cs_name: "x86",
    },
    CapstoneArchInfo {
        header_name: "xcore.h",
        cs_name: "xcore",
    },
];

pub static BINDINGS_FILE: &'static str = "capstone.rs";
