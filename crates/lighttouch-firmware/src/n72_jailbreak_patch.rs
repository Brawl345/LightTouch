use std::fmt;

pub const STOCK_SHA256: &str = "8caf1738b15fe4df99ddebb1f976b8582364af27ef738b93dcac60be1b26c63e";
pub const PATCHED_SHA256: &str = "eef2c04feb1a137c7b05020abe1b4b6d4b34d9bd3961f0f06d48b1933835ab9d";
pub const IBOOT_STOCK_SHA256: &str = "9337ac9381669f29dc7086244c6e63e1714c3c37457947602734d4446ff21f8b";
pub const IBOOT_PATCHED_SHA256: &str = "8ae8b2312d5033368775ea8ef63045b0d4b368d58f1aca963140df0435d4637f";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPatch {
    pub name: &'static str,
    pub address: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    NotTarget { image: &'static str, sha256: String },
    AlreadyPatched(&'static str),
    Missing(&'static str),
    Ambiguous(&'static str),
    UnexpectedBytes { name: &'static str, found: Vec<u8> },
    NotMachO,
    OutputHash { image: &'static str, sha256: String },
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::NotTarget { image, sha256 } => write!(f, "unsupported N72 {image} SHA-256 {sha256}"),
            PatchError::AlreadyPatched(image) => write!(f, "N72 {image} is already patched"),
            PatchError::Missing(name) => write!(f, "N72 jailbreak patch site missing: {name}"),
            PatchError::Ambiguous(name) => write!(f, "N72 jailbreak patch site occurs more than once: {name}"),
            PatchError::UnexpectedBytes { name, found } => {
                write!(f, "N72 jailbreak patch site has unexpected bytes for {name}: {}", hex::encode(found))
            }
            PatchError::NotMachO => f.write_str("N72 jailbreak target is not a mapped 32-bit Mach-O"),
            PatchError::OutputHash { image, sha256 } => {
                write!(f, "N72 jailbreak {image} patch produced unexpected SHA-256 {sha256}")
            }
        }
    }
}

impl std::error::Error for PatchError {}

impl From<PatchError> for crate::Error {
    fn from(error: PatchError) -> Self {
        crate::Error::unsupported(error.to_string())
    }
}

struct PatchSpec {
    name: &'static str,
    before: &'static [u8],
    original: &'static [u8],
    replacement: &'static [u8],
    after: &'static [u8],
}

type Located = Vec<(&'static PatchSpec, usize)>;

const IBOOT_PATCHES: &[PatchSpec] = &[
    PatchSpec {
        name: "iBoot PROD personalization",
        before: &[0x01, 0x92, 0x02, 0x92, 0x10, 0x98, 0x91, 0x49, 0x01, 0x22, 0x00, 0x23, 0x00, 0x94, 0x03, 0x94],
        original: &[0xff, 0xf7, 0x0d, 0xff],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x04, 0x1e, 0x5a, 0xd1, 0x10, 0x9c, 0x0a, 0xf0, 0x6c, 0xfd, 0x00, 0x21, 0x00, 0x91, 0x03, 0x91],
    },
    PatchSpec {
        name: "iBoot SEPO personalization",
        before: &[0x01, 0x40, 0x00, 0x91, 0x00, 0x21, 0x01, 0x91, 0x02, 0x91, 0x03, 0x91, 0x20, 0x1c, 0x78, 0x49],
        original: &[0xff, 0xf7, 0xd9, 0xfe],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x04, 0x1e, 0x26, 0xd1, 0x10, 0x9a, 0x93, 0x46, 0x02, 0xf0, 0x17, 0xfd, 0x00, 0x23, 0x74, 0x49],
    },
    PatchSpec {
        name: "iBoot ECID personalization",
        before: &[0x6c, 0x49, 0x06, 0x9a, 0x07, 0x9b, 0x00, 0x94, 0x02, 0x94, 0x03, 0x94, 0x01, 0x90, 0x58, 0x46],
        original: &[0xff, 0xf7, 0xb5, 0xfe],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x04, 0x1e, 0x02, 0xd1, 0x00, 0x20, 0x08, 0x90, 0x0e, 0xe0, 0x28, 0x69, 0x81, 0x07, 0x00, 0xd5],
    },
    PatchSpec {
        name: "iBoot RSA signature",
        before: &[0x1c, 0x43, 0xa8, 0x42, 0xf7, 0xd2, 0x00, 0x2c, 0x01, 0xd1, 0x00, 0x20, 0x01, 0xe0, 0x01, 0x20],
        original: &[0x40, 0x42],
        replacement: &[0x00, 0x20],
        after: &[0x88, 0x23, 0xdb, 0x00, 0x6b, 0x44, 0x51, 0x46, 0x1a, 0x68, 0x0b, 0x68, 0x9a, 0x42, 0x01, 0xd0],
    },
];

const KERNEL_PATCHES: &[PatchSpec] = &[
    PatchSpec {
        name: "vm_map_enter executable memory",
        before: &[0x5b, 0x0f, 0x0f, 0x90, 0x8b, 0x46, 0x92, 0x46, 0x00, 0x2b, 0x2e, 0xd1, 0x35, 0x98, 0x80, 0x07],
        original: &[0x33, 0xd4],
        replacement: &[0x00, 0x28],
        after: &[0x6b, 0x08, 0x1e, 0x1c, 0xeb, 0x0a, 0x01, 0x22, 0x1c, 0x1c, 0x16, 0x40, 0x14, 0x40, 0x18, 0x94],
    },
    PatchSpec {
        name: "code-signing enforcement flag",
        before: &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        original: &[0x00],
        replacement: &[0x01],
        after: &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    },
    PatchSpec {
        name: "Image3 PROD personalization",
        before: &[0x58, 0x46, 0x2a, 0x49, 0x01, 0x22, 0x00, 0x23, 0x00, 0x94, 0x01, 0x95, 0x02, 0x95, 0x03, 0x94],
        original: &[0xff, 0xf7, 0x16, 0xff],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x00, 0x28, 0x1f, 0xd0, 0x1c, 0xe0, 0x00, 0x21, 0x00, 0x91, 0x01, 0x91, 0x02, 0x91, 0x03, 0x91],
    },
    PatchSpec {
        name: "Image3 ECID personalization",
        before: &[0x00, 0x90, 0x01, 0x90, 0x02, 0x90, 0x03, 0x90, 0x06, 0x9a, 0x07, 0x9b, 0x58, 0x46, 0x1c, 0x49],
        original: &[0xff, 0xf7, 0xfc, 0xfe],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x43, 0x42, 0x18, 0x43, 0xc0, 0x0f, 0x12, 0xe0, 0x19, 0x48, 0x10, 0xe0, 0x01, 0x20, 0x0e, 0xe0],
    },
    PatchSpec {
        name: "Image3 SHSH certificate type",
        before: &[0x01, 0x92, 0x90, 0x47, 0x00, 0x28, 0x00, 0xd0, 0xb5, 0xe0, 0x06, 0x98, 0x02, 0x21, 0x6d, 0x4b],
        original: &[0x98, 0x47],
        replacement: &[0x00, 0x20],
        after: &[0x00, 0x28, 0x00, 0xd0, 0xae, 0xe0, 0x06, 0x98, 0xff, 0xf7, 0xa8, 0xfd, 0x05, 0x1e, 0x00, 0xd0],
    },
    PatchSpec {
        name: "Image3 manifest personalization",
        before: &[0x06, 0x98, 0x02, 0x21, 0x6d, 0x4b, 0x98, 0x47, 0x00, 0x28, 0x00, 0xd0, 0xae, 0xe0, 0x06, 0x98],
        original: &[0xff, 0xf7, 0xa8, 0xfd],
        replacement: &[0x00, 0x20, 0x00, 0x20],
        after: &[0x05, 0x1e, 0x00, 0xd0, 0xa8, 0xe0, 0x03, 0x9b, 0x1a, 0x69, 0x68, 0x4b, 0x9a, 0x42, 0x00, 0xd0],
    },
    PatchSpec {
        name: "Image3 RSA signature",
        before: &[0x33, 0x4b, 0x98, 0x47, 0x00, 0x28, 0x1f, 0xd1, 0x21, 0x4c, 0x20, 0xe0, 0x20, 0x1c, 0x03, 0x99],
        original: &[0xff, 0xf7, 0x6c, 0xfc],
        replacement: &[0x01, 0x20, 0x01, 0x20],
        after: &[0x00, 0x28, 0x21, 0xd0, 0xe0, 0x6f, 0x03, 0x99, 0x42, 0x46, 0x2c, 0x4b, 0x98, 0x47, 0x00, 0x28],
    },
    PatchSpec {
        name: "Image3 PKCS#1 digest validation",
        before: &[0x01, 0x31, 0x01, 0x30, 0x53, 0x40, 0x1c, 0x43, 0xa8, 0x42, 0xf7, 0xd9, 0x00, 0x2c, 0x00, 0xd0],
        original: &[0xff],
        replacement: &[0x00],
        after: &[0x24, 0x30, 0x1c, 0x51, 0x46, 0x09, 0x4b, 0x98, 0x47, 0x12, 0xb0, 0x20, 0x1c, 0x1c, 0xbc, 0x90],
    },
    PatchSpec {
        name: "AMFI certificate lookup",
        before: &[0x24, 0x30, 0x9f, 0xe5, 0x33, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x50, 0xe3, 0x00, 0x00, 0x00, 0x0a],
        original: &[0x00],
        replacement: &[0x01],
        after: &[0x40, 0xa0, 0xe3, 0x04, 0x00, 0xa0, 0xe1, 0x90, 0x80, 0xbd, 0xe8, 0x04, 0x96, 0x45, 0xc0, 0x7b],
    },
    PatchSpec {
        name: "AMFI certificate chain validation",
        before: &[0x81, 0xe5, 0x14, 0x20, 0x97, 0xe5, 0x00, 0x00, 0x82, 0xe5, 0x1c, 0x00, 0x00, 0xea, 0x00, 0x00],
        original: &[0xe0],
        replacement: &[0xa0],
        after: &[0xe3, 0x1a, 0x00, 0x00, 0xea, 0xc8, 0x30, 0x17, 0xe5, 0xc4, 0x40, 0x17, 0xe5, 0xbc, 0xa0, 0x17],
    },
];

pub fn apply_iboot(iboot: &[u8]) -> Result<Vec<u8>, PatchError> {
    let (out, _) = apply_verified("iBoot", iboot, IBOOT_STOCK_SHA256, IBOOT_PATCHED_SHA256, IBOOT_PATCHES)?;
    Ok(out)
}

pub fn apply(kernel: &[u8]) -> Result<(Vec<u8>, Vec<AppliedPatch>), PatchError> {
    let (out, located) = apply_verified("kernel", kernel, STOCK_SHA256, PATCHED_SHA256, KERNEL_PATCHES)?;
    let image = crate::sandbox_patch::Image::new(kernel).map_err(|_| PatchError::NotMachO)?;
    let patches = located
        .into_iter()
        .map(|(spec, offset)| {
            let address = image.off_to_addr(offset).ok_or(PatchError::NotMachO)?;
            Ok(AppliedPatch { name: spec.name, address })
        })
        .collect::<Result<_, PatchError>>()?;
    Ok((out, patches))
}

fn apply_verified(
    image: &'static str,
    input: &[u8],
    stock: &str,
    patched: &str,
    specs: &'static [PatchSpec],
) -> Result<(Vec<u8>, Located), PatchError> {
    let sha256 = crate::files::sha256(input);
    if sha256 == patched {
        return Err(PatchError::AlreadyPatched(image));
    }
    if sha256 != stock {
        return Err(PatchError::NotTarget { image, sha256 });
    }
    let (out, located) = apply_specs(input, specs)?;
    let sha256 = crate::files::sha256(&out);
    if sha256 != patched {
        return Err(PatchError::OutputHash { image, sha256 });
    }
    Ok((out, located))
}

fn apply_specs(input: &[u8], specs: &'static [PatchSpec]) -> Result<(Vec<u8>, Located), PatchError> {
    let mut out = input.to_vec();
    let mut located = Vec::with_capacity(specs.len());
    for spec in specs {
        let offset = locate(input, spec)?;
        let slot = &mut out[offset..offset + spec.original.len()];
        if slot != spec.original {
            return Err(PatchError::UnexpectedBytes { name: spec.name, found: slot.to_vec() });
        }
        slot.copy_from_slice(spec.replacement);
        located.push((spec, offset));
    }
    Ok((out, located))
}

fn locate(input: &[u8], spec: &PatchSpec) -> Result<usize, PatchError> {
    let required = spec.before.len() + spec.original.len() + spec.after.len();
    let mut hit = None;
    for (start, window) in input.windows(required).enumerate() {
        if window.starts_with(spec.before)
            && window.ends_with(spec.after)
            && hit.replace(start + spec.before.len()).is_some()
        {
            return Err(PatchError::Ambiguous(spec.name));
        }
    }
    hit.ok_or(PatchError::Missing(spec.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(spec: &PatchSpec, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x5a; 7];
        out.extend_from_slice(spec.before);
        out.extend_from_slice(bytes);
        out.extend_from_slice(spec.after);
        out.extend_from_slice(&[0xa5; 7]);
        out
    }

    #[test]
    fn locates_and_patches_unique_sites() {
        let input: Vec<u8> = KERNEL_PATCHES.iter().flat_map(|spec| block(spec, spec.original)).collect();
        let (patched, found) = apply_specs(&input, KERNEL_PATCHES).unwrap();
        assert_eq!(found.len(), KERNEL_PATCHES.len());
        for (spec, offset) in found {
            assert_eq!(&patched[offset..offset + spec.replacement.len()], spec.replacement);
        }
    }

    #[test]
    fn missing_site_is_refused() {
        assert_eq!(locate(&[], &KERNEL_PATCHES[0]), Err(PatchError::Missing(KERNEL_PATCHES[0].name)));
    }

    #[test]
    fn duplicate_site_is_refused() {
        let spec = &KERNEL_PATCHES[0];
        let mut input = block(spec, spec.original);
        input.extend(block(spec, spec.original));
        assert_eq!(locate(&input, spec), Err(PatchError::Ambiguous(spec.name)));
    }

    #[test]
    fn unexpected_original_bytes_are_refused() {
        let spec = &KERNEL_PATCHES[0];
        let input = block(spec, &[0xaa, 0xbb]);
        assert_eq!(
            apply_specs(&input, std::slice::from_ref(spec)).err(),
            Some(PatchError::UnexpectedBytes { name: spec.name, found: vec![0xaa, 0xbb] })
        );
    }

    #[test]
    #[ignore = "set LTM_N72_7E18_IBOOT to the decrypted iPod2,1 3.1.3 iBoot.bin"]
    fn patches_the_verified_iboot() {
        let iboot = std::fs::read(std::env::var("LTM_N72_7E18_IBOOT").unwrap()).unwrap();
        let patched = apply_iboot(&iboot).unwrap();
        assert_eq!(crate::files::sha256(&patched), IBOOT_PATCHED_SHA256);
        assert_eq!(apply_iboot(&patched), Err(PatchError::AlreadyPatched("iBoot")));
    }

    #[test]
    #[ignore = "set LTM_N72_7E18_KERNEL to the decrypted iPod2,1 3.1.3 kernelcache.mach"]
    fn patches_the_verified_kernel() {
        let kernel = std::fs::read(std::env::var("LTM_N72_7E18_KERNEL").unwrap()).unwrap();
        let (patched, report) = apply(&kernel).unwrap();
        assert_eq!(crate::files::sha256(&patched), PATCHED_SHA256);
        assert_eq!(apply(&patched), Err(PatchError::AlreadyPatched("kernel")));
        assert_eq!(
            report.iter().map(|patch| patch.address).collect::<Vec<_>>(),
            vec![
                0xc0046af2, 0xc020daac, 0xc0432260, 0xc0432294, 0xc043262e, 0xc0432638, 0xc0432748, 0xc0432fd0,
                0xc044d08c, 0xc0451222,
            ]
        );
    }
}
