pub trait ToUsize {
    fn to_usize(self) -> usize;
}

pub trait ToU64 {
    fn to_u64(self) -> u64;
}

const _: () = assert!(std::mem::size_of::<usize>() == std::mem::size_of::<u64>());

impl ToUsize for u16 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

impl ToUsize for u32 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

impl ToUsize for u64 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

impl ToU64 for usize {
    fn to_u64(self) -> u64 {
        self as u64
    }
}

//
//
//

// Most of those leaks have to exist to "leak" Streams which for some reason are owning in pdb crate.
pub fn leak<T>(object: T) -> &'static T {
    Box::leak(Box::new(object))
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|s| s == needle)
}
