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

/// Canonicalize an MSVC static-init thunk symbol (`??__E<var>` dynamic
/// initializer / `??__F<var>` dynamic atexit destructor) to the
/// UnDecorateSymbolName form the original-game PDB stores:
/// `` `dynamic initializer for 'X'' `` / `` `dynamic atexit destructor for 'X'' ``.
///
/// These thunks carry no Public symbol, so both delinks fall back to the module
/// Procedure name — raw mangled on the freshly built (base) side, but already
/// demangled on the original-game (target) side. Emitting the *same* demangled
/// COFF symbol name on both sides lets objdiff pair the same thunk.
///
/// Returns `None` for any non-thunk symbol (emit it unchanged).
pub fn canonicalize_static_init_thunk(sym: &[u8]) -> Option<String> {
    let sym = std::str::from_utf8(sym).ok()?;
    let (kind, rest) = if let Some(r) = sym.strip_prefix("??__E") {
        ("dynamic initializer for", r)
    } else if let Some(r) = sym.strip_prefix("??__F") {
        ("dynamic atexit destructor for", r)
    } else {
        return None;
    };
    // NAME_ONLY drops return type / calling convention; NO_CLASS_TYPE drops the
    // `class`/`struct` keyword inside template args — both match the target form.
    let flags =
        msvc_demangler::DemangleFlags::NAME_ONLY | msvc_demangler::DemangleFlags::NO_CLASS_TYPE;
    let inner = if rest.starts_with('?') {
        // Member / templated form: `rest` is a complete mangled DATA symbol plus
        // the thunk's `@@YAXXZ` suffix; demangling the whole `??__E?…` trips the
        // demangler, so demangle the inner data symbol directly.
        let data_sym = rest.strip_suffix("@@YAXXZ").unwrap_or(rest);
        msvc_demangler::demangle(data_sym, flags).ok()?
    } else {
        // Simple / namespaced form: the whole thunk demangles to
        // `<scope>::`dynamic initializer'`; the scope is the variable name.
        let dm = msvc_demangler::demangle(sym, flags).ok()?;
        dm.strip_suffix("::`dynamic initializer'")
            .or_else(|| dm.strip_suffix("::`dynamic atexit destructor'"))?
            .to_string()
    };
    Some(format!("`{kind} '{inner}''"))
}

#[cfg(test)]
mod tests {
    use super::canonicalize_static_init_thunk as c;

    fn run(s: &str) -> Option<String> {
        c(s.as_bytes())
    }

    #[test]
    fn simple_and_namespaced() {
        assert_eq!(
            run("??__Es_application@@YAXXZ").unwrap(),
            "`dynamic initializer for 's_application''"
        );
        assert_eq!(
            run("??__Eg_allocator@engine@vostok@@YAXXZ").unwrap(),
            "`dynamic initializer for 'vostok::engine::g_allocator''"
        );
        assert_eq!(
            run("??__Fs_world@@YAXXZ").unwrap(),
            "`dynamic atexit destructor for 's_world''"
        );
    }

    #[test]
    fn templated_static_member_strips_class_keyword() {
        assert_eq!(
            run("??__E?Format@Image9GridVertex@Render@Scaleform@@2UVertexFormat@23@A@@YAXXZ")
                .unwrap(),
            "`dynamic initializer for 'Scaleform::Render::Image9GridVertex::Format''"
        );
        assert_eq!(
            run("??__E?area_max@?$tree_space_param@$01Vgrasping_tree_space_params@rtp@vostok@@@rtp@vostok@@2Vgrasping_tree_space_params@23@B@@YAXXZ")
                .unwrap(),
            "`dynamic initializer for 'vostok::rtp::tree_space_param<2,vostok::rtp::grasping_tree_space_params>::area_max''"
        );
    }

    #[test]
    fn non_thunk_untouched() {
        assert!(run("??0foo@@QAE@XZ").is_none());
        assert!(run("__FindPESection").is_none());
    }
}
