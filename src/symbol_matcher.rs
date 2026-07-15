//! Reconcile symbol names across folded groups between the target (original
//! game) and base (freshly compiled) delinks.
//!
//! The MSVC linker folds multiple identical functions / data into a single
//! location (COMDAT folding / ICF). When that happens one location carries
//! several mangled symbol names — *overloads*. The delinker has to pick one
//! name per location. Picking is fine in isolation, but target and base may
//! pick *different* names for the *same* underlying body, which makes objdiff
//! treat two otherwise-identical symbols as unrelated.
//!
//! The fix: when delinking the target we record which name it chose for every
//! folded group (`--write-symbol-map`). When delinking the base we load that
//! record (`--read-symbol-map`) and, for each folded group, try to emit the
//! exact name target chose — provided base actually has that symbol. If it
//! doesn't, we fall back to base's own local default. Because the recorded
//! choice is keyed by member name, and the member names are content-derived
//! (same source → same mangling), the two binaries correlate even though their
//! RVAs and exact overload sets differ.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use pdb2::RawString;

/// Deterministic representative for a folded symbol group: the shortest name,
/// ties broken lexicographically.
///
/// This is a pure function of the *set* of names, so two binaries that fold the
/// same names independently arrive at the same representative without any map.
/// The map is only needed when the two sides' overload sets differ.
pub fn canonical_name<'p>(overloads: &[RawString<'p>]) -> RawString<'p> {
    overloads
        .iter()
        .copied()
        .min_by(|a, b| {
            a.as_bytes()
                .len()
                .cmp(&b.as_bytes().len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes()))
        })
        .expect("symbol group must not be empty")
}

#[derive(Default, Clone, Copy)]
pub struct MatchStats {
    /// Folded references where target's recorded choice was present in base and
    /// adopted.
    pub reconciled: usize,
    /// Subset of `reconciled` where the adopted name differs from base's local
    /// default — i.e. symbols that *became the same* as target purely thanks to
    /// this reconciliation. This is the number that proves the feature works.
    pub became_same: usize,
    /// Target had a choice for the group but base lacks that exact symbol, so we
    /// kept base's local default.
    pub fallback_missing: usize,
}

pub enum SymbolMatcher {
    /// No map loaded: always emit the local default. Used on the target side and
    /// whenever neither map flag is passed.
    Off,
    /// Reconcile against a target choice map loaded from disk (base side).
    Reconcile {
        /// member mangled name -> name target chose for that folded group.
        target_choice: HashMap<Vec<u8>, Vec<u8>>,
        stats: Cell<MatchStats>,
    },
}

impl SymbolMatcher {
    pub fn off() -> Self {
        Self::Off
    }

    /// Load a `member\tchosen` map written by [`write_function_map`].
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let mut target_choice = HashMap::new();
        for line in data.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let Some(tab) = line.iter().position(|&b| b == b'\t') else {
                continue;
            };
            target_choice.insert(line[..tab].to_vec(), line[tab + 1..].to_vec());
        }
        Ok(Self::Reconcile {
            target_choice,
            stats: Cell::new(MatchStats::default()),
        })
    }

    /// Pick the name to emit for a (possibly folded) symbol group.
    ///
    /// `default` is the name this side would pick on its own. When a target map
    /// is loaded we try to adopt target's recorded choice for the group — found
    /// via any member name we share with target — provided that exact name also
    /// exists in this side's overloads. Otherwise `default` is kept.
    pub fn pick<'p>(&self, overloads: &[RawString<'p>], default: RawString<'p>) -> RawString<'p> {
        let Self::Reconcile {
            target_choice,
            stats,
        } = self
        else {
            return default;
        };
        // A single-name location is unambiguous; nothing to reconcile.
        if overloads.len() <= 1 {
            return default;
        }

        // Target recorded the same choice for every member of the group, so the
        // first member we share with target tells us what target picked.
        let Some(chosen) = overloads
            .iter()
            .find_map(|o| target_choice.get(o.as_bytes()))
        else {
            return default;
        };

        let mut s = stats.get();
        let result = match overloads.iter().find(|o| o.as_bytes() == chosen.as_slice()) {
            // Target's choice exists here too: emit it so both sides agree.
            Some(found) => {
                s.reconciled += 1;
                if found.as_bytes() != default.as_bytes() {
                    s.became_same += 1;
                }
                *found
            }
            // Target chose a name base doesn't have; keep the local default.
            None => {
                s.fallback_missing += 1;
                default
            }
        };
        stats.set(s);
        result
    }

    pub fn stats(&self) -> Option<MatchStats> {
        match self {
            Self::Reconcile { stats, .. } => Some(stats.get()),
            Self::Off => None,
        }
    }
}

/// Record, for the target side, the representative name chosen for every folded
/// function group, keyed by each member name. Serialized as `member\tchosen\n`
/// (mangled names are ASCII without tabs/newlines). Returns the number of folded
/// groups written.
pub fn write_function_map(
    path: &Path,
    functions: &BTreeMap<usize, Vec<RawString<'static>>>,
) -> anyhow::Result<usize> {
    let mut out: Vec<u8> = Vec::new();
    let mut groups = 0usize;

    for overloads in functions.values() {
        if overloads.len() <= 1 {
            continue;
        }
        let chosen = canonical_name(overloads);
        groups += 1;

        // Dedup members so a name that appears twice doesn't emit twice.
        let mut seen: Vec<&[u8]> = Vec::new();
        for member in overloads {
            let bytes = member.as_bytes();
            if seen.contains(&bytes) {
                continue;
            }
            seen.push(bytes);
            out.extend_from_slice(bytes);
            out.push(b'\t');
            out.extend_from_slice(chosen.as_bytes());
            out.push(b'\n');
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &out)?;
    Ok(groups)
}
