use crate::manifest_tsv::{self, column, field};
use crate::pdb_symbols::PdbSymbols;

use nom::{IResult, Parser};
use pdb2::RawString;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Identities come from the PDB: each row names the PDB data symbol that starts
/// at its RVA.
const PDB_HEADER: &[u8] =
    b"object\trva\tsize\tstorage\talignment\tsection_ordinal\tsection_offset\tscope";

/// Identities come from the manifest itself, for images whose PDB is synthetic
/// or incomplete. `provenance` is free text, except that a value starting with
/// `provisional-` marks the row as an extent hypothesis (see `DataDefinition`).
const NAMED_HEADER: &[u8] = b"name\tobject\trva\tsize\tstorage\talignment\tsection_ordinal\tsection_offset\tscope\tprovenance";

const PROVISIONAL_PREFIX: &[u8] = b"provisional-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Schema {
    Pdb,
    Named,
}

const SCHEMAS: &[(&[u8], Schema)] = &[(PDB_HEADER, Schema::Pdb), (NAMED_HEADER, Schema::Named)];

impl Schema {
    fn column_count(self) -> &'static str {
        match self {
            Self::Pdb => "eight",
            Self::Named => "ten",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ManifestRow<'a> {
    name: Option<&'a [u8]>,
    object: &'a [u8],
    rva: &'a [u8],
    size: &'a [u8],
    storage: &'a [u8],
    alignment: &'a [u8],
    section_ordinal: &'a [u8],
    section_offset: &'a [u8],
    scope: &'a [u8],
    provenance: Option<&'a [u8]>,
}

fn pdb_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, (object, rva, size, storage, alignment, section_ordinal, section_offset, scope)) =
        (
            column, column, column, column, column, column, column, field,
        )
            .parse(input)?;

    Ok((
        input,
        ManifestRow {
            name: None,
            object,
            rva,
            size,
            storage,
            alignment,
            section_ordinal,
            section_offset,
            scope,
            provenance: None,
        },
    ))
}

fn named_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, (name, object, rva, size, storage, alignment, section_ordinal, section_offset)) = (
        column, column, column, column, column, column, column, column,
    )
        .parse(input)?;
    let (input, (scope, provenance)) = (column, field).parse(input)?;

    Ok((
        input,
        ManifestRow {
            name: Some(name),
            object,
            rva,
            size,
            storage,
            alignment,
            section_ordinal,
            section_offset,
            scope,
            provenance: Some(provenance),
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DataStorage {
    Data,
    Rdata,
    Bss,
}

/// Source-level linkage of a reviewed definition; see `docs/scope.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataScope {
    /// Non-`static` global (external linkage) — emitted `SymbolScope::Linkage`.
    External,
    /// `static` / anonymous-namespace (internal linkage) — emitted `SymbolScope::Compilation`.
    Local,
}

#[derive(Clone, Copy, Debug)]
pub struct DataDefinition {
    pub symbol_name: RawString<'static>,
    pub object: &'static [u8],
    pub rva: usize,
    pub size: usize,
    pub storage: DataStorage,
    pub alignment: u64,
    pub section_ordinal: Option<usize>,
    pub section_offset: Option<usize>,
    pub scope: DataScope,
    /// An extent hypothesis rather than proven ownership. It is still emitted,
    /// but it may overlap other rows, it never answers `owner_and_addend_for_rva`,
    /// and it only names a relocation target that no proven row contains.
    pub provisional: bool,
}

impl DataDefinition {
    fn contains(&self, rva: usize) -> bool {
        self.rva <= rva && rva - self.rva < self.size
    }

    fn emission_key(&self) -> (&'static [u8], DataStorage, usize, usize, usize) {
        (
            self.object,
            self.storage,
            self.section_ordinal.unwrap_or(0),
            self.section_offset.unwrap_or(self.rva),
            self.rva,
        )
    }

    /// One COMDAT that the compiler emitted into several objects and the linker
    /// folded onto one RVA: every column but the object agrees. This is the
    /// definition-level analogue of `compatible_folded_comdat_alias` for sections.
    fn is_folded_copy_of(&self, other: &Self) -> bool {
        self.object != other.object
            && self.symbol_name == other.symbol_name
            && self.rva == other.rva
            && self.size == other.size
            && self.storage == other.storage
            && self.alignment == other.alignment
            && self.scope == DataScope::External
            && other.scope == DataScope::External
    }
}

type FoldedComdatKey = (&'static [u8], usize, usize, DataStorage, u64);

#[derive(Default)]
pub struct DataManifest {
    /// Every row, in emission order.
    definitions: Vec<DataDefinition>,
    /// Proven rows sorted by RVA; only folded copies share an extent.
    owners: Vec<DataDefinition>,
    /// Every definition's start and scope, by name.
    names: HashMap<&'static [u8], Vec<(usize, DataScope)>>,
}

impl DataManifest {
    pub fn load(path: Option<&Path>, symbols: &PdbSymbols) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path, symbols)
    }

    fn parse(bytes: &[u8], path: &Path, symbols: &PdbSymbols) -> anyhow::Result<Self> {
        let mut definitions = Vec::new();
        let mut rvas = HashSet::new();
        let mut external_names = HashSet::new();
        let mut object_names = HashMap::new();
        let mut folded_comdat_owners = HashMap::<FoldedComdatKey, HashSet<&[u8]>>::new();

        let (schema, rows) = manifest_tsv::read(bytes, path, "data manifest", SCHEMAS)?;
        for line in rows {
            let row = match schema {
                Schema::Pdb => line.columns(pdb_row, schema.column_count())?,
                Schema::Named => line.columns(named_row, schema.column_count())?,
            };
            let object = line.object(row.object)?;
            for (field, value) in [("name", row.name), ("provenance", row.provenance)] {
                if let Some(value) = value {
                    line.non_empty_text(field, value)?;
                }
            }

            let rva = line.number("rva", row.rva)?;
            let size = line.number("size", row.size)?;
            if size == 0 {
                anyhow::bail!("{line}: data size must be non-zero");
            }
            if rva.checked_add(size).is_none() {
                anyhow::bail!("{line}: data extent overflows the address space");
            }
            let storage = match row.storage {
                b"data" => DataStorage::Data,
                b"rdata" => DataStorage::Rdata,
                b"bss" => DataStorage::Bss,
                value => anyhow::bail!(
                    "{line}: unsupported storage {}",
                    String::from_utf8_lossy(value)
                ),
            };
            let alignment = line.number("alignment", row.alignment)? as u64;
            if alignment == 0 || !alignment.is_power_of_two() {
                anyhow::bail!("{line}: alignment must be a non-zero power of two");
            }
            let section_offset = if row.section_offset == b"-" {
                None
            } else {
                let offset = line.number("section_offset", row.section_offset)?;
                if offset.checked_add(size).is_none() {
                    anyhow::bail!("{line}: candidate data extent overflows the object section");
                }
                Some(offset)
            };
            let section_ordinal = if row.section_ordinal == b"-" {
                None
            } else {
                let ordinal = line.number("section_ordinal", row.section_ordinal)?;
                if ordinal == 0 {
                    anyhow::bail!("{line}: section ordinal must be non-zero");
                }
                Some(ordinal)
            };
            if section_ordinal.is_some() && section_offset.is_none() {
                anyhow::bail!("{line}: a section ordinal requires a section offset");
            }
            let scope = match row.scope {
                b"external" => DataScope::External,
                b"local" => DataScope::Local,
                value => anyhow::bail!(
                    "{line}: unsupported scope {}",
                    String::from_utf8_lossy(value)
                ),
            };
            let provisional = row
                .provenance
                .is_some_and(|provenance| provenance.starts_with(PROVISIONAL_PREFIX));

            let symbol_name = match row.name {
                Some(name) => RawString::from(&*name.to_vec().leak()),
                None => match storage {
                    DataStorage::Data | DataStorage::Bss => {
                        symbols.statics.get(&rva).map(|symbol| symbol.name)
                    }
                    DataStorage::Rdata => symbols
                        .constants
                        .get(&rva)
                        .map(|symbol| symbol.name)
                        .or_else(|| symbols.strings.get(&rva).map(|(name, _)| *name)),
                }
                .ok_or_else(|| {
                    anyhow::anyhow!("{line}: no compatible PDB data symbol starts at RVA {rva:#x}")
                })?,
            };
            let name: &'static [u8] = symbol_name.as_bytes();

            let folded_copy = scope == DataScope::External
                && match folded_comdat_owners.entry((name, rva, size, storage, alignment)) {
                    Entry::Occupied(mut owners) => {
                        if !owners.get_mut().insert(object) {
                            anyhow::bail!("{line}: duplicate data definition in one object");
                        }
                        true
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(HashSet::from([object]));
                        false
                    }
                };
            if !provisional && !folded_copy && !rvas.insert(rva) {
                anyhow::bail!("{line}: duplicate data RVA");
            }
            if scope == DataScope::External && !folded_copy && !external_names.insert(name) {
                anyhow::bail!("{line}: duplicate external data name {symbol_name}");
            }
            // An object cannot define one name twice, whatever the scopes.
            if let Some(defined) = object_names.insert((object, name), scope) {
                anyhow::bail!(
                    "{line}: duplicate {} data name {symbol_name}",
                    match (defined, scope) {
                        (DataScope::Local, DataScope::Local) => "local",
                        _ => "external and local",
                    }
                );
            }

            definitions.push(DataDefinition {
                symbol_name,
                object,
                rva,
                size,
                storage,
                alignment,
                section_ordinal,
                section_offset,
                scope,
                provisional,
            });
        }

        let mut owners = definitions
            .iter()
            .filter(|definition| !definition.provisional)
            .copied()
            .collect::<Vec<_>>();
        owners.sort_by_key(|definition| (definition.rva, definition.emission_key()));
        for pair in owners.windows(2) {
            if pair[0].rva.checked_add(pair[0].size).unwrap() > pair[1].rva
                && !pair[1].is_folded_copy_of(&pair[0])
            {
                anyhow::bail!(
                    "{}: overlapping data manifest definitions {} at {:#x} and {} at {:#x}",
                    path.display(),
                    pair[0].symbol_name,
                    pair[0].rva,
                    pair[1].symbol_name,
                    pair[1].rva
                );
            }
        }
        definitions.sort_by_key(DataDefinition::emission_key);
        let mut names = HashMap::<_, Vec<_>>::new();
        for definition in &definitions {
            names
                .entry(definition.symbol_name.as_bytes())
                .or_default()
                .push((definition.rva, definition.scope));
        }
        Ok(Self {
            definitions,
            owners,
            names,
        })
    }

    #[cfg(test)]
    pub fn definitions(&self) -> Vec<DataDefinition> {
        let mut definitions = self.definitions.clone();
        definitions.sort_by_key(|definition| (definition.rva, definition.emission_key()));
        definitions
    }

    pub fn definitions_in_emission_order(&self) -> &[DataDefinition] {
        &self.definitions
    }

    /// Whether a row defines `name` as an external, or at `rva` in any scope.
    pub fn defines(&self, name: &[u8], rva: usize) -> bool {
        self.names.get(name).is_some_and(|definitions| {
            definitions
                .iter()
                .any(|(start, scope)| *scope == DataScope::External || *start == rva)
        })
    }

    /// The proven definition containing `rva`. Among folded copies the first in
    /// emission order answers; they share every column but the object.
    pub fn owner_and_addend_for_rva(&self, rva: usize) -> Option<(DataDefinition, usize)> {
        let mut index = self
            .owners
            .partition_point(|definition| definition.rva <= rva)
            .checked_sub(1)?;
        while index > 0 && self.owners[index - 1].rva == self.owners[index].rva {
            index -= 1;
        }
        let definition = self.owners[index];
        definition
            .contains(rva)
            .then_some((definition, rva - definition.rva))
    }

    /// The provisional definition of `storage` containing `rva`, for a target no
    /// proven row owns: the nearest start wins, then the lower candidate offset.
    pub fn provisional_owner_and_addend_for_rva(
        &self,
        rva: usize,
        storage: DataStorage,
    ) -> Option<(DataDefinition, usize)> {
        let definition = self
            .definitions
            .iter()
            .filter(|definition| {
                definition.provisional && definition.storage == storage && definition.contains(rva)
            })
            .min_by_key(|definition| {
                (
                    rva - definition.rva,
                    definition.section_offset.unwrap_or(definition.rva),
                    definition.symbol_name.as_bytes(),
                )
            })?;
        Some((*definition, rva - definition.rva))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_TEXT: &str =
        "object\trva\tsize\tstorage\talignment\tsection_ordinal\tsection_offset\tscope\n";

    fn symbols() -> PdbSymbols {
        let mut symbols = PdbSymbols::default();
        for (rva, name) in [
            (0x100, &b"table"[..]),
            (0x110, &b"overlap"[..]),
            (0x120, &b"adjacent"[..]),
            (0x140, &b"later"[..]),
            (0x180, &b"\x80raw"[..]),
            (0x300, &b"scratch"[..]),
        ] {
            symbols.statics.insert(
                rva,
                crate::pdb_symbols::PdbDataSymbol::new(RawString::from(name), None),
            );
        }
        symbols.constants.insert(
            0x200,
            crate::pdb_symbols::PdbDataSymbol::new(RawString::from(&b"constant"[..]), None),
        );
        symbols
    }

    fn parse(body: &str) -> anyhow::Result<DataManifest> {
        DataManifest::parse(body.as_bytes(), Path::new("test.tsv"), &symbols())
    }

    fn manifest(row: &str) -> String {
        format!("{HEADER_TEXT}{row}\n")
    }

    fn error(row: &str) -> String {
        parse(&manifest(row)).err().unwrap().to_string()
    }

    #[test]
    fn absent_manifest_supplies_no_reviewed_definitions() {
        let parsed = DataManifest::load(None, &symbols()).unwrap();
        assert!(parsed.definitions().is_empty());
    }

    #[test]
    fn accepts_comments_crlf_paths_and_all_storage_classes() {
        let text = concat!(
            "# generated evidence\r\n",
            "object\trva\tsize\tstorage\talignment\tsection_ordinal\tsection_offset\tscope\r\n",
            "engine/world.c\t0x100\t0x20\tdata\t0x4\t-\t0\texternal\r\n",
            "engine/constants.c\t0X200\t16\trdata\t8\t-\t-\tlocal\r\n",
            "engine/state.c\t0x300\t4\tbss\t1\t-\t0\texternal\r\n",
        );
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.definitions().len(), 3);
        let table = parsed
            .definitions()
            .into_iter()
            .find(|row| row.symbol_name.as_bytes() == b"table")
            .unwrap();
        assert_eq!(table.object, b"engine\\world.c");
        assert_eq!(table.storage, DataStorage::Data);
        assert_eq!(table.alignment, 4);
        assert_eq!(table.section_offset, Some(0));
        assert!(
            parsed
                .definitions()
                .iter()
                .any(|row| row.symbol_name.as_bytes() == b"constant")
        );
        let constant = parsed
            .definitions()
            .into_iter()
            .find(|row| row.symbol_name.as_bytes() == b"constant")
            .unwrap();
        assert_eq!(constant.section_offset, None);
        assert_eq!(constant.scope, DataScope::Local);
    }

    #[test]
    fn accepts_missing_final_line_ending_and_uses_raw_pdb_symbol_bytes() {
        let mut bytes = PDB_HEADER.to_vec();
        bytes.extend_from_slice(b"\nu.c\t0x180\t4\tdata\t4\t-\t0\texternal");
        let parsed = DataManifest::parse(&bytes, Path::new("test.tsv"), &symbols()).unwrap();
        assert_eq!(parsed.definitions()[0].symbol_name.as_bytes(), b"\x80raw");
    }

    #[test]
    fn rejects_bare_carriage_return_line_endings() {
        let mut bytes = PDB_HEADER.to_vec();
        bytes.extend_from_slice(b"\ru.c\t0x100\t4\tdata\t4\t-\t0\texternal");
        let error = DataManifest::parse(&bytes, Path::new("test.tsv"), &symbols())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("invalid line ending"));
    }

    #[test]
    fn rejects_missing_header() {
        assert!(
            parse("# only a comment\n")
                .err()
                .unwrap()
                .to_string()
                .contains("missing")
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_headers() {
        assert!(
            parse("object\trva\n")
                .err()
                .unwrap()
                .to_string()
                .contains("invalid")
        );
        let duplicate = format!("{HEADER_TEXT}{HEADER_TEXT}");
        assert!(
            parse(&duplicate)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn rejects_wrong_column_counts() {
        assert!(error("u.c\t0x100\t4\tdata\t4\t-\t0").contains("exactly eight"));
        assert!(error("u.c\t0x100\t4\tdata\t4\t-\t0\texternal\textra").contains("exactly eight"));
    }

    #[test]
    fn rejects_absolute_drive_and_non_normalized_object_paths() {
        for object in [
            "/tmp/u.c",
            "\\tmp\\u.c",
            "C:\\src\\u.c",
            "C:u.c",
            "\\\\server\\share\\u.c",
            "a/../u.c",
            "a/./u.c",
            "a//u.c",
        ] {
            let row = format!("{object}\t0x100\t4\tdata\t4\t-\t0\texternal");
            assert!(
                error(&row).contains("relative and normalized"),
                "accepted {object}"
            );
        }
    }

    #[test]
    fn rejects_nul_and_control_bytes_in_text_fields() {
        for row in [
            "a\0b.c\t0x100\t4\tdata\t4\t-\t0\texternal",
            "u\x7f.c\t0x100\t4\tdata\t4\t-\t0\texternal",
        ] {
            assert!(error(row).contains("control byte"));
        }
    }

    #[test]
    fn rejects_allocations_without_compatible_pdb_symbols() {
        assert!(error("u.c\t0x101\t4\tdata\t4\t-\t0\texternal").contains("PDB data symbol"));
        assert!(error("u.c\t0x100\t4\trdata\t4\t-\t0\texternal").contains("PDB data symbol"));
    }

    #[test]
    fn rejects_duplicate_rvas() {
        for second in [
            "two.c\t0x100\t8\tdata\t4\t-\t0\texternal",
            "two.c\t0x100\t4\tdata\t8\t-\t0\texternal",
            "two.c\t0x100\t4\tdata\t4\t-\t0\tlocal",
        ] {
            let text = format!("{HEADER_TEXT}one.c\t0x100\t4\tdata\t4\t-\t0\texternal\n{second}\n");
            assert!(
                parse(&text)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("duplicate data RVA"),
                "accepted {second}"
            );
        }
    }

    #[test]
    fn accepts_one_folded_comdat_claimed_by_several_objects() {
        let text = format!(
            "{HEADER_TEXT}one.c\t0x100\t4\tdata\t4\t-\t0\texternal\n\
             two.c\t0x100\t4\tdata\t4\t-\t0\texternal\n\
             three.c\t0x100\t4\tdata\t4\t-\t0\texternal\n"
        );
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.definitions().len(), 3);
        let (owner, addend) = parsed.owner_and_addend_for_rva(0x102).unwrap();
        assert_eq!(owner.symbol_name.as_bytes(), b"table");
        assert_eq!(owner.object, b"one.c");
        assert_eq!(addend, 2);

        let repeated = format!(
            "{HEADER_TEXT}one.c\t0x100\t4\tdata\t4\t-\t0\texternal\n\
             one.c\t0x100\t4\tdata\t4\t-\t0\texternal\n"
        );
        assert!(
            parse(&repeated)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate data definition in one object")
        );
    }

    const NAMED_HEADER_TEXT: &str = "name\tobject\trva\tsize\tstorage\talignment\tsection_ordinal\tsection_offset\tscope\tprovenance\n";

    fn named(rows: &str) -> anyhow::Result<DataManifest> {
        parse(&format!("{NAMED_HEADER_TEXT}{rows}"))
    }

    #[test]
    fn named_rows_carry_their_own_identities() {
        let parsed = named(
            "??_C@_05FOO@foo?$AA@\tu.c\t0x900\t6\trdata\t1\t2\t0\texternal\tcandidate\n\
             g_local\tu.c\t0x910\t4\tbss\t4\t-\t-\tlocal\treviewed\n",
        )
        .unwrap();
        let definitions = parsed.definitions();
        assert_eq!(
            definitions[0].symbol_name.as_bytes(),
            b"??_C@_05FOO@foo?$AA@"
        );
        assert_eq!(definitions[0].section_ordinal, Some(2));
        assert_eq!(definitions[1].symbol_name.as_bytes(), b"g_local");
        assert!(parsed.defines(b"g_local", 0x910));
        assert!(!parsed.defines(b"g_local", 0x4000));
        assert!(parsed.defines(b"??_C@_05FOO@foo?$AA@", 0x4000));
        assert!(!parsed.defines(b"table", 0x100));
        for row in [
            "\tu.c\t0x900\t4\tdata\t4\t-\t-\texternal\treviewed\n",
            "x\tu.c\t0x900\t4\tdata\t4\t-\t-\texternal\t\n",
        ] {
            assert!(named(row).err().unwrap().to_string().contains("non-empty"));
        }
        assert!(
            named("x\tu.c\t0x900\t4\tdata\t4\t-\t-\texternal\n")
                .err()
                .unwrap()
                .to_string()
                .contains("exactly ten")
        );
    }

    #[test]
    fn named_external_names_are_unique_and_local_names_unique_per_object() {
        assert!(
            named(
                "x\tone.c\t0x900\t4\tdata\t4\t-\t-\texternal\treviewed\n\
                 x\ttwo.c\t0x910\t4\tdata\t4\t-\t-\texternal\treviewed\n"
            )
            .err()
            .unwrap()
            .to_string()
            .contains("duplicate external data name x")
        );
        assert_eq!(
            named(
                "s\tone.c\t0x900\t4\tdata\t4\t-\t-\tlocal\treviewed\n\
                 s\ttwo.c\t0x910\t4\tdata\t4\t-\t-\tlocal\treviewed\n"
            )
            .unwrap()
            .definitions()
            .len(),
            2
        );
        assert!(
            named(
                "s\tone.c\t0x900\t4\tdata\t4\t-\t-\tlocal\treviewed\n\
                 s\tone.c\t0x910\t4\tdata\t4\t-\t-\tlocal\treviewed\n"
            )
            .err()
            .unwrap()
            .to_string()
            .contains("duplicate local data name s")
        );
        for rows in [
            "s\tone.c\t0x900\t4\tdata\t4\t-\t-\texternal\treviewed\n\
             s\tone.c\t0x910\t4\tdata\t4\t-\t-\tlocal\treviewed\n",
            "s\tone.c\t0x900\t4\tdata\t4\t-\t-\tlocal\treviewed\n\
             s\tone.c\t0x910\t4\tdata\t4\t-\t-\texternal\treviewed\n",
        ] {
            let error = named(rows).err().unwrap().to_string();
            assert!(
                error.contains("duplicate external and local data name s"),
                "{error}"
            );
        }
    }

    #[test]
    fn provisional_rows_are_emitted_but_own_only_uncovered_targets() {
        let parsed = named(
            "gap\tone.c\t0x900\t0x20\tdata\t4\t-\t-\texternal\tprovisional-band-gap\n\
             proved\ttwo.c\t0x910\t4\tdata\t4\t-\t-\texternal\treviewed\n\
             near\tthree.c\t0x908\t0x10\tdata\t4\t-\t-\texternal\tprovisional-band-gap\n\
             zero\tfour.c\t0x908\t4\tbss\t4\t-\t-\texternal\tprovisional-band-gap\n",
        )
        .unwrap();
        assert_eq!(parsed.definitions_in_emission_order().len(), 4);
        assert_eq!(
            parsed.owner_and_addend_for_rva(0x912).unwrap().0.object,
            b"two.c"
        );
        assert!(parsed.owner_and_addend_for_rva(0x904).is_none());
        let (owner, addend) = parsed
            .provisional_owner_and_addend_for_rva(0x90c, DataStorage::Data)
            .unwrap();
        assert_eq!((owner.symbol_name.as_bytes(), addend), (&b"near"[..], 4));
        let (owner, addend) = parsed
            .provisional_owner_and_addend_for_rva(0x904, DataStorage::Data)
            .unwrap();
        assert_eq!((owner.symbol_name.as_bytes(), addend), (&b"gap"[..], 4));
        assert_eq!(
            parsed
                .provisional_owner_and_addend_for_rva(0x908, DataStorage::Bss)
                .unwrap()
                .0
                .object,
            b"four.c"
        );
        assert!(
            parsed
                .provisional_owner_and_addend_for_rva(0x920, DataStorage::Data)
                .is_none()
        );
    }

    #[test]
    fn proven_rows_may_not_overlap_through_a_provisional_row() {
        let error = named(
            "a\tone.c\t0x900\t0x20\tdata\t4\t-\t-\texternal\treviewed\n\
             p\ttwo.c\t0x904\t4\tdata\t4\t-\t-\texternal\tprovisional-band-gap\n\
             b\tthree.c\t0x910\t4\tdata\t4\t-\t-\texternal\treviewed\n",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("overlapping data manifest definitions a at 0x900 and b at 0x910"));
    }

    #[test]
    fn rejects_overlaps_across_owner_objects() {
        let text = format!(
            "{HEADER_TEXT}one.c\t0x100\t0x20\tdata\t4\t-\t0\texternal\ntwo.c\t0x110\t4\tdata\t4\t-\t0\texternal\n"
        );
        assert!(
            parse(&text)
                .err()
                .unwrap()
                .to_string()
                .contains("overlapping")
        );
    }

    #[test]
    fn accepts_adjacent_extents_across_owner_objects() {
        let text = format!(
            "{HEADER_TEXT}one.c\t0x100\t0x20\tdata\t4\t-\t0\texternal\ntwo.c\t0x120\t4\tdata\t4\t-\t0\texternal\n"
        );
        assert_eq!(parse(&text).unwrap().definitions().len(), 2);
    }

    #[test]
    fn rejects_extent_overflow_and_zero_size() {
        let overflow = format!("u.c\t{}\t2\tdata\t4\t-\t0\texternal", usize::MAX);
        assert!(error(&overflow).contains("overflows"));
        assert!(error("u.c\t0x100\t0\tdata\t4\t-\t0\texternal").contains("non-zero"));
        let offset_overflow = format!("u.c\t0x100\t4\tdata\t4\t-\t{}\texternal", usize::MAX);
        assert!(error(&offset_overflow).contains("object section"));
        assert!(error("u.c\t0x100\t4\tdata\t4\t-\t0\tglobal").contains("unsupported scope"));
        assert!(error("u.c\t0x100\t4\tdata\t4\t1\t-\texternal").contains("requires"));
    }

    #[test]
    fn rejects_zero_and_non_power_of_two_alignment() {
        assert!(error("u.c\t0x100\t4\tdata\t0\t-\t0\texternal").contains("power of two"));
        assert!(error("u.c\t0x100\t4\tdata\t3\t-\t0\texternal").contains("power of two"));
    }

    #[test]
    fn resolves_interior_owner_and_addend_at_exact_boundaries() {
        let parsed = parse(&format!(
            "{HEADER_TEXT}v.c\t0x140\t0x10\tdata\t4\t-\t0\texternal\nu.c\t0x100\t0x20\tdata\t4\t-\t0\texternal\n"
        ))
        .unwrap();
        assert_eq!(parsed.definitions()[0].symbol_name.as_bytes(), b"table");
        assert_eq!(parsed.definitions()[1].symbol_name.as_bytes(), b"later");
        assert!(parsed.owner_and_addend_for_rva(0xff).is_none());
        let (owner, addend) = parsed.owner_and_addend_for_rva(0x100).unwrap();
        assert_eq!(owner.symbol_name.as_bytes(), b"table");
        assert_eq!(addend, 0);
        assert_eq!(parsed.owner_and_addend_for_rva(0x10f).unwrap().1, 0xf);
        assert_eq!(parsed.owner_and_addend_for_rva(0x11f).unwrap().1, 0x1f);
        assert!(parsed.owner_and_addend_for_rva(0x120).is_none());
        assert!(parsed.owner_and_addend_for_rva(0x13f).is_none());
        assert_eq!(parsed.owner_and_addend_for_rva(0x140).unwrap().1, 0);
        assert_eq!(parsed.owner_and_addend_for_rva(0x14f).unwrap().1, 0xf);
        assert!(parsed.owner_and_addend_for_rva(0x150).is_none());
    }

    #[test]
    fn candidate_offsets_control_emission_without_changing_the_rva_index() {
        let parsed = parse(&format!(
            "{HEADER_TEXT}u.c\t0x100\t4\tdata\t4\t-\t4\texternal\nu.c\t0x140\t4\tdata\t4\t-\t0\texternal\n"
        ))
        .unwrap();
        assert_eq!(parsed.definitions()[0].symbol_name.as_bytes(), b"table");
        assert_eq!(parsed.definitions()[1].symbol_name.as_bytes(), b"later");

        let emission = parsed.definitions_in_emission_order();
        assert_eq!(emission[0].symbol_name.as_bytes(), b"later");
        assert_eq!(emission[1].symbol_name.as_bytes(), b"table");
    }
}
