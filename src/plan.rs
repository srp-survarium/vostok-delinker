//! The object plan: everything the backend needs to write one COFF object,
//! and nothing it would have to decide.
//!
//! The frontend reads the executable, its debug information and the reviewed
//! manifests, and decides how the image splits into objects: which bytes land
//! in which section, which symbols they define, and which relocations they
//! carry. It records those decisions as one `ObjectPlan` per output object. The
//! backend writes each plan as a COFF object without consulting any input.
//!
//! An `ObjectPlan` keeps the state an `object::write::Object` would, in the same
//! order (sections, symbols, relocations per section, COMDATs), so writing a
//! plan yields exactly the bytes of building the object directly.

use object::write::{Comdat, Mangling, Object, Relocation};
use object::{
    Architecture, BinaryFormat, ComdatKind, Endianness, RelocationEncoding, RelocationFlags,
    RelocationKind, SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A section of a plan, by its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectionId(pub usize);

/// A symbol of a plan, by its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SymbolId(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolSection {
    Undefined,
    Common,
    Section(SectionId),
}

/// A symbol as `object::write::Symbol` holds it, without flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: Vec<u8>,
    pub value: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub scope: SymbolScope,
    pub weak: bool,
    pub section: SymbolSection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSection {
    pub name: Vec<u8>,
    pub kind: SectionKind,
    pub characteristics: Option<u32>,
    pub align: u64,
    pub contents: SectionContents,
    pub relocations: Vec<PlanRelocation>,
    symbol: Option<SymbolId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionContents {
    Data(Vec<u8>),
    Bss(u64),
}

/// A 32-bit relocation against a symbol of the same plan. Its addend is
/// implicit: the field's bytes in the section hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanRelocation {
    pub offset: u64,
    pub symbol: SymbolId,
    pub kind: RelocationKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanComdat {
    pub kind: ComdatKind,
    pub symbol: SymbolId,
    pub sections: Vec<SectionId>,
}

/// How the section-definition checksums of the written object are set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanChecksums {
    /// The writer's checksums, except for these leading sections, which must
    /// have exactly these names.
    Reviewed(Vec<([u8; 8], u32)>),
    /// Zero in every section definition.
    Zero,
}

impl Default for PlanChecksums {
    fn default() -> Self {
        Self::Reviewed(Vec::new())
    }
}

#[derive(Debug, Default)]
pub struct ObjectPlan {
    sections: Vec<PlanSection>,
    symbols: Vec<Symbol>,
    /// Text and data symbol names, as `object` indexes them for `symbol_id`.
    symbol_map: HashMap<Vec<u8>, SymbolId>,
    comdats: Vec<PlanComdat>,
    pub checksums: PlanChecksums,
}

/// The implicit addend COFF i386 adds to a relocation of `kind`.
fn implicit_addend(kind: RelocationKind) -> i64 {
    match kind {
        RelocationKind::Relative => 4,
        _ => 0,
    }
}

impl ObjectPlan {
    pub fn add_section(&mut self, name: Vec<u8>, kind: SectionKind) -> SectionId {
        let id = SectionId(self.sections.len());
        let contents = match kind {
            SectionKind::UninitializedData => SectionContents::Bss(0),
            _ => SectionContents::Data(Vec::new()),
        };
        self.sections.push(PlanSection {
            name,
            kind,
            characteristics: None,
            align: 1,
            contents,
            relocations: Vec::new(),
            symbol: None,
        });
        id
    }

    pub fn set_characteristics(&mut self, id: SectionId, characteristics: u32) {
        self.sections[id.0].characteristics = Some(characteristics);
    }

    /// The section's bytes; it must hold initialized data.
    pub fn section_data_mut(&mut self, id: SectionId) -> &mut [u8] {
        match &mut self.sections[id.0].contents {
            SectionContents::Data(data) => data.as_mut_slice(),
            SectionContents::Bss(_) => panic!("zero-fill section has no bytes"),
        }
    }

    /// Set the bytes of a section that has none yet.
    pub fn set_section_data(&mut self, id: SectionId, data: Vec<u8>, align: u64) {
        let section = &mut self.sections[id.0];
        debug_assert_eq!(section.contents, SectionContents::Data(Vec::new()));
        section.contents = SectionContents::Data(data);
        section.align = align;
    }

    /// Append `data` at the next `align` boundary, zero-filling the gap, and
    /// return its offset.
    pub fn append_section_data(&mut self, id: SectionId, data: &[u8], align: u64) -> u64 {
        let section = &mut self.sections[id.0];
        section.align = section.align.max(align);
        let SectionContents::Data(bytes) = &mut section.contents else {
            panic!("zero-fill section has no bytes");
        };
        let offset = bytes.len().next_multiple_of(align as usize);
        bytes.resize(offset, 0);
        bytes.extend_from_slice(data);
        offset as u64
    }

    /// Reserve `size` zero-fill bytes at the next `align` boundary and return
    /// their offset.
    pub fn append_section_bss(&mut self, id: SectionId, size: u64, align: u64) -> u64 {
        let section = &mut self.sections[id.0];
        section.align = section.align.max(align);
        let SectionContents::Bss(total) = &mut section.contents else {
            panic!("initialized section has no zero-fill");
        };
        let offset = total.next_multiple_of(align);
        *total = offset + size;
        offset
    }

    pub fn section_symbol(&mut self, id: SectionId) -> SymbolId {
        if let Some(symbol) = self.sections[id.0].symbol {
            return symbol;
        }
        let symbol = SymbolId(self.symbols.len());
        self.symbols.push(Symbol {
            name: self.sections[id.0].name.clone(),
            value: 0,
            size: 0,
            kind: SymbolKind::Section,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(id),
        });
        self.sections[id.0].symbol = Some(symbol);
        symbol
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> SymbolId {
        if symbol.kind == SymbolKind::Section {
            let SymbolSection::Section(section) = symbol.section else {
                panic!("section symbol without a section");
            };
            return self.section_symbol(section);
        }
        let id = SymbolId(self.symbols.len());
        if !symbol.name.is_empty()
            && matches!(
                symbol.kind,
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Tls
            )
        {
            self.symbol_map.insert(symbol.name.clone(), id);
        }
        self.symbols.push(symbol);
        id
    }

    pub fn symbol_id(&self, name: &[u8]) -> Option<SymbolId> {
        self.symbol_map.get(name).copied()
    }

    pub fn symbol(&self, id: SymbolId) -> &Symbol {
        &self.symbols[id.0]
    }

    pub fn symbol_mut(&mut self, id: SymbolId) -> &mut Symbol {
        &mut self.symbols[id.0]
    }

    /// Relocate the 32-bit field at `offset` against `symbol`. As the COFF
    /// writer does, the addend net of the implicit one is stored in the field.
    pub fn add_relocation(
        &mut self,
        section: SectionId,
        offset: u64,
        symbol: SymbolId,
        kind: RelocationKind,
        addend: i64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(kind, RelocationKind::Absolute | RelocationKind::Relative),
            "unsupported relocation kind {kind:?}"
        );
        let net = addend + implicit_addend(kind);
        if net != 0 {
            let field = usize::try_from(offset)
                .ok()
                .and_then(|offset| self.section_data_mut(section).get_mut(offset..offset + 4))
                .ok_or_else(|| {
                    anyhow::anyhow!("relocation at {offset:#x} is outside its section")
                })?;
            field.copy_from_slice(&(net as u32).to_le_bytes());
        }
        self.sections[section.0].relocations.push(PlanRelocation {
            offset,
            symbol,
            kind,
        });
        Ok(())
    }

    pub fn add_comdat(&mut self, comdat: PlanComdat) {
        self.comdats.push(comdat);
    }

    /// Build the COFF object this plan describes.
    fn to_object(&self) -> anyhow::Result<Object<'static>> {
        let mut object = Object::new(BinaryFormat::Coff, Architecture::I386, Endianness::Little);
        object.set_mangling(Mangling::None);
        let mut sections = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            let id = object.add_section(Vec::new(), section.name.clone(), section.kind);
            sections.push(id);
            if let Some(characteristics) = section.characteristics {
                object.section_mut(id).flags = SectionFlags::Coff { characteristics };
            }
            match &section.contents {
                SectionContents::Data(data) => {
                    object.set_section_data(id, data.clone(), section.align)
                }
                SectionContents::Bss(size) => {
                    object.append_section_bss(id, *size, section.align);
                }
            }
        }
        let mut symbols = Vec::with_capacity(self.symbols.len());
        for symbol in &self.symbols {
            symbols.push(object.add_symbol(object::write::Symbol {
                name: symbol.name.clone(),
                value: symbol.value,
                size: symbol.size,
                kind: symbol.kind,
                scope: symbol.scope,
                weak: symbol.weak,
                section: match symbol.section {
                    SymbolSection::Undefined => object::write::SymbolSection::Undefined,
                    SymbolSection::Common => object::write::SymbolSection::Common,
                    SymbolSection::Section(id) => {
                        object::write::SymbolSection::Section(sections[id.0])
                    }
                },
                flags: SymbolFlags::None,
            }));
        }
        for (section, plan_section) in sections.iter().zip(&self.sections) {
            for relocation in &plan_section.relocations {
                object.add_relocation(
                    *section,
                    Relocation {
                        offset: relocation.offset,
                        symbol: symbols[relocation.symbol.0],
                        addend: -implicit_addend(relocation.kind),
                        flags: RelocationFlags::Generic {
                            kind: relocation.kind,
                            encoding: RelocationEncoding::Generic,
                            size: 32,
                        },
                    },
                )?;
            }
        }
        for comdat in &self.comdats {
            object.add_comdat(Comdat {
                kind: comdat.kind,
                symbol: symbols[comdat.symbol.0],
                sections: comdat.sections.iter().map(|id| sections[id.0]).collect(),
            });
        }
        Ok(object)
    }

    /// The COFF object this plan describes, with its checksum policy applied.
    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = self.to_object()?.write()?;
        match &self.checksums {
            PlanChecksums::Reviewed(reviewed) => {
                apply_reviewed_section_checksums(&mut bytes, reviewed)?;
            }
            PlanChecksums::Zero => {
                zero_section_checksums(&mut bytes)?;
            }
        }
        Ok(bytes)
    }
}

/// The backend: write each plan as `<directory>/<object>.obj`, where `object`
/// is its relative path with `\` separators.
pub fn write_objects<'a>(
    plans: impl IntoIterator<Item = (&'a [u8], &'a ObjectPlan)>,
    directory: &Path,
) -> anyhow::Result<()> {
    let mut symbolless_objects = Vec::new();
    for (object, plan) in plans {
        let path = object_path(directory, object, "obj");
        let bytes = plan.write()?;
        let symbolless = symbolless_comdats(&bytes)?;
        if symbolless != 0 {
            symbolless_objects.push((path.clone(), symbolless));
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, bytes)?;
    }
    if let Some((example, count)) = symbolless_objects.first() {
        eprintln!(
            "[comdat] {} object(s) carry COMDAT sections that define no symbol \
             (e.g. {count} in {}); object readers ignore such a COMDAT and link.exe \
             rejects it",
            symbolless_objects.len(),
            example.display()
        );
    }
    Ok(())
}

/// Write each plan as `<directory>/<object>.plan`.
pub fn write_plans<'a>(
    plans: impl IntoIterator<Item = (&'a [u8], &'a ObjectPlan)>,
    directory: &Path,
) -> anyhow::Result<()> {
    for (object, plan) in plans {
        let path = object_path(directory, object, "plan");
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, plan.to_text()?)?;
    }
    Ok(())
}

/// Every `.plan` file under `directory`, keyed by its object path.
pub fn read_plans(directory: &Path) -> anyhow::Result<Vec<(Vec<u8>, ObjectPlan)>> {
    let mut plans = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|error| anyhow::anyhow!("{}: {error}", dir.display()))?;
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "plan") {
                continue;
            }
            let relative = path.strip_prefix(directory)?.with_extension("");
            let object = relative
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("{}: path is not UTF-8", path.display()))?
                .replace('/', "\\");
            let text = std::fs::read_to_string(&path)?;
            let plan = ObjectPlan::parse(&text)
                .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
            plans.push((object.into_bytes(), plan));
        }
    }
    plans.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(plans)
}

fn object_path(directory: &Path, object: &[u8], extension: &str) -> PathBuf {
    let object = object
        .iter()
        .map(|&byte| match byte {
            b'\\' => '/',
            _ => char::from(byte),
        })
        .collect::<String>();
    let mut path = directory.as_os_str().to_owned();
    path.push("/");
    path.push(object);
    path.push(".");
    path.push(extension);
    PathBuf::from(path)
}

/// The number of non-associative COMDAT sections without a symbol after their
/// section symbol. That symbol is the COMDAT symbol: link.exe requires it and
/// object readers find the group through it. A manifest can declare a COMDAT
/// that nothing is placed into, such as a second `.text` COMDAT while every
/// function lands in the first `.text` section.
pub(crate) fn symbolless_comdats(bytes: &[u8]) -> anyhow::Result<usize> {
    use object::read::coff::ImageSymbol as _;
    use object::{Object as _, ObjectComdat as _, ObjectSection as _};

    let file = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)?;
    let grouped = file
        .comdats()
        .filter_map(|comdat| comdat.sections().next())
        .collect::<HashSet<_>>();
    let mut symbolless = 0;
    for section in file.sections() {
        let object::SectionFlags::Coff { characteristics } = section.flags() else {
            continue;
        };
        let selection = file
            .coff_symbol_table()
            .iter()
            .find(|(_, symbol)| {
                symbol.has_aux_section()
                    && symbol.section_number.get(object::LittleEndian) as usize == section.index().0
            })
            .and_then(|(index, _)| file.coff_symbol_table().aux_section(index).ok())
            .map_or(0, |aux| aux.selection);
        if characteristics & object::pe::IMAGE_SCN_LNK_COMDAT != 0
            && selection != object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE
            && !grouped.contains(&section.index())
        {
            symbolless += 1;
        }
    }
    Ok(symbolless)
}

/// The checksum field of one section-definition auxiliary record.
struct SectionChecksumField {
    section_number: usize,
    section_name: [u8; 8],
    offset: usize,
}

fn section_checksum_fields(bytes: &[u8]) -> anyhow::Result<Vec<SectionChecksumField>> {
    use object::endian::LittleEndian;
    use object::read::SectionIndex;

    let coff = object::read::coff::CoffFile::<&[u8], object::pe::ImageFileHeader>::parse(bytes)?;
    let symbol_table_offset = coff.coff_header().pointer_to_symbol_table.get(LittleEndian) as usize;
    let sections = coff.coff_section_table();
    let symbols = coff.coff_symbol_table();
    let checksum_in_aux = std::mem::offset_of!(object::pe::ImageAuxSymbolSection, check_sum);
    let mut fields = Vec::new();

    for (index, symbol) in symbols.iter() {
        let section_number = symbol.section_number.get(LittleEndian) as usize;
        if symbol.storage_class != object::pe::IMAGE_SYM_CLASS_STATIC
            || symbol.number_of_aux_symbols != 1
            || symbol.value.get(LittleEndian) != 0
            || symbol.typ.get(LittleEndian) != object::pe::IMAGE_SYM_TYPE_NULL
            || section_number == 0
            || section_number > sections.len()
        {
            continue;
        }
        let section = sections.section(SectionIndex(section_number))?;
        if symbol.name != section.name {
            continue;
        }
        symbols.aux_section(index)?;
        let offset = symbol_table_offset
            .checked_add(
                (index.0 + 1)
                    .checked_mul(object::pe::IMAGE_SIZEOF_SYMBOL)
                    .ok_or_else(|| anyhow::anyhow!("COFF auxiliary symbol offset overflows"))?,
            )
            .and_then(|offset| offset.checked_add(checksum_in_aux))
            .ok_or_else(|| anyhow::anyhow!("COFF section checksum offset overflows"))?;
        bytes
            .get(offset..offset + std::mem::size_of::<u32>())
            .ok_or_else(|| anyhow::anyhow!("COFF section checksum is outside the symbol table"))?;
        fields.push(SectionChecksumField {
            section_number,
            section_name: section.name,
            offset,
        });
    }
    Ok(fields)
}

pub(crate) fn apply_reviewed_section_checksums(
    bytes: &mut [u8],
    reviewed: &[([u8; 8], u32)],
) -> anyhow::Result<usize> {
    let mut seen = vec![false; reviewed.len()];
    let mut writes = Vec::with_capacity(reviewed.len());
    for field in section_checksum_fields(bytes)? {
        if field.section_number > reviewed.len() {
            continue;
        }
        let (expected_name, checksum) = reviewed[field.section_number - 1];
        if field.section_name != expected_name {
            anyhow::bail!("reviewed section checksum order/name mismatch");
        }
        if std::mem::replace(&mut seen[field.section_number - 1], true) {
            anyhow::bail!("duplicate COFF section-definition symbol");
        }
        writes.push((field.offset, checksum));
    }
    if seen.iter().any(|seen| !seen) {
        anyhow::bail!("reviewed COFF section has no section-definition symbol");
    }
    for (offset, checksum) in writes {
        bytes[offset..offset + std::mem::size_of::<u32>()].copy_from_slice(&checksum.to_le_bytes());
    }
    Ok(seen.len())
}

pub(crate) fn zero_section_checksums(bytes: &mut [u8]) -> anyhow::Result<usize> {
    let fields = section_checksum_fields(bytes)?;
    for field in &fields {
        bytes[field.offset..field.offset + std::mem::size_of::<u32>()].fill(0);
    }
    Ok(fields.len())
}

// On-disk form
//
// One text file per object, one record per line, fields separated by tabs.
// Names escape `\` and bytes outside printable ASCII as `\xHH`; section data
// is lowercase hex. Sections and symbols are numbered by their order in the
// file.
//
//     vostok-object-plan	1
//     checksums	reviewed|zero
//     checksum	<section name>	<value>                          (reviewed only)
//     section	<name>	<kind>	<characteristics|->	<align>	data	<hex>
//     section	<name>	<kind>	<characteristics|->	<align>	bss	<size>
//     symbol	<name>	<value>	<size|->	<kind>	<scope>	<weak>	<section>
//     reloc	<section>	<offset>	<symbol>	<absolute|relative>
//     comdat	<selection>	<symbol>	<section>[,<section>...]

const PLAN_HEADER: &str = "vostok-object-plan\t1";

fn escape(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7e => text.push(char::from(byte)),
            _ => write!(text, "\\x{byte:02x}").unwrap(),
        }
    }
    text
}

fn unescape(text: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match (bytes[index], bytes.get(index + 1)) {
            (b'\\', Some(b'\\')) => {
                out.push(b'\\');
                index += 2;
            }
            (b'\\', Some(b'x')) => {
                let hex = text
                    .get(index + 2..index + 4)
                    .ok_or_else(|| anyhow::anyhow!("truncated escape in {text:?}"))?;
                out.push(u8::from_str_radix(hex, 16)?);
                index += 4;
            }
            (b'\\', _) => anyhow::bail!("invalid escape in {text:?}"),
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Ok(out)
}

const SECTION_KINDS: &[(SectionKind, &str)] = &[
    (SectionKind::Text, "text"),
    (SectionKind::Data, "data"),
    (SectionKind::ReadOnlyData, "rdata"),
    (SectionKind::UninitializedData, "bss"),
    (SectionKind::Other, "other"),
];

const SYMBOL_KINDS: &[(SymbolKind, &str)] = &[
    (SymbolKind::Text, "text"),
    (SymbolKind::Data, "data"),
    (SymbolKind::Unknown, "unknown"),
    (SymbolKind::Section, "section"),
];

const SYMBOL_SCOPES: &[(SymbolScope, &str)] = &[
    (SymbolScope::Linkage, "linkage"),
    (SymbolScope::Compilation, "compilation"),
];

const RELOCATION_KINDS: &[(RelocationKind, &str)] = &[
    (RelocationKind::Absolute, "absolute"),
    (RelocationKind::Relative, "relative"),
];

const COMDAT_KINDS: &[(ComdatKind, &str)] = &[
    (ComdatKind::NoDuplicates, "noduplicates"),
    (ComdatKind::Any, "any"),
    (ComdatKind::SameSize, "samesize"),
    (ComdatKind::ExactMatch, "exactmatch"),
    (ComdatKind::Largest, "largest"),
    (ComdatKind::Newest, "newest"),
];

fn spell<T: PartialEq + std::fmt::Debug>(
    table: &[(T, &'static str)],
    value: T,
) -> anyhow::Result<&'static str> {
    table
        .iter()
        .find(|(known, _)| *known == value)
        .map(|(_, name)| *name)
        .ok_or_else(|| anyhow::anyhow!("{value:?} has no object plan spelling"))
}

fn unspell<T: Copy>(table: &[(T, &str)], name: &str, what: &str) -> anyhow::Result<T> {
    table
        .iter()
        .find(|(_, known)| *known == name)
        .map(|(value, _)| *value)
        .ok_or_else(|| anyhow::anyhow!("unknown {what} {name}"))
}

impl ObjectPlan {
    pub fn to_text(&self) -> anyhow::Result<String> {
        let mut text = String::new();
        writeln!(text, "{PLAN_HEADER}")?;
        match &self.checksums {
            PlanChecksums::Zero => writeln!(text, "checksums\tzero")?,
            PlanChecksums::Reviewed(rows) => {
                writeln!(text, "checksums\treviewed")?;
                for (name, value) in rows {
                    let length = name.iter().position(|&byte| byte == 0).unwrap_or(8);
                    writeln!(text, "checksum\t{}\t{value:#x}", escape(&name[..length]))?;
                }
            }
        }
        for section in &self.sections {
            let characteristics = section
                .characteristics
                .map_or_else(|| "-".to_owned(), |value| format!("{value:#x}"));
            write!(
                text,
                "section\t{}\t{}\t{characteristics}\t{:#x}\t",
                escape(&section.name),
                spell(SECTION_KINDS, section.kind)?,
                section.align
            )?;
            match &section.contents {
                SectionContents::Data(data) => {
                    text.push_str("data\t");
                    for byte in data {
                        write!(text, "{byte:02x}")?;
                    }
                    text.push('\n');
                }
                SectionContents::Bss(size) => writeln!(text, "bss\t{size:#x}")?,
            }
        }
        for symbol in &self.symbols {
            let size = match symbol.size {
                u64::MAX => "-".to_owned(),
                size => format!("{size:#x}"),
            };
            let section = match symbol.section {
                SymbolSection::Undefined => "undefined".to_owned(),
                SymbolSection::Common => "common".to_owned(),
                SymbolSection::Section(id) => id.0.to_string(),
            };
            writeln!(
                text,
                "symbol\t{}\t{:#x}\t{size}\t{}\t{}\t{}\t{section}",
                escape(&symbol.name),
                symbol.value,
                spell(SYMBOL_KINDS, symbol.kind)?,
                spell(SYMBOL_SCOPES, symbol.scope)?,
                u8::from(symbol.weak),
            )?;
        }
        for (index, section) in self.sections.iter().enumerate() {
            for relocation in &section.relocations {
                writeln!(
                    text,
                    "reloc\t{index}\t{:#x}\t{}\t{}",
                    relocation.offset,
                    relocation.symbol.0,
                    spell(RELOCATION_KINDS, relocation.kind)?
                )?;
            }
        }
        for comdat in &self.comdats {
            let sections = comdat
                .sections
                .iter()
                .map(|section| section.0.to_string())
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                text,
                "comdat\t{}\t{}\t{sections}",
                spell(COMDAT_KINDS, comdat.kind)?,
                comdat.symbol.0
            )?;
        }
        Ok(text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines().enumerate();
        anyhow::ensure!(
            lines.next().map(|(_, line)| line) == Some(PLAN_HEADER),
            "missing object plan header"
        );
        let mut plan = Self::default();
        for (index, line) in lines {
            plan.parse_record(line)
                .map_err(|error| anyhow::anyhow!("line {}: {error}", index + 1))?;
        }
        Ok(plan)
    }

    fn parse_record(&mut self, line: &str) -> anyhow::Result<()> {
        let fields = line.split('\t').collect::<Vec<_>>();
        let expect = |count: usize| {
            anyhow::ensure!(fields.len() == count, "expected {count} fields");
            Ok(())
        };
        let section_index = |text: &str, count: usize| -> anyhow::Result<SectionId> {
            let index: usize = text.parse()?;
            anyhow::ensure!(index < count, "section {index} is out of range");
            Ok(SectionId(index))
        };
        let symbol_index = |text: &str, count: usize| -> anyhow::Result<SymbolId> {
            let index: usize = text.parse()?;
            anyhow::ensure!(index < count, "symbol {index} is out of range");
            Ok(SymbolId(index))
        };
        match fields[0] {
            "checksums" => {
                expect(2)?;
                self.checksums = match fields[1] {
                    "reviewed" => PlanChecksums::Reviewed(Vec::new()),
                    "zero" => PlanChecksums::Zero,
                    policy => anyhow::bail!("unknown checksum policy {policy}"),
                };
            }
            "checksum" => {
                expect(3)?;
                let PlanChecksums::Reviewed(rows) = &mut self.checksums else {
                    anyhow::bail!("checksum outside a reviewed policy");
                };
                let name = unescape(fields[1])?;
                anyhow::ensure!(name.len() <= 8, "section name is longer than eight bytes");
                let mut padded = [0; 8];
                padded[..name.len()].copy_from_slice(&name);
                rows.push((padded, u32::try_from(parse_u64(fields[2])?)?));
            }
            "section" => {
                expect(7)?;
                let kind = unspell(SECTION_KINDS, fields[2], "section kind")?;
                let id = self.add_section(unescape(fields[1])?, kind);
                if fields[3] != "-" {
                    self.set_characteristics(id, u32::try_from(parse_u64(fields[3])?)?);
                }
                let align = parse_u64(fields[4])?;
                anyhow::ensure!(align.is_power_of_two(), "alignment is not a power of two");
                let contents = match (fields[5], kind) {
                    ("bss", SectionKind::UninitializedData) => {
                        SectionContents::Bss(parse_u64(fields[6])?)
                    }
                    ("data", kind) if kind != SectionKind::UninitializedData => {
                        SectionContents::Data(parse_hex(fields[6])?)
                    }
                    (contents, _) => anyhow::bail!("{contents} contents disagree with the kind"),
                };
                let section = &mut self.sections[id.0];
                section.contents = contents;
                section.align = align;
            }
            "symbol" => {
                expect(8)?;
                let section = match fields[7] {
                    "undefined" => SymbolSection::Undefined,
                    "common" => SymbolSection::Common,
                    index => SymbolSection::Section(section_index(index, self.sections.len())?),
                };
                let size = match fields[3] {
                    "-" => u64::MAX,
                    size => parse_u64(size)?,
                };
                let id = self.add_symbol(Symbol {
                    name: unescape(fields[1])?,
                    value: parse_u64(fields[2])?,
                    size,
                    kind: unspell(SYMBOL_KINDS, fields[4], "symbol kind")?,
                    scope: unspell(SYMBOL_SCOPES, fields[5], "symbol scope")?,
                    weak: match fields[6] {
                        "0" => false,
                        "1" => true,
                        weak => anyhow::bail!("invalid weak flag {weak}"),
                    },
                    section,
                });
                anyhow::ensure!(
                    id.0 + 1 == self.symbols.len(),
                    "a section's symbol must be its first"
                );
            }
            "reloc" => {
                expect(5)?;
                let section = section_index(fields[1], self.sections.len())?;
                self.sections[section.0].relocations.push(PlanRelocation {
                    offset: parse_u64(fields[2])?,
                    symbol: symbol_index(fields[3], self.symbols.len())?,
                    kind: unspell(RELOCATION_KINDS, fields[4], "relocation kind")?,
                });
            }
            "comdat" => {
                expect(4)?;
                let comdat = PlanComdat {
                    kind: unspell(COMDAT_KINDS, fields[1], "COMDAT selection")?,
                    symbol: symbol_index(fields[2], self.symbols.len())?,
                    sections: fields[3]
                        .split(',')
                        .map(|index| section_index(index, self.sections.len()))
                        .collect::<anyhow::Result<_>>()?,
                };
                self.add_comdat(comdat);
            }
            record => anyhow::bail!("unknown record {record}"),
        }
        Ok(())
    }
}

fn parse_u64(text: &str) -> anyhow::Result<u64> {
    Ok(match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16)?,
        None => text.parse()?,
    })
}

fn parse_hex(text: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(text.len() % 2 == 0, "section data has an odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ObjectPlan {
        let mut plan = ObjectPlan::default();
        let text = plan.add_section(b".text".to_vec(), SectionKind::Text);
        let data = plan.add_section(b".data$r".to_vec(), SectionKind::Data);
        let bss = plan.add_section(b".bss".to_vec(), SectionKind::UninitializedData);
        plan.set_characteristics(data, 0xc000_0040);
        plan.append_section_data(text, &[0xe8, 0, 0, 0, 0, 0xc3], 16);
        plan.append_section_data(data, &[1, 2, 3, 4], 4);
        plan.append_section_bss(bss, 12, 8);
        plan.section_symbol(text);
        let leader = plan.section_symbol(data);
        let callee = plan.add_symbol(Symbol {
            name: b"_callee\\\x01".to_vec(),
            value: 0,
            size: u64::MAX,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
        });
        plan.add_symbol(Symbol {
            name: b"_table".to_vec(),
            value: 0,
            size: 4,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(data),
        });
        plan.add_relocation(text, 1, callee, RelocationKind::Relative, -4)
            .unwrap();
        plan.add_relocation(data, 0, leader, RelocationKind::Absolute, 0)
            .unwrap();
        plan.add_comdat(PlanComdat {
            kind: ComdatKind::Any,
            symbol: leader,
            sections: vec![data],
        });
        plan.checksums = PlanChecksums::Reviewed(vec![(*b".text\0\0\0", 0x1234)]);
        plan
    }

    #[test]
    fn text_form_round_trips_to_the_same_object() {
        let plan = sample();
        let text = plan.to_text().unwrap();
        let parsed = ObjectPlan::parse(&text).unwrap();
        assert_eq!(parsed.to_text().unwrap(), text);
        assert_eq!(parsed.write().unwrap(), plan.write().unwrap());
    }

    #[test]
    fn replay_matches_building_the_object_directly() {
        let mut object = Object::new(BinaryFormat::Coff, Architecture::I386, Endianness::Little);
        object.set_mangling(Mangling::None);
        let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        object.append_section_data(text, &[0xe8, 0, 0, 0, 0, 0xc3], 16);
        let callee = object.add_symbol(object::write::Symbol {
            name: b"_callee".to_vec(),
            value: 0,
            size: u64::MAX,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        object
            .add_relocation(
                text,
                Relocation {
                    offset: 1,
                    symbol: callee,
                    addend: 0,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Relative,
                        encoding: RelocationEncoding::Generic,
                        size: 32,
                    },
                },
            )
            .unwrap();

        let mut plan = ObjectPlan::default();
        let text = plan.add_section(b".text".to_vec(), SectionKind::Text);
        plan.append_section_data(text, &[0xe8, 0, 0, 0, 0, 0xc3], 16);
        let callee = plan.add_symbol(Symbol {
            name: b"_callee".to_vec(),
            value: 0,
            size: u64::MAX,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
        });
        plan.add_relocation(text, 1, callee, RelocationKind::Relative, 0)
            .unwrap();
        // A REL32 addend of zero is stored as +4 in the field.
        assert_eq!(plan.section_data_mut(text)[1..5], 4u32.to_le_bytes());
        assert_eq!(plan.write().unwrap(), object.write().unwrap());
    }

    #[test]
    fn rejects_malformed_plans() {
        let text = sample().to_text().unwrap();
        for (from, to, error) in [
            ("vostok-object-plan\t1", "vostok-object-plan\t2", "header"),
            (
                "reloc\t0\t0x1\t",
                "reloc\t9\t0x1\t",
                "section 9 is out of range",
            ),
            (
                "\tbss\t0xc",
                "\tdata\t0xc",
                "data contents disagree with the kind",
            ),
            ("\tdata\t", "\tdata\t0", "odd hex length"),
            (
                "checksums\treviewed",
                "checksums\tsome",
                "unknown checksum policy",
            ),
        ] {
            assert!(text.contains(from), "{from}");
            let message = ObjectPlan::parse(&text.replacen(from, to, 1))
                .unwrap_err()
                .to_string();
            assert!(message.contains(error), "{message}");
        }
    }
}
