#![feature(os_string_truncate)]

mod data_manifest;
mod object_files;
mod pdb_symbols;
mod relocs;
mod symbol_matcher;
mod utils;

use crate::object_files::ObjectFiles;
use crate::pdb_symbols::PdbSymbols;
use crate::symbol_matcher::SymbolMatcher;
use crate::utils::{ToUsize, leak};

use clap::Parser;
use object::LittleEndian;
use object::{Object, ObjectSection};

#[derive(clap::Parser)]
pub struct Cli {
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub pdb_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub exe_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub output_path: std::path::PathBuf,

    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub engine_path: String,

    /// Pad each empty object's `.rdata` with 4 bytes. objdiff treats two
    /// allocations as matching when their name OR their offset into the reloc
    /// table is equal, so distinct relocations can match purely on a shared
    /// offset; this padding shifts those offsets apart and prevents it.
    #[arg(long)]
    pub pad_empty_rdata: bool,

    /// Target side: record the name chosen for every folded symbol group to this
    /// file, so the base delink can reproduce the same choices.
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub write_symbol_map: Option<std::path::PathBuf>,

    /// Base side: reconcile folded symbol names against the target choices
    /// recorded here. Missing file is tolerated (no reconciliation).
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub read_symbol_map: Option<std::path::PathBuf>,

    /// Project-supplied TSV of data owner objects, RVAs, sizes, storage, and
    /// alignment. Symbol identities come from the PDB. See README.md, "Data
    /// manifest".
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub data_manifest: Option<std::path::PathBuf>,

    /// Require every PE base relocation targeting `.data` or `.rdata` to
    /// resolve to a definition in `--data-manifest`.
    #[arg(long, requires = "data_manifest")]
    pub strict: bool,

    /// Rediscover absolute relocation sites from the PDB by scanning the image for
    /// fields that hold a known symbol address. For images whose `.reloc`
    /// directory is missing or incomplete. Best-effort — may introduce a few false
    /// relocations; superseded by a reviewed reloc manifest.
    #[arg(long)]
    pub rediscover_relocations_from_pdb: bool,

    /// When rediscovering, accept a target within this many bytes after a known
    /// symbol start (to catch interior pointers). 0 = exact symbol starts only.
    #[arg(long, default_value_t = 32)]
    pub rediscovery_interior_bound: usize,
}

#[derive(Clone, Debug, Default, Copy)]
pub struct SecInfo<'a> {
    pub rva: usize,
    pub va: usize,

    pub size: usize,
    pub id: u16,

    pub data: &'a [u8],
}

// # Notes
//
// 1. Figure out how to not leak memory excessively with `pdb2` crate.
// Why does tie lifetime of `RawString` to a module info?
// This doesn't make sense, since it should tie it to `pdb` file itself.

fn main() -> anyhow::Result<()> {
    let Cli {
        pdb_path,
        exe_path,
        output_path,
        engine_path,
        pad_empty_rdata,
        write_symbol_map,
        read_symbol_map,
        data_manifest,
        strict,
        rediscover_relocations_from_pdb,
        rediscovery_interior_bound,
    } = Cli::parse();

    let exe: &[u8] = std::fs::read(exe_path)?.leak();
    let exe = object::read::pe::PeFile32::parse(exe)?;
    let exe: &'static object::read::pe::PeFile32 = leak(exe);

    let pdb = std::fs::read(pdb_path)?.leak();
    let pdb = std::io::Cursor::new(pdb);
    let pdb = pdb2::PDB::open(pdb)?;

    let mut engine_path = engine_path.to_lowercase().replace('/', "\\");
    if !engine_path.ends_with('\\') {
        engine_path.push('\\');
    }
    let manifest_coverage = if strict {
        relocs::ManifestCoverage::RequireComplete
    } else {
        relocs::ManifestCoverage::AllowPartial
    };

    process_executable(
        exe,
        pdb,
        engine_path.as_bytes(),
        pad_empty_rdata,
        output_path.as_path(),
        write_symbol_map.as_deref(),
        read_symbol_map.as_deref(),
        data_manifest.as_deref(),
        manifest_coverage,
        rediscover_relocations_from_pdb,
        rediscovery_interior_bound,
    )?;

    Ok(())
}

fn process_executable<S: pdb2::Source<'static> + 'static>(
    exe: &'static object::read::pe::PeFile32<'static>,
    mut pdb: pdb2::PDB<'static, S>,
    engine_path: &[u8],
    pad_empty_rdata: bool,
    output_path: &std::path::Path,
    write_symbol_map: Option<&std::path::Path>,
    read_symbol_map: Option<&std::path::Path>,
    data_manifest_path: Option<&std::path::Path>,
    manifest_coverage: relocs::ManifestCoverage,
    rediscover_relocations_from_pdb: bool,
    rediscovery_interior_bound: usize,
) -> anyhow::Result<()> {
    let env = Env::build(exe, &mut pdb)?;

    let pdb_symbols = PdbSymbols::parse(&env, &mut pdb)?;
    let data_manifest = data_manifest::DataManifest::load(data_manifest_path, &pdb_symbols)?;
    let (coff_data, relocs_rva) = relocs::resolve_absolute_relocations(
        &env,
        exe,
        &pdb_symbols,
        &data_manifest,
        manifest_coverage,
        rediscover_relocations_from_pdb,
        rediscovery_interior_bound,
    )?;

    // Base side reconciles its folded names against the target's recorded
    // choices; the target side (and a plain run) just emits local defaults.
    let matcher = match read_symbol_map {
        Some(path) if path.is_file() => SymbolMatcher::load(path)?,
        Some(path) => {
            eprintln!(
                "[symbol-matcher] no target symbol map at {} yet; emitting local defaults",
                path.display()
            );
            SymbolMatcher::off()
        }
        None => SymbolMatcher::off(),
    };

    let object_files = ObjectFiles::parse(
        &env,
        &mut pdb,
        &pdb_symbols,
        &coff_data,
        relocs_rva,
        engine_path,
        pad_empty_rdata,
        &matcher,
        &data_manifest,
    )?;
    object_files.write(output_path)?;

    // Target side: record the choices base will later try to reproduce.
    if let Some(path) = write_symbol_map {
        let groups = symbol_matcher::write_function_map(path, &pdb_symbols.functions)?;
        eprintln!(
            "[symbol-matcher] recorded {groups} folded function groups -> {}",
            path.display()
        );
    }

    // Base side: report how many folded references were pulled into agreement
    // with the target (`became_same` is the verification number).
    if let Some(stats) = matcher.stats() {
        eprintln!(
            "[symbol-matcher] reconciled {} folded references against target \
             ({} became the same as target, {} fell back: target's choice absent in base)",
            stats.reconciled, stats.became_same, stats.fallback_missing
        );
    }

    Ok(())
}

pub struct Env<'a> {
    pub image_base: u32,
    pub text: SecInfo<'a>,
    pub rdata: SecInfo<'a>,
    pub data: SecInfo<'a>,

    pub dbi: &'static pdb2::DebugInformation<'static>,
    pub string_table: &'static pdb2::StringTable<'static>,
    pub symbol_table: &'static pdb2::SymbolTable<'static>,
}

impl Env<'_> {
    fn build<S>(
        exe: &'static object::read::pe::PeFile32<'static>,
        pdb: &mut pdb2::PDB<'static, S>,
    ) -> anyhow::Result<Self>
    where
        S: pdb2::Source<'static> + 'static,
    {
        let image_base = exe
            .nt_headers()
            .optional_header
            .image_base
            .get(LittleEndian);

        let dbi = leak(pdb.debug_information()?);
        let string_table: &'static pdb2::StringTable<'static> = leak(pdb.string_table()?);
        let symbol_table: &'static pdb2::SymbolTable = leak(pdb.global_symbols()?);

        let build_sec_info = |sec: object::read::pe::PeSection<'static, 'static, _>| {
            Ok::<_, anyhow::Error>(SecInfo {
                rva: sec.address().to_usize() - image_base.to_usize(),
                va: sec.address().to_usize(),

                size: sec.size().to_usize(),
                id: u16::try_from(sec.index().0)?,

                data: sec.data()?,
            })
        };

        let Some(text_sec) = exe.section_by_name(".text") else {
            anyhow::bail!("Missing .text section");
        };
        let Some(rdata_sec) = exe.section_by_name(".rdata") else {
            anyhow::bail!("Missing .rdata section");
        };
        let Some(data_sec) = exe.section_by_name(".data") else {
            anyhow::bail!("Missing .data section");
        };

        let text = build_sec_info(text_sec)?;
        let rdata = build_sec_info(rdata_sec)?;
        let data = build_sec_info(data_sec)?;

        Ok(Self {
            image_base,
            text,
            rdata,
            data,

            dbi,
            string_table,
            symbol_table,
        })
    }
}
