#![feature(os_string_truncate)]

mod object_files;
mod pdb_symbols;
mod relocs;
mod utils;

use crate::object_files::ObjectFiles;
use crate::pdb_symbols::PdbSymbols;
use crate::utils::{leak, ToUsize};

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
//
// ## 2. sushi@TODO: Relocations in .data and .rdata
// ## 3. sushi@TODO: Initialized statics in .rdata

fn main() -> anyhow::Result<()> {
    let Cli {
        pdb_path,
        exe_path,
        output_path,
        engine_path,
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

    process_executable(exe, pdb, engine_path.as_bytes(), output_path.as_path())?;

    Ok(())
}

fn process_executable<S: pdb2::Source<'static> + 'static>(
    exe: &'static object::read::pe::PeFile32<'static>,
    mut pdb: pdb2::PDB<'static, S>,
    engine_path: &[u8],
    output_path: &std::path::Path,
) -> anyhow::Result<()> {
    let env = Env::build(exe, &mut pdb)?;

    let pdb_symbols = PdbSymbols::parse(&env, &mut pdb)?;

    let (coff_data, relocs_rva) = relocs::resolve_absolute_relocations(&env, exe, &pdb_symbols)?;

    let object_files = ObjectFiles::parse(
        &env,
        &mut pdb,
        &pdb_symbols,
        &coff_data,
        relocs_rva,
        engine_path,
    )?;
    object_files.write(output_path)?;

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
