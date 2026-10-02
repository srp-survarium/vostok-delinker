use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};

use std::collections::HashSet;
use std::path::Path;

const HEADER: &[u8] = b"object\tname\tsize";

/// An uninitialized global that an object declares COMMON: it owns no section
/// bytes, and the linker allocates the largest size any object asks for.
#[derive(Clone, Copy, Debug)]
pub struct CommonSymbol {
    pub object: &'static [u8],
    pub name: &'static [u8],
    pub size: u64,
}

#[derive(Default)]
pub struct CommonSymbolManifest {
    symbols: Vec<CommonSymbol>,
}

fn manifest_lines(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    terminated(
        separated_list0(line_ending, not_line_ending),
        opt(line_ending),
    )
    .parse(input)
}

fn field(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_till(|byte| byte == b'\t').parse(input)
}

struct ManifestRow<'a> {
    object: &'a [u8],
    name: &'a [u8],
    size: &'a [u8],
}

fn manifest_row(input: &[u8]) -> IResult<&[u8], ManifestRow<'_>> {
    let (input, (object, name, size)) = (
        terminated(field, tag(&b"\t"[..])),
        terminated(field, tag(&b"\t"[..])),
        field,
    )
        .parse(input)?;
    Ok((input, ManifestRow { object, name, size }))
}

impl CommonSymbolManifest {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        Self::parse(&std::fs::read(path)?, path)
    }

    fn parse(bytes: &[u8], path: &Path) -> anyhow::Result<Self> {
        let (_, lines) = all_consuming(manifest_lines)
            .parse(bytes)
            .map_err(|_| anyhow::anyhow!("{}: invalid line ending", path.display()))?;
        let mut symbols = Vec::new();
        let mut seen = HashSet::new();
        let mut saw_header = false;

        for (line_index, line) in lines.into_iter().enumerate() {
            let line_number = line_index + 1;
            if line.is_empty() || line.starts_with(b"#") {
                continue;
            }
            if !saw_header {
                if line != HEADER {
                    anyhow::bail!(
                        "{}:{}: invalid COMMON symbol manifest header",
                        path.display(),
                        line_number
                    );
                }
                saw_header = true;
                continue;
            }
            if line == HEADER {
                anyhow::bail!(
                    "{}:{}: duplicate COMMON symbol manifest header",
                    path.display(),
                    line_number
                );
            }
            let (_, ManifestRow { object, name, size }) =
                all_consuming(manifest_row).parse(line).map_err(|_| {
                    anyhow::anyhow!(
                        "{}:{}: expected exactly three tab-separated columns",
                        path.display(),
                        line_number
                    )
                })?;
            let object = normalize_object(object, path, line_number)?;
            if name.is_empty() || name.iter().any(|byte| byte.is_ascii_control()) {
                anyhow::bail!(
                    "{}:{}: COMMON symbol name must be non-empty printable bytes",
                    path.display(),
                    line_number
                );
            }
            let size = parse_number(size)? as u64;
            if size == 0 {
                anyhow::bail!(
                    "{}:{}: COMMON symbol size must be non-zero",
                    path.display(),
                    line_number
                );
            }
            let name: &'static [u8] = name.to_vec().leak();
            if !seen.insert((object, name)) {
                anyhow::bail!(
                    "{}:{}: duplicate COMMON symbol {} in {}",
                    path.display(),
                    line_number,
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(object)
                );
            }
            symbols.push(CommonSymbol { object, name, size });
        }
        if !saw_header {
            anyhow::bail!("{}: missing COMMON symbol manifest header", path.display());
        }
        Ok(Self { symbols })
    }

    pub fn symbols(&self) -> &[CommonSymbol] {
        &self.symbols
    }
}

fn normalize_object(value: &[u8], path: &Path, line: usize) -> anyhow::Result<&'static [u8]> {
    let object = std::str::from_utf8(value)?.replace('/', "\\");
    if object.is_empty()
        || object.contains(':')
        || object
            .split('\\')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        anyhow::bail!(
            "{}:{}: object path must be relative and normalized",
            path.display(),
            line
        );
    }
    Ok(object.into_bytes().leak())
}

fn parse_number(value: &[u8]) -> anyhow::Result<usize> {
    let value = std::str::from_utf8(value)?;
    Ok(match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => usize::from_str_radix(hex, 16),
        None => value.parse(),
    }?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> anyhow::Result<CommonSymbolManifest> {
        CommonSymbolManifest::parse(text.as_bytes(), Path::new("common.tsv"))
    }

    #[test]
    fn parses_rows_per_object() {
        let manifest = parse(
            "# generated\nobject\tname\tsize\nSOURCE/A.c\t_gGuard\t1\nSOURCE/B.c\t_gGuard\t0x4\n",
        )
        .unwrap();
        let symbols = manifest.symbols();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].object, b"SOURCE\\A.c");
        assert_eq!((symbols[1].name, symbols[1].size), (&b"_gGuard"[..], 4));
    }

    #[test]
    fn rejects_malformed_rows() {
        for (rows, error) in [
            ("a.c\tx\t0\n", "non-zero"),
            ("a.c\t\t4\n", "non-empty"),
            ("C:\\a.c\tx\t4\n", "relative"),
            ("a.c\tx\n", "three"),
            ("a.c\tx\t4\na.c\tx\t8\n", "duplicate COMMON symbol x"),
        ] {
            let message = parse(&format!("object\tname\tsize\n{rows}"))
                .err()
                .unwrap()
                .to_string();
            assert!(message.contains(error), "{rows:?}: {message}");
        }
        assert!(parse("name\tsize\n").is_err());
    }
}
