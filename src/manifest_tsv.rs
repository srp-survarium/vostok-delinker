//! The tab-separated manifest format: blank lines and lines starting with `#`
//! are skipped, the first other line is a header that selects the schema, and
//! every later line is one row. Errors name the row as `path:line`.

use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{line_ending, not_line_ending};
use nom::combinator::{all_consuming, opt};
use nom::multi::separated_list0;
use nom::sequence::terminated;
use nom::{IResult, Parser};

use std::fmt;
use std::path::Path;

/// One row of a manifest.
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    pub path: &'a Path,
    pub line: usize,
    pub text: &'a [u8],
}

impl fmt::Display for Row<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.path.display(), self.line)
    }
}

/// The schema `bytes`' header selects among `schemas`, and its rows. `manifest`
/// names the manifest kind in errors.
pub fn read<'a, S: Copy>(
    bytes: &'a [u8],
    path: &'a Path,
    manifest: &str,
    schemas: &[(&[u8], S)],
) -> anyhow::Result<(S, Vec<Row<'a>>)> {
    let (_, lines) = all_consuming(terminated(
        separated_list0(line_ending, not_line_ending),
        opt(line_ending),
    ))
    .parse(bytes)
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
        anyhow::anyhow!("{}: invalid line ending", path.display())
    })?;
    let schema_of = |text: &[u8]| {
        schemas
            .iter()
            .find(|(header, _)| *header == text)
            .map(|(_, schema)| *schema)
    };
    let mut schema = None;
    let mut rows = Vec::new();
    for (index, text) in lines.into_iter().enumerate() {
        if text.is_empty() || text.starts_with(b"#") {
            continue;
        }
        let row = Row {
            path,
            line: index + 1,
            text,
        };
        match (schema, schema_of(text)) {
            (None, None) => anyhow::bail!("{row}: invalid {manifest} header"),
            (None, header) => schema = header,
            (Some(_), Some(_)) => anyhow::bail!("{row}: duplicate {manifest} header"),
            (Some(_), None) => rows.push(row),
        }
    }
    let Some(schema) = schema else {
        anyhow::bail!("{}: missing {manifest} header", path.display());
    };
    Ok((schema, rows))
}

/// A field that runs to the next tab or the end of the row.
pub fn field(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_till(|byte| byte == b'\t').parse(input)
}

/// A field followed by its tab.
pub fn column(input: &[u8]) -> IResult<&[u8], &[u8]> {
    terminated(field, tag(&b"\t"[..])).parse(input)
}

impl<'a> Row<'a> {
    /// Split the row with `parser`, which must consume it whole; `count` names
    /// the expected column count in the error.
    pub fn columns<T>(
        &self,
        parser: impl Parser<&'a [u8], Output = T, Error = nom::error::Error<&'a [u8]>>,
        count: &str,
    ) -> anyhow::Result<T> {
        all_consuming(parser)
            .parse(self.text)
            .map(|(_, columns)| columns)
            .map_err(|_| anyhow::anyhow!("{self}: expected exactly {count} tab-separated columns"))
    }

    /// A decimal or `0x`-prefixed hexadecimal number.
    pub fn number(&self, field: &str, value: &[u8]) -> anyhow::Result<usize> {
        std::str::from_utf8(value)
            .ok()
            .and_then(
                |text| match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => usize::from_str_radix(hex, 16).ok(),
                    None => text.parse().ok(),
                },
            )
            .ok_or_else(|| {
                anyhow::anyhow!("{self}: invalid {field} {}", String::from_utf8_lossy(value))
            })
    }

    /// A number, or `-` for none.
    pub fn optional_number(&self, field: &str, value: &[u8]) -> anyhow::Result<Option<usize>> {
        match value {
            b"-" => Ok(None),
            value => self.number(field, value).map(Some),
        }
    }

    /// A number that must fit in 32 bits.
    pub fn u32(&self, field: &str, value: &[u8]) -> anyhow::Result<u32> {
        u32::try_from(self.number(field, value)?)
            .map_err(|_| anyhow::anyhow!("{self}: {field} does not fit in 32 bits"))
    }

    /// Text free of control bytes.
    pub fn text(&self, field: &str, value: &[u8]) -> anyhow::Result<()> {
        if value.iter().any(|byte| byte.is_ascii_control()) {
            anyhow::bail!("{self}: {field} contains a control byte");
        }
        Ok(())
    }

    /// Non-empty text free of control bytes.
    pub fn non_empty_text(&self, field: &str, value: &[u8]) -> anyhow::Result<()> {
        if value.is_empty() {
            anyhow::bail!("{self}: {field} must be non-empty");
        }
        self.text(field, value)
    }

    /// A relative object path without `.` or `..` components, with `\`
    /// separators.
    pub fn object(&self, value: &[u8]) -> anyhow::Result<&'static [u8]> {
        self.text("object", value)?;
        let object = String::from_utf8_lossy(value).replace('/', "\\");
        if object.contains(':')
            || object
                .split('\\')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            anyhow::bail!("{self}: object path must be relative and normalized");
        }
        Ok(object.into_bytes().leak())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Schema {
        Short,
        Long,
    }

    const SCHEMAS: &[(&[u8], Schema)] = &[(b"a\tb", Schema::Short), (b"a\tb\tc", Schema::Long)];

    fn read_text(text: &str) -> anyhow::Result<(Schema, Vec<(usize, String)>)> {
        let (schema, rows) = read(
            text.as_bytes(),
            Path::new("m.tsv"),
            "test manifest",
            SCHEMAS,
        )?;
        let rows = rows
            .into_iter()
            .map(|row| (row.line, String::from_utf8_lossy(row.text).into_owned()))
            .collect();
        Ok((schema, rows))
    }

    #[test]
    fn header_selects_the_schema_and_rows_keep_their_lines() {
        let (schema, rows) = read_text("# note\n\na\tb\tc\r\n1\t2\t3\n\n# x\n4\t5\t6").unwrap();
        assert_eq!(schema, Schema::Long);
        assert_eq!(rows, [(4, "1\t2\t3".into()), (7, "4\t5\t6".into())]);
    }

    #[test]
    fn rejects_bad_headers() {
        for (text, error) in [
            ("", "m.tsv: missing test manifest header"),
            ("# only\n", "m.tsv: missing test manifest header"),
            ("x\n", "m.tsv:1: invalid test manifest header"),
            (
                "a\tb\n1\t2\na\tb\tc\n",
                "m.tsv:3: duplicate test manifest header",
            ),
        ] {
            assert_eq!(read_text(text).unwrap_err().to_string(), error);
        }
    }

    #[test]
    fn parses_fields() {
        let row = Row {
            path: Path::new("m.tsv"),
            line: 2,
            text: b"",
        };
        assert_eq!(row.number("rva", b"0x1F").unwrap(), 0x1f);
        assert_eq!(row.number("rva", b"31").unwrap(), 31);
        let error = row.number("rva", b"0xg").unwrap_err().to_string();
        assert_eq!(error, "m.tsv:2: invalid rva 0xg");
        assert!(row.u32("checksum", b"0x100000000").is_err());
        assert_eq!(row.object(b"src/a.c").unwrap(), b"src\\a.c");
        for object in [&b""[..], b"C:\\a.c", b"a\\..\\b.c", b"\\a.c", b"a\tb"] {
            assert!(row.object(object).is_err(), "{object:?}");
        }
        assert!(row.non_empty_text("name", b"").is_err());
        assert!(row.non_empty_text("name", b"a\x01").is_err());
    }
}
