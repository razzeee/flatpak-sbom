//! Download and inspect declared payloads; never execute install scripts.
use crate::{content::ContentTree, cyclonedx::Component};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component as Part, Path, PathBuf},
    time::Duration,
};

const MAX_DOWNLOAD: u64 = 2 * 1024 * 1024 * 1024;
const MAX_EXPANDED: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;

#[derive(Clone, Serialize, Deserialize)]
pub struct Source {
    name: String,
    url: String,
    sha256: String,
    size: Option<u64>,
}

pub struct Payload {
    pub tree: ContentTree,
    pub evidence: Value,
}

fn prop<'a>(c: &'a Component, key: &str) -> Option<&'a str> {
    c.properties
        .iter()
        .find(|p| p.name == key)
        .map(|p| p.value.as_str())
}

pub fn acquire(artifact: &Component, components: &[Component]) -> Result<Vec<Payload>> {
    let mut groups: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for property in &artifact.properties {
        if let Some((group, key)) = property
            .name
            .strip_prefix("flatpak:metadata:")
            .and_then(|p| p.rsplit_once(':'))
        {
            if group == "Extra_Data" || group.starts_with("Extra_Data_") {
                groups
                    .entry(group)
                    .or_default()
                    .insert(key, &property.value);
            }
        }
    }
    let mut sources = Vec::new();
    for fields in groups.values() {
        sources.push(Source {
            name: fields.get("name").copied().unwrap_or("payload").into(),
            url: fields
                .get("uri")
                .context("extra-data metadata missing URI")?
                .to_string(),
            sha256: fields
                .get("checksum")
                .context("extra-data metadata missing checksum")?
                .to_string(),
            size: fields
                .get("size")
                .map(|s| s.parse())
                .transpose()
                .context("invalid extra-data size")?,
        });
    }
    // Older artifacts may declare payloads only in their committed manifest.
    if sources.is_empty() {
        for component in components.iter().filter(|c| {
            prop(c, "flatpak:ref") == prop(artifact, "flatpak:ref")
                && prop(c, "flatpak:source-type") == Some("extra-data")
        }) {
            sources.push(Source {
                name: prop(component, "flatpak:source-filename")
                    .unwrap_or("payload")
                    .into(),
                url: prop(component, "flatpak:source-url")
                    .context("extra-data source missing URL")?
                    .into(),
                sha256: prop(component, "flatpak:source-sha256")
                    .context("extra-data source missing SHA-256")?
                    .into(),
                size: prop(component, "flatpak:source-size")
                    .map(str::parse)
                    .transpose()?,
            });
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut payloads = Vec::new();
    let mut total_download = 0;
    let mut total_expanded = 0;
    for source in sources {
        if !seen.insert((source.url.clone(), source.sha256.clone())) {
            continue;
        }
        let payload = download_and_unpack(
            &source,
            MAX_DOWNLOAD - total_download,
            MAX_EXPANDED - total_expanded,
        )?;
        total_download += payload.evidence["downloaded_bytes"].as_u64().unwrap();
        total_expanded += payload.evidence["expanded_bytes"].as_u64().unwrap();
        if total_download > MAX_DOWNLOAD || total_expanded > MAX_EXPANDED {
            bail!("extra-data aggregate acquisition budget exceeded");
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

fn allowed_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
}

fn download_and_unpack(
    source: &Source,
    download_budget: u64,
    expanded_budget: u64,
) -> Result<Payload> {
    if source.sha256.len() != 64 || !source.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("extra-data requires a full SHA-256 checksum");
    }
    if source.size.is_some_and(|n| n > download_budget) {
        bail!("extra-data declared size exceeds remaining download budget (2 GiB total)");
    }
    let url = reqwest::Url::parse(&source.url).context("parse extra-data URL")?;
    if !allowed_url(&url) {
        bail!("extra-data requires HTTPS (or loopback HTTP for fixtures)");
    }
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("flatpak-sbom/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10
                || !allowed_url(attempt.url())
                || (attempt.url().scheme() == "http"
                    && attempt
                        .previous()
                        .first()
                        .is_some_and(|u| u.scheme() == "https"))
            {
                attempt.error("disallowed extra-data redirect")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .context("download extra-data")?
        .error_for_status()
        .context("extra-data HTTP response")?;
    let directory = tempfile::tempdir().context("create extra-data workspace")?;
    let archive_path = directory.path().join("payload");
    let mut archive = File::create(&archive_path)?;
    let mut hash = Sha256::new();
    let mut downloaded = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let count = response.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        downloaded += count as u64;
        if downloaded > download_budget || source.size.is_some_and(|n| downloaded > n) {
            bail!("extra-data download exceeds size limit");
        }
        hash.update(&buffer[..count]);
        archive.write_all(&buffer[..count])?;
    }
    let checksum = format!("{:x}", hash.finalize());
    if checksum != source.sha256.to_ascii_lowercase() {
        bail!("extra-data SHA-256 mismatch");
    }
    if source.size.is_some_and(|size| size != downloaded) {
        bail!("extra-data size mismatch");
    }
    drop(archive);
    let tree = ContentTree::checkout(directory);
    std::fs::create_dir(&tree.path)?;
    let mut extraction = Extraction {
        limit: Some(expanded_budget),
        ..Default::default()
    };
    let format = unpack(&archive_path, &tree.path, &mut extraction, 0)?;
    if format == "opaque" {
        // Keep an unsupported payload visible to binary catalogers, but never
        // claim its container contents were enumerated.
        std::fs::hard_link(&archive_path, tree.path.join("opaque-payload"))?;
    }
    Ok(Payload {
        tree,
        evidence: json!({"name":source.name, "url":source.url, "sha256":checksum,
        "downloaded_bytes":downloaded, "format":format, "expanded_bytes":extraction.bytes,
        "regular_files":extraction.files, "skipped_links":extraction.links,
        "status":if format == "opaque" { "opaque-payload" } else { "archive-inspected" },
        "package_metadata_projection":if format == "deb" { Some("debian-control-only") } else { None },
        "install_scripts_executed":false, "deployment_equivalence":"not-established"}),
    })
}

#[derive(Default)]
struct Extraction {
    limit: Option<u64>,
    bytes: u64,
    entries: usize,
    files: usize,
    links: usize,
}

impl Extraction {
    fn entry(&mut self) -> Result<()> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            bail!("extra-data archive entry budget exceeded");
        }
        Ok(())
    }
    fn file(&mut self, root: &Path, name: &Path, size: u64, input: impl Read) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(size)
            .context("archive size overflow")?;
        if self.bytes > self.limit.unwrap_or(MAX_EXPANDED) {
            bail!("extra-data expanded size exceeds 4 GiB");
        }
        let target = safe_path(root, name)?;
        std::fs::create_dir_all(target.parent().context("archive file without parent")?)?;
        // No archive symlinks are created. Duplicate regular paths are rejected
        // rather than silently replacing previously cataloged data.
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .context("create extracted regular file")?;
        let count = std::io::copy(&mut input.take(size + 1), &mut output)?;
        if count != size {
            bail!("archive entry length disagrees with header");
        }
        self.files += 1;
        Ok(())
    }
}

fn safe_path(root: &Path, name: &Path) -> Result<PathBuf> {
    if name.as_os_str().len() > 4096
        || name
            .components()
            .any(|p| !matches!(p, Part::Normal(_) | Part::CurDir))
    {
        bail!("unsafe extra-data archive path");
    }
    Ok(root.join(name))
}

fn untar(input: impl Read, root: &Path, extraction: &mut Extraction) -> Result<()> {
    let mut next_path: Option<PathBuf> = None;
    for entry in tar::Archive::new(input).entries()?.raw(true) {
        let mut entry = entry?;
        extraction.entry()?;
        let kind = entry.header().entry_type();
        // Bound extension headers before tar can allocate for them. Metadata
        // can supply a long path but must not hide sparse or oversized data.
        if kind.is_gnu_longname()
            || kind.is_gnu_longlink()
            || kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions()
        {
            if entry.size() > 65536 {
                bail!("tar metadata header exceeds 64 KiB");
            }
            if kind.is_gnu_longname() {
                let mut name = String::new();
                entry.read_to_string(&mut name)?;
                next_path = Some(PathBuf::from(name.trim_end_matches('\0')));
            } else if kind.is_pax_local_extensions() || kind.is_pax_global_extensions() {
                if let Some(fields) = entry.pax_extensions()? {
                    for field in fields {
                        let field = field?;
                        let key = field.key()?;
                        if key == "size" || key.starts_with("GNU.sparse") {
                            bail!("unsupported tar size/sparse override");
                        }
                        if key == "path" {
                            if kind.is_pax_global_extensions() {
                                bail!("global tar path override is unsupported");
                            }
                            next_path = Some(PathBuf::from(field.value()?));
                        }
                    }
                }
            }
            continue;
        }
        let name = next_path.take().unwrap_or(entry.path()?.into_owned());
        let target = safe_path(root, &name)?;
        if kind.is_file() {
            extraction.file(root, &name, entry.size(), &mut entry)?;
        } else if kind.is_dir() {
            std::fs::create_dir_all(target)?;
        } else if kind.is_symlink() || kind.is_hard_link() {
            extraction.links += 1;
        } else {
            bail!("unsupported special entry in extra-data tar archive");
        }
    }
    Ok(())
}

fn unpack(
    path: &Path,
    root: &Path,
    extraction: &mut Extraction,
    depth: usize,
) -> Result<&'static str> {
    if depth > 1 {
        bail!("nested Debian containers are unsupported");
    }
    let mut input = File::open(path)?;
    let mut magic = [0; 512];
    let count = input.read(&mut magic)?;
    input.seek(SeekFrom::Start(0))?;
    if magic.starts_with(b"hsqs") {
        if count < 96 {
            bail!("truncated SquashFS superblock");
        }
        let inodes = u32::from_le_bytes(magic[4..8].try_into().unwrap());
        let blocks = u32::from_le_bytes(magic[12..16].try_into().unwrap());
        let fragments = u32::from_le_bytes(magic[16..20].try_into().unwrap());
        let bytes_used = u64::from_le_bytes(magic[40..48].try_into().unwrap());
        if inodes as usize > MAX_ENTRIES
            || fragments as usize > MAX_ENTRIES
            || !(4096..=1048576).contains(&blocks)
            || !blocks.is_power_of_two()
            || bytes_used > input.metadata()?.len()
        {
            bail!("SquashFS metadata exceeds acquisition bounds");
        }
        let filesystem = backhand::FilesystemReader::from_reader(std::io::BufReader::new(input))
            .context("read SquashFS payload")?;
        for node in filesystem.files() {
            extraction.entry()?;
            // SquashFS paths are rooted within the image, not the host.
            let name = node.fullpath.strip_prefix("/").unwrap_or(&node.fullpath);
            let target = safe_path(root, name)?;
            match &node.inner {
                backhand::InnerNode::File(file) => {
                    let handle = filesystem.file(file);
                    extraction.file(root, name, file.file_len() as u64, handle.reader())?;
                }
                backhand::InnerNode::Dir(_) => std::fs::create_dir_all(target)?,
                backhand::InnerNode::Symlink(_) => extraction.links += 1,
                _ => bail!("unsupported special file in SquashFS payload"),
            }
        }
        return Ok("squashfs");
    }
    if magic.starts_with(b"!<arch>\n") {
        // Reuse Syft's Debian metadata parser without making it decompress the
        // potentially very large data archive again just to search licenses.
        // Control bytes are unchanged; the data tree is scanned separately.
        let metadata_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("__flatpak_sbom_package_metadata.deb"))?;
        let mut metadata_archive = ar::Builder::new(metadata_file);
        metadata_archive.append(
            &metadata_header(b"debian-binary".to_vec(), 4),
            &b"2.0\n"[..],
        )?;
        let mut found_control = false;
        let mut found = false;
        let mut archive = ar::Archive::new(input);
        while let Some(entry) = archive.next_entry() {
            let mut entry = entry?;
            if entry.header().identifier().starts_with(b"control.tar") {
                if found_control || entry.header().size() > 16 * 1024 * 1024 {
                    bail!("duplicate or oversized Debian control archive");
                }
                found_control = true;
                let name = entry
                    .header()
                    .identifier()
                    .strip_suffix(b"/")
                    .unwrap_or(entry.header().identifier())
                    .to_vec();
                metadata_archive
                    .append(&metadata_header(name, entry.header().size()), &mut entry)?;
            } else if entry.header().identifier().starts_with(b"data.tar") {
                if found {
                    bail!("duplicate Debian data archive");
                }
                found = true;
                let mut temporary = tempfile::NamedTempFile::new()?;
                let count =
                    std::io::copy(&mut entry.by_ref().take(MAX_DOWNLOAD + 1), &mut temporary)?;
                if count > MAX_DOWNLOAD {
                    bail!("Debian data archive exceeds size budget");
                }
                if unpack(temporary.path(), root, extraction, depth + 1)? == "opaque" {
                    bail!("unsupported Debian data archive");
                }
            }
        }
        if !found || !found_control {
            bail!("ar payload is missing Debian control/data archives");
        }
        let empty_tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            Default::default(),
        ))
        .into_inner()?
        .finish()?;
        metadata_archive.append(
            &metadata_header(b"data.tar.gz".to_vec(), empty_tar.len() as u64),
            &empty_tar[..],
        )?;
        return Ok("deb");
    }
    if magic.starts_with(b"PK\x03\x04") || magic.starts_with(b"PK\x05\x06") {
        let mut archive = zip::ZipArchive::new(input)?;
        if archive.len() > MAX_ENTRIES {
            bail!("zip entry budget exceeded");
        }
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            extraction.entry()?;
            let name = PathBuf::from(entry.name());
            let target = safe_path(root, &name)?;
            if entry.is_symlink() {
                extraction.links += 1;
            } else if entry.is_dir() {
                std::fs::create_dir_all(target)?;
            } else {
                extraction.file(root, &name, entry.size(), &mut entry)?;
            }
        }
        return Ok("zip");
    }
    let format = if magic.starts_with(&[0x1f, 0x8b]) {
        untar(flate2::read::GzDecoder::new(input), root, extraction)?;
        "tar.gz"
    } else if magic.starts_with(b"\xfd7zXZ\0") {
        let stream = liblzma::stream::Stream::new_stream_decoder(512 * 1024 * 1024, 0)?;
        untar(
            liblzma::read::XzDecoder::new_stream(input, stream),
            root,
            extraction,
        )?;
        "tar.xz"
    } else if magic.starts_with(b"BZh") {
        untar(bzip2::read::BzDecoder::new(input), root, extraction)?;
        "tar.bz2"
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let mut decoder = zstd::stream::read::Decoder::new(input)?;
        decoder.window_log_max(27)?;
        untar(decoder, root, extraction)?;
        "tar.zst"
    } else if count >= 262 && &magic[257..262] == b"ustar" {
        untar(input, root, extraction)?;
        "tar"
    } else {
        "opaque"
    };
    Ok(format)
}

fn metadata_header(name: Vec<u8>, size: u64) -> ar::Header {
    let mut header = ar::Header::new(name, size);
    header.set_mode(0o100644);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squashfs_extracts_files_skips_links_and_enforces_bounds() {
        let mut writer = backhand::FilesystemWriter::default();
        let header = backhand::NodeHeader::new(0o755, 0, 0, 0);
        writer.push_dir_all("/usr/share", header).unwrap();
        writer
            .push_file(&b"hello"[..], "/usr/share/package", header)
            .unwrap();
        writer
            .push_symlink("../../outside", "/escape", header)
            .unwrap();
        let mut image = std::io::Cursor::new(Vec::new());
        writer.write(&mut image).unwrap();
        let bytes = image.into_inner();
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload.snap");
        let root = dir.path().join("files");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(&payload, &bytes).unwrap();
        let mut extraction = Extraction::default();
        assert_eq!(
            unpack(&payload, &root, &mut extraction, 0).unwrap(),
            "squashfs"
        );
        assert_eq!(
            std::fs::read(root.join("usr/share/package")).unwrap(),
            b"hello"
        );
        assert_eq!(
            (extraction.files, extraction.links, extraction.bytes),
            (1, 1, 5)
        );
        assert!(!root.join("escape").exists());
        let bounded = dir.path().join("bounded");
        std::fs::create_dir(&bounded).unwrap();
        assert!(unpack(
            &payload,
            &bounded,
            &mut Extraction {
                limit: Some(4),
                ..Default::default()
            },
            0
        )
        .is_err());
        assert!(!bounded.join("usr/share/package").exists());
        for (offset, value) in [
            (4, (MAX_ENTRIES + 1) as u32),
            (12, 3),
            (16, (MAX_ENTRIES + 1) as u32),
        ] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            std::fs::write(&payload, invalid).unwrap();
            assert!(unpack(&payload, &root, &mut Extraction::default(), 0).is_err());
        }
        std::fs::write(&payload, &bytes[..48]).unwrap();
        assert!(unpack(&payload, &root, &mut Extraction::default(), 0).is_err());
    }

    fn tar_bytes(name: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, &b"hello"[..])
            .unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn inspects_supported_archives_with_bounded_regular_file_extraction() {
        let name = format!("{}/package.json", "long-directory-".repeat(12));
        let tar = tar_bytes(&name);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), Default::default());
        gzip.write_all(&tar).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut xz = liblzma::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(&tar).unwrap();
        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), Default::default());
        bz.write_all(&tar).unwrap();
        let mut deb = ar::Builder::new(Vec::new());
        deb.append(
            &ar::Header::new(b"debian-binary".to_vec(), 4),
            &b"2.0\n"[..],
        )
        .unwrap();
        deb.append(
            &ar::Header::new(b"control.tar.gz".to_vec(), gzip.len() as u64),
            &gzip[..],
        )
        .unwrap();
        deb.append(
            &ar::Header::new(b"data.tar.gz".to_vec(), gzip.len() as u64),
            &gzip[..],
        )
        .unwrap();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file(&name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"hello").unwrap();
        for (bytes, format) in [
            (tar.clone(), "tar"),
            (gzip, "tar.gz"),
            (xz.finish().unwrap(), "tar.xz"),
            (bz.finish().unwrap(), "tar.bz2"),
            (zstd::encode_all(&tar[..], 1).unwrap(), "tar.zst"),
            (deb.into_inner().unwrap(), "deb"),
            (zip.finish().unwrap().into_inner(), "zip"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let payload = dir.path().join("payload");
            std::fs::write(&payload, bytes).unwrap();
            let root = dir.path().join("files");
            std::fs::create_dir(&root).unwrap();
            let mut extraction = Extraction::default();
            assert_eq!(unpack(&payload, &root, &mut extraction, 0).unwrap(), format);
            assert_eq!(std::fs::read(root.join(&name)).unwrap(), b"hello");
            assert_eq!(extraction.files, 1);
            assert_eq!(extraction.bytes, 5);
        }
    }

    #[test]
    fn rejects_traversal_duplicates_and_expansion_bombs_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("files");
        std::fs::create_dir(&root).unwrap();
        for name in ["../escape", "/absolute", "safe/../../escape"] {
            assert!(safe_path(&root, Path::new(name)).is_err());
        }
        let mut archive = tar_bytes("safe");
        archive[..100].fill(0);
        archive[..9].copy_from_slice(b"../escape");
        let checksum = archive[..512]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u32
                }
            })
            .sum::<u32>();
        archive[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        assert!(untar(&archive[..], &root, &mut Extraction::default()).is_err());
        assert!(!dir.path().join("escape").exists());
        let mut extraction = Extraction::default();
        assert!(extraction
            .file(&root, Path::new("huge"), MAX_EXPANDED + 1, std::io::empty())
            .is_err());
        assert!(!root.join("huge").exists());
        untar(&tar_bytes("safe")[..], &root, &mut Extraction::default()).unwrap();
        assert!(untar(&tar_bytes("safe")[..], &root, &mut Extraction::default()).is_err());
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        builder
            .append_link(&mut header, "link", "../../outside")
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        let mut extraction = Extraction::default();
        untar(&bytes[..], &root, &mut extraction).unwrap();
        assert_eq!(extraction.links, 1);
        assert!(!root.join("link").exists());
    }
}
