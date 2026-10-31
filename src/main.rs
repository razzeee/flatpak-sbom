use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::PathBuf;

mod content;
mod coverage;
mod cyclonedx;
mod extensions;
mod extra_data;
mod grype;
mod identity;
mod installed;
mod manifest;
mod metadata;
mod native;
mod ostree;
mod osv;
mod package_identity;
mod refname;
mod sbom;

const DEFAULT_REPO: &str = "https://dl.flathub.org/repo";

#[derive(Debug, Parser)]
#[command(
    name = "flatpak-sbom",
    version,
    about = "Generate Flatpak manifest-derived CycloneDX SBOMs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Generate(GenerateArgs),
    Scan(ScanArgs),
    Report(ReportArgs),
    /// Explain security-relevant inventory coverage and gaps in an existing SBOM.
    Coverage(CoverageArgs),
}

#[derive(Debug, Parser)]
struct GenerateArgs {
    /// Flatpak app ref, for example app/org.example.App/x86_64/stable.
    app_ref: String,

    /// Flatpak OSTree remote URL.
    #[arg(long, default_value = DEFAULT_REPO)]
    repo: String,

    /// Output CycloneDX JSON path. Defaults to <app-id>.cdx.json; use '-' for stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(flatten)]
    inventory: InventoryArgs,
}

#[derive(Debug, Default, clap::Args)]
struct InventoryArgs {
    /// Read pinned installed app/runtime deployments instead of the remote.
    #[arg(long)]
    installed: bool,
    /// Catalog files from pinned remote commits (or installed deployments).
    #[arg(long, value_enum)]
    content_scanner: Option<ContentScanner>,
    /// Enrich exact repository identities with the bundled purl2cpe snapshot.
    #[arg(long)]
    cpe_mapping: bool,
    /// Include a declared extension's pinned contents; repeat for multiple refs.
    #[arg(long = "extension", requires = "content_scanner")]
    extensions: Vec<String>,
    /// Ask Flatpak which installed extensions are enabled on this host.
    #[arg(long, requires_all = ["installed", "content_scanner"])]
    active_extensions: bool,
    /// Download checksum-verified extra-data archives and inspect without executing scripts.
    #[arg(long, requires = "content_scanner", conflicts_with = "installed")]
    acquire_extra_data: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum ContentScanner {
    Syft,
}

#[derive(Debug, Parser)]
#[command(group(clap::ArgGroup::new("osv_scan").args(["osv_commits", "osv_packages"]).multiple(true)))]
struct ScanArgs {
    /// Flatpak app ref, for example app/org.example.App/x86_64/stable.
    app_ref: String,

    /// Flatpak OSTree remote URL.
    #[arg(long, default_value = DEFAULT_REPO)]
    repo: String,

    /// Vulnerability scanner backend.
    #[arg(long, default_value = "grype", value_parser = ["grype"])]
    scanner: String,

    /// Scanner output format.
    #[arg(long, default_value = "json")]
    format: String,
    #[command(flatten)]
    inventory: InventoryArgs,
    /// Also query OSV for manifest Git commits (JSON output only; network access).
    #[arg(long)]
    osv_commits: bool,
    /// Also query OSV for versioned ecosystem PURLs (JSON only; network access).
    #[arg(long)]
    osv_packages: bool,
    /// OSV query endpoint, for a mirror or local acceptance fixture.
    #[arg(
        long,
        requires = "osv_scan",
        default_value = "https://api.osv.dev/v1/query"
    )]
    osv_endpoint: String,
}

#[derive(Debug, Parser)]
struct ReportArgs {
    /// Grype JSON output to summarize with Flatpak scope information.
    findings: PathBuf,
}

#[derive(Debug, Parser)]
struct CoverageArgs {
    /// Generated CycloneDX JSON to summarize by app and runtime scope.
    sbom: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let reader = ostree::CliOstreeFileReader::new();

    match cli.command {
        Command::Generate(args) => generate(&reader, args),
        Command::Scan(args) => scan(&reader, args),
        Command::Report(args) => report(args),
        Command::Coverage(args) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&coverage::read(&args.sbom)?)?
            );
            Ok(())
        }
    }
}

fn generate(
    reader: &(impl ostree::OstreeFileReader + content::ContentSource),
    args: GenerateArgs,
) -> Result<()> {
    let document = inventory(reader, &args.repo, &args.app_ref, &args.inventory)?;
    let json = serde_json::to_string_pretty(&document).context("serialize CycloneDX document")?;
    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&args.app_ref));

    if output.as_os_str() == "-" {
        println!("{json}");
    } else {
        // Stage in the destination directory so replacement is atomic, including
        // when the temporary-files filesystem is on a different mount.
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let existing_permissions = match std::fs::metadata(&output) {
            Ok(metadata) => Some(metadata.permissions()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("read output permissions"),
        };
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // New outputs use ordinary file permissions, filtered by umask.
            // Existing outputs stay private until their contents are ready.
            if existing_permissions.is_none() {
                builder.permissions(std::fs::Permissions::from_mode(0o666));
            }
        }
        let mut staged = builder
            .tempfile_in(parent)
            .with_context(|| format!("stage {}", output.display()))?;
        staged
            .write_all(json.as_bytes())
            .context("write staged SBOM")?;
        if let Some(permissions) = existing_permissions {
            staged
                .as_file()
                .set_permissions(permissions)
                .context("preserve output permissions")?;
        }
        staged.as_file().sync_all().context("sync staged SBOM")?;
        staged
            .persist(&output)
            .with_context(|| format!("replace {}", output.display()))?;
    }

    Ok(())
}

fn default_output_path(app_ref: &str) -> PathBuf {
    refname::FlatpakRef::parse(app_ref)
        .map(|flatpak_ref| PathBuf::from(format!("{}.cdx.json", flatpak_ref.id())))
        .unwrap_or_else(|_| PathBuf::from("flatpak-sbom.cdx.json"))
}

fn scan(
    reader: &(impl ostree::OstreeFileReader + content::ContentSource),
    args: ScanArgs,
) -> Result<()> {
    if (args.osv_commits || args.osv_packages) && args.format != "json" {
        anyhow::bail!("OSV scanning requires --format json");
    }
    let document = inventory(reader, &args.repo, &args.app_ref, &args.inventory)?;
    let output = grype::scan(&document, &args.format)?;
    if args.format == "json" {
        let mut findings: serde_json::Value =
            serde_json::from_str(&output).context("parse scanner JSON output")?;
        findings
            .get("matches")
            .and_then(serde_json::Value::as_array)
            .context("scanner JSON output has no matches array")?;
        let coverage = coverage::summarize(&serde_json::to_value(&document)?)?;
        findings
            .as_object_mut()
            .context("scanner JSON output is not an object")?
            .insert("flatpakCoverage".into(), serde_json::to_value(coverage)?);
        let reviews: Vec<_> = document
            .components
            .iter()
            .filter(|c| content::is_quarantined(c))
            .collect();
        findings.as_object_mut().unwrap().insert(
            "flatpakIdentityReviews".into(),
            serde_json::to_value(reviews)?,
        );
        if args.osv_commits {
            findings.as_object_mut().unwrap().insert(
                "flatpakOsv".into(),
                serde_json::to_value(osv::scan(
                    &document,
                    &args.osv_endpoint,
                    osv::Mode::Commits,
                )?)?,
            );
        }
        if args.osv_packages {
            findings.as_object_mut().unwrap().insert(
                "flatpakOsvPackages".into(),
                serde_json::to_value(osv::scan(
                    &document,
                    &args.osv_endpoint,
                    osv::Mode::Packages,
                )?)?,
            );
        }
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print!("{output}");
    }
    Ok(())
}

fn inventory(
    reader: &(impl ostree::OstreeFileReader + content::ContentSource),
    repo: &str,
    reference: &str,
    args: &InventoryArgs,
) -> Result<cyclonedx::Bom> {
    if args.installed {
        let installed = installed::InstalledReader::default();
        // A deployment is not necessarily from the configured/default remote.
        let mut bom = sbom::generate_for_app(&installed, "urn:flatpak:installed", reference)?;
        extensions::include(
            &mut bom,
            &installed,
            "urn:flatpak:installed",
            &args.extensions,
        )?;
        if args.active_extensions {
            extensions::discover_active(&mut bom, &installed)?;
        }
        bom.metadata.component.properties.push(cyclonedx::property(
            "flatpak:input-kind",
            "installed-deployment",
        ));
        if args.content_scanner.is_some() {
            content::enrich(&mut bom, &installed, false)?;
        }
        if args.cpe_mapping {
            identity::enrich(&mut bom)?;
        }
        Ok(bom)
    } else {
        let mut bom = sbom::generate_for_app(reader, repo, reference)?;
        extensions::include(&mut bom, reader, repo, &args.extensions)?;
        if args.content_scanner.is_some() {
            content::enrich(&mut bom, reader, args.acquire_extra_data)?;
        }
        if args.cpe_mapping {
            identity::enrich(&mut bom)?;
        }
        Ok(bom)
    }
}

fn report(args: ReportArgs) -> Result<()> {
    let report = grype::map_report(&args.findings)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_uses_reverse_dns_id() {
        assert_eq!(
            default_output_path("app/im.riot.Riot/x86_64/stable"),
            PathBuf::from("im.riot.Riot.cdx.json")
        );
    }

    #[test]
    fn default_output_falls_back_for_invalid_refs() {
        assert_eq!(
            default_output_path("im.riot.Riot"),
            PathBuf::from("flatpak-sbom.cdx.json")
        );
    }

    #[test]
    fn scanner_option_remains_compatible_without_dispatch() {
        let args = ["flatpak-sbom", "scan", "app/org.example.App/x86_64/stable"];
        assert!(Cli::try_parse_from(args).is_ok());
        assert!(Cli::try_parse_from(args.into_iter().chain(["--scanner", "grype"])).is_ok());
        assert!(Cli::try_parse_from(args.into_iter().chain(["--scanner", "unknown"])).is_err());
    }
}
