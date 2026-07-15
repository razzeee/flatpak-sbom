use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod cyclonedx;
mod grype;
mod manifest;
mod metadata;
mod ostree;
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
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Flatpak app ref, for example app/org.example.App/x86_64/stable.
    app_ref: String,

    /// Flatpak OSTree remote URL.
    #[arg(long, default_value = DEFAULT_REPO)]
    repo: String,

    /// Vulnerability scanner backend.
    #[arg(long, default_value = "grype")]
    scanner: Scanner,

    /// Scanner output format.
    #[arg(long, default_value = "json")]
    format: String,
}

#[derive(Debug, Clone, ValueEnum)]
enum Scanner {
    Grype,
}

#[derive(Debug, Parser)]
struct ReportArgs {
    /// Grype JSON output to summarize with Flatpak scope information.
    findings: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let reader = ostree::CliOstreeFileReader::new();

    match cli.command {
        Command::Generate(args) => generate(&reader, args),
        Command::Scan(args) => scan(&reader, args),
        Command::Report(args) => report(args),
    }
}

fn generate(reader: &impl ostree::OstreeFileReader, args: GenerateArgs) -> Result<()> {
    let document = sbom::generate_for_app(reader, &args.repo, &args.app_ref)?;
    let json = serde_json::to_string_pretty(&document).context("serialize CycloneDX document")?;
    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&args.app_ref));

    if output.as_os_str() == "-" {
        println!("{json}");
    } else {
        std::fs::write(&output, json).with_context(|| format!("write {}", output.display()))?;
    }

    Ok(())
}

fn default_output_path(app_ref: &str) -> PathBuf {
    refname::FlatpakRef::parse(app_ref)
        .map(|flatpak_ref| PathBuf::from(format!("{}.cdx.json", flatpak_ref.id)))
        .unwrap_or_else(|_| PathBuf::from("flatpak-sbom.cdx.json"))
}

fn scan(reader: &impl ostree::OstreeFileReader, args: ScanArgs) -> Result<()> {
    match args.scanner {
        Scanner::Grype => {
            let mut document = sbom::generate_for_app(reader, &args.repo, &args.app_ref)?;
            make_grype_compatible(&mut document);
            let json =
                serde_json::to_vec_pretty(&document).context("serialize CycloneDX document")?;
            let tempdir = tempfile::tempdir().context("create temporary scan directory")?;
            let sbom_path = tempdir.path().join("flatpak-sbom.cdx.json");
            std::fs::write(&sbom_path, json).context("write temporary CycloneDX document")?;
            let output = grype::run_grype(&sbom_path, &args.format)?;
            print!("{output}");
            Ok(())
        }
    }
}

fn make_grype_compatible(document: &mut cyclonedx::Bom) {
    // Grype/Syft v1.40 rejects CycloneDX 1.7 JSON, but accepts the fields we emit as 1.6.
    document.schema = "https://cyclonedx.org/schema/bom-1.6.schema.json".to_string();
    document.spec_version = "1.6".to_string();
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
    fn grype_compatibility_downgrades_cyclonedx_version() {
        let mut document = cyclonedx::Bom {
            schema: "https://cyclonedx.org/schema/bom-1.7.schema.json".to_string(),
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.7".to_string(),
            serial_number: "urn:uuid:00000000-0000-0000-0000-000000000000".to_string(),
            version: 1,
            metadata: cyclonedx::Metadata {
                timestamp: None,
                lifecycles: vec![],
                tools: None,
                component: cyclonedx::Component {
                    component_type: "application".to_string(),
                    name: "test".to_string(),
                    bom_ref: "test".to_string(),
                    version: None,
                    purl: None,
                    external_references: vec![],
                    hashes: vec![],
                    licenses: vec![],
                    evidence: None,
                    properties: vec![],
                },
            },
            components: vec![],
            dependencies: vec![],
            compositions: vec![],
        };

        make_grype_compatible(&mut document);
        assert_eq!(
            document.schema,
            "https://cyclonedx.org/schema/bom-1.6.schema.json"
        );
        assert_eq!(document.spec_version, "1.6");
    }
}
