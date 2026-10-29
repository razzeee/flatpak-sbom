//! Opt-in OSV queries using exact Git commits or ecosystem package identities.
use crate::cyclonedx::{Bom, Component};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::Duration,
};

#[derive(Serialize)]
pub struct Report {
    endpoint: String,
    evidence_kind: &'static str,
    note: &'static str,
    queries: Vec<Query>,
    skipped: Vec<Skipped>,
}

#[derive(Serialize)]
struct Query {
    #[serde(flatten)]
    identity: Identity,
    components: Vec<Source>,
    vulnerabilities: Vec<Value>,
}

#[derive(Serialize)]
struct Source {
    bom_ref: String,
    name: String,
    scope: Option<String>,
    flatpak_ref: Option<String>,
    deployment_commit: Option<String>,
    source_url: Option<String>,
    inventory_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_sha256: Option<String>,
}

#[derive(Clone, Copy)]
pub enum Mode {
    Commits,
    Packages,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Identity {
    Commit { source_commit: String },
    Package { package_purl: String },
}

#[derive(Serialize)]
struct Skipped {
    component: Source,
    reason: &'static str,
}

fn prop<'a>(component: &'a Component, name: &str) -> Option<&'a str> {
    component
        .properties
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.value.as_str())
}

fn source(c: &Component) -> Source {
    Source {
        bom_ref: c.bom_ref.clone(),
        name: c.name.clone(),
        scope: prop(c, "flatpak:scope").map(str::to_owned),
        flatpak_ref: prop(c, "flatpak:ref").map(str::to_owned),
        deployment_commit: prop(c, "flatpak:commit").map(str::to_owned),
        source_url: prop(c, "flatpak:source-url")
            .or_else(|| prop(c, "flatpak:extra-data-url"))
            .map(str::to_owned),
        payload_sha256: prop(c, "flatpak:extra-data-sha256").map(str::to_owned),
        inventory_kind: if matches!(
            prop(c, "flatpak:inventory-kind"),
            Some("content-detected" | "extra-data-content")
        ) {
            prop(c, "flatpak:inventory-kind").map(str::to_owned)
        } else if prop(c, "flatpak:source-type").is_some() {
            Some("manifest-source".into())
        } else {
            None
        },
    }
}

pub fn scan(bom: &Bom, endpoint: &str, mode: Mode) -> Result<Report> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut grouped: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    let mut skipped = Vec::new();
    for c in &bom.components {
        let identity = match mode {
            Mode::Commits => {
                if prop(c, "flatpak:source-type") != Some("git") {
                    continue;
                }
                prop(c, "flatpak:source-commit")
                    .filter(|s| {
                        matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                    .map(str::to_ascii_lowercase)
                    .ok_or("missing-full-git-commit")
            }
            Mode::Packages => {
                if !matches!(
                    prop(c, "flatpak:inventory-kind"),
                    Some("content-detected" | "extra-data-content")
                ) && !matches!(
                    prop(c, "flatpak:source-type"),
                    Some("archive" | "git" | "extra-data" | "file")
                ) {
                    continue;
                }
                package_identity(c)
            }
        };
        match identity {
            Ok(key) => grouped.entry(key).or_default().push(source(c)),
            Err(reason) => skipped.push(Skipped {
                component: source(c),
                reason,
            }),
        }
    }
    let grouped: Vec<_> = grouped.into_iter().collect();
    let requests: Vec<_> = grouped
        .iter()
        .map(|(key, _)| match mode {
            Mode::Commits => json!({"commit":key}),
            Mode::Packages => json!({"package":{"purl":key}}),
        })
        .collect();
    let results = if requests.len() > 32 {
        batch_query(&client, endpoint, &requests)?
    } else {
        requests
            .into_iter()
            .zip(&grouped)
            .map(|(request, (key, _))| {
                query(&client, endpoint, request).with_context(|| format!("query OSV {key}"))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let mut queries = Vec::new();
    for ((key, components), vulnerabilities) in grouped.into_iter().zip(results) {
        let identity = match mode {
            Mode::Commits => Identity::Commit { source_commit: key },
            Mode::Packages => Identity::Package { package_purl: key },
        };
        queries.push(Query {
            identity,
            components,
            vulnerabilities,
        });
    }
    Ok(Report {
        endpoint: endpoint.into(), evidence_kind: match mode {
            Mode::Commits => "manifest-git-source", Mode::Packages => "ecosystem-package-identity",
        },
        note: "OSV matches supplied identities. Consult each component's inventory_kind: manifest sources may be build-only, patched, or removed; content detection does not establish exploitability. No matches does not prove safety or database coverage.",
        queries, skipped,
    })
}

// OSV guarantees querybatch results have the same order as the requests. Keep
// each query's pagination state separate and fetch shared advisory details once.
fn batch_query(client: &Client, endpoint: &str, requests: &[Value]) -> Result<Vec<Vec<Value>>> {
    let endpoint = reqwest::Url::parse(endpoint).context("parse OSV endpoint")?;
    if !endpoint.path().ends_with("/query")
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("bulk OSV scans require an endpoint ending in /query with sibling querybatch and vulns endpoints");
    }
    let batch_url = endpoint.join("querybatch")?;
    let detail_url = endpoint.join("vulns/")?;
    let mut ids = vec![BTreeSet::<String>::new(); requests.len()];
    let mut total_bytes = 0usize;
    for (chunk_index, chunk) in requests.chunks(100).enumerate() {
        let mut pending: Vec<_> = chunk.iter().cloned().enumerate().collect();
        let mut tokens = vec![BTreeSet::new(); chunk.len()];
        for page in 0..100 {
            let body =
                json!({"queries":pending.iter().map(|(_, request)| request).collect::<Vec<_>>()});
            let (response, bytes) = read_response(
                client
                    .post(batch_url.clone())
                    .json(&body)
                    .send()
                    .context("send OSV batch query")?,
            )?;
            total_bytes += bytes;
            check_response_budget(total_bytes)?;
            let results = response["results"]
                .as_array()
                .context("OSV batch response must contain results array")?;
            if results.len() != pending.len() {
                bail!("OSV batch result count does not match query count");
            }
            let mut next = Vec::new();
            for ((index, mut request), result) in pending.into_iter().zip(results) {
                let object = result
                    .as_object()
                    .context("OSV batch item must be an object")?;
                if object.contains_key("error")
                    || object.contains_key("code")
                    || (!object.is_empty()
                        && !object.contains_key("vulns")
                        && !object.contains_key("next_page_token"))
                {
                    bail!("invalid OSV batch item: {result}");
                }
                if let Some(vulns) = object.get("vulns") {
                    for vuln in vulns
                        .as_array()
                        .context("OSV batch vulns must be an array")?
                    {
                        let id = vuln["id"]
                            .as_str()
                            .filter(|id| !id.is_empty())
                            .context("OSV batch advisory missing id")?;
                        ids[chunk_index * 100 + index].insert(id.to_owned());
                    }
                }
                let token = match object.get("next_page_token") {
                    None => "",
                    Some(token) => token.as_str().context("OSV page token must be a string")?,
                };
                if !token.is_empty() {
                    if !tokens[index].insert(token.to_owned()) {
                        bail!("OSV repeated a batch pagination token");
                    }
                    request["page_token"] = json!(token);
                    next.push((index, request));
                }
            }
            if next.is_empty() {
                break;
            }
            if page == 99 {
                bail!("OSV batch pagination exceeded 100 pages");
            }
            pending = next;
        }
    }
    let unique: Vec<_> = ids
        .iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut details = BTreeMap::new();
    // At most four detail requests in flight. A failure stops new groups and
    // the caller emits no partial report. Sorting below makes output stable.
    for chunk in unique.chunks(4) {
        let records = std::thread::scope(|scope| -> Result<Vec<_>> {
            let handles: Vec<_> = chunk
                .iter()
                .map(|id| {
                    let mut url = detail_url.clone();
                    url.path_segments_mut()
                        .expect("HTTP URL supports path segments")
                        .pop_if_empty()
                        .push(id);
                    scope.spawn(move || -> Result<_> {
                        let (record, bytes) = read_response(
                            client
                                .get(url)
                                .send()
                                .context("fetch OSV advisory details")?,
                        )?;
                        if record["id"].as_str() != Some(id.as_str()) {
                            bail!("OSV advisory detail ID disagrees with requested ID {id}");
                        }
                        Ok(((*id).clone(), record, bytes))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("OSV detail worker panicked"))?
                })
                .collect()
        })?;
        for (id, record, bytes) in records {
            total_bytes += bytes;
            check_response_budget(total_bytes)?;
            details.insert(id, record);
        }
    }
    Ok(ids
        .into_iter()
        .map(|ids| ids.into_iter().map(|id| details[&id].clone()).collect())
        .collect())
}

fn check_response_budget(bytes: usize) -> Result<()> {
    if bytes > 128 * 1024 * 1024 {
        bail!("OSV bulk scan exceeds 128 MiB response budget");
    }
    Ok(())
}

fn read_response(response: reqwest::blocking::Response) -> Result<(Value, usize)> {
    if !response.status().is_success() {
        bail!("OSV HTTP status {}", response.status());
    }
    let mut bytes = Vec::new();
    response.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 {
        bail!("OSV response exceeds 8 MiB");
    }
    let value = serde_json::from_slice(&bytes).context("parse OSV response")?;
    Ok((value, bytes.len()))
}

fn package_identity(c: &Component) -> std::result::Result<String, &'static str> {
    let raw = c.purl.as_deref().ok_or("missing-package-identity")?;
    let purl = raw
        .parse::<packageurl::PackageUrl>()
        .map_err(|_| "invalid-package-url")?;
    // Repository and generic identities must not be guessed into a registry
    // package of the same name. These ecosystems are supported by OSV.
    if !matches!(
        purl.ty(),
        "npm" | "pypi" | "cargo" | "golang" | "maven" | "nuget" | "gem"
    ) {
        return Err("unsupported-osv-package-ecosystem");
    }
    if !purl.qualifiers().is_empty() || purl.subpath().is_some() {
        return Err("qualified-or-subpath-package-identity");
    }
    let version = purl
        .version()
        .filter(|v| !v.is_empty() && !matches!(*v, "UNKNOWN" | "unknown"))
        .ok_or("missing-package-release-version")?;
    if c.version.as_deref().is_some_and(|v| v != version) {
        return Err("conflicting-package-versions");
    }
    if matches!(
        prop(c, "flatpak:version-kind"),
        Some("git-commit" | "filename")
    ) || prop(c, "flatpak:source-commit") == Some(version)
    {
        return Err("unconfirmed-package-release-version");
    }
    Ok(purl.to_string())
}

fn query(client: &Client, endpoint: &str, mut request: Value) -> Result<Vec<Value>> {
    let mut tokens = BTreeSet::new();
    let mut advisories = BTreeMap::new();
    let mut total_bytes = 0usize;
    for _ in 0..100 {
        let response = client
            .post(endpoint)
            .json(&request)
            .send()
            .context("send OSV query")?
            .error_for_status()
            .context("OSV HTTP status")?;
        let mut bytes = Vec::new();
        response.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 8 * 1024 * 1024 {
            bail!("OSV response exceeds 8 MiB");
        }
        total_bytes += bytes.len();
        if total_bytes > 32 * 1024 * 1024 {
            bail!("OSV query exceeds 32 MiB across pages");
        }
        let value: Value = serde_json::from_slice(&bytes).context("parse OSV response")?;
        let object = value
            .as_object()
            .context("OSV response must be an object")?;
        if !object.is_empty()
            && !object.contains_key("vulns")
            && !object.contains_key("next_page_token")
        {
            bail!("unrecognized OSV response: {value}");
        }
        if object.contains_key("error") || object.contains_key("code") {
            bail!("OSV returned an error object: {value}");
        }
        if let Some(vulns) = object.get("vulns") {
            for advisory in vulns.as_array().context("OSV vulns must be an array")? {
                let id = advisory["id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .context("OSV advisory missing id")?;
                // Retain full records, including withdrawn status and affected
                // ranges; don't relabel Git fixed commits as fixed versions.
                advisories.insert(id.to_owned(), advisory.clone());
            }
        }
        let token = match object.get("next_page_token") {
            None => "",
            Some(token) => token.as_str().context("OSV page token must be a string")?,
        };
        if token.is_empty() {
            return Ok(advisories.into_values().collect());
        }
        if !tokens.insert(token.to_owned()) {
            bail!("OSV repeated a pagination token");
        }
        request["page_token"] = json!(token);
    }
    bail!("OSV pagination exceeded 100 pages")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cyclonedx::property;

    fn component(purl: &str) -> Component {
        Component {
            component_type: "library".into(),
            name: "example".into(),
            bom_ref: "example".into(),
            version: Some("1.2.3".into()),
            purl: Some(purl.into()),
            cpe: None,
            external_references: vec![],
            hashes: vec![],
            licenses: vec![],
            evidence: None,
            properties: vec![property("flatpak:inventory-kind", "content-detected")],
        }
    }

    #[test]
    fn ecosystem_queries_preserve_namespace_and_release() {
        for purl in [
            "pkg:npm/%40scope/example@1.2.3",
            "pkg:pypi/example@1.2.3",
            "pkg:cargo/example@1.2.3",
            "pkg:golang/github.com/example/module@1.2.3",
            "pkg:maven/org.example/library@1.2.3",
            "pkg:nuget/example@1.2.3",
            "pkg:gem/example@1.2.3",
        ] {
            assert_eq!(package_identity(&component(purl)).unwrap(), purl);
        }
    }

    #[test]
    fn package_queries_do_not_guess_versions_or_ecosystems() {
        for (purl, reason) in [
            (
                "pkg:generic/example@1.2.3",
                "unsupported-osv-package-ecosystem",
            ),
            (
                "pkg:github/example/library@1.2.3",
                "unsupported-osv-package-ecosystem",
            ),
            ("pkg:pypi/example", "missing-package-release-version"),
            ("pkg:npm/example@UNKNOWN", "missing-package-release-version"),
            ("pkg:pypi/example@9.9.9", "conflicting-package-versions"),
            (
                "pkg:golang/github.com/example/module@1.2.3#child",
                "qualified-or-subpath-package-identity",
            ),
            (
                "pkg:pypi/example@1.2.3?arch=x86_64",
                "qualified-or-subpath-package-identity",
            ),
            ("not-a-purl", "invalid-package-url"),
        ] {
            assert_eq!(package_identity(&component(purl)), Err(reason));
        }
        let mut package = component("pkg:pypi/example@1.2.3");
        package
            .properties
            .push(property("flatpak:version-kind", "filename"));
        assert_eq!(
            package_identity(&package),
            Err("unconfirmed-package-release-version")
        );
        package.properties = vec![property("flatpak:source-commit", "1.2.3")];
        assert_eq!(
            package_identity(&package),
            Err("unconfirmed-package-release-version")
        );
    }
}
