use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compositions: Vec<Composition>,
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lifecycles: Vec<Lifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Tools>,
    pub component: Component,
}

#[derive(Debug, Serialize)]
pub struct Lifecycle {
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Tools {
    pub components: Vec<Component>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<LicenseChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<EvidenceIdentity>,
}

#[derive(Debug, Serialize, Clone)]
pub struct EvidenceIdentity {
    pub field: String,
    pub confidence: f32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<EvidenceIdentityMethod>,
}

#[derive(Debug, Serialize, Clone)]
pub struct EvidenceIdentityMethod {
    pub technique: String,
    pub confidence: f32,
    pub value: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct LicenseChoice {
    pub expression: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct Hash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference {
    #[serde(rename = "type")]
    pub reference_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub bom_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Composition {
    pub aggregate: String,
    pub assemblies: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

pub fn property(name: impl Into<String>, value: impl Into<String>) -> Property {
    Property {
        name: name.into(),
        value: value.into(),
    }
}
