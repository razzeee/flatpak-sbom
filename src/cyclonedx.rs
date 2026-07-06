use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    pub bom_format: String,
    pub spec_version: String,
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
    pub component: Component,
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
    pub properties: Vec<Property>,
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
}

pub fn property(name: impl Into<String>, value: impl Into<String>) -> Property {
    Property {
        name: name.into(),
        value: value.into(),
    }
}
