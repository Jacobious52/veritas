use std::path::Path;

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, CoverageReport, GeneratedArtifact, LanguagePlugin, LineRange,
    PluginCapability, ProjectInfo, RiskLevel, TargetKind, TestRunResult, VerificationPlan,
    VerificationTarget,
};

pub struct ExamplePlugin;

impl LanguagePlugin for ExamplePlugin {
    fn id(&self) -> &'static str {
        "example"
    }

    fn display_name(&self) -> &'static str {
        "Example"
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::TargetDiscovery,
            PluginCapability::SymbolGraph,
            PluginCapability::GeneratedTests,
            PluginCapability::ExistingTests,
        ]
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo> {
        if !root.join("example.toml").exists() {
            return Err(anyhow!("example project not found"));
        }
        Ok(ProjectInfo {
            language: self.id().to_string(),
            name: "example-project".to_string(),
            root: Utf8PathBuf::from_path_buf(root.to_path_buf())
                .map_err(|path| anyhow!("path is not UTF-8: {}", path.display()))?,
            manifests: vec![Utf8PathBuf::from("example.toml")],
        })
    }

    fn discover_targets(&self, _root: &Path) -> Result<Vec<VerificationTarget>> {
        Ok(vec![
            VerificationTarget {
                id: "example:project".to_string(),
                language: self.id().to_string(),
                kind: TargetKind::Project,
                path: Utf8PathBuf::from("."),
                symbol: None,
                signature: None,
                line_range: None,
                description: "Example project".to_string(),
                risk: RiskLevel::Medium,
            },
            VerificationTarget {
                id: "example:src/main.example:parse_total".to_string(),
                language: self.id().to_string(),
                kind: TargetKind::Function,
                path: Utf8PathBuf::from("src/main.example"),
                symbol: Some("parse_total".to_string()),
                signature: Some("fn parse_total(raw)".to_string()),
                line_range: Some(LineRange { start: 10, end: 24 }),
                description: "Example function parse_total".to_string(),
                risk: RiskLevel::High,
            },
        ])
    }

    fn generate_tests(
        &self,
        target: &VerificationTarget,
        _plan: &VerificationPlan,
    ) -> Result<Vec<GeneratedArtifact>> {
        Ok(vec![GeneratedArtifact {
            id: "example-symbol-graph".to_string(),
            language: self.id().to_string(),
            kind: ArtifactKind::SymbolGraph,
            target_id: target.id.clone(),
            path: Utf8PathBuf::from(".veritas/symbol_graph/example.json"),
            contents: r#"{"version":1,"symbols":[]}"#.to_string(),
            description: "Example Tree-sitter symbol graph".to_string(),
            status: ArtifactStatus::Planned,
        }])
    }

    fn run_tests(
        &self,
        _root: &Path,
        _artifacts: &[GeneratedArtifact],
        _plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        Ok(TestRunResult {
            language: self.id().to_string(),
            status: veritas_plugin_api::RunStatus::Passed,
            commands: vec![],
            failures: vec![],
            duration_ms: 0,
            quality: veritas_plugin_api::VerificationQuality::default(),
        })
    }

    fn collect_coverage(&self, _root: &Path) -> Result<Option<CoverageReport>> {
        Ok(Some(CoverageReport {
            tool: "example coverage".to_string(),
            summary: "not collected: skeleton plugin".to_string(),
            files: vec![],
        }))
    }
}
