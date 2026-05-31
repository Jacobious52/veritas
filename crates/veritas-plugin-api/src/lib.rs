use std::path::Path;

use anyhow::Result;
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

pub trait LanguagePlugin: Send + Sync {
    fn id(&self) -> &'static str;

    fn display_name(&self) -> &'static str;

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo>;

    fn discover_targets(&self, root: &Path) -> Result<Vec<VerificationTarget>>;

    fn generate_tests(
        &self,
        target: &VerificationTarget,
        plan: &VerificationPlan,
    ) -> Result<Vec<GeneratedArtifact>>;

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        plan: &VerificationPlan,
    ) -> Result<TestRunResult>;

    fn collect_coverage(&self, root: &Path) -> Result<Option<CoverageReport>>;
}

pub trait VerificationPlanner: Send + Sync {
    fn plan(&self, project: &ProjectInfo, target: &VerificationTarget) -> Result<VerificationPlan>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectInfo {
    pub language: String,
    pub name: String,
    pub root: Utf8PathBuf,
    pub manifests: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationTarget {
    pub id: String,
    pub language: String,
    pub kind: TargetKind,
    pub path: Utf8PathBuf,
    pub symbol: Option<String>,
    pub signature: Option<String>,
    pub line_range: Option<LineRange>,
    pub description: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineRange {
    pub start: usize,
    pub end: usize,
}

impl LineRange {
    pub fn overlaps(&self, other: &LineRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Project,
    Package,
    File,
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FailureSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationPlan {
    pub target_id: String,
    pub strategies: Vec<VerificationStrategy>,
    pub budget_seconds: u64,
    pub write_generated_tests: bool,
    pub run_existing_tests: bool,
    pub run_generated_tests: bool,
    pub fail_on_generated_test_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStrategy {
    ExistingTests,
    UnitTests,
    PropertyTests,
    Fuzzing,
    DifferentialTests,
    MutationChecks,
    CoverageFeedback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratedArtifact {
    pub id: String,
    pub language: String,
    pub kind: ArtifactKind,
    pub target_id: String,
    pub path: Utf8PathBuf,
    pub contents: String,
    pub description: String,
    pub status: ArtifactStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    UnitTest,
    PropertyTest,
    FuzzHarness,
    HarnessIndex,
    MutationCheck,
    CoverageFeedback,
    DifferentialBaseline,
    ReproCase,
    PackageAwareness,
    PackageGraph,
    SymbolGraph,
    ChangeDigest,
    AiFeedback,
    CandidatePatch,
    FindingBaseline,
    RegressionTest,
    DifferentialReplay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Planned,
    Written,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestRunResult {
    pub language: String,
    pub status: RunStatus,
    pub commands: Vec<CommandRecord>,
    pub failures: Vec<Failure>,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Utf8PathBuf,
    pub exit_code: Option<i32>,
    pub status: RunStatus,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub message: String,
    #[serde(default = "default_failure_severity")]
    pub severity: FailureSeverity,
    pub target_id: Option<String>,
    pub artifact_id: Option<String>,
    pub command: String,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    pub repro: Option<ReproCase>,
}

fn default_failure_severity() -> FailureSeverity {
    FailureSeverity::Error
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproCase {
    pub command: String,
    pub input: Option<String>,
    pub path: Option<Utf8PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageReport {
    pub tool: String,
    pub summary: String,
    pub files: Vec<CoverageFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageFile {
    pub path: Utf8PathBuf,
    pub line_coverage_percent: Option<u8>,
    pub uncovered_ranges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub project: Option<ProjectInfo>,
    pub targets: Vec<VerificationTarget>,
    pub plan: Option<VerificationPlan>,
    pub artifacts: Vec<GeneratedArtifact>,
    pub runs: Vec<TestRunResult>,
    pub coverage: Vec<CoverageReport>,
    pub findings: Vec<Failure>,
    pub suggested_next_steps: Vec<String>,
}

impl VerificationReport {
    pub fn empty() -> Self {
        Self {
            project: None,
            targets: Vec::new(),
            plan: None,
            artifacts: Vec::new(),
            runs: Vec::new(),
            coverage: Vec::new(),
            findings: Vec::new(),
            suggested_next_steps: Vec::new(),
        }
    }
}
