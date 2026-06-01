use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use veritas_plugin_api::{FailureSeverity, RiskLevel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VeritasConfig {
    pub budget_seconds: u64,
    pub write_generated_tests: bool,
    pub fail_on_generated_test_failure: bool,
    pub fail_on_findings: bool,
    pub planner: PlannerConfig,
    pub policy: PolicyConfig,
    pub plugins: PluginConfigs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannerConfig {
    pub mode: PlannerMode,
    pub command: Option<String>,
    pub fail_on_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlannerMode {
    Deterministic,
    ExternalLlm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginConfigs {
    pub rust: RustPluginConfig,
    pub go: GoPluginConfig,
    pub python: PythonPluginConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustPluginConfig {
    pub property_framework: String,
    pub command_timeout_seconds: u64,
    pub coverage_enabled: bool,
    pub coverage_timeout_seconds: u64,
    pub cargo_jobs: usize,
    pub test_threads: usize,
    pub systemd_scope: bool,
    pub memory_max: Option<String>,
    pub cpu_quota: Option<String>,
    pub mutation: MutationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoPluginConfig {
    pub fuzz_seconds: u64,
    pub fuzz_existing: bool,
    pub fuzz_concurrency: usize,
    pub coverage_enabled: bool,
    pub reverse_dependency_depth: usize,
    pub max_fuzz_targets: usize,
    pub command_timeout_seconds: u64,
    pub max_packages: usize,
    pub max_mutants: usize,
    pub build_tags: Vec<String>,
    pub mutation: MutationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PythonPluginConfig {
    pub command_timeout_seconds: u64,
    pub coverage_enabled: bool,
    pub mutation: MutationConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationConfig {
    pub enabled_domains: Vec<String>,
    pub disabled_domains: Vec<String>,
    pub enabled_operators: Vec<String>,
    pub disabled_operators: Vec<String>,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub include_symbols: Vec<String>,
    pub exclude_symbols: Vec<String>,
    pub include_mutant_ids: Vec<String>,
    pub exclude_mutant_ids: Vec<String>,
    pub dry_run: bool,
    pub max_mutants: Option<usize>,
    pub workers: usize,
    pub test_cpu: Option<usize>,
    pub timeout_coefficient: u64,
    pub timeout_min_seconds: Option<u64>,
    pub timeout_max_seconds: Option<u64>,
    pub shard_index: Option<usize>,
    pub shard_count: Option<usize>,
    pub output_statuses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    pub fail_on_severity: FailureSeverity,
    pub fail_on_languages: Vec<String>,
    pub fail_on_artifact_kinds: Vec<String>,
    pub fail_on_target_risks: Vec<RiskLevel>,
    pub min_mutation_score: Option<u8>,
    pub min_mutation_efficacy: Option<u8>,
    pub min_mutant_coverage: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigFile {
    veritas: Option<VeritasSection>,
    planner: Option<PlannerSection>,
    policy: Option<PolicySection>,
    mutation: Option<MutationConfigPartial>,
    plugins: Option<PluginSection>,
}

#[derive(Debug, Clone, Deserialize)]
struct VeritasSection {
    budget_seconds: Option<u64>,
    write_generated_tests: Option<bool>,
    fail_on_generated_test_failure: Option<bool>,
    fail_on_findings: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct PlannerSection {
    mode: Option<PlannerMode>,
    command: Option<String>,
    fail_on_error: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicySection {
    fail_on_severity: Option<FailureSeverity>,
    fail_on_languages: Option<Vec<String>>,
    fail_on_artifact_kinds: Option<Vec<String>>,
    fail_on_target_risks: Option<Vec<RiskLevel>>,
    min_mutation_score: Option<u8>,
    min_mutation_efficacy: Option<u8>,
    min_mutant_coverage: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginSection {
    rust: Option<RustPluginConfigPartial>,
    go: Option<GoPluginConfigPartial>,
    python: Option<PythonPluginConfigPartial>,
}

#[derive(Debug, Clone, Deserialize)]
struct RustPluginConfigPartial {
    property_framework: Option<String>,
    command_timeout_seconds: Option<u64>,
    coverage_enabled: Option<bool>,
    coverage_timeout_seconds: Option<u64>,
    cargo_jobs: Option<usize>,
    test_threads: Option<usize>,
    systemd_scope: Option<bool>,
    memory_max: Option<String>,
    cpu_quota: Option<String>,
    mutation: Option<MutationConfigPartial>,
}

#[derive(Debug, Clone, Deserialize)]
struct GoPluginConfigPartial {
    fuzz_seconds: Option<u64>,
    fuzz_existing: Option<bool>,
    fuzz_concurrency: Option<usize>,
    coverage_enabled: Option<bool>,
    reverse_dependency_depth: Option<usize>,
    max_fuzz_targets: Option<usize>,
    command_timeout_seconds: Option<u64>,
    max_packages: Option<usize>,
    max_mutants: Option<usize>,
    build_tags: Option<Vec<String>>,
    mutation: Option<MutationConfigPartial>,
}

#[derive(Debug, Clone, Deserialize)]
struct PythonPluginConfigPartial {
    command_timeout_seconds: Option<u64>,
    coverage_enabled: Option<bool>,
    mutation: Option<MutationConfigPartial>,
}

#[derive(Debug, Clone, Deserialize)]
struct MutationConfigPartial {
    enabled_domains: Option<Vec<String>>,
    disabled_domains: Option<Vec<String>>,
    enabled_operators: Option<Vec<String>>,
    disabled_operators: Option<Vec<String>>,
    include_paths: Option<Vec<String>>,
    exclude_paths: Option<Vec<String>>,
    include_symbols: Option<Vec<String>>,
    exclude_symbols: Option<Vec<String>>,
    include_mutant_ids: Option<Vec<String>>,
    exclude_mutant_ids: Option<Vec<String>>,
    dry_run: Option<bool>,
    max_mutants: Option<usize>,
    workers: Option<usize>,
    test_cpu: Option<usize>,
    timeout_coefficient: Option<u64>,
    timeout_min_seconds: Option<u64>,
    timeout_max_seconds: Option<u64>,
    shard_index: Option<usize>,
    shard_count: Option<usize>,
    output_statuses: Option<Vec<String>>,
}

impl Default for VeritasConfig {
    fn default() -> Self {
        Self {
            budget_seconds: 120,
            write_generated_tests: true,
            fail_on_generated_test_failure: true,
            fail_on_findings: false,
            planner: PlannerConfig {
                mode: PlannerMode::Deterministic,
                command: None,
                fail_on_error: false,
            },
            policy: PolicyConfig {
                fail_on_severity: FailureSeverity::Error,
                fail_on_languages: Vec::new(),
                fail_on_artifact_kinds: Vec::new(),
                fail_on_target_risks: Vec::new(),
                min_mutation_score: None,
                min_mutation_efficacy: None,
                min_mutant_coverage: None,
            },
            plugins: PluginConfigs {
                rust: RustPluginConfig {
                    property_framework: "proptest".to_string(),
                    command_timeout_seconds: 120,
                    coverage_enabled: false,
                    coverage_timeout_seconds: 120,
                    cargo_jobs: 1,
                    test_threads: 1,
                    systemd_scope: false,
                    memory_max: None,
                    cpu_quota: None,
                    mutation: MutationConfig::default(),
                },
                go: GoPluginConfig {
                    fuzz_seconds: 10,
                    fuzz_existing: true,
                    fuzz_concurrency: 2,
                    coverage_enabled: true,
                    reverse_dependency_depth: 1,
                    max_fuzz_targets: 20,
                    command_timeout_seconds: 120,
                    max_packages: 64,
                    max_mutants: 8,
                    build_tags: Vec::new(),
                    mutation: MutationConfig::default(),
                },
                python: PythonPluginConfig {
                    command_timeout_seconds: 120,
                    coverage_enabled: false,
                    mutation: MutationConfig::default(),
                },
            },
        }
    }
}

impl VeritasConfig {
    pub fn load(root: &Path) -> Result<Self> {
        let mut config = Self::default();
        let Some(path) = config_path(root) else {
            return Ok(config);
        };

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let parsed: ConfigFile = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config {}", path.display()))?;

        if let Some(veritas) = parsed.veritas {
            if let Some(value) = veritas.budget_seconds {
                config.budget_seconds = value;
            }
            if let Some(value) = veritas.write_generated_tests {
                config.write_generated_tests = value;
            }
            if let Some(value) = veritas.fail_on_generated_test_failure {
                config.fail_on_generated_test_failure = value;
            }
            if let Some(value) = veritas.fail_on_findings {
                config.fail_on_findings = value;
            }
        }

        if let Some(planner) = parsed.planner {
            if let Some(value) = planner.mode {
                config.planner.mode = value;
            }
            if let Some(value) = planner.command {
                config.planner.command = Some(value);
            }
            if let Some(value) = planner.fail_on_error {
                config.planner.fail_on_error = value;
            }
        }

        if let Some(policy) = parsed.policy {
            if let Some(value) = policy.fail_on_severity {
                config.policy.fail_on_severity = value;
            }
            if let Some(value) = policy.fail_on_languages {
                config.policy.fail_on_languages = value;
            }
            if let Some(value) = policy.fail_on_artifact_kinds {
                config.policy.fail_on_artifact_kinds = value;
            }
            if let Some(value) = policy.fail_on_target_risks {
                config.policy.fail_on_target_risks = value;
            }
            if let Some(value) = policy.min_mutation_score {
                config.policy.min_mutation_score = Some(value.min(100));
            }
            if let Some(value) = policy.min_mutation_efficacy {
                config.policy.min_mutation_efficacy = Some(value.min(100));
            }
            if let Some(value) = policy.min_mutant_coverage {
                config.policy.min_mutant_coverage = Some(value.min(100));
            }
        }

        if let Some(mutation) = parsed.mutation {
            apply_mutation_config(&mut config.plugins.rust.mutation, &mutation);
            apply_mutation_config(&mut config.plugins.go.mutation, &mutation);
        }

        if let Some(plugins) = parsed.plugins {
            if let Some(rust) = plugins.rust {
                if let Some(value) = rust.property_framework {
                    config.plugins.rust.property_framework = value;
                }
                if let Some(value) = rust.command_timeout_seconds {
                    config.plugins.rust.command_timeout_seconds = value;
                }
                if let Some(value) = rust.coverage_enabled {
                    config.plugins.rust.coverage_enabled = value;
                }
                if let Some(value) = rust.coverage_timeout_seconds {
                    config.plugins.rust.coverage_timeout_seconds = value;
                }
                if let Some(value) = rust.cargo_jobs {
                    config.plugins.rust.cargo_jobs = value;
                }
                if let Some(value) = rust.test_threads {
                    config.plugins.rust.test_threads = value;
                }
                if let Some(value) = rust.systemd_scope {
                    config.plugins.rust.systemd_scope = value;
                }
                if let Some(value) = rust.memory_max {
                    config.plugins.rust.memory_max = Some(value);
                }
                if let Some(value) = rust.cpu_quota {
                    config.plugins.rust.cpu_quota = Some(value);
                }
                if let Some(value) = rust.mutation {
                    apply_mutation_config(&mut config.plugins.rust.mutation, &value);
                }
            }
            if let Some(go) = plugins.go {
                if let Some(value) = go.fuzz_seconds {
                    config.plugins.go.fuzz_seconds = value;
                }
                if let Some(value) = go.fuzz_existing {
                    config.plugins.go.fuzz_existing = value;
                }
                if let Some(value) = go.fuzz_concurrency {
                    config.plugins.go.fuzz_concurrency = value.max(1);
                }
                if let Some(value) = go.coverage_enabled {
                    config.plugins.go.coverage_enabled = value;
                }
                if let Some(value) = go.reverse_dependency_depth {
                    config.plugins.go.reverse_dependency_depth = value;
                }
                if let Some(value) = go.max_fuzz_targets {
                    config.plugins.go.max_fuzz_targets = value;
                }
                if let Some(value) = go.command_timeout_seconds {
                    config.plugins.go.command_timeout_seconds = value;
                }
                if let Some(value) = go.max_packages {
                    config.plugins.go.max_packages = value;
                }
                if let Some(value) = go.max_mutants {
                    config.plugins.go.max_mutants = value;
                }
                if let Some(value) = go.build_tags {
                    config.plugins.go.build_tags = value;
                }
                if let Some(value) = go.mutation {
                    apply_mutation_config(&mut config.plugins.go.mutation, &value);
                }
            }
            if let Some(python) = plugins.python {
                if let Some(value) = python.command_timeout_seconds {
                    config.plugins.python.command_timeout_seconds = value;
                }
                if let Some(value) = python.coverage_enabled {
                    config.plugins.python.coverage_enabled = value;
                }
                if let Some(value) = python.mutation {
                    apply_mutation_config(&mut config.plugins.python.mutation, &value);
                }
            }
        }

        Ok(config)
    }
}

fn apply_mutation_config(config: &mut MutationConfig, partial: &MutationConfigPartial) {
    if let Some(value) = &partial.enabled_domains {
        config.enabled_domains = value.clone();
    }
    if let Some(value) = &partial.disabled_domains {
        config.disabled_domains = value.clone();
    }
    if let Some(value) = &partial.enabled_operators {
        config.enabled_operators = value.clone();
    }
    if let Some(value) = &partial.disabled_operators {
        config.disabled_operators = value.clone();
    }
    if let Some(value) = &partial.include_paths {
        config.include_paths = value.clone();
    }
    if let Some(value) = &partial.exclude_paths {
        config.exclude_paths = value.clone();
    }
    if let Some(value) = &partial.include_symbols {
        config.include_symbols = value.clone();
    }
    if let Some(value) = &partial.exclude_symbols {
        config.exclude_symbols = value.clone();
    }
    if let Some(value) = &partial.include_mutant_ids {
        config.include_mutant_ids = value.clone();
    }
    if let Some(value) = &partial.exclude_mutant_ids {
        config.exclude_mutant_ids = value.clone();
    }
    if let Some(value) = partial.dry_run {
        config.dry_run = value;
    }
    if let Some(value) = partial.max_mutants {
        config.max_mutants = Some(value.max(1));
    }
    if let Some(value) = partial.workers {
        config.workers = value;
    }
    if let Some(value) = partial.test_cpu {
        config.test_cpu = Some(value.max(1));
    }
    if let Some(value) = partial.timeout_coefficient {
        config.timeout_coefficient = value;
    }
    if let Some(value) = partial.timeout_min_seconds {
        config.timeout_min_seconds = Some(value);
    }
    if let Some(value) = partial.timeout_max_seconds {
        config.timeout_max_seconds = Some(value);
    }
    if let Some(value) = partial.shard_index {
        config.shard_index = Some(value);
    }
    if let Some(value) = partial.shard_count {
        config.shard_count = Some(value.max(1));
    }
    if let Some(value) = &partial.output_statuses {
        config.output_statuses = value.clone();
    }
}

fn config_path(root: &Path) -> Option<std::path::PathBuf> {
    let candidates = [root.join("veritas.toml"), root.join(".veritas.toml")];
    candidates.into_iter().find(|candidate| candidate.exists())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use veritas_plugin_api::{FailureSeverity, RiskLevel};

    use super::VeritasConfig;

    #[test]
    fn loads_go_production_and_policy_config() {
        let root = TempRoot::new();
        fs::write(
            root.path().join("veritas.toml"),
            r#"
[policy]
fail_on_severity = "warning"
fail_on_languages = ["go"]
fail_on_artifact_kinds = ["mutation_check"]
fail_on_target_risks = ["high"]
min_mutation_score = 70
min_mutation_efficacy = 75
min_mutant_coverage = 80

[mutation]
disabled_operators = ["loop"]
exclude_paths = ["vendor/", "_generated.go$"]
dry_run = true
max_mutants = 17
workers = 4
test_cpu = 2
timeout_coefficient = 3
output_statuses = ["lived", "timed_out"]

[plugins.go]
fuzz_seconds = 3
fuzz_existing = false
fuzz_concurrency = 3
coverage_enabled = false
reverse_dependency_depth = 2
max_fuzz_targets = 4
command_timeout_seconds = 9
max_packages = 12
max_mutants = 5
build_tags = ["integration", "sqlite"]

[plugins.go.mutation]
enabled_operators = ["arithmetic", "comparison"]
dry_run = false

[plugins.rust]
property_framework = "proptest"
command_timeout_seconds = 33
coverage_enabled = true
coverage_timeout_seconds = 44
cargo_jobs = 2
test_threads = 3
systemd_scope = true
memory_max = "4G"
cpu_quota = "150%"
"#,
        )
        .expect("write config");

        let config = VeritasConfig::load(root.path()).expect("load config");

        assert_eq!(config.policy.fail_on_severity, FailureSeverity::Warning);
        assert_eq!(config.policy.fail_on_languages, vec!["go"]);
        assert_eq!(config.policy.fail_on_artifact_kinds, vec!["mutation_check"]);
        assert_eq!(config.policy.fail_on_target_risks, vec![RiskLevel::High]);
        assert_eq!(config.policy.min_mutation_score, Some(70));
        assert_eq!(config.policy.min_mutation_efficacy, Some(75));
        assert_eq!(config.policy.min_mutant_coverage, Some(80));
        assert_eq!(
            config.plugins.rust.mutation.disabled_operators,
            vec!["loop"]
        );
        assert!(config.plugins.rust.mutation.dry_run);
        assert_eq!(config.plugins.rust.mutation.max_mutants, Some(17));
        assert_eq!(config.plugins.rust.mutation.test_cpu, Some(2));
        assert_eq!(config.plugins.rust.mutation.timeout_coefficient, 3);
        assert_eq!(
            config.plugins.go.mutation.enabled_operators,
            vec!["arithmetic", "comparison"]
        );
        assert_eq!(
            config.plugins.go.mutation.exclude_paths,
            vec!["vendor/", "_generated.go$"]
        );
        assert!(!config.plugins.go.mutation.dry_run);
        assert_eq!(config.plugins.go.fuzz_seconds, 3);
        assert!(!config.plugins.go.fuzz_existing);
        assert_eq!(config.plugins.go.fuzz_concurrency, 3);
        assert!(!config.plugins.go.coverage_enabled);
        assert_eq!(config.plugins.go.reverse_dependency_depth, 2);
        assert_eq!(config.plugins.go.max_fuzz_targets, 4);
        assert_eq!(config.plugins.go.command_timeout_seconds, 9);
        assert_eq!(config.plugins.go.max_packages, 12);
        assert_eq!(config.plugins.go.max_mutants, 5);
        assert_eq!(config.plugins.go.build_tags, vec!["integration", "sqlite"]);
        assert_eq!(config.plugins.rust.command_timeout_seconds, 33);
        assert!(config.plugins.rust.coverage_enabled);
        assert_eq!(config.plugins.rust.coverage_timeout_seconds, 44);
        assert_eq!(config.plugins.rust.cargo_jobs, 2);
        assert_eq!(config.plugins.rust.test_threads, 3);
        assert!(config.plugins.rust.systemd_scope);
        assert_eq!(config.plugins.rust.memory_max.as_deref(), Some("4G"));
        assert_eq!(config.plugins.rust.cpu_quota.as_deref(), Some("150%"));
    }

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after UNIX_EPOCH")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("veritas-config-test-{}-{nanos}", process::id()));
            fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
