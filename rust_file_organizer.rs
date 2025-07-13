use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug)]
struct HealthReport {
    score: u32,
    max_score: u32,
    issues: Vec<Issue>,
    suggestions: Vec<String>,
    stats: RepoStats,
}

#[derive(Debug)]
struct Issue {
    category: String,
    severity: Severity,
    description: String,
    file_path: Option<PathBuf>,
}

#[derive(Debug)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug)]
struct RepoStats {
    total_files: usize,
    lines_of_code: usize,
    commit_count: usize,
    branch_count: usize,
    last_commit_days: Option<u32>,
    file_types: HashMap<String, usize>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        print_help();
        return;
    }
    
    let path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        env::current_dir().unwrap()
    };
    
    println!("🔍 Git Health Scanner v1.0");
    println!("Analyzing: {}", path.display());
    println!();
    
    let start = Instant::now();
    
    match analyze_repository(&path) {
        Ok(report) => {
            print_report(&report);
            println!("⏱️  Analysis completed in {:.2}s", start.elapsed().as_secs_f64());
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn analyze_repository(path: &Path) -> io::Result<HealthReport> {
    if !path.join(".git").exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Not a Git repository"));
    }
    
    let mut report = HealthReport {
        score: 0,
        max_score: 0,
        issues: Vec::new(),
        suggestions: Vec::new(),
        stats: RepoStats {
            total_files: 0,
            lines_of_code: 0,
            commit_count: 0,
            branch_count: 0,
            last_commit_days: None,
            file_types: HashMap::new(),
        },
    };
    
    // Gather repository statistics
    gather_stats(path, &mut report)?;
    
    // Run health checks
    check_readme(path, &mut report)?;
    check_license(path, &mut report)?;
    check_gitignore(path, &mut report)?;
    check_large_files(path, &mut report)?;
    check_secrets(path, &mut report)?;
    check_commit_history(path, &mut report)?;
    check_dependencies(path, &mut report)?;
    check_code_quality(path, &mut report)?;
    check_documentation(path, &mut report)?;
    
    // Generate suggestions
    generate_suggestions(&mut report);
    
    Ok(report)
}

fn gather_stats(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    let mut total_files = 0;
    let mut lines_of_code = 0;
    let mut file_types = HashMap::new();
    
    fn walk_dir(dir: &Path, stats: &mut (usize, usize, &mut HashMap<String, usize>)) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    walk_dir(&path, stats)?;
                }
            } else {
                stats.0 += 1;
                
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_str().unwrap().to_lowercase();
                    *stats.2.entry(ext_str).or_insert(0) += 1;
                    
                    if is_code_file(&path) {
                        if let Ok(content) = fs::read_to_string(&path) {
                            stats.1 += content.lines().count();
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    walk_dir(path, &mut (total_files, lines_of_code, &mut file_types))?;
    
    report.stats.total_files = total_files;
    report.stats.lines_of_code = lines_of_code;
    report.stats.file_types = file_types;
    
    // Git stats
    if let Ok(output) = Command::new("git").args(&["rev-list", "--count", "HEAD"]).current_dir(path).output() {
        if let Ok(count_str) = String::from_utf8(output.stdout) {
            report.stats.commit_count = count_str.trim().parse().unwrap_or(0);
        }
    }
    
    if let Ok(output) = Command::new("git").args(&["branch", "-r"]).current_dir(path).output() {
        if let Ok(branches) = String::from_utf8(output.stdout) {
            report.stats.branch_count = branches.lines().count();
        }
    }
    
    if let Ok(output) = Command::new("git").args(&["log", "-1", "--format=%cr"]).current_dir(path).output() {
        if let Ok(last_commit) = String::from_utf8(output.stdout) {
            if last_commit.contains("days ago") {
                if let Some(days) = last_commit.split_whitespace().next().and_then(|s| s.parse().ok()) {
                    report.stats.last_commit_days = Some(days);
                }
            }
        }
    }
    
    Ok(())
}

fn check_readme(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 15;
    
    let readme_files = ["README.md", "README.rst", "README.txt", "readme.md"];
    let mut has_readme = false;
    
    for filename in &readme_files {
        if path.join(filename).exists() {
            has_readme = true;
            report.score += 10;
            
            // Check README quality
            if let Ok(content) = fs::read_to_string(path.join(filename)) {
                if content.len() > 500 {
                    report.score += 5;
                } else {
                    report.issues.push(Issue {
                        category: "Documentation".to_string(),
                        severity: Severity::Medium,
                        description: "README is too short - consider adding more details".to_string(),
                        file_path: Some(PathBuf::from(filename)),
                    });
                }
            }
            break;
        }
    }
    
    if !has_readme {
        report.issues.push(Issue {
            category: "Documentation".to_string(),
            severity: Severity::High,
            description: "Missing README file".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn check_license(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 10;
    
    let license_files = ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"];
    let mut has_license = false;
    
    for filename in &license_files {
        if path.join(filename).exists() {
            has_license = true;
            report.score += 10;
            break;
        }
    }
    
    if !has_license {
        report.issues.push(Issue {
            category: "Legal".to_string(),
            severity: Severity::Medium,
            description: "Missing LICENSE file".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn check_gitignore(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 10;
    
    let gitignore_path = path.join(".gitignore");
    if gitignore_path.exists() {
        report.score += 10;
        
        if let Ok(content) = fs::read_to_string(&gitignore_path) {
            let important_patterns = [
                "*.log", "node_modules/", "target/", "*.tmp", "*.swp", 
                ".DS_Store", "*.pyc", "__pycache__/", ".env"
            ];
            
            let mut missing_patterns = Vec::new();
            for pattern in &important_patterns {
                if !content.contains(pattern) {
                    missing_patterns.push(*pattern);
                }
            }
            
            if !missing_patterns.is_empty() {
                report.issues.push(Issue {
                    category: "Configuration".to_string(),
                    severity: Severity::Low,
                    description: format!("Consider adding these patterns to .gitignore: {}", missing_patterns.join(", ")),
                    file_path: Some(PathBuf::from(".gitignore")),
                });
            }
        }
    } else {
        report.issues.push(Issue {
            category: "Configuration".to_string(),
            severity: Severity::Medium,
            description: "Missing .gitignore file".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn check_large_files(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 5;
    
    let mut large_files = Vec::new();
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    
    fn find_large_files(dir: &Path, large_files: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    find_large_files(&path, large_files)?;
                }
            } else {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > MAX_FILE_SIZE {
                        large_files.push(path);
                    }
                }
            }
        }
        Ok(())
    }
    
    find_large_files(path, &mut large_files)?;
    
    if large_files.is_empty() {
        report.score += 5;
    } else {
        for file in large_files {
            report.issues.push(Issue {
                category: "Performance".to_string(),
                severity: Severity::Medium,
                description: format!("Large file detected (>10MB): {}", file.display()),
                file_path: Some(file),
            });
        }
    }
    
    Ok(())
}

fn check_secrets(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 20;
    
    let secret_patterns = [
        r"api[_-]?key",
        r"secret[_-]?key",
        r"password",
        r"token",
        r"bearer",
        r"aws[_-]?access",
        r"private[_-]?key",
    ];
    
    let mut potential_secrets = Vec::new();
    
    fn scan_files(dir: &Path, patterns: &[&str], secrets: &mut Vec<(PathBuf, String)>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    scan_files(&path, patterns, secrets)?;
                }
            } else if is_text_file(&path) {
                if let Ok(content) = fs::read_to_string(&path) {
                    for line in content.lines() {
                        let lower_line = line.to_lowercase();
                        for pattern in patterns {
                            if lower_line.contains(pattern) && line.contains('=') {
                                secrets.push((path.clone(), line.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    scan_files(path, &secret_patterns, &mut potential_secrets)?;
    
    if potential_secrets.is_empty() {
        report.score += 20;
    } else {
        for (file, line) in potential_secrets {
            report.issues.push(Issue {
                category: "Security".to_string(),
                severity: Severity::Critical,
                description: format!("Potential secret found: {}", line.trim()),
                file_path: Some(file),
            });
        }
    }
    
    Ok(())
}

fn check_commit_history(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 15;
    
    if report.stats.commit_count > 0 {
        report.score += 5;
        
        if report.stats.commit_count > 10 {
            report.score += 5;
        }
        
        if let Some(days) = report.stats.last_commit_days {
            if days <= 30 {
                report.score += 5;
            } else {
                report.issues.push(Issue {
                    category: "Maintenance".to_string(),
                    severity: Severity::Medium,
                    description: format!("Last commit was {} days ago - consider updating", days),
                    file_path: None,
                });
            }
        }
    } else {
        report.issues.push(Issue {
            category: "Maintenance".to_string(),
            severity: Severity::High,
            description: "No commits found".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn check_dependencies(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 10;
    
    let mut has_deps = false;
    
    // Check for various dependency files
    let dep_files = [
        ("Cargo.toml", "Rust"),
        ("package.json", "Node.js"),
        ("requirements.txt", "Python"),
        ("Gemfile", "Ruby"),
        ("pom.xml", "Java"),
        ("go.mod", "Go"),
    ];
    
    for (filename, lang) in &dep_files {
        if path.join(filename).exists() {
            has_deps = true;
            report.score += 10;
            
            // Check for lock files
            let lock_files = match *filename {
                "Cargo.toml" => Some("Cargo.lock"),
                "package.json" => Some("package-lock.json"),
                "Gemfile" => Some("Gemfile.lock"),
                "go.mod" => Some("go.sum"),
                _ => None,
            };
            
            if let Some(lock_file) = lock_files {
                if !path.join(lock_file).exists() {
                    report.issues.push(Issue {
                        category: "Dependencies".to_string(),
                        severity: Severity::Medium,
                        description: format!("Missing {} lock file for {}", lock_file, lang),
                        file_path: None,
                    });
                }
            }
            break;
        }
    }
    
    if !has_deps {
        report.issues.push(Issue {
            category: "Dependencies".to_string(),
            severity: Severity::Low,
            description: "No dependency management files found".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn check_code_quality(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 15;
    
    let mut long_files = 0;
    let mut total_code_files = 0;
    
    fn analyze_code_files(dir: &Path, stats: &mut (usize, usize)) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    analyze_code_files(&path, stats)?;
                }
            } else if is_code_file(&path) {
                stats.1 += 1;
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.lines().count() > 500 {
                        stats.0 += 1;
                    }
                }
            }
        }
        Ok(())
    }
    
    analyze_code_files(path, &mut (long_files, total_code_files))?;
    
    if total_code_files > 0 {
        report.score += 5;
        
        let long_file_ratio = long_files as f64 / total_code_files as f64;
        if long_file_ratio < 0.2 {
            report.score += 10;
        } else {
            report.issues.push(Issue {
                category: "Code Quality".to_string(),
                severity: Severity::Medium,
                description: format!("{}% of files are >500 lines - consider refactoring", (long_file_ratio * 100.0) as u32),
                file_path: None,
            });
        }
    }
    
    Ok(())
}

fn check_documentation(path: &Path, report: &mut HealthReport) -> io::Result<()> {
    report.max_score += 10;
    
    let doc_dirs = ["docs", "documentation", "doc"];
    let mut has_docs = false;
    
    for dir_name in &doc_dirs {
        if path.join(dir_name).is_dir() {
            has_docs = true;
            report.score += 10;
            break;
        }
    }
    
    if !has_docs {
        report.issues.push(Issue {
            category: "Documentation".to_string(),
            severity: Severity::Low,
            description: "No documentation directory found".to_string(),
            file_path: None,
        });
    }
    
    Ok(())
}

fn generate_suggestions(report: &mut HealthReport) {
    let score_percentage = (report.score as f64 / report.max_score as f64) * 100.0;
    
    if score_percentage < 70.0 {
        report.suggestions.push("🚨 Repository health is below 70% - consider addressing critical issues".to_string());
    }
    
    if report.issues.iter().any(|i| matches!(i.severity, Severity::Critical)) {
        report.suggestions.push("🔐 Address security issues immediately".to_string());
    }
    
    if report.stats.commit_count < 5 {
        report.suggestions.push("📝 Make more frequent commits to establish development history".to_string());
    }
    
    if report.stats.lines_of_code > 0 && report.stats.lines_of_code < 100 {
        report.suggestions.push("💡 Add more substantial code to demonstrate project functionality".to_string());
    }
}

fn print_report(report: &HealthReport) {
    let score_percentage = (report.score as f64 / report.max_score as f64) * 100.0;
    
    println!("📊 REPOSITORY HEALTH REPORT");
    println!("═══════════════════════════");
    println!();
    
    // Overall Score
    let grade = match score_percentage {
        90.0..=100.0 => "A+ 🌟",
        80.0..=89.9 => "A 🎯",
        70.0..=79.9 => "B 👍",
        60.0..=69.9 => "C ⚠️",
        _ => "D 🚨",
    };
    
    println!("🏆 Overall Score: {}/100 ({})", score_percentage as u32, grade);
    println!("📈 Raw Score: {}/{}", report.score, report.max_score);
    println!();
    
    // Statistics
    println!("📈 REPOSITORY STATISTICS");
    println!("────────────────────────");
    println!("📁 Total Files: {}", report.stats.total_files);
    println!("📝 Lines of Code: {}", report.stats.lines_of_code);
    println!("🔄 Commits: {}", report.stats.commit_count);
    println!("🌿 Branches: {}", report.stats.branch_count);
    if let Some(days) = report.stats.last_commit_days {
        println!("⏰ Last Commit: {} days ago", days);
    }
    println!();
    
    // File Types
    if !report.stats.file_types.is_empty() {
        println!("📄 File Types:");
        for (ext, count) in &report.stats.file_types {
            println!("   .{}: {}", ext, count);
        }
        println!();
    }
    
    // Issues
    if !report.issues.is_empty() {
        println!("🚨 ISSUES FOUND");
        println!("───────────────");
        
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        
        for issue in &report.issues {
            match issue.severity {
                Severity::Critical => critical.push(issue),
                Severity::High => high.push(issue),
                Severity::Medium => medium.push(issue),
                Severity::Low => low.push(issue),
            }
        }
        
        for (severity, issues, icon) in [
            ("CRITICAL", critical, "🔥"),
            ("HIGH", high, "🚨"),
            ("MEDIUM", medium, "⚠️"),
            ("LOW", low, "ℹ️"),
        ] {
            if !issues.is_empty() {
                println!("{} {} ({}):", icon, severity, issues.len());
                for issue in issues {
                    println!("  • [{}] {}", issue.category, issue.description);
                    if let Some(file) = &issue.file_path {
                        println!("    📁 {}", file.display());
                    }
                }
                println!();
            }
        }
    }
    
    // Suggestions
    if !report.suggestions.is_empty() {
        println!("💡 SUGGESTIONS");
        println!("──────────────");
        for suggestion in &report.suggestions {
            println!("  {}", suggestion);
        }
        println!();
    }
    
    // Final message
    match score_percentage {
        90.0..=100.0 => println!("🎉 Excellent! Your repository is in great shape!"),
        80.0..=89.9 => println!("👍 Good work! Just a few minor improvements needed."),
        70.0..=79.9 => println!("⚠️  Not bad, but there's room for improvement."),
        60.0..=69.9 => println!("🚨 Several issues need attention."),
        _ => println!("🔥 This repository needs significant improvements!"),
    }
}

fn is_code_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_str().unwrap().to_lowercase();
        matches!(ext_str.as_str(), 
            "rs" | "py" | "js" | "ts" | "java" | "cpp" | "c" | "go" | "rb" | "php" | 
            "swift" | "kt" | "scala" | "hs" | "clj" | "elm" | "dart" | "r" | "m" | "mm"
        )
    } else {
        false
    }
}

fn is_text_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_str().unwrap().to_lowercase();
        matches!(ext_str.as_str(), 
            "txt" | "md" | "rst" | "json" | "yaml" | "yml" | "toml" | "xml" | "html" | 
            "css" | "js" | "ts" | "py" | "rs" | "go" | "java" | "cpp" | "c" | "h" | "hpp" |
            "rb" | "php" | "sh" | "bash" | "zsh" | "fish" | "env" | "conf" | "config"
        )
    } else {
        false
    }
}

fn print_help() {
    println!("🔍 Git Health Scanner - Analyze your repository's health");
    println!();
    println!("USAGE:");
    println!("    git-health [DIRECTORY]");
    println!();
    println!("ARGUMENTS:");
    println!("    <DIRECTORY>    Path to Git repository (default: current directory)");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help     Show this help message");
    println!();
    println!("FEATURES:");
    println!("    • 📊 Overall health score and grade");
    println!("    • 🔍 Security vulnerability detection");
    println!("    • 📝 Documentation completeness check");
    println!("    • 🏗️  Code quality analysis");
    println!("    • 📦 Dependency management review");
    println!("    • 🔄 Git history analysis");
    println!("    • 💡 Actionable improvement suggestions");
    println!();
    println!("EXAMPLES:");
    println!("    git-health                    # Analyze current directory");
    println!("    git-health /path/to/repo      # Analyze specific repository");
    println!("    git-health ~/my-project       # Analyze project in home directory");
}