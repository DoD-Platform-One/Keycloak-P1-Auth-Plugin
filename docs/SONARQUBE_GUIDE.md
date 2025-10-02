# SonarQube Analysis Guide

## Overview
This project has two SonarQube projects for different types of analysis:
1. **Main Code Analysis** - Code quality, bugs, and test coverage
2. **Dependency Check** - Security vulnerabilities in dependencies

## Prerequisites

### Environment Variables
```bash
# Required for main code analysis
export SONAR_LOGIN=your-main-token

# Required for dependency check analysis  
export SONAR_LOGIN_DEPENDENCY_CHECK=your-dependency-token
```

### Optional (for faster dependency updates)
```bash
# Get free key at: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-nvd-api-key
```

---

## Quick Start - One Script for Everything

```bash
# Show all available commands
./scripts/sonar-scan.sh help

# Run code quality scan with coverage
./scripts/sonar-scan.sh code

# Run dependency vulnerability scan
./scripts/sonar-scan.sh deps

# Run fast offline dependency scan
./scripts/sonar-scan.sh deps-fast

# Run everything (code + dependencies)
./scripts/sonar-scan.sh all

# Update vulnerability database
./scripts/sonar-scan.sh update
```

---

## Manual Commands

### Code Quality Analysis

#### Step 1: Run Tests with Coverage
```bash
# Generate test coverage reports
./gradlew clean test jacocoTestReport
```

#### Step 2: Run SonarQube Scan
```bash
# Scan with coverage data
sonar-scanner -Dproject.settings=sonar-project-dev.properties
```

#### View Results
- http://localhost:9000/dashboard?id=keycloak-plugin

### Dependency Check Analysis

#### Step 1: Update Vulnerability Database (Optional)
```bash
# Update CVE database (do this weekly/monthly)
./scripts/sonar-scan.sh update

# Or manually:
./gradlew dependencyCheckUpdate
```

#### Step 2: Run Dependency Analysis
```bash
# Analyze dependencies for vulnerabilities
./gradlew dependencyCheckAnalyze

# Faster offline mode (uses cached data):
./gradlew dependencyCheckAnalyze --offline
```

#### Step 3: Run SonarQube Scan
```bash
# Send results to SonarQube
sonar-scanner -Dproject.settings=sonar-project-dependency-check-dev.properties
```

#### View Results
- http://localhost:9000/dashboard?id=keycloak-plugin-dependency-check

---

## Use Cases

### Daily Development
```bash
# Quick code quality check with coverage
./scripts/sonar-scan.sh code

# Fast security check (if dependencies changed)
./scripts/sonar-scan.sh deps-fast
```
- **When**: Before committing code
- **Purpose**: Catch bugs, code smells, maintain coverage
- **Time**: 1-2 minutes (add <1 min for dependency check)

### Pull Request Validation
```bash
# Full analysis
./scripts/sonar-scan.sh all
```
- **When**: Before merging PRs
- **Purpose**: Ensure code quality and no new vulnerabilities
- **Time**: 5-10 minutes

### Weekly Security Check
```bash
# Update vulnerability database and scan
./scripts/sonar-scan.sh update
./scripts/sonar-scan.sh deps
```
- **When**: Weekly or after adding new dependencies
- **Purpose**: Identify vulnerable dependencies
- **Time**: 10-15 minutes (first run), 5 minutes (subsequent)

### CI/CD Pipeline
```bash
# Fast mode without network calls
./gradlew clean test jacocoTestReport
./gradlew dependencyCheckAnalyze --offline \
  -PossIndexEnabled=false \
  -PcentralEnabled=false \
  -PretireJSEnabled=false \
  -PnodeEnabled=false
sonar-scanner -Dproject.settings=sonar-project-dev.properties

# Or use the fast mode:
./scripts/sonar-scan.sh deps-fast
```
- **When**: Automated builds
- **Purpose**: Fast feedback without external dependencies
- **Time**: 2-3 minutes

---

## Configuration Files

### Main Analysis
- **Config**: `sonar-project-dev.properties`
- **Covers**: Java code, JavaScript, CSS, HTML
- **Metrics**: Coverage, duplications, complexity, bugs

### Dependency Check
- **Config**: `sonar-project-dependency-check-dev.properties`
- **Database**: `~/.gradle/dependency-check-data/`
- **Reports**: `build/reports/dependency-check-report.*`

---

## Troubleshooting

### Dependency Check Timeouts
```bash
# Kill stuck processes
ps aux | grep dependencyCheck
kill <process-id>

# Remove lock file
rm -f ~/.gradle/dependency-check-data/*/odc.update.lock

# Clear cache and retry
./gradlew dependencyCheckPurge
./gradlew dependencyCheckUpdate
```

### Zero Coverage Reported
```bash
# Ensure JaCoCo reports exist
ls -la */build/jacoco/test.xml

# Regenerate coverage
./gradlew clean test jacocoTestReport

# Verify XML content
head -20 p1-keycloak-plugin/build/jacoco/test.xml
```

### Slow Dependency Analysis
```bash
# Use offline mode
./gradlew dependencyCheckAnalyze --offline

# Or disable slow analyzers in build.gradle:
dependencyCheck {
    analyzers {
        ossIndexEnabled = false
        centralEnabled = false
    }
}
```

---

## Performance Tips

### Speed Up Dependency Check

1. **Disable unnecessary analyzers** (in `build.gradle`):
```gradle
dependencyCheck {
    analyzers {
        ossIndexEnabled = false    // Skip OSS Index
        centralEnabled = false     // Skip Maven Central
        retirejs = false          // Skip JavaScript
        nodeEnabled = false       // Skip Node.js
    }
}
```

2. **Skip test dependencies**:
```gradle
dependencyCheck {
    skipConfigurations = ['testCompileClasspath', 'testRuntimeClasspath']
}
```

3. **Use cached data**:
```bash
./gradlew dependencyCheckAnalyze --offline
```

### Database Management

- **Size**: ~400MB when fully updated
- **Location**: `~/.gradle/dependency-check-data/`
- **Update frequency**: Weekly or monthly
- **Shared**: Across all projects on machine

---

## Scripts Explained

### Main Script: `sonar-scan.sh`
Unified script for all SonarQube operations. Replaces multiple individual scripts.

| Command | What it Does | Time | Details |
|---------|--------------|------|---------|
| `./scripts/sonar-scan.sh code` | Runs tests, generates JaCoCo coverage, scans code quality | 1-2 min | Analyzes main code for bugs, smells, coverage |
| `./scripts/sonar-scan.sh deps` | Runs dependency vulnerability check with NVD database | 1-2 min | Scans for CVEs in dependencies |
| `./scripts/sonar-scan.sh deps-fast` | Offline dependency check (no network calls) | <1 min | Uses cached vulnerability data |
| `./scripts/sonar-scan.sh all` | Runs both code and dependency scans | 2-3 min | Complete analysis for both projects |
| `./scripts/sonar-scan.sh update` | Updates NVD vulnerability database | 10-20 min* | Downloads latest CVE data |

*With NVD API key. Without key: 2-4 hours

### Helper Scripts

#### `manual-nvd-download.sh`
- **Purpose**: Downloads raw NVD JSON data files when gradle update fails
- **What it downloads**:
  - `nvdcve-2.0-{year}.json.gz` - Vulnerability data by year
  - `nvdcve-2.0-{year}.meta` - Metadata files
  - CPE match data
- **What it DOESN'T do**: Create the `odc.mv.db` database (gradle does that)
- **Use**: Emergency fallback when automated update fails

### Database Files Explained

| File/Directory | Purpose | Created By | Size |
|----------------|---------|------------|------|
| `~/.gradle/dependency-check-data/11.0/` | Main data directory | Gradle | ~500MB total |
| `odc.mv.db` | H2 database with indexed CVE data | Gradle from JSON files | ~400MB |
| `nvdcve-*.json` | Raw vulnerability data | Manual script or gradle | ~100MB each |
| `*.meta` | Checksums and timestamps | Downloads | <1KB each |

### How They Work Together

1. **Initial Setup**:
   - `./scripts/sonar-scan.sh update` OR `./gradlew dependencyCheckUpdate` downloads NVD data
   - Creates/updates `odc.mv.db` from JSON files

2. **If Update Fails**:
   - `./scripts/manual-nvd-download.sh` downloads raw JSON files
   - Then run `./gradlew dependencyCheckUpdate` to build database

3. **Daily Use**:
   - `./scripts/sonar-scan.sh all` uses the existing database
   - No downloads needed until next update

---

## Best Practices

1. **Daily**: Run code quality checks before committing
2. **Weekly**: Update vulnerability database
3. **Per PR**: Run full analysis before merging
4. **Monthly**: Review dependency vulnerabilities and update libraries

## Useful Links

- [SonarQube Dashboard](http://localhost:9000)
- [NVD API Key Registration](https://nvd.nist.gov/developers/request-an-api-key)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [JaCoCo Documentation](https://www.jacoco.org/jacoco/)
