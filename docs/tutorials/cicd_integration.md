# CI/CD Integration Tutorial

This tutorial shows how to integrate V-NAPE into your continuous integration and deployment pipeline for automated protocol security verification.

## Overview

V-NAPE can be integrated into CI/CD pipelines to:

- Automatically verify protocol traces on every commit
- Enforce security policies before deployment
- Generate compliance reports
- Block deployments that fail security checks

## GitHub Actions Integration

### Basic Workflow

Create `.github/workflows/vnape-security.yml`:

```yaml
name: V-NAPE Security Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-verification:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install V-NAPE
        run: |
          pip install vnape
      
      - name: Run Protocol Verification
        run: |
          python -m vnape.verify \
            --traces ./protocol_traces/ \
            --policy ./policies/security_policy.mfotl \
            --output ./reports/verification_report.json
      
      - name: Check Verification Results
        run: |
          python -c "
          import json
          with open('./reports/verification_report.json') as f:
              report = json.load(f)
          if report['violations'] > 0:
              print(f'FAILED: {report[\"violations\"]} violations found')
              exit(1)
          print('PASSED: No violations detected')
          "
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: vnape-report
          path: ./reports/
```

### Advanced Workflow with Quantum Assessment

```yaml
name: V-NAPE Full Security Suite

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly quantum assessment

jobs:
  protocol-verification:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install vnape
          pip install pytest pytest-cov
      
      - name: Run Unit Tests
        run: pytest tests/ -v
      
      - name: Verify Protocol Traces
        run: |
          python scripts/verify_protocols.py
      
      - name: Generate Coverage Report
        run: |
          python scripts/generate_coverage.py

  quantum-assessment:
    runs-on: ubuntu-latest
    needs: protocol-verification
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install V-NAPE
        run: pip install vnape
      
      - name: Run Quantum Assessment
        run: |
          python -c "
          from vnape.pqae.quantum_context import QuantumThreatContext
          
          context = QuantumThreatContext()
          report = context.generate_assessment_report(format='markdown')
          
          with open('quantum_report.md', 'w') as f:
              f.write(report)
          "
      
      - name: Upload Quantum Report
        uses: actions/upload-artifact@v4
        with:
          name: quantum-assessment
          path: quantum_report.md
```

## GitLab CI Integration

Create `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - verify
  - assess
  - deploy

variables:
  VNAPE_POLICY: "./policies/security_policy.mfotl"
  VNAPE_TRACES: "./traces/"

vnape-verification:
  stage: verify
  image: python:3.11
  script:
    - pip install vnape
    - python -m vnape.verify --traces $VNAPE_TRACES --policy $VNAPE_POLICY
  artifacts:
    reports:
      junit: verification_report.xml
    paths:
      - verification_report.json
    expire_in: 1 week

quantum-assessment:
  stage: assess
  image: python:3.11
  script:
    - pip install vnape
    - python scripts/quantum_assessment.py
  artifacts:
    paths:
      - quantum_report.md
  only:
    - schedules
    - main

deploy-production:
  stage: deploy
  script:
    - ./deploy.sh
  needs:
    - vnape-verification
  only:
    - main
  when: manual
```

## Jenkins Integration

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        VNAPE_HOME = "${WORKSPACE}/vnape"
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    python -m venv venv
                    . venv/bin/activate
                    pip install vnape
                '''
            }
        }
        
        stage('Protocol Verification') {
            steps {
                sh '''
                    . venv/bin/activate
                    python -m vnape.verify \
                        --traces ./traces/ \
                        --policy ./policies/main.mfotl \
                        --output verification_report.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'verification_report.json'
                }
            }
        }
        
        stage('Quantum Assessment') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    . venv/bin/activate
                    python scripts/quantum_assessment.py
                '''
            }
        }
        
        stage('Deploy') {
            when {
                allOf {
                    branch 'main'
                    expression { 
                        def report = readJSON file: 'verification_report.json'
                        return report.violations == 0
                    }
                }
            }
            steps {
                sh './deploy.sh'
            }
        }
    }
    
    post {
        failure {
            emailext (
                subject: "V-NAPE Security Check Failed: ${env.JOB_NAME}",
                body: "Security verification failed. Check the report.",
                to: 'security-team@example.com'
            )
        }
    }
}
```

## Python Verification Script

Create `scripts/verify_protocols.py`:

```python
#!/usr/bin/env python3
"""Protocol verification script for CI/CD integration."""

import json
import sys
from pathlib import Path

from vnape.core.framework import VNAPEFramework
from vnape.core.types import PolicyFormula, TraceEvent
from vnape.pqae.enforcer import ProactiveEnforcer, EnforcementMode


def load_traces(traces_dir: Path) -> list[list[TraceEvent]]:
    """Load protocol traces from directory."""
    traces = []
    for trace_file in traces_dir.glob("*.json"):
        with open(trace_file) as f:
            data = json.load(f)
            events = [
                TraceEvent(
                    event_type=e["type"],
                    timestamp=e["timestamp"],
                    data=e.get("data", {})
                )
                for e in data["events"]
            ]
            traces.append(events)
    return traces


def load_policy(policy_file: Path) -> PolicyFormula:
    """Load security policy from file."""
    with open(policy_file) as f:
        formula = f.read().strip()
    return PolicyFormula(formula=formula, name=policy_file.stem)


def main():
    # Configuration
    traces_dir = Path("./traces")
    policy_file = Path("./policies/security_policy.mfotl")
    output_file = Path("./reports/verification_report.json")
    
    # Load inputs
    traces = load_traces(traces_dir)
    policy = load_policy(policy_file)
    
    # Initialize enforcer
    enforcer = ProactiveEnforcer(mode=EnforcementMode.AUDIT)
    enforcer.set_policy(policy)
    
    # Verify all traces
    results = {
        "total_traces": len(traces),
        "violations": 0,
        "passed": 0,
        "details": []
    }
    
    for i, trace in enumerate(traces):
        for event in trace:
            result = enforcer.process_event(event)
            if not result.permitted:
                results["violations"] += 1
                results["details"].append({
                    "trace": i,
                    "event": event.event_type,
                    "reason": result.reason
                })
        
        if not any(d["trace"] == i for d in results["details"]):
            results["passed"] += 1
    
    # Write report
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Exit with appropriate code
    if results["violations"] > 0:
        print(f"FAILED: {results['violations']} violations in {len(traces)} traces")
        sys.exit(1)
    
    print(f"PASSED: All {len(traces)} traces verified successfully")
    sys.exit(0)


if __name__ == "__main__":
    main()
```

## Best Practices

1. **Fail Fast**: Configure pipelines to fail immediately on security violations
2. **Artifact Retention**: Keep verification reports for compliance auditing
3. **Scheduled Assessments**: Run quantum assessments weekly on a schedule
4. **Branch Protection**: Require passing V-NAPE checks before merge
5. **Notification**: Alert security team on any failures

## Next Steps

- [Monitoring Dashboard](monitoring_dashboard.md) - Set up real-time visualization
- [Basic Verification](basic_verification.md) - Review verification basics
