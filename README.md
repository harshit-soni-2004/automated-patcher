# AMI Automated Patcher (`ami-patcher`)

Automated tooling for unattended weekly patch runs and vulnerability validation of hardened golden AMIs in AWS.

## Overview

`ami-patcher` orchestrates the lifecycle of testing and patching AMIs:
1. Provisions temporary EC2 instances from a base/source AMI.
2. Executes baseline vulnerability scans using Trivy via AWS Systems Manager (SSM).
3. Securely extracts and synchronizes reports to Amazon S3.
4. Compares findings against known exceptions (`exceptions.yaml`).
5. Handles clean teardown and termination of temporary build resources.

## Installation

Requires Python 3.11+.

```powershell
python -m pip install -e .
```

To install development dependencies (e.g., `pytest`):

```powershell
python -m pip install -e ".[dev]"
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and configure your AWS parameters:

```powershell
Copy-Item config.example.yaml config.yaml
```

> **Note:** `config.yaml` contains environment-specific resource IDs and is gitignored.

## Usage

Run the CLI:

```powershell
ami-patcher --help
```

See [DEVELOPERS.md](DEVELOPERS.md) for step-by-step developer setup and AWS authentication guidance.

## Testing

Run unit tests:

```powershell
pytest
```
