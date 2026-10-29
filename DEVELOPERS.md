# ami-patcher developer guide

This guide is for a personal AWS account on Windows PowerShell. It starts at `aws login` and ends at `check`.

The tool currently launches a temporary instance, runs a baseline Trivy scan through SSM, uploads the reports to S3 from that instance, and terminates the instance. Patching and replacement AMI creation are not implemented. `setup`, `cleanup-orphans`, and `prune` exit 2 with "not available yet".

Do not put access keys, session tokens, or private keys in `config.yaml`. The tool reads credentials from the environment.

## 1. Sign in

Use a profile named `personal`. The `default` profile on this PC already has access-key credentials, and `aws login` will not replace them.

```powershell
aws --version
aws login --profile personal
```

The CLI must be 2.32.0 or newer. A browser opens. Sign in to your personal AWS account and approve the request. Leave the tab open until it tells you to return to the terminal.

Then point this PowerShell session at that profile:

```powershell
$env:AWS_PROFILE = "personal"
aws sts get-caller-identity
```

The `Account` value must be your personal account. If the command fails, run `aws login --profile personal` again. Later commands in this same window use `$env:AWS_PROFILE`. A new window needs that line again.

## 2. Collect the values for config.yaml

`config.example.yaml` still contains the earlier template (`ap-south-1`, the Veefin AMI name, and an example bucket). Replace every account-specific value. `000000000000` is only a placeholder.

Set the region to the region where your Ubuntu AMI exists, then run the lookups with that same region:

```powershell
$Region = "YOUR_REGION"
aws ec2 describe-images --region $Region --owners self --query "sort_by(Images,&CreationDate)[-10].[ImageId,Name,CreationDate,Description]" --output table
aws ec2 describe-security-groups --region $Region --query "SecurityGroups[].[GroupId,GroupName,VpcId]" --output table
aws ec2 describe-subnets --region $Region --query "Subnets[].[SubnetId,VpcId,AvailabilityZone,CidrBlock]" --output table
aws s3 ls
aws iam list-instance-profiles --query "InstanceProfiles[].InstanceProfileName" --output table
```

Use these results:

| Config field | What to copy |
|---|---|
| `account_id` | `Account` from `aws sts get-caller-identity`. Keep the quotes so YAML keeps all 12 digits. |
| `region` | The same value as `$Region`. |
| `source_ami` | The AMI id of the Ubuntu 26.04 image created from `ec2_test`. Prefer the id form shown below, not a name pattern. |
| `security_group_id` | A group with no inbound rules, in the same VPC as the subnet. Outbound HTTPS (443) must stay open. |
| `subnet_id` | A subnet in that VPC. Set this explicitly. |
| `instance_profile_name` | An existing EC2 instance profile whose role can use SSM and `s3:PutObject` on the report prefix. |
| `s3_bucket` | An existing bucket in this account. |
| `s3_prefix` | A prefix you choose, such as `ami-patcher-personal`. |
| `project_tag` | A tag you choose, such as `ami-patcher-personal`. `check` fails if any non-terminated instance already has this `Project` tag. |
| `new_ami_name_prefix` | Required by the file. This baseline does not create an AMI. Use a personal prefix such as `personal-ubuntu-scan`. |

`check` does not create the security group, instance profile, or bucket. `setup` is not available. If any of those three is missing, stop here and create it in the personal account before continuing.

## 3. Write config.yaml

From the tool directory:

```powershell
cd C:\Workspace\terraform_poc\automated_patcher
Copy-Item config.example.yaml config.yaml
```

Edit `config.yaml`. The personal test shape is:

```yaml
region: YOUR_REGION
account_id: "YOUR_12_DIGIT_ACCOUNT"

source_ami: ami-YOUR_UBUNTU_AMI

new_ami_name_prefix: personal-ubuntu-scan
instance_type: t3.medium
subnet_id: subnet-YOUR_SUBNET
security_group_id: sg-YOUR_SECURITY_GROUP
instance_profile_name: YOUR_INSTANCE_PROFILE
s3_bucket: YOUR_EXISTING_BUCKET
s3_prefix: ami-patcher-personal
sns_topic_arn: null
exceptions_file: exceptions.yaml
min_free_disk_gb: 2
phase_timeouts:
  launch_seconds: 600
  ssm_online_seconds: 900
  command_seconds: 1200
  dnf_update_seconds: 3600
  reboot_seconds: 900
  image_available_seconds: 1800
max_total_runtime_minutes: 180
keep_amis: 4
project_tag: ami-patcher-personal
bootstrap_ssm_agent: false
root_volume_size_gb: null
```

`bootstrap_ssm_agent` must stay `false`. The source AMI has to already include SSM Agent. The tool does not install it.

## 4. Install and run check

```powershell
cd C:\Workspace\terraform_poc\automated_patcher
python -m pip install -e .
ami-patcher --config config.yaml check
```

A good result looks like:

```text
check ok account=YOUR_12_DIGIT_ACCOUNT source_ami=ami-YOUR_UBUNTU_AMI subnet=subnet-YOUR_SUBNET
```

The account in that line must match `account_id`. If it does not, `check` stops before any EC2 call.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Check passed, or a later run finished and cleaned up. |
| 1 | Config or preflight failed. No instance is launched. |
| 2 | AWS or infrastructure error. `setup`, `cleanup-orphans`, and `prune` also return 2. |
| 3 | Another `run` already holds the lock on this config file. |

`check` confirms the account, AMI, security group, subnet, bucket, and instance profile name. It does not prove that the AMI contains SSM Agent or the AWS CLI, that the role can write to S3, or that the security group allows outbound HTTPS.

## 5. Dry-run, then stop

This asks EC2 whether the launch would be allowed. It does not start an instance or run a scan.

```powershell
ami-patcher --config config.yaml run --dry-run
```

`run` without `--dry-run` launches a billable instance, scans it, uploads the baseline reports, applies OS package updates, rescans the same instance, and uploads the post-patch and comparison reports. It does not create an AMI. On Ubuntu and Debian it installs Trivy with apt and patches with `apt-get upgrade`. On RHEL-family images it uses dnf or yum. If `aws` is missing, the instance installs AWS CLI v2 from `awscli.amazonaws.com` and uses the instance profile for `aws s3 cp`. It does not skip the upload.

The source AMI must already be running SSM Agent, and the security group must allow outbound HTTPS. `check` does not prove either of those. A failed install, scan, patch, or upload exits non-zero and still terminates the temporary instance unless you pass `--keep-on-failure`.
