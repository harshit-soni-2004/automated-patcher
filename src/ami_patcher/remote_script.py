"""Shell text sent to the instance. Reports are created and uploaded there."""

from __future__ import annotations

import base64
import re
from pathlib import Path

_SAFE = re.compile(r"^[A-Za-z0-9_./:=+-]+$")
_PACKAGE_FILES = (
    "__init__.py",
    "trivy.py",
    "exceptions.py",
    "redact.py",
    "baseline_summary.py",
    "patch_report.py",
    "compare_reports.py",
)


def report_object_keys(prefix: str, run_id: str, stage: str) -> dict[str, str]:
    base = "/".join(part.strip("/") for part in (prefix, run_id, stage) if part and part.strip("/"))
    return {
        "json": f"{base}/trivy-report.json",
        "txt": f"{base}/trivy-report.txt",
        "summary": f"{base}/summary.json",
    }


def baseline_object_keys(prefix: str, run_id: str) -> dict[str, str]:
    return report_object_keys(prefix, run_id, "baseline")


def patch_object_key(prefix: str, run_id: str) -> str:
    base = "/".join(part.strip("/") for part in (prefix, run_id, "patch") if part and part.strip("/"))
    return f"{base}/patch-report.json"


def comparison_object_key(prefix: str, run_id: str) -> str:
    base = "/".join(part.strip("/") for part in (prefix, run_id, "comparison") if part and part.strip("/"))
    return f"{base}/comparison.json"


def package_files(exceptions_path: Path) -> dict[str, bytes]:
    root = Path(__file__).resolve().parent
    files = {f"ami_patcher/{name}": (root / name).read_bytes() for name in _PACKAGE_FILES}
    files["exceptions.yaml"] = exceptions_path.read_bytes()
    return files


def file_delivery_scripts(files: dict[str, bytes], remote_root: str, chunk_size: int = 6000) -> list[str]:
    """Chunk base64 so each SSM command stays under the parameter size limit."""
    _require_safe(remote_root, "remote path")
    scripts: list[str] = []
    for relative, payload in files.items():
        _require_safe(relative, "relative path")
        remote = f"{remote_root}/{relative}"
        directory = remote.rsplit("/", 1)[0]
        encoded = base64.b64encode(payload).decode("ascii")
        for index in range(0, max(len(encoded), 1), chunk_size):
            piece = encoded[index : index + chunk_size]
            redirect = ">" if index == 0 else ">>"
            scripts.append(f"mkdir -p '{directory}'\nprintf '%s' '{piece}' {redirect} '{remote}.b64'\n")
        scripts.append(f"base64 -d '{remote}.b64' > '{remote}' && rm -f '{remote}.b64'\n")
    return scripts


def baseline_scan_script(
    *,
    workdir: str,
    bucket: str,
    keys: dict[str, str],
    run_id: str,
    source_ami_id: str,
    instance_id: str,
    min_free_disk_gb: float,
    report_dir: str = "baseline",
) -> str:
    for label, value in {
        "workdir": workdir,
        "bucket": bucket,
        "run_id": run_id,
        "source_ami_id": source_ami_id,
        "instance_id": instance_id,
        "report_dir": report_dir,
        "json_key": keys["json"],
        "txt_key": keys["txt"],
        "summary_key": keys["summary"],
    }.items():
        _require_safe(value, label)
    if min_free_disk_gb < 0:
        raise ValueError("min_free_disk_gb must be >= 0")
    return f"""#!/bin/bash
set -u
WORKDIR='{workdir}'
mkdir -p "$WORKDIR/{report_dir}"
export PYTHONPATH="$WORKDIR/lib"
export HOME=/root
export PATH="/usr/local/bin:$PATH"
workflow_swap=
cleanup_workflow_files() {{
  rc=$?
  trap - EXIT
  if [ -n "$workflow_swap" ] && [ -f "$workflow_swap" ]; then
    if ! swapoff "$workflow_swap"; then
      echo "cleanup failed: could not disable workflow swap $workflow_swap" >&2
    fi
    if ! rm -f "$workflow_swap"; then
      echo "cleanup failed: could not remove workflow swap $workflow_swap" >&2
    fi
  fi
  if ! rm -rf "$WORKDIR/tmp" "$WORKDIR/awscli-install"; then
    echo "cleanup failed: could not remove workflow temp files" >&2
  fi
  exit "$rc"
}}
trap cleanup_workflow_files EXIT
mkdir -p "$WORKDIR/tmp" "$WORKDIR/trivy-cache"
export TMPDIR="$WORKDIR/tmp"
export TRIVY_CACHE_DIR="$WORKDIR/trivy-cache"
grow_root() {{
  root_src=$(findmnt -no SOURCE / 2>/dev/null || true)
  root_fstype=$(findmnt -no FSTYPE / 2>/dev/null || true)
  if [ -z "$root_src" ] || ! command -v growpart >/dev/null 2>&1; then
    return 0
  fi
  root_disk=
  root_part=
  case "$root_src" in
    /dev/nvme*p[0-9]*)
      root_disk=$(printf '%s' "$root_src" | sed 's/p[0-9]*$//')
      root_part=$(printf '%s' "$root_src" | sed 's/.*p//')
      ;;
    /dev/*[0-9])
      root_disk=$(printf '%s' "$root_src" | sed 's/[0-9]*$//')
      root_part=$(printf '%s' "$root_src" | sed 's/.*[^0-9]//')
      ;;
  esac
  if [ -z "$root_disk" ] || [ -z "$root_part" ]; then
    return 0
  fi
  growpart "$root_disk" "$root_part" >"$WORKDIR/growpart.log" 2>&1 || true
  if [ "$root_fstype" = xfs ] && command -v xfs_growfs >/dev/null 2>&1; then
    xfs_growfs / >"$WORKDIR/resize.log" 2>&1 || true
  elif command -v resize2fs >/dev/null 2>&1; then
    resize2fs "$root_src" >"$WORKDIR/resize.log" 2>&1 || true
  fi
}}
grow_root
log_resources() {{
  echo "resource disk before Trivy:" >&2
  df -h / >&2 || true
  echo "resource memory before Trivy:" >&2
  awk '/MemTotal|MemAvailable|SwapTotal|SwapFree/ {{ print }}' /proc/meminfo >&2 || true
}}
log_resources
maybe_swap() {{
  if [ -n "$workflow_swap" ]; then
    return 0
  fi
  SWAP_MB=1024
  if awk 'NR>1 {{ found=1 }} END {{ exit found ? 0 : 1 }}' /proc/swaps >/dev/null 2>&1; then
    echo "existing swap is already configured; not creating another swap file" >&2
    return 0
  fi
  avail_kb=$(df -Pk / | awk 'NR==2 {{print $4}}')
  mem_avail_kb=$(awk '/MemAvailable/ {{ print $2 }}' /proc/meminfo)
  if [ -z "$mem_avail_kb" ]; then
    mem_avail_kb=0
  fi
  swap_kb=$(awk -v mb="$SWAP_MB" 'BEGIN {{ printf "%.0f", mb * 1024 }}')
  reserve_kb=$(awk 'BEGIN {{ printf "%.0f", 3 * 1024 * 1024 }}')
  if [ "$mem_avail_kb" -ge 700000 ]; then
    echo "available RAM is ${{mem_avail_kb}}KB; swap was not created" >&2
  elif [ "$avail_kb" -lt "$((swap_kb + reserve_kb))" ]; then
    echo "root disk is too low for swap (free ${{avail_kb}}KB). Swap was not created and does not fix disk exhaustion." >&2
  else
    workflow_swap="$WORKDIR/swapfile"
    if ! fallocate -l "${{SWAP_MB}}M" "$workflow_swap" >"$WORKDIR/swap.log" 2>&1; then
      if ! dd if=/dev/zero of="$workflow_swap" bs=1M count="$SWAP_MB" >"$WORKDIR/swap.log" 2>&1; then
        echo "swap creation failed; continuing without swap" >&2
        workflow_swap=
      fi
    fi
    if [ -n "$workflow_swap" ] && [ -f "$workflow_swap" ]; then
      chmod 600 "$workflow_swap"
      if ! mkswap "$workflow_swap" >>"$WORKDIR/swap.log" 2>&1 || ! swapon "$workflow_swap" >>"$WORKDIR/swap.log" 2>&1; then
        echo "swap activation failed; continuing without swap" >&2
        tail -n 20 "$WORKDIR/swap.log" >&2 || true
      elif ! awk 'NR>1 {{ found=1 }} END {{ exit found ? 0 : 1 }}' /proc/swaps >/dev/null 2>&1; then
        echo "swap file was enabled but is not active; continuing" >&2
      else
        echo "workflow swap is active at $workflow_swap" >&2
      fi
    fi
  fi
}}
maybe_swap
avail_kb=$(df -Pk / | awk 'NR==2 {{print $4}}')
need_kb=$(awk -v gb='{min_free_disk_gb}' 'BEGIN {{printf "%.0f", gb * 1024 * 1024}}')
if [ "$avail_kb" -lt "$need_kb" ]; then
  echo "free disk on / is ${{avail_kb}}KB, need ${{need_kb}}KB" >&2
  exit 1
fi
if [ ! -r /etc/os-release ]; then
  echo "cannot detect the OS because /etc/os-release is missing" >&2
  exit 1
fi
os_id=$(awk -F= '$1=="ID" {{ gsub(/"/, "", $2); print $2; exit }}' /etc/os-release)
os_like=$(awk -F= '$1=="ID_LIKE" {{ gsub(/"/, "", $2); print $2; exit }}' /etc/os-release)
family=unknown
case "$os_id" in
  ubuntu|debian) family=deb ;;
  amzn|almalinux|rhel|centos|fedora|rocky|ol) family=rpm ;;
esac
if [ "$family" = unknown ]; then
  case "$os_like" in
    *debian*) family=deb ;;
    *rhel*|*fedora*|*centos*) family=rpm ;;
  esac
fi
if [ "$family" = unknown ]; then
  echo "unsupported OS id=$os_id like=$os_like; Trivy install supports apt on Debian/Ubuntu and dnf on RHEL-family images" >&2
  exit 1
fi
if [ "$family" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update >"$WORKDIR/apt-update.log" 2>&1; then
    echo "apt-get update failed" >&2
    tail -n 40 "$WORKDIR/apt-update.log" >&2 || true
    exit 1
  fi
  if ! apt-get install -y curl unzip ca-certificates gnupg cloud-guest-utils >"$WORKDIR/apt-bootstrap.log" 2>&1; then
    echo "failed to install curl and unzip, which are required before the AWS CLI and Trivy" >&2
    tail -n 40 "$WORKDIR/apt-bootstrap.log" >&2 || true
    exit 1
  fi
else
  if ! dnf install -y curl unzip ca-certificates cloud-utils-growpart >"$WORKDIR/dnf-bootstrap.log" 2>&1; then
    echo "dnf failed to install curl and unzip, which are required before the AWS CLI and Trivy" >&2
    tail -n 40 "$WORKDIR/dnf-bootstrap.log" >&2 || true
    exit 1
  fi
fi
if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is not on PATH; installing AWS CLI v2 so this instance can upload its own reports" >&2
  arch=$(uname -m)
  case "$arch" in
    x86_64) aws_zip=awscli-exe-linux-x86_64.zip ;;
    aarch64|arm64) aws_zip=awscli-exe-linux-aarch64.zip ;;
    *)
      echo "aws CLI is required to upload reports and is not installed. No AWS CLI v2 build is available for architecture $arch. Reports were not uploaded." >&2
      exit 1
      ;;
  esac
  rm -rf "$WORKDIR/awscli-install"
  mkdir -p "$WORKDIR/awscli-install"
  if ! curl -fsSL "https://awscli.amazonaws.com/$aws_zip" -o "$WORKDIR/awscli-install/awscliv2.zip"; then
    echo "failed to download AWS CLI v2 from awscli.amazonaws.com. Outbound HTTPS is required. Reports were not uploaded." >&2
    exit 1
  fi
  if ! unzip -q "$WORKDIR/awscli-install/awscliv2.zip" -d "$WORKDIR/awscli-install"; then
    echo "failed to unpack AWS CLI v2. Reports were not uploaded." >&2
    exit 1
  fi
  if ! "$WORKDIR/awscli-install/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update; then
    echo "AWS CLI v2 installer failed. Reports were not uploaded." >&2
    exit 1
  fi
  if ! command -v aws >/dev/null 2>&1; then
    echo "AWS CLI v2 install did not put aws on PATH. Reports were not uploaded." >&2
    exit 1
  fi
  rm -rf "$WORKDIR/awscli-install"
fi
trivy_need_kb=$(awk 'BEGIN {{ printf "%.0f", 2 * 1024 * 1024 }}')
full_scan_kb=$(awk 'BEGIN {{ printf "%.0f", 12 * 1024 * 1024 }}')
rm -rf "$WORKDIR/tmp" "$WORKDIR/trivy-cache"
mkdir -p "$WORKDIR/tmp" "$WORKDIR/trivy-cache"
grow_root
maybe_swap
log_resources
avail_kb=$(df -Pk / | awk 'NR==2 {{print $4}}')
if [ "$avail_kb" -lt "$trivy_need_kb" ]; then
  echo "free disk on / is ${{avail_kb}}KB before Trivy; need at least 2GiB for the OS vulnerability database. The scan was not run and reports were not uploaded." >&2
  exit 1
fi
if [ "$family" = deb ]; then
  mkdir -p /usr/share/keyrings
  rm -f /usr/share/keyrings/trivy.gpg
  if ! curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key -o "$WORKDIR/trivy-archive.key"; then
    echo "Trivy apt install failed: could not download the repository signing key" >&2
    exit 1
  fi
  if ! gpg --batch --yes --dearmor -o /usr/share/keyrings/trivy.gpg "$WORKDIR/trivy-archive.key"; then
    echo "Trivy apt install failed: could not install the repository signing key" >&2
    exit 1
  fi
  printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' > /etc/apt/sources.list.d/trivy.list
  if ! apt-get update >"$WORKDIR/apt-trivy-update.log" 2>&1; then
    echo "Trivy apt install failed: apt-get update after adding the Trivy repository" >&2
    tail -n 40 "$WORKDIR/apt-trivy-update.log" >&2 || true
    exit 1
  fi
  if ! apt-get install -y trivy python3 python3-yaml >"$WORKDIR/trivy-install.log" 2>&1; then
    echo "Trivy apt install failed" >&2
    tail -n 40 "$WORKDIR/trivy-install.log" >&2 || true
    exit 1
  fi
else
  printf '%s\\n' '[trivy]' 'name=Trivy repository' 'baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/' 'gpgcheck=1' 'enabled=1' 'gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key' > /etc/yum.repos.d/trivy.repo
  if ! dnf install -y trivy python3 python3-pyyaml >"$WORKDIR/trivy-install.log" 2>&1; then
    echo "Trivy dnf install failed" >&2
    tail -n 40 "$WORKDIR/trivy-install.log" >&2 || true
    exit 1
  fi
fi
if ! command -v trivy >/dev/null 2>&1; then
  echo "Trivy install finished but trivy is not on PATH" >&2
  exit 1
fi
trivy --version | head -n 1 > "$WORKDIR/trivy-version.txt"
log_resources
avail_kb=$(df -Pk / | awk 'NR==2 {{print $4}}')
if [ "$avail_kb" -lt "$trivy_need_kb" ]; then
  echo "free disk on / is ${{avail_kb}}KB after installing Trivy; the OS package scan cannot run. Reports were not uploaded." >&2
  exit 1
fi
scan_coverage=full
pkg_types=os,library
if [ "$avail_kb" -lt "$full_scan_kb" ]; then
  scan_coverage=os-only
  pkg_types=os
  echo "low disk: free ${{avail_kb}}KB is below 12GiB, so this is a partial OS-only scan. Package types are os. The Java database is not downloaded." >&2
fi
echo "scan coverage=$scan_coverage package_types=$pkg_types" >&2
SCAN_EXIT=0
trivy rootfs / --cache-dir "$WORKDIR/trivy-cache" --pkg-types "$pkg_types" --scanners vuln --severity HIGH,CRITICAL --skip-dirs "/proc,/sys,/dev,/run,/tmp,$WORKDIR" --skip-files /usr/bin/trivy --format json --quiet --output "$WORKDIR/{report_dir}/trivy-report.json" >"$WORKDIR/trivy-json.log" 2>&1 || SCAN_EXIT=$?
trivy rootfs / --cache-dir "$WORKDIR/trivy-cache" --pkg-types "$pkg_types" --scanners vuln --severity HIGH,CRITICAL --skip-dirs "/proc,/sys,/dev,/run,/tmp,$WORKDIR" --skip-files /usr/bin/trivy --format table --output "$WORKDIR/{report_dir}/trivy-report.txt" >"$WORKDIR/trivy-table.log" 2>&1 || SCAN_EXIT=$?
SECRET_EXIT=0
trivy rootfs / --cache-dir "$WORKDIR/trivy-cache" --scanners secret --severity HIGH,CRITICAL --skip-dirs "/proc,/sys,/dev,/run,/tmp,$WORKDIR" --format json --quiet --output "$WORKDIR/secrets.json" >"$WORKDIR/trivy-secret.log" 2>&1 || SECRET_EXIT=$?
if [ "$SCAN_EXIT" -ne 0 ]; then
  echo "trivy vulnerability scan failed" >&2
  tail -n 40 "$WORKDIR/trivy-json.log" >&2 || true
  exit "$SCAN_EXIT"
fi
if [ ! -f "$WORKDIR/{report_dir}/trivy-report.json" ] || [ ! -f "$WORKDIR/{report_dir}/trivy-report.txt" ]; then
  echo "trivy did not write the vulnerability reports; S3 upload was not attempted" >&2
  exit 1
fi
if [ "$SECRET_EXIT" -ne 0 ]; then
  echo "trivy secret scan failed" >&2
  tail -n 40 "$WORKDIR/trivy-secret.log" >&2 || true
  exit "$SECRET_EXIT"
fi
if [ ! -f "$WORKDIR/secrets.json" ]; then
  echo "trivy secret scan did not write secrets.json; S3 upload was not attempted" >&2
  exit 1
fi
UPLOAD_EXIT=0
aws s3 cp "$WORKDIR/{report_dir}/trivy-report.json" 's3://{bucket}/{keys["json"]}' >"$WORKDIR/upload-json.log" 2>&1 || UPLOAD_EXIT=$?
aws s3 cp "$WORKDIR/{report_dir}/trivy-report.txt" 's3://{bucket}/{keys["txt"]}' >"$WORKDIR/upload-txt.log" 2>&1 || UPLOAD_EXIT=$?
if [ "$UPLOAD_EXIT" -eq 0 ]; then
  if ! python3 -m ami_patcher.baseline_summary --scan "$WORKDIR/{report_dir}/trivy-report.json" --secrets "$WORKDIR/secrets.json" --exceptions "$WORKDIR/lib/exceptions.yaml" --output "$WORKDIR/{report_dir}/summary.json" --run-id '{run_id}' --source-ami '{source_ami_id}' --instance-id '{instance_id}' --trivy-version-file "$WORKDIR/trivy-version.txt" --scan-exit "$SCAN_EXIT" --secret-exit "$SECRET_EXIT" --upload-exit "$UPLOAD_EXIT" --scan-coverage "$scan_coverage" >"$WORKDIR/summary-status.json"; then
    echo "summary builder failed" >&2
    exit 1
  fi
  aws s3 cp "$WORKDIR/{report_dir}/summary.json" 's3://{bucket}/{keys["summary"]}' >"$WORKDIR/upload-summary.log" 2>&1 || UPLOAD_EXIT=$?
fi
if [ -f "$WORKDIR/summary-status.json" ]; then
  cat "$WORKDIR/summary-status.json"
fi
if [ "$UPLOAD_EXIT" -ne 0 ]; then
  echo "S3 upload failed; reports were not uploaded" >&2
  tail -n 40 "$WORKDIR/upload-json.log" >&2 || true
  tail -n 40 "$WORKDIR/upload-txt.log" >&2 || true
  tail -n 40 "$WORKDIR/upload-summary.log" >&2 || true
  exit "$UPLOAD_EXIT"
fi
exit 0
"""


def patch_script(
    *,
    workdir: str,
    bucket: str,
    patch_key: str,
    run_id: str,
    instance_id: str,
    min_free_disk_gb: float,
) -> str:
    for label, value in {
        "workdir": workdir,
        "bucket": bucket,
        "patch_key": patch_key,
        "run_id": run_id,
        "instance_id": instance_id,
    }.items():
        _require_safe(value, label)
    if min_free_disk_gb < 0:
        raise ValueError("min_free_disk_gb must be >= 0")
    return f"""#!/bin/bash
set -u
WORKDIR='{workdir}'
mkdir -p "$WORKDIR/patch"
export PYTHONPATH="$WORKDIR/lib"
export PATH="/usr/local/bin:$PATH"
echo "resource disk before patch:" >&2
df -h / >&2 || true
echo "resource memory before patch:" >&2
awk '/MemTotal|MemAvailable|SwapTotal|SwapFree/ {{ print }}' /proc/meminfo >&2 || true
avail_kb=$(df -Pk / | awk 'NR==2 {{print $4}}')
need_kb=$(awk -v gb='{min_free_disk_gb}' 'BEGIN {{printf "%.0f", gb * 1024 * 1024}}')
if [ "$avail_kb" -lt "$need_kb" ]; then
  echo "free disk on / is ${{avail_kb}}KB, need ${{need_kb}}KB. Patching cannot proceed safely. Swap was not created and does not fix disk exhaustion." >&2
  exit 1
fi
if [ ! -r /etc/os-release ]; then
  echo "cannot detect the OS because /etc/os-release is missing" >&2
  exit 1
fi
os_id=$(awk -F= '$1=="ID" {{ gsub(/"/, "", $2); print $2; exit }}' /etc/os-release)
os_like=$(awk -F= '$1=="ID_LIKE" {{ gsub(/"/, "", $2); print $2; exit }}' /etc/os-release)
family=unknown
case "$os_id" in
  ubuntu|debian) family=deb ;;
  amzn|almalinux|rhel|centos|fedora|rocky|ol) family=rpm ;;
esac
if [ "$family" = unknown ]; then
  case "$os_like" in
    *debian*) family=deb ;;
    *rhel*|*fedora*|*centos*) family=rpm ;;
  esac
fi
if [ "$family" = unknown ]; then
  echo "unsupported OS id=$os_id like=$os_like; patching supports apt-get on Debian/Ubuntu and dnf or yum on RPM images" >&2
  exit 1
fi
pm=
if [ "$family" = deb ]; then
  pm=apt-get
else
  if command -v dnf >/dev/null 2>&1; then
    pm=dnf
  elif command -v yum >/dev/null 2>&1; then
    pm=yum
  else
    echo "unsupported RPM OS id=$os_id; neither dnf nor yum is installed" >&2
    exit 1
  fi
fi
run_pkg() {{
  attempt=1
  while [ "$attempt" -le 5 ]; do
    if "$@" >"$WORKDIR/patch/attempt.log" 2>&1; then
      cat "$WORKDIR/patch/attempt.log" >>"$WORKDIR/patch/upgrade.log"
      return 0
    fi
    cat "$WORKDIR/patch/attempt.log" >>"$WORKDIR/patch/upgrade.log"
    if grep -Eq 'Could not get lock|Unable to acquire the dpkg frontend lock|Unable to lock|Waiting for cache lock|another copy of (dnf|yum|apt)' "$WORKDIR/patch/attempt.log"; then
      echo "package manager lock, retry $attempt of 5" >&2
      sleep 15
      attempt=$((attempt + 1))
      continue
    fi
    echo "package manager command failed" >&2
    tail -n 40 "$WORKDIR/patch/upgrade.log" >&2 || true
    return 1
  done
  echo "package manager remained locked after 5 attempts" >&2
  return 1
}}
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
: >"$WORKDIR/patch/upgrade.log"
upgrade_exit=0
reboot_required=false
reboot_check=not-checked
if [ "$pm" = apt-get ]; then
  export DEBIAN_FRONTEND=noninteractive
  reboot_check=reboot-required-file
  if ! run_pkg apt-get update; then
    upgrade_exit=1
  elif ! run_pkg apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; then
    upgrade_exit=1
  fi
  if [ -f /var/run/reboot-required ]; then
    reboot_required=true
  fi
else
  if ! run_pkg "$pm" makecache; then
    upgrade_exit=1
  elif ! run_pkg "$pm" upgrade -y; then
    upgrade_exit=1
  fi
  if command -v needs-restarting >/dev/null 2>&1; then
    reboot_check=needs-restarting
    if ! needs-restarting -r >"$WORKDIR/patch/reboot.log" 2>&1; then
      reboot_required=true
    fi
  else
    reboot_check=running-kernel
    running_kernel=$(uname -r)
    newest_kernel=$(rpm -q kernel --qf '%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' 2>/dev/null | sort | tail -n 1 || true)
    if [ -n "$newest_kernel" ] && [ "$newest_kernel" != "$running_kernel" ]; then
      reboot_required=true
    fi
  fi
fi
ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if ! python3 -m ami_patcher.patch_report --os-release /etc/os-release --log "$WORKDIR/patch/upgrade.log" --output "$WORKDIR/patch/patch-report.json" --run-id '{run_id}' --instance-id '{instance_id}' --package-manager "$pm" --started-at "$started_at" --ended-at "$ended_at" --exit-status "$upgrade_exit" --reboot-required "$reboot_required" --reboot-check "$reboot_check"; then
  echo "patch report builder failed" >&2
  exit 1
fi
if ! aws s3 cp "$WORKDIR/patch/patch-report.json" 's3://{bucket}/{patch_key}' >"$WORKDIR/patch/upload.log" 2>&1; then
  echo "patch report was not uploaded" >&2
  tail -n 40 "$WORKDIR/patch/upload.log" >&2 || true
  exit 1
fi
exit "$upgrade_exit"
"""


def reboot_script() -> str:
    return """#!/bin/bash
set -u
echo '{"stage":"reboot","scheduled":true}'
(sleep 5; reboot) >/dev/null 2>&1 &
exit 0
"""


def finalize_patch_report_script(*, workdir: str, bucket: str, patch_key: str, performed: bool, recovery: str) -> str:
    for label, value in {"workdir": workdir, "bucket": bucket, "patch_key": patch_key, "recovery": recovery}.items():
        _require_safe(value, label)
    performed_text = "true" if performed else "false"
    return f"""#!/bin/bash
set -u
WORKDIR='{workdir}'
export PYTHONPATH="$WORKDIR/lib"
export PATH="/usr/local/bin:$PATH"
if ! python3 -m ami_patcher.patch_report --output "$WORKDIR/patch/patch-report.json" --run-id placeholder --instance-id placeholder --mark-reboot --reboot-performed {performed_text} --ssm-recovery '{recovery}'; then
  echo "could not record reboot result" >&2
  exit 1
fi
if ! aws s3 cp "$WORKDIR/patch/patch-report.json" 's3://{bucket}/{patch_key}' >"$WORKDIR/patch/upload-reboot.log" 2>&1; then
  echo "updated patch report was not uploaded" >&2
  exit 1
fi
exit 0
"""


def comparison_script(
    *,
    workdir: str,
    bucket: str,
    comparison_key: str,
    run_id: str,
    baseline_prefix: str,
    post_prefix: str,
) -> str:
    for label, value in {
        "workdir": workdir,
        "bucket": bucket,
        "comparison_key": comparison_key,
        "run_id": run_id,
        "baseline_prefix": baseline_prefix,
        "post_prefix": post_prefix,
    }.items():
        _require_safe(value, label)
    return f"""#!/bin/bash
set -u
WORKDIR='{workdir}'
mkdir -p "$WORKDIR/comparison"
export PYTHONPATH="$WORKDIR/lib"
export PATH="/usr/local/bin:$PATH"
if ! python3 -m ami_patcher.compare_reports --baseline-scan "$WORKDIR/baseline/trivy-report.json" --post-scan "$WORKDIR/post-patch/trivy-report.json" --baseline-summary "$WORKDIR/baseline/summary.json" --post-summary "$WORKDIR/post-patch/summary.json" --output "$WORKDIR/comparison/comparison.json" --run-id '{run_id}' --baseline-prefix '{baseline_prefix}' --post-prefix '{post_prefix}'; then
  echo "comparison builder failed" >&2
  exit 1
fi
if ! aws s3 cp "$WORKDIR/comparison/comparison.json" 's3://{bucket}/{comparison_key}' >"$WORKDIR/comparison/upload.log" 2>&1; then
  echo "comparison report was not uploaded" >&2
  tail -n 40 "$WORKDIR/comparison/upload.log" >&2 || true
  exit 1
fi
exit 0
"""


def swap_cleanup_script(workdir: str) -> str:
    _require_safe(workdir, "workdir")
    return f"""#!/bin/bash
set -u
swapfile='{workdir}/swapfile'
if [ -f "$swapfile" ]; then
  if ! swapoff "$swapfile"; then
    echo "cleanup failed: could not disable workflow swap $swapfile" >&2
    exit 1
  fi
  if ! rm -f "$swapfile"; then
    echo "cleanup failed: could not remove workflow swap $swapfile" >&2
    exit 1
  fi
fi
echo '{{"stage":"swap-cleanup"}}'
exit 0
"""


def parse_status_line(stdout: str, stage: str = "baseline") -> dict:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if not text.startswith("{"):
            continue
        import json

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if payload.get("stage") == stage:
            return payload
    raise ValueError(f"{stage} command did not print a status line")


def _require_safe(value: str, label: str) -> None:
    if not value or not _SAFE.match(value) or ".." in value.split("/"):
        raise ValueError(f"{label} contains characters that cannot be embedded in a shell command")
