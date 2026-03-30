# SIGMA Rule Templates

Ready-to-use templates for creating detection rules. Copy the appropriate template and fill in the `TODO` fields.

| Template | Use Case |
|----------|----------|
| [process_creation_windows.yml](process_creation_windows.yml) | Windows process execution (Sysmon EID 1, Security 4688) |
| [registry_windows.yml](registry_windows.yml) | Windows registry modifications |
| [powershell_windows.yml](powershell_windows.yml) | PowerShell script block / module logging |
| [cloud_aws.yml](cloud_aws.yml) | AWS CloudTrail API detections |
| [linux_process.yml](linux_process.yml) | Linux process creation / command execution |
| [cve_exploit.yml](cve_exploit.yml) | CVE-specific exploit detection |
| [threat_actor.yml](threat_actor.yml) | APT / threat actor campaign rules |
| [network_zeek.yml](network_zeek.yml) | Zeek/Bro network log detections |

## How to Use

```bash
# 1. Copy the template
cp templates/process_creation_windows.yml \
   windows/process_creation/proc_creation_win_your_rule_name.yml

# 2. Generate a UUID
uuidgen
# or: python -c "import uuid; print(uuid.uuid4())"

# 3. Fill in all TODO fields

# 4. Validate
python -c "import yaml; yaml.safe_load(open('windows/process_creation/proc_creation_win_your_rule_name.yml'))"

# 5. Test with Muninn
muninn -e /path/to/test/logs -r windows/process_creation/proc_creation_win_your_rule_name.yml --stats
```
