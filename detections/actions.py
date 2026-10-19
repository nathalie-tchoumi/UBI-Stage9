"""Containment and recovery action planner.

This module NEVER executes anything against a real system. Every
function returns a structured, fully-specified action plan (exact
command, target, justification, evidence locator) that a human
operator would review and run manually, or that a future real
executor module could consume.
"""
from dataclasses import dataclass, asdict


@dataclass
class ContainmentAction:
    action_id: str
    action_type: str
    target: str
    command: str
    justification: str
    evidence_locator: str
    destructive: bool
    requires_evidence_preservation_first: bool


def isolate_host(hostname, evidence_locator):
    return ContainmentAction(
        action_id="ISOLATE-HOST",
        action_type="network_isolation",
        target=hostname,
        command='New-NetFirewallRule -DisplayName "SOC-Isolate" -Direction Outbound -Action Block -RemoteAddress Any -Profile Any -Enabled True',
        justification="Host confirmed source of exfiltration per attack chain",
        evidence_locator=evidence_locator,
        destructive=False,
        requires_evidence_preservation_first=True,
    )


def kill_process_tree(hostname, root_image, evidence_locator):
    return ContainmentAction(
        action_id="KILL-PROCESS-TREE",
        action_type="process_termination",
        target=hostname + ":" + root_image,
        command="Get-CimInstance Win32_Process -Filter \"Name='" + root_image + "'\" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }",
        justification=root_image + " is confirmed parent of persistence, staging, and exfiltration steps",
        evidence_locator=evidence_locator,
        destructive=True,
        requires_evidence_preservation_first=True,
    )


def remove_scheduled_task(hostname, task_name, evidence_locator):
    return ContainmentAction(
        action_id="REMOVE-SCHEDULED-TASK",
        action_type="persistence_removal",
        target=hostname + ":" + task_name,
        command='Unregister-ScheduledTask -TaskName "' + task_name + '" -Confirm:$false',
        justification="Scheduled task confirmed as attacker-created persistence mechanism",
        evidence_locator=evidence_locator,
        destructive=True,
        requires_evidence_preservation_first=True,
    )


def block_c2_indicator(hostname_or_ip, port, evidence_locator):
    return ContainmentAction(
        action_id="BLOCK-C2",
        action_type="network_block",
        target=hostname_or_ip + ":" + str(port),
        command='New-NetFirewallRule -DisplayName "SOC-Block-C2" -Direction Outbound -Action Block -RemoteAddress ' + hostname_or_ip + ' -RemotePort ' + str(port) + ' -Protocol TCP -Enabled True',
        justification="Confirmed C2/exfiltration endpoint per PCAP HTTP POST and matching sysmon network_connect event",
        evidence_locator=evidence_locator,
        destructive=False,
        requires_evidence_preservation_first=False,
    )


def preserve_memory_before_action(hostname, evidence_locator):
    return ContainmentAction(
        action_id="PRESERVE-MEMORY",
        action_type="evidence_preservation",
        target=hostname,
        command="(optional path, per evidence/lab-source/README.md) Invoke-SyntheticIncident.ps1 then Capture-Memory.ps1 on an isolated VM, NOT the live host",
        justification="Destructive containment actions should be preceded by memory capture where feasible",
        evidence_locator=evidence_locator,
        destructive=False,
        requires_evidence_preservation_first=False,
    )


def build_response_plan():
    """Full ordered response plan for this confirmed incident, evidence
    preservation actions first, destructive actions last, per the
    principle that destructive actions must not precede preservation.
    """
    plan = [
        preserve_memory_before_action("NS-WKS-101", "sysmon.jsonl:line:50001-50006"),
        isolate_host("NS-WKS-101", "sysmon.jsonl:line:50001-50006"),
        block_c2_indicator("sync-v1.updates-example.invalid", 8443, "incident.pcap:frame:49"),
        kill_process_tree("NS-WKS-101", "powershell.exe", "sysmon.jsonl:line:50002"),
        remove_scheduled_task("NS-WKS-101", "Northstar Support Sync", "sysmon.jsonl:line:50003"),
    ]
    return plan


def plan_to_dicts(plan):
    return [asdict(a) for a in plan]
