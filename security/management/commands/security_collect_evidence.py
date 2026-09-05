"""Collect trusted CI evidence for security controls."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from security.operational_evidence import collect_ci_evidence


def _parse_outcome(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise CommandError("--outcome must use CONTROL_KEY=RESULT format.")
    control_key, result = value.split("=", 1)
    control_key = control_key.strip()
    result = result.strip().upper()
    if not control_key or not result:
        raise CommandError("--outcome must use CONTROL_KEY=RESULT format.")
    return control_key, result


class Command(BaseCommand):
    help = "Record deterministic CI evidence for the security control registry."

    def add_arguments(self, parser):
        parser.add_argument("--source-name", default="auth-security-ci")
        parser.add_argument("--source-reference", default="")
        parser.add_argument("--environment", default="")
        parser.add_argument("--commit-sha", default="")
        parser.add_argument("--workflow", default="")
        parser.add_argument("--job", default="")
        parser.add_argument("--run-id", default="")
        parser.add_argument("--run-attempt", default="")
        parser.add_argument(
            "--outcome",
            action="append",
            default=[],
            metavar="CONTROL_KEY=RESULT",
            help="Override a control result for a specific ingestion run.",
        )

    def handle(self, *args, **options):
        outcomes = dict(_parse_outcome(item) for item in options["outcome"])
        result = collect_ci_evidence(
            source_name=options["source_name"],
            source_reference=options["source_reference"],
            environment=options["environment"] or None,
            commit_sha=options["commit_sha"],
            workflow=options["workflow"],
            job=options["job"],
            run_id=options["run_id"],
            run_attempt=options["run_attempt"],
            outcomes=outcomes,
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Recorded CI evidence for {result.created_count} controls "
                f"and reused {result.reused_count} existing rows."
            )
        )
        for record in result.records:
            self.stdout.write(
                f"{record.control_key}: evidence={record.evidence_id} created={record.created} "
                f"finding={record.finding_key or '-'}"
            )

