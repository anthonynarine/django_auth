"""Record runtime security-configuration evidence."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from security.operational_evidence import collect_configuration_evidence


class Command(BaseCommand):
    help = "Verify the allowlisted runtime security settings and record evidence."

    def add_arguments(self, parser):
        parser.add_argument("--source-name", default="production-security-config")
        parser.add_argument("--source-reference", default="")
        parser.add_argument("--environment", default="")
        parser.add_argument(
            "--check",
            action="append",
            default=[],
            dest="checks",
            help="Allowlisted configuration check name to run.",
        )

    def handle(self, *args, **options):
        result = collect_configuration_evidence(
            source_name=options["source_name"],
            source_reference=options["source_reference"],
            environment=options["environment"] or None,
            check_names=tuple(options["checks"]),
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Recorded configuration evidence for {result.created_count} controls "
                f"and reused {result.reused_count} existing rows."
            )
        )
        for record in result.records:
            self.stdout.write(
                f"{record.control_key}: evidence={record.evidence_id} created={record.created} "
                f"finding={record.finding_key or '-'}"
            )

