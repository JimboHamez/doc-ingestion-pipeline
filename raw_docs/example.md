# Example Ingestion Document

This is a clean sample document used by the CI pipeline to exercise all three
stages end to end. It contains ordinary prose with no macros, no embedded
executables, no secrets, no personal data, and no prompt-injection payloads.

The pipeline should pass it through: stage 1 finds no binary threats, stage 2
converts it to normalized UTF-8 Markdown, and stage 3 finds no content threats.
