# reports/

Where `devforge eval run` writes its reports. One JSON file per run, named
`<config>-<timestamp>-<report-id>.json`, so sorting the directory sorts by time.

Nothing here is ever overwritten. A saved report is evidence of what happened at a
moment, and a benchmark that quietly replaces the previous run destroys the only
thing that makes a regression detectable.

```bash
devforge eval report                       # render the newest as Markdown
devforge eval report mock-baseline         # the newest for one configuration
devforge eval report reports/x.json -o report.md
devforge eval compare mock-baseline mock-indexed
```

The JSON files themselves are gitignored — they are build output, they are
machine-specific (latency depends on the machine that produced them), and a
repository that accumulates them turns every benchmark run into a diff. Commit a
report deliberately when it is the baseline an investigation refers to, and say in
the commit message what it is a baseline *for*.

`reports/workspaces/` holds the failed case workspaces kept by
`devforge eval run --keep-failures`. A failure nobody can inspect is a failure
nobody can fix. It is also gitignored, and it is deleted and rewritten on each run
that uses the flag.
