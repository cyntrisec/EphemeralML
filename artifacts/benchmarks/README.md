# Benchmark Bundles

This directory contains the published benchmark bundles that are part of the
public evidence surface for EphemeralML.

Do not add raw ad-hoc cloud run output here unless it has been reviewed for
public release. Prefer redacted summaries, SHA-256 manifests, or GitHub Release
assets for bulky/raw traces.

Tracked historical bundles:

- `aws-nitro-modern-20260225/`
- `aws-nitro-modern-20260225-clean/`
- `multimodel-20260205/`

These are preserved as reproducibility artifacts and are referenced from the
publication and benchmarking docs.

Generated benchmark output roots such as `benchmark_results/` and
`benchmark_results_final/` remain operational scratch/output paths used by
scripts and are not part of this tracked evidence directory.
