# Data

Local storage for real, authorized activity/log data collected from Windows
machines. Nothing under `raw/` or `processed/` is committed to git (see
`.gitignore`) — this data may be sensitive.

- `raw/` — untouched logs as collected
- `processed/` — cleaned/feature-engineered data used for ML (later phase)

No synthetic data is ever placed here.
