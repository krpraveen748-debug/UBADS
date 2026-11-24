# `frontend/public/downloads/`

Local development/demo artifact only. The endpoint enrollment UI does not
link to this folder; endpoint-specific packages are issued only through the
authenticated backend after request approval.

`*.exe` files here are gitignored (a ~20MB rebuildable artifact, not
source) — this `README.md` is the only tracked file in this directory.
An existing ignored installer copy may be stale; do not use or upload it as
a release. The authoritative local installer output is
`agent/dist/UBADS-Agent-Setup.exe`.

## Populating it

Build the agent installer first (see `agent/README.md`), then copy it
here:

```powershell
cd "path\to\this\project"
Copy-Item agent\dist\UBADS-Agent-Setup.exe frontend\public\downloads\UBADS-Agent-Setup.exe
```

## Production

Production uses a private pre-existing Azure Blob container read by the
backend's managed identity. The authenticated API streams the artifact only
to the owner of an approved request. The production Vite build strips this
folder from its output (see `vite.config.js`); do not configure a public
installer URL or SAS token.
