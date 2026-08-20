# Downloaded Surge modules and remote assets

These files are downloaded from the URLs listed in `config/modules.manifest.yaml`.
They are untrusted input: SongsterX must parse, hash-pin, sandbox, and review them
before activation. Downloading a module never executes its scripts; runtime
execution is limited to the pinned local asset after hash verification.

The `modules/remote-scripts/` directory contains every unique `script-path` asset
referenced by the nine modules in the supplied `Untitled-1.md`. The two
`modules/remote-assets/` files are the referenced Zhihu blank JSON and Tieba rule
set. Their source URLs and SHA-256 values are recorded in
`config/module-assets.manifest.json`.

The Module Engine now parses the Surge hook, injects module arguments, buffers
request/response bodies according to the hook, and runs the pinned JavaScript
asset in the embedded QuickJS bridge. The bridge has no filesystem or process
access; HTTP helper calls, persistent storage, notifications, binary bodies,
and response/request edits are mediated by the host.
