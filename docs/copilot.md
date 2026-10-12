# Faustus in DiskHoard

The shared Faustus panel is available from every DiskHoard screen. Its chats,
drafts, history and tool execution stay in Faustus. DiskHoard hosts the standard
library HoardLink transport at `/api/copilot/info`, `/api/copilot/panel.js`,
`/api/copilot/launcher.js` and `/api/copilot/proxy`; no extra Python packages
or model server are required. The existing Host/Origin checks apply.

The server reads the configured Faustus connection through HoardLink. Its token
stays on the server. `data/copilot-space-id` supplies the stable installation
identity, and each scanned root supplies the project identity.

The context includes the current view, scanned folder verified by `disk_dir`,
selected files still present in that folder, selected text, and unsaved scan,
ZIP or Ollama-backup form values. A start screen or missing folder has no active
object. The panel follows the page language. ZIP and backup forms remain open
after a turn; scan results refresh through the existing native agent workflow.
These forms submit the current values explicitly when their own action is used;
they do not overwrite a persistent app configuration.

The native disk MCP catalogue and operations remain available. Text inference
uses the global Faustus model on Sparks. Verification uses disposable scan data
and a scripted provider; it does not establish autonomous model quality.
