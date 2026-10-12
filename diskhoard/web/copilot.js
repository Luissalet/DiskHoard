/* App context for the family Faustus panel; chats and tools live in Faustus. */
const copilotEditedFields = new Set();
for (const event of ['input', 'change']) document.addEventListener(event, e => {
  if (e.target.id) copilotEditedFields.add(e.target.id);
});
async function copilotSelection(folder) {
  const folders = new Map();
  if (folder && folder.path) folders.set(folder.path, folder);
  const selected = [];
  for (const item of S.sel.values()) {
    const split = Math.max(item.path.lastIndexOf('/'), item.path.lastIndexOf('\\'));
    let parent = item.path.slice(0, split) || '/';
    if (/^[A-Za-z]:$/.test(parent)) parent += '\\';
    if (!folders.has(parent)) folders.set(parent, await get('/api/dir', {path: parent}));
    const listing = folders.get(parent);
    const current = !listing.error && (listing.entries || []).find(entry => entry.path === item.path);
    if (current) selected.push({kind: current.dir ? 'folder' : 'file',
      object_id: current.path, title: current.name, size: current.size});
  }
  return selected;
}
window.hoardCopilot = {
  async reconcileSelection() {
    const valid = new Set((await copilotSelection()).map(item => item.object_id));
    for (const path of S.sel.keys()) if (!valid.has(path)) S.sel.delete(path);
  },
  async context() {
    const zip = $('#zipsec').style.display === 'flex';
    const ollama = $('#ollsec').style.display === 'flex';
    const start = $('#start').style.display !== 'none';
    const view = zip ? 'zip' : ollama ? 'ollama' : start ? 'start' : S.tab;
    const active = [];
    if (!zip && !ollama && !start && S.path) {
      const folder = await get('/api/dir', {path: S.path});
      if (!folder.error && folder.path) {
        active.push({kind: 'folder', object_id: folder.path, title: folder.path,
          tool: 'disk_dir', size: folder.size});
        active.push(...await copilotSelection(folder));
      }
    }
    let editor;
    if (zip) editor = {kind: 'zip-draft', fields: zArgs(),
      dirty: [...copilotEditedFields].some(id => id.startsWith('z')), job_id: Z.job || null};
    else if (ollama) editor = {kind: 'ollama-draft', dirty: copilotEditedFields.has('olDir') || O.sel.size > 0,
      fields: {models_dir: $('#olDir').value, mode: ollMode(), selected: [...O.sel]}};
    else if (start) editor = {kind: 'scan-draft', dirty: copilotEditedFields.has('pathin'),
      fields: {path: $('#pathin').value.trim()}};
    const selected = window.getSelection();
    return {
      project: S.root ? {external_project_id: S.root,
        title: (S.root.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || 'Escaneo').slice(0, 80),
        workspace_root: S.root} : null,
      active_objects: active,
      selection: {text: selected ? selected.toString() : '',
        paths: active.slice(1).map(item => item.object_id)},
      view: {name: view, path: location.pathname, title: document.title,
        locale: document.documentElement.lang || 'es', editor},
    };
  },
  async onTurnEnd() {
    // Refresh the scan without replacing the unsaved ZIP/backup form.
    if ($('#zipsec').style.display === 'flex') {
      if (Z.job) await zPoll();
      return;
    }
    if ($('#ollsec').style.display === 'flex') {
      if (O.data && !O.run) {
        const result = await get('/api/ollama/backups', {dir: O.data.models_dir || ''});
        if (!result.error) { O.data = result; ollRender(); }
      }
      return;
    }
    await followAgent();
  },
};
