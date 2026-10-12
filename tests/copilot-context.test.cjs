const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('diskhoard/web/copilot.js', 'utf8');
function fixture() {
  const els = Object.fromEntries(['zipsec', 'ollsec', 'start', 'pathin', 'olDir'].map(id =>
    [id, {style: {display: id === 'start' ? 'block' : 'none'}, value: 'draft path'}]));
  const listeners = {};
  const env = {window: {getSelection: () => ({toString: () => 'selected text'})},
    document: {title: 'DiskHoard', documentElement: {lang: 'es'},
      addEventListener: (name, fn) => {listeners[name] = fn;}},
    location: {pathname: '/'}, S: {root: '', path: '', tab: 'tree', sel: new Map()},
    Z: {job: null}, O: {sel: new Set(), data: null, run: false},
    $: selector => els[selector.slice(1)], zArgs: () => ({path: els.pathin.value, limit: '25mb'}),
    ollMode: () => 'permanent', zPoll: async () => {env.zipPolled = true;},
    ollRender: () => {env.ollRendered = true;}, followAgent: async () => {env.followed = true;},
    get: async () => ({path: 'C:/fixture', size: 25,
      entries: [{path: 'C:/fixture/a.txt', name: 'a.txt', size: 25, dir: false}]}),
  };
  vm.runInNewContext(source, env);
  return {env, els, listeners, hook: env.window.hoardCopilot};
}
test('new scan has no invented object and carries unsubmitted input', async () => {
  const {hook, listeners} = fixture();
  let ctx = await hook.context();
  assert.equal(ctx.active_objects.length, 0);
  assert.equal(ctx.project, null);
  assert.equal(ctx.view.editor.fields.path, 'draft path');
  assert.equal(ctx.view.editor.dirty, false);
  listeners.input({target: {id: 'pathin'}});
  ctx = await hook.context();
  assert.equal(ctx.view.editor.dirty, true);
});
test('folder resolves by real API and stale selection is excluded', async () => {
  const {env, els, hook} = fixture();
  els.start.style.display = 'none';
  Object.assign(env.S, {root: 'C:/fixture', path: 'C:/fixture'});
  env.S.sel.set('C:/fixture/a.txt', {path: 'C:/fixture/a.txt'});
  env.S.sel.set('C:/fixture/gone.txt', {path: 'C:/fixture/gone.txt'});
  const ctx = await hook.context();
  assert.equal(ctx.project.workspace_root, 'C:/fixture');
  assert.equal(ctx.project.title, 'fixture');
  assert.equal(ctx.active_objects.length, 2);
  assert.equal(ctx.active_objects[1].title, 'a.txt');
  assert.equal(ctx.selection.paths.length, 1);
  assert.equal(ctx.view.locale, 'es');
  env.get = async () => ({error: 'gone'});
  assert.equal((await hook.context()).active_objects.length, 0);
});
test('ZIP draft survives turn completion', async () => {
  const {env, els, listeners, hook} = fixture();
  els.zipsec.style.display = 'flex';
  listeners.change({target: {id: 'zLimit'}});
  const ctx = await hook.context();
  assert.equal(ctx.view.editor.kind, 'zip-draft');
  assert.equal(ctx.view.editor.dirty, true);
  assert.equal(ctx.active_objects.length, 0);
  await hook.onTurnEnd();
  assert.equal(els.pathin.value, 'draft path');
  assert.equal(env.followed, undefined);
  env.Z.job = 'job-1';
  await hook.onTurnEnd();
  assert.equal(env.zipPolled, true);
});
test('backup refresh preserves entered path and chosen mode', async () => {
  const {env, els, hook} = fixture();
  els.ollsec.style.display = 'flex';
  env.O.data = {models_dir: 'C:/verified-models'};
  env.get = async () => ({models_dir: 'C:/verified-models', items: []});
  const ctx = await hook.context();
  assert.equal(ctx.view.editor.fields.mode, 'permanent');
  await hook.onTurnEnd();
  assert.equal(els.olDir.value, 'draft path');
  assert.equal(env.ollRendered, true);
  assert.equal(env.followed, undefined);
});
test('native scan refresh runs outside forms', async () => {
  const {env, hook} = fixture();
  await hook.onTurnEnd();
  assert.equal(env.followed, true);
});
