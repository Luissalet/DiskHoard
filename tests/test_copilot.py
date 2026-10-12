import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def test_copilot_http_contract_and_native_routes(server, tmp_path):
    from diskhoard.hoard_link.copilot_stdlib import CopilotRelay
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            body = (b'{"contract_version":"1.0"}' if self.path.endswith('capabilities')
                    else b'export const qaPanel = true;')
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    old = server['httpd'].copilot
    relay = CopilotRelay('diskhoard', tmp_path, token='', env={},
      faustus_urls=['http://127.0.0.1:'+str(upstream.server_port)])
    server['httpd'].copilot = relay
    try:
        with urllib.request.urlopen(server['url']+'/api/copilot/info') as response:
            info = json.load(response)
        assert info['app_id'] == 'diskhoard'
        assert info['data_space_id'] == relay.space_id
        with urllib.request.urlopen(server['url']+'/') as response:
            html = response.read()
        assert html.count(b'/api/copilot/launcher.js') == 1
        assert b'/copilot.js' in html
        with urllib.request.urlopen(server['url']+'/api/copilot/launcher.js') as response:
            assert b'faustus-chat' in response.read()
        with urllib.request.urlopen(server['url']+'/api/agent/tools') as response:
            tools = json.load(response)['tools']
        assert {'disk_dir','disk_status','disk_zip_plan'} <= {tool['name'] for tool in tools}
        request = urllib.request.Request(server['url']+'/api/drives', headers={'X-DH-Token':server['token']})
        with urllib.request.urlopen(request) as response:
            assert 'drives' in json.load(response)
        assert CopilotRelay('diskhoard', tmp_path, token='', env={}).space_id == relay.space_id
    finally:
        server['httpd'].copilot = old
        upstream.shutdown()
        upstream.server_close()
        worker.join(timeout=3)


def test_manifest_points_at_native_tools():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root/'faustus-plugin.json').read_text(encoding='utf8'))
    copilot = manifest['x-family']['copilot']
    assert copilot['provider'] == 'faustus'
    assert copilot['panel'] == '/api/copilot/panel.js'
    from diskhoard.agent import CATALOG
    names = {tool['name'] for tool in CATALOG}
    assert set(copilot['project_tools'].values()) <= names
