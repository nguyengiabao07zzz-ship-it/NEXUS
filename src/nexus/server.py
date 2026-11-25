import argparse
import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
import secrets
import os
import socket
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Invalid, Store, redact, load_json_bounded
from .lab import probe
from .intake import inspect_events
from . import indexer, llm
from .analysis import AnalysisService
from .monitor import Monitor
from . import rules

ROOT = Path(__file__).resolve().parents[2]
WEB = Path(__file__).parent / 'web'
MAX_BODY = 2_000_000


class LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def server_close(self):
        if hasattr(self,'monitor'):
            self.monitor.stop()
        super().server_close()
        for handler in getattr(self, 'private_log_handlers', []):
            handler.close()


def log_error(logger, exc):
    # Never log exception text, request body, query or local variables.
    frames = [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
              for f in traceback.extract_tb(exc.__traceback__)]
    logger.error(json.dumps({'type': type(exc).__name__, 'frames': frames}))


def make_server(port=8765, data_dir=None):
    local = Path(data_dir) if data_dir else ROOT / 'data' / 'private' / 'app'
    store = Store(local / 'nexus.sqlite3')
    key_path = local / 'hmac.key'
    try:
        with key_path.open('xb') as f:
            f.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = key_path.read_bytes()
    if len(key) < 32:
        raise Invalid('HMAC key invalid: expected at least 32 bytes; existing file was not replaced')
    analyses = AnalysisService(key, local / 'ai.json', local / 'ai_requests',store=store)
    monitor = Monitor(local/'indexer.json',analyses)
    token = secrets.token_urlsafe(32)
    logger = logging.Logger('nexus-private-' + secrets.token_hex(8))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # No raw request paths or data in terminal logs.

        def reply(self, status, data, content_type='application/json; charset=utf-8'):
            content = json.dumps(data, ensure_ascii=False).encode() if isinstance(data, (dict, list)) else data
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(content)

        def trusted(self):
            expected = f'127.0.0.1:{self.server.server_port}'
            return (self.headers.get('Host') == expected and
                    self.headers.get('Origin') in (None, 'http://' + expected))

        def do_GET(self):
            try:
                self.get_response()
            except Invalid as exc:
                self.reply(400, {'error':str(exc)})
            except Exception as exc:
                log_error(logger, exc)
                self.reply(500, {'error': 'Lỗi nội bộ; xem private error log'})

        def get_response(self):
            if not self.trusted():
                return self.reply(403, {'error': 'Host/Origin không hợp lệ'})
            if self.path == '/api/session':
                return self.reply(200, {'token': token})
            if self.path.startswith('/api/'):
                if not secrets.compare_digest(self.headers.get('X-Nexus-Token', ''), token):
                    return self.reply(403, {'error': 'Thiếu token local'})
                if self.path == '/api/state':
                    report = store.report()
                    if report['corrupt_records']:
                        logger.warning('corrupt_records=%d', report['corrupt_records'])
                    return self.reply(200, {'records': store.list(), 'report': report})
                if self.path == '/api/indexer/status':
                    return self.reply(200, indexer.connection_status(local / 'indexer.json'))
                if self.path == '/api/ai/status':
                    return self.reply(200, llm.status(local / 'ai.json'))
                if self.path == '/api/ai/history':
                    return self.reply(200, analyses.history())
                if self.path.startswith('/api/ai/history/'):
                    return self.reply(200, analyses.detail(self.path.removeprefix('/api/ai/history/')))
                if self.path == '/api/monitor/status':
                    return self.reply(200, monitor.status())
                if self.path == '/api/monitor/latest':
                    return self.reply(200, monitor.latest())
                if self.path.startswith('/api/rules/bundle/'):
                    from .bundle import build_bundle
                    identifier=self.path.removeprefix('/api/rules/bundle/')
                    candidate=store.get(identifier,'candidate')
                    return self.reply(200,build_bundle(candidate),'application/zip')
                if self.path == '/api/export':
                    return self.reply(200, {'warning': 'Dữ liệu nội bộ, chưa làm sạch để công khai',
                                            'records': store.list(), 'report': store.report()})
                return self.reply(404, {'error': 'Không tìm thấy API'})
            files = {'/': ('index.html', 'text/html; charset=utf-8'),
                     '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                     '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if self.path not in files:
                return self.reply(404, {'error': 'Không tìm thấy trang'})
            name, mime = files[self.path]
            self.reply(200, (WEB / name).read_bytes(), mime)

        def do_POST(self):
            if not self.trusted() or not secrets.compare_digest(self.headers.get('X-Nexus-Token', ''), token):
                return self.reply(403, {'error': 'Host/Origin/token không hợp lệ'})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if size <= 0 or size > MAX_BODY:
                    raise Invalid('Yêu cầu rỗng hoặc vượt 2 MB')
                if self.headers.get_content_type() != 'application/json':
                    raise Invalid('Cần application/json')
                self.connection.settimeout(10)
                data = load_json_bounded(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise Invalid('Cần một JSON object')
                if self.path == '/api/records':
                    if not isinstance(data.get('data'), dict):
                        raise Invalid('Thiếu data object')
                    return self.reply(201, store.add(data.get('kind'), data['data']))
                if self.path == '/api/redact':
                    if not isinstance(data.get('text'), str):
                        raise Invalid('Thiếu text')
                    return self.reply(200, redact(data['text'], key))
                if self.path == '/api/logs/preview':
                    return self.reply(200, inspect_events(data.get('text'), data.get('source'), data.get('origin')))
                if self.path == '/api/indexer/collect':
                    if set(data) - {'source', 'minutes', 'limit', 'agent_id'}:
                        raise Invalid('Có trường truy vấn không được phép')
                    try:
                        result = indexer.collect(local / 'indexer.json', **data)
                    except indexer.CollectionError as exc:
                        return self.reply(502, {'error': 'Không thu được dữ liệu Wazuh', 'code': exc.code})
                    result['snapshot_id'] = analyses.remember(result)
                    return self.reply(200, result)
                if self.path == '/api/ai/preview':
                    if not {'snapshot_id','event_indexes'}<=set(data) or set(data)-{'snapshot_id','event_indexes','include_text','purpose','case_id'}:
                        raise Invalid('Preview cần snapshot_id và event_indexes')
                    return self.reply(200, analyses.prepare(**data))
                if self.path == '/api/ai/run':
                    if set(data) != {'preview_id', 'request_sha256', 'approved'}:
                        raise Invalid('Cần ID, hash preview và xác nhận gửi')
                    return self.reply(200, analyses.run(**data))
                if self.path == '/api/ai/save-candidate':
                    if set(data)!={'request_id','confirmed'}:raise Invalid('Cần request_id và confirmed')
                    return self.reply(201,analyses.save_candidate(data['request_id'],data['confirmed']))
                if self.path == '/api/rules/validate':
                    if set(data)!={'xml'}:raise Invalid('Cần XML')
                    return self.reply(200,rules.validate_xml(data['xml']))
                if self.path == '/api/monitor/start':
                    if set(data)!={'query','interval'}:raise Invalid('Cần query và interval')
                    return self.reply(200,monitor.start(**data))
                if self.path == '/api/monitor/stop':
                    if data:raise Invalid('Stop không có tham số')
                    return self.reply(200,monitor.stop())
                if self.path == '/api/lab/probe':
                    return self.reply(200, probe())
                return self.reply(404, {'error': 'Không tìm thấy API'})
            except RecursionError as exc:
                log_error(logger, exc)
                self.reply(400, {'error': 'JSON vượt giới hạn độ sâu'})
            except llm.AIError as exc:
                self.reply(502, {'error': 'Chưa hoàn tất phân tích AI', 'code': exc.code})
            except (Invalid, ValueError, TypeError) as e:
                log_error(logger, e)
                self.reply(400, {'error': str(e)})
            except Exception as exc:
                log_error(logger, exc)
                self.reply(500, {'error': 'Lỗi nội bộ; dữ liệu chưa được xác nhận lưu'})

    server = LocalHTTPServer(('127.0.0.1', port), Handler)
    server.monitor = monitor
    try:
        handler = RotatingFileHandler(local / 'errors.log', maxBytes=1_000_000, backupCount=2, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(handler)
        server.private_log_handlers = [handler]
    except Exception:
        server.server_close()
        raise
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--setup-indexer', action='store_true', help='Configure read-only indexer access locally')
    parser.add_argument('--ask-indexer-password', action='store_true', help='Read indexer password from this terminal')
    parser.add_argument('--setup-ai', action='store_true', help='Configure OpenAI model and enter API key locally')
    parser.add_argument('--ask-ai-key', action='store_true', help='Read OpenAI API key from this terminal')
    parser.add_argument('--setup-codex', action='store_true', help='Use local Codex CLI with ChatGPT sign-in (no API key)')
    parser.add_argument('--codex-model', default='gpt-6.1-sol', help='Model for --setup-codex')
    parser.add_argument('--check-codex', action='store_true', help='Check CLI/login without sending a prompt')
    parser.add_argument('--doctor',action='store_true',help='Local configuration and tunnel checks; no AI prompt')
    args = parser.parse_args()
    if args.doctor:
        local=ROOT/'data/private/app'
        connected=False
        try:
            with socket.create_connection(('127.0.0.1',19200),timeout=2):connected=True
        except OSError:pass
        print(json.dumps({'ai':llm.status(local/'ai.json'),
                          'indexer':indexer.connection_status(local/'indexer.json'),
                          'local_tunnel_port_19200_open':connected,
                          'note':'TCP/config checks only, not indexer auth or model quality.'},ensure_ascii=True,indent=2))
        parser.exit(0)
    if args.check_codex:
        from .codex_cli import readiness
        result = readiness()
        print(json.dumps(result))
        parser.exit(0 if result['ready'] else 1)
    if args.setup_codex and (args.setup_ai or args.ask_ai_key):
        parser.error('Choose --setup-codex or OpenAI API setup/key flags, not both.')
    if (args.setup_indexer or args.ask_indexer_password or args.setup_ai or args.ask_ai_key) and not sys.stdin.isatty():
        parser.exit(1, 'Open an interactive terminal to enter credentials.\n')
    config_path = ROOT / 'data' / 'private' / 'app' / 'indexer.json'
    if args.setup_indexer:
        try:
            config = indexer.validate_config({
                'url': input('Indexer HTTPS URL [https://127.0.0.1:19200 via SSH tunnel]: ').strip() or 'https://127.0.0.1:19200',
                'username': input('Read-only indexer username: ').strip(),
                'password_env': 'NEXUS_INDEXER_PASSWORD',
                'ca_file': str(Path(input('Verified root CA PEM file on this computer: ').strip().strip('"')).expanduser().resolve()),
            })
            if not Path(config['ca_file']).is_file():
                raise Invalid('CA file not found')
            config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = config_path.with_name('indexer-' + secrets.token_hex(8) + '.tmp')
            try:
                temporary.write_text(json.dumps(config, indent=2), encoding='utf-8')
                temporary.replace(config_path)
            finally:
                temporary.unlink(missing_ok=True)
        except (Invalid, OSError, EOFError):
            parser.exit(1, 'Cannot configure indexer. Check URL, username and verified CA file.\n')
    if args.setup_indexer or args.ask_indexer_password:
        try:
            config = indexer.load_config(config_path)
            password = getpass.getpass('Indexer password (not saved): ')
            if not password:
                parser.exit(1, 'Empty password.\n')
            os.environ[config['password_env']] = password
            del password
        except (indexer.CollectionError, EOFError):
            parser.exit(1, 'Cannot read local indexer configuration or password.\n')
    ai_config_path = config_path.with_name('ai.json')
    if args.setup_codex:
        try:
            ai_config = llm.validate_config({'provider': 'codex_cli', 'model': args.codex_model,
                                             'max_output_tokens': 2048})
            ai_config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = ai_config_path.with_name('ai-' + secrets.token_hex(8) + '.tmp')
            try:
                temporary.write_text(json.dumps(ai_config, indent=2), encoding='utf-8')
                temporary.replace(ai_config_path)
            finally:
                temporary.unlink(missing_ok=True)
        except (ValueError, OSError):
            parser.exit(1, 'Cannot configure Codex CLI. Check model ID and local data access.\n')
    if args.setup_ai:
        try:
            ai_config = llm.validate_config({'provider': 'openai',
                'model': input('OpenAI model ID supporting structured outputs (no default): ').strip(),
                'max_output_tokens': int(input('Max output tokens [2048, range 512-4096]: ').strip() or '2048')})
            ai_config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = ai_config_path.with_name('ai-' + secrets.token_hex(8) + '.tmp')
            try:
                temporary.write_text(json.dumps(ai_config, indent=2), encoding='utf-8')
                temporary.replace(ai_config_path)
            finally:
                temporary.unlink(missing_ok=True)
        except (ValueError, OSError, EOFError):
            parser.exit(1, 'Cannot configure OpenAI. Check model ID and output limit.\n')
    if args.setup_ai or args.ask_ai_key:
        try:
            if llm.load_config(ai_config_path)['provider'] != 'openai':
                parser.exit(1, 'Codex CLI uses ChatGPT sign-in. Omit --ask-ai-key.\n')
            api_key = getpass.getpass('OpenAI API key (not saved): ')
            if not api_key:
                parser.exit(1, 'Empty API key.\n')
            os.environ[llm.KEY_ENV] = api_key
            del api_key
        except (llm.AIError, EOFError):
            parser.exit(1, 'Cannot read local AI configuration or API key.\n')
    try:
        server = make_server(args.port)
    except (OSError, Invalid) as exc:
        if isinstance(exc,OSError) and (getattr(exc,'winerror',None)==10048 or exc.errno in (48,98,10048)):
            parser.exit(1,f'Port {args.port} is already in use. Stop the OLD NEXUS terminal with Ctrl+C, then run again.\n')
        parser.exit(1, f'Cannot start NEXUS ({type(exc).__name__}). Check port {args.port}, data access and HMAC key.\n')
    print(f'NEXUS local: http://127.0.0.1:{server.server_port}', flush=True)
    print('Ctrl+C to stop. AI requires preview approval. No rule deployment runner.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
