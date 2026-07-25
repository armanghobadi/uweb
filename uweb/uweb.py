"""
UWeb - Ultra Web Framework for MicroPython
Version 1.1.0 - Final Production Ready (Fully Corrected)
Fixed: path routing (multi-segment), multipart parser, memory, rate-limit, static/media, robustness
"""

import uasyncio as asyncio
import ujson as json
import uhashlib as hashlib
import urandom as random
import time
import re
import gc
import machine
import ubinascii
import sys
import os

# ============================================
# MEMORY OPTIMIZATION
# ============================================
gc.collect()
gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())

import micropython
micropython.alloc_emergency_exception_buf(256)

# ============================================
# CONSTANTS
# ============================================
VERSION = "1.1.0"
DEFAULT_RATE_LIMIT = 100
DEFAULT_TOKEN_EXPIRY = 3600
DEFAULT_REFRESH_EXPIRY = 86400
MAX_REQUEST_SIZE = 512 * 1024
MAX_WS_MESSAGE_SIZE = 8192
MAX_CACHE_SIZE = 40
CHUNK_SIZE = 8192
MAX_UPLOAD_SIZE = 256 * 1024

# ============================================
# SIMPLE DEFAULTDICT
# ============================================
class DefaultDict:
    __slots__ = ('data', 'default_factory')

    def __init__(self, default_factory):
        self.data = {}
        self.default_factory = default_factory

    def __getitem__(self, key):
        try:
            return self.data[key]
        except KeyError:
            val = self.default_factory()
            self.data[key] = val
            return val

    def __setitem__(self, key, value):
        self.data[key] = value

    def __contains__(self, key):
        return key in self.data

    def get(self, key, default=None):
        return self.data.get(key, default)

    def items(self):
        return self.data.items()

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def pop(self, key, default=None):
        return self.data.pop(key, default)

    def clear(self):
        self.data.clear()

# ============================================
# VALIDATOR
# ============================================
class Validator:
    __slots__ = ()

    SQL_PATTERNS = (
        'select', 'insert', 'update', 'delete', 'drop', 'union',
        'exec', 'eval', 'system', 'xp_', '--', ';', ' or ', ' and '
    )
    XSS_PATTERNS = (
        '<script', 'javascript:', 'onerror', 'onclick',
        'onload', 'onmouseover', 'onfocus', 'onchange'
    )

    @staticmethod
    def string(value, max_len=1000, min_len=1, pattern=None, required=True):
        if not required and value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Must be string")
        value = value.strip()
        if len(value) < min_len:
            raise ValueError("Minimum length " + str(min_len))
        if len(value) > max_len:
            raise ValueError("Maximum length " + str(max_len))
        value_lower = value.lower()
        for p in Validator.SQL_PATTERNS:
            if p in value_lower:
                raise ValueError("SQL injection pattern detected")
        for p in Validator.XSS_PATTERNS:
            if p in value_lower:
                raise ValueError("XSS pattern detected")
        if pattern:
            try:
                if not re.match(pattern, value):
                    raise ValueError("Invalid format")
            except Exception:
                pass
        for char, escaped in (
            ('&', '&amp;'), ('<', '&lt;'), ('>', '&gt;'),
            ('"', '&quot;'), ("'", '&#x27;'), ('/', '&#x2F;'),
            ('`', '&#x60;'), ('=', '&#x3D;')
        ):
            value = value.replace(char, escaped)
        return value

    @staticmethod
    def integer(value, min_val=None, max_val=None, required=True):
        if not required and value is None:
            return None
        try:
            v = int(value)
            if min_val is not None and v < min_val:
                raise ValueError("Minimum " + str(min_val))
            if max_val is not None and v > max_val:
                raise ValueError("Maximum " + str(max_val))
            return v
        except Exception:
            raise ValueError("Invalid integer")

    @staticmethod
    def email(value, required=True):
        if not required and value is None:
            return None
        value = Validator.string(value, max_len=100, required=required)
        if value and '@' in value and '.' in value:
            parts = value.split('@')
            if len(parts) == 2 and parts[0] and parts[1]:
                return value
        raise ValueError("Invalid email")

    @staticmethod
    def boolean(value, required=True):
        if not required and value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on', 'y')
        return bool(value)

    @staticmethod
    def filename(value, allowed_extensions=None):
        value = Validator.string(value, max_len=255)
        value = value.replace('../', '').replace('..\\', '').replace('/', '').replace('\\', '')
        allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-'
        filtered = ''.join(c for c in value if c in allowed)
        if not filtered:
            raise ValueError("Invalid filename")
        if allowed_extensions:
            ext = filtered.split('.')[-1].lower() if '.' in filtered else ''
            if ext not in [e.lower() for e in allowed_extensions]:
                raise ValueError("Extension not allowed: " + ext)
        return filtered

    @staticmethod
    def path(value):
        if not isinstance(value, str):
            value = str(value)
        value = value.replace('../', '').replace('..\\', '')
        allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-'
        cleaned = ''.join(c for c in value if c in allowed)
        # prevent absolute or empty dangerous paths
        while '//' in cleaned:
            cleaned = cleaned.replace('//', '/')
        return cleaned.lstrip('/')

    @staticmethod
    def json(data, schema=None):
        if schema is None:
            return data
        if not isinstance(data, dict):
            raise ValueError("Expected object")
        for key, rules in schema.items():
            if key not in data:
                if rules.get('required', False):
                    raise ValueError("Missing field: " + key)
                continue
            val = data[key]
            t = rules.get('type')
            if t == 'str' and not isinstance(val, str):
                raise ValueError(key + " must be string")
            if t == 'int' and not isinstance(val, int):
                raise ValueError(key + " must be int")
            if t == 'bool' and not isinstance(val, bool):
                raise ValueError(key + " must be bool")
            if 'max_len' in rules and isinstance(val, str) and len(val) > rules['max_len']:
                raise ValueError(key + " too long")
        return data

# ============================================
# AUTH
# ============================================
class Auth:
    __slots__ = ('secret_key', 'token_expiry', 'refresh_expiry',
                 'blacklist', 'sessions')

    def __init__(self, secret_key, token_expiry=DEFAULT_TOKEN_EXPIRY,
                 refresh_expiry=DEFAULT_REFRESH_EXPIRY):
        self.secret_key = secret_key
        self.token_expiry = token_expiry
        self.refresh_expiry = refresh_expiry
        self.blacklist = {}
        self.sessions = {}

    def generate_token(self, user_id, extra_data=None):
        timestamp = int(time.time())
        expiry = timestamp + self.token_expiry
        payload = {
            'user_id': user_id,
            'exp': expiry,
            'iat': timestamp,
            'data': extra_data or {},
            'jti': self._generate_jti()
        }
        payload_json = json.dumps(payload)
        signature = self._sign(payload_json)
        token = ubinascii.b2a_base64(payload_json.encode()).decode().strip() + '.' + signature
        return token

    def generate_refresh_token(self, user_id):
        timestamp = int(time.time())
        expiry = timestamp + self.refresh_expiry
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': expiry,
            'iat': timestamp,
            'jti': self._generate_jti()
        }
        payload_json = json.dumps(payload)
        signature = self._sign(payload_json)
        token = ubinascii.b2a_base64(payload_json.encode()).decode().strip() + '.' + signature
        return token

    def verify_token(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None
            payload_json = ubinascii.a2b_base64(parts[0]).decode()
            signature = parts[1]
            if signature != self._sign(payload_json):
                return None
            payload = json.loads(payload_json)
            if payload.get('exp', 0) < int(time.time()):
                return None
            jti = payload.get('jti')
            if jti and jti in self.blacklist:
                if self.blacklist[jti] > int(time.time()):
                    return None
                else:
                    del self.blacklist[jti]
            return payload
        except Exception:
            return None

    def verify_refresh_token(self, token):
        payload = self.verify_token(token)
        if payload and payload.get('type') == 'refresh':
            return payload.get('user_id')
        return None

    def refresh_access_token(self, refresh_token):
        user_id = self.verify_refresh_token(refresh_token)
        if user_id:
            return self.generate_token(user_id)
        return None

    def revoke_token(self, token, expiry=3600):
        try:
            parts = token.split('.')
            if len(parts) == 2:
                payload_json = ubinascii.a2b_base64(parts[0]).decode()
                payload = json.loads(payload_json)
                jti = payload.get('jti')
                if jti:
                    self.blacklist[jti] = int(time.time()) + expiry
                    if len(self.blacklist) > 80:
                        self._cleanup_blacklist()
                    return True
        except Exception:
            pass
        return False

    def create_session(self, user_id, session_data=None):
        session_id = self._generate_session_id()
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': int(time.time()),
            'expiry': int(time.time()) + self.token_expiry,
            'data': session_data or {}
        }
        return session_id

    def get_session(self, session_id):
        session = self.sessions.get(session_id)
        if session and session['expiry'] > int(time.time()):
            return session
        if session:
            del self.sessions[session_id]
        return None

    def update_session(self, session_id, session_data):
        session = self.get_session(session_id)
        if session:
            session['data'].update(session_data)
            self.sessions[session_id] = session
            return True
        return False

    def delete_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

    def _sign(self, data):
        return hashlib.sha256((data + self.secret_key).encode()).hexdigest()[:32]

    def _generate_session_id(self):
        return ubinascii.b2a_base64(
            random.getrandbits(128).to_bytes(16, 'little')
        ).decode().strip()

    def _generate_jti(self):
        return ubinascii.b2a_base64(
            random.getrandbits(64).to_bytes(8, 'little')
        ).decode().strip()

    def _cleanup_blacklist(self):
        current = int(time.time())
        to_del = [jti for jti, exp in self.blacklist.items() if exp < current]
        for jti in to_del:
            del self.blacklist[jti]

# ============================================
# FILE SYSTEM MANAGER
# ============================================
class FileSystemManager:
    __slots__ = ('templates_dir', 'static_dir', 'media_dir',
                 'cache', 'cache_time', 'cache_size', 'cache_duration')

    def __init__(self, templates_dir='templates', static_dir='static', media_dir='media'):
        self.templates_dir = templates_dir.rstrip('/')
        self.static_dir = static_dir.rstrip('/')
        self.media_dir = media_dir.rstrip('/')
        self.cache = {}
        self.cache_time = {}
        self.cache_size = 0
        self.cache_duration = 300
        self._init_directories()

    def _init_directories(self):
        for d in (self.templates_dir, self.static_dir, self.media_dir):
            try:
                os.mkdir(d)
            except OSError:
                pass

    def _get_mime_type(self, filename):
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        return {
            'html': 'text/html', 'css': 'text/css', 'js': 'application/javascript',
            'json': 'application/json', 'png': 'image/png', 'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg', 'gif': 'image/gif', 'svg': 'image/svg+xml',
            'ico': 'image/x-icon', 'txt': 'text/plain', 'pdf': 'application/pdf',
            'mp4': 'video/mp4', 'webm': 'video/webm', 'mp3': 'audio/mpeg',
            'wav': 'audio/wav', 'woff': 'font/woff', 'woff2': 'font/woff2',
            'ttf': 'font/ttf', 'eot': 'font/eot'
        }.get(ext, 'application/octet-stream')

    def _get_cache_key(self, path, dir_type):
        return dir_type + ':' + path

    def _cache_get(self, key):
        if key in self.cache:
            if time.time() - self.cache_time.get(key, 0) < self.cache_duration:
                return self.cache[key]
            del self.cache[key]
            self.cache_time.pop(key, None)
            self.cache_size -= 1
        return None

    def _cache_put(self, key, data):
        if self.cache_size >= MAX_CACHE_SIZE:
            oldest_key = min(self.cache_time, key=self.cache_time.get) if self.cache_time else None
            if oldest_key:
                del self.cache[oldest_key]
                self.cache_time.pop(oldest_key, None)
                self.cache_size -= 1
        self.cache[key] = data
        self.cache_time[key] = time.time()
        self.cache_size += 1

    def read_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except OSError:
            return None

    def write_file(self, filepath, data):
        try:
            temp = filepath + '.tmp'
            with open(temp, 'wb') as f:
                f.write(data)
            os.rename(temp, filepath)
            return True
        except OSError:
            try:
                os.remove(temp)
            except Exception:
                pass
            return False

    def delete_file(self, filepath):
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False

    def file_exists(self, filepath):
        try:
            os.stat(filepath)
            return True
        except OSError:
            return False

    def get_file_info(self, filepath):
        try:
            st = os.stat(filepath)
            return {'size': st[6], 'modified': st[8], 'created': st[9]}
        except OSError:
            return None

    def list_directory(self, dirpath, pattern=None):
        try:
            files = []
            for item in os.listdir(dirpath):
                full = dirpath + '/' + item
                try:
                    st = os.stat(full)
                    is_dir = bool(st[0] & 0x4000)
                    files.append({
                        'name': item,
                        'path': full,
                        'is_dir': is_dir,
                        'size': 0 if is_dir else st[6],
                        'modified': st[8]
                    })
                except Exception:
                    pass
            if pattern:
                files = [f for f in files if pattern.lower() in f['name'].lower()]
            files.sort(key=lambda x: (0 if x['is_dir'] else 1, x['name']))
            return files
        except OSError:
            return []

    def get_template(self, name):
        key = self._get_cache_key(name, 'template')
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        content = self.read_file(self.templates_dir + '/' + name)
        if content:
            self._cache_put(key, content)
        return content

    def render_template(self, name, context=None):
        content = self.get_template(name)
        if not content:
            return None
        if context:
            for k, v in context.items():
                placeholder = b'{{' + k.encode() + b'}}'
                if isinstance(v, bool):
                    content = content.replace(placeholder, b'true' if v else b'false')
                else:
                    content = content.replace(placeholder, str(v).encode())
        return content

    def get_static(self, path):
        path = Validator.path(path)
        if not path:
            return None
        key = self._get_cache_key(path, 'static')
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        content = self.read_file(self.static_dir + '/' + path)
        if content:
            self._cache_put(key, content)
        return content

    def get_media(self, path):
        path = Validator.path(path)
        if not path:
            return None
        return self.read_file(self.media_dir + '/' + path)

    def upload_media(self, filename, data):
        if len(data) > MAX_UPLOAD_SIZE:
            return False
        filename = Validator.filename(filename)
        return self.write_file(self.media_dir + '/' + filename, data)

    def delete_media(self, filename):
        filename = Validator.filename(filename)
        return self.delete_file(self.media_dir + '/' + filename)

    def serve_file(self, path, dir_type='static'):
        if dir_type == 'template':
            content = self.get_template(path)
        elif dir_type == 'static':
            content = self.get_static(path)
        elif dir_type == 'media':
            content = self.get_media(path)
        else:
            return None, None
        if content:
            return content, self._get_mime_type(path)
        return None, None

# ============================================
# REQUEST
# ============================================
class Request:
    __slots__ = ('reader', 'headers', 'method', 'path', 'query_params',
                 'body', '_json_data', '_form_data', 'client_ip',
                 'user_agent', 'request_time', 'user', 'files')

    def __init__(self, reader, headers, method, path, query_params, body):
        self.reader = reader
        self.headers = headers
        self.method = method
        self.path = path
        self.query_params = query_params
        self.body = body
        self._json_data = None
        self._form_data = None
        self.client_ip = None
        self.user_agent = headers.get('user-agent', 'unknown')
        self.request_time = time.time()
        self.user = None
        self.files = {}

    def json(self, schema=None):
        if self._json_data is None:
            try:
                raw = self.body
                if isinstance(raw, bytes):
                    raw = raw.decode()
                self._json_data = json.loads(raw) if raw else {}
            except Exception:
                raise ValueError("Invalid JSON")
        if schema:
            return Validator.json(self._json_data, schema)
        return self._json_data

    def form(self, schema=None):
        if self._form_data is None:
            self._form_data = {}
            content_type = self.headers.get('content-type', '')
            if self.body:
                if 'application/x-www-form-urlencoded' in content_type:
                    body_str = self.body if isinstance(self.body, str) else self.body.decode()
                    for pair in body_str.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            self._form_data[k] = v
                elif 'multipart/form-data' in content_type:
                    self._parse_multipart(content_type)
        if schema:
            return Validator.json(self._form_data, schema)
        return self._form_data

    def _parse_multipart(self, content_type):
        try:
            if 'boundary=' not in content_type:
                return
            boundary = content_type.split('boundary=')[1].strip().strip('"')
            if not boundary:
                return
            boundary_bytes = ('--' + boundary).encode()
            data = self.body if isinstance(self.body, bytes) else self.body.encode()
            if len(data) > MAX_UPLOAD_SIZE:
                return
            parts = data.split(boundary_bytes)
            for part in parts:
                if not part or part in (b'--', b'--\r\n', b'\r\n', b'--\r\n--'):
                    continue
                if part.startswith(b'\r\n'):
                    part = part[2:]
                if part.endswith(b'\r\n'):
                    part = part[:-2]
                if part.endswith(b'--'):
                    part = part[:-2]
                headers_end = part.find(b'\r\n\r\n')
                if headers_end == -1:
                    continue
                headers_str = part[:headers_end].decode('utf-8', 'ignore')
                content = part[headers_end + 4:]
                if content.endswith(b'\r\n'):
                    content = content[:-2]
                name = None
                filename = None
                for line in headers_str.split('\r\n'):
                    line_lower = line.lower()
                    if 'content-disposition' in line_lower:
                        if 'name="' in line:
                            ns = line.find('name="') + 6
                            ne = line.find('"', ns)
                            if ne > ns:
                                name = line[ns:ne]
                        if 'filename="' in line:
                            fs = line.find('filename="') + 10
                            fe = line.find('"', fs)
                            if fe > fs:
                                filename = line[fs:fe]
                if not name:
                    continue
                if filename:
                    self.files[name] = {
                        'filename': filename,
                        'data': content,
                        'size': len(content)
                    }
                else:
                    try:
                        self._form_data[name] = content.decode().strip()
                    except Exception:
                        self._form_data[name] = content
        except Exception:
            pass

    def query(self, key, default=None, validator=None):
        value = self.query_params.get(key, default)
        if validator and value is not None:
            return validator(value)
        return value

    def header(self, key, default=None):
        return self.headers.get(key.lower(), default)

    def file(self, name):
        return self.files.get(name)

    def validate(self, schema):
        ct = self.headers.get('content-type', '')
        if 'application/json' in ct:
            return self.json(schema)
        return self.form(schema)

# ============================================
# RESPONSE
# ============================================
class Response:
    __slots__ = ('body', 'status', 'headers', 'content_type',
                 'cookies', 'cors_headers', 'is_stream')

    def __init__(self, body="", status=200, headers=None,
                 content_type="text/plain", is_stream=False):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.content_type = content_type
        self.cookies = []
        self.cors_headers = {}
        self.is_stream = is_stream

    def set_cookie(self, name, value, max_age=3600, http_only=True,
                   secure=False, path='/'):
        cookie = name + "=" + value + "; Path=" + path
        if max_age:
            cookie += "; Max-Age=" + str(max_age)
        if http_only:
            cookie += "; HttpOnly"
        if secure:
            cookie += "; Secure"
        cookie += "; SameSite=Strict"
        self.cookies.append(cookie)
        return self

    def delete_cookie(self, name):
        self.cookies.append(name + "=; Path=/; Max-Age=0; HttpOnly")
        return self

    def to_bytes(self):
        status_line = "HTTP/1.1 " + str(self.status) + " " + self._get_status_message() + "\r\n"
        headers = []

        if self.is_stream:
            headers.append("Transfer-Encoding: chunked")
        else:
            headers.append("Content-Type: " + self.content_type)
            if isinstance(self.body, bytes):
                headers.append("Content-Length: " + str(len(self.body)))
            else:
                body_str = str(self.body)
                headers.append("Content-Length: " + str(len(body_str)))
                self.body = body_str

        for cookie in self.cookies:
            headers.append("Set-Cookie: " + cookie)

        for k, v in self.headers.items():
            headers.append(k + ": " + v)

        headers.extend([
            "X-Frame-Options: DENY",
            "X-Content-Type-Options: nosniff",
            "X-XSS-Protection: 1; mode=block",
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Cache-Control: no-store, no-cache, must-revalidate",
            "Pragma: no-cache"
        ])

        for k, v in self.cors_headers.items():
            headers.append("Access-Control-" + k + ": " + v)

        response = status_line + "\r\n".join(headers) + "\r\n\r\n"

        if self.is_stream:
            return response.encode()
        if isinstance(self.body, bytes):
            return response.encode() + self.body
        return response.encode() + str(self.body).encode()

    def _get_status_message(self):
        return {
            200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
            301: "Moved Permanently", 302: "Found",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
            413: "Payload Too Large", 429: "Too Many Requests",
            500: "Internal Server Error", 503: "Service Unavailable"
        }.get(self.status, "Unknown")

# ============================================
# WEBSOCKET MANAGER
# ============================================
class WebSocketManager:
    __slots__ = ('connections', 'rooms', 'max_connections', 'heartbeat_interval')

    def __init__(self, max_connections=50):
        self.connections = {}
        self.rooms = DefaultDict(set)
        self.max_connections = max_connections
        self.heartbeat_interval = 30

    def add(self, client_id, websocket, room=None):
        if len(self.connections) >= self.max_connections:
            return False
        self.connections[client_id] = {
            'ws': websocket,
            'room': room,
            'connected_at': time.time(),
            'last_ping': time.time(),
            'last_pong': time.time()
        }
        if room:
            self.rooms[room].add(client_id)
        return True

    def remove(self, client_id):
        if client_id in self.connections:
            room = self.connections[client_id].get('room')
            if room and client_id in self.rooms[room]:
                self.rooms[room].remove(client_id)
                if not self.rooms[room]:
                    del self.rooms[room]
            del self.connections[client_id]

    def get_client(self, client_id):
        return self.connections.get(client_id)

    async def send(self, client_id, message):
        client = self.get_client(client_id)
        if client:
            try:
                await client['ws'].send(message)
                return True
            except Exception:
                self.remove(client_id)
        return False

    async def broadcast(self, room, message, exclude=None):
        if room not in self.rooms:
            return
        for cid in list(self.rooms[room]):
            if exclude and cid == exclude:
                continue
            await self.send(cid, message)

    def get_room_clients(self, room):
        return list(self.rooms.get(room, set()))

    def get_client_count(self):
        return len(self.connections)

    async def heartbeat(self):
        now = time.time()
        to_remove = []
        for cid, client in list(self.connections.items()):
            if now - client['last_pong'] > self.heartbeat_interval * 2.5:
                to_remove.append(cid)
            elif now - client['last_ping'] > self.heartbeat_interval:
                try:
                    await client['ws'].ping()
                    client['last_ping'] = now
                except Exception:
                    to_remove.append(cid)
        for cid in to_remove:
            self.remove(cid)

# ============================================
# WEBSOCKET
# ============================================
class WebSocket:
    __slots__ = ('req', 'reader', 'writer', 'connected', 'client_id')

    def __init__(self, req, reader, writer):
        self.req = req
        self.reader = reader
        self.writer = writer
        self.connected = True
        self.client_id = None

    async def send(self, message):
        if not self.connected:
            return False
        try:
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            if isinstance(message, str):
                message = message.encode()
            length = len(message)
            frame = b'\x81'
            if length <= 125:
                frame += bytes([length])
            elif length <= 65535:
                frame += b'\x7e' + length.to_bytes(2, 'big')
            else:
                frame += b'\x7f' + length.to_bytes(8, 'big')
            frame += message
            self.writer.write(frame)
            await self.writer.drain()
            return True
        except Exception:
            self.connected = False
            return False

    async def receive(self):
        if not self.connected:
            return None
        try:
            header = await self.reader.read(2)
            if not header or len(header) < 2:
                self.connected = False
                return None

            opcode = header[0] & 0x0F
            mask = header[1] & 0x80
            length = header[1] & 0x7F

            if opcode == 0x08:  # close
                self.connected = False
                return None
            if opcode == 0x0A:  # pong
                return {'type': 'pong'}
            if opcode == 0x09:  # ping
                await self.pong()
                return {'type': 'ping'}

            if length == 126:
                length = int.from_bytes(await self.reader.read(2), 'big')
            elif length == 127:
                length = int.from_bytes(await self.reader.read(8), 'big')

            if length > MAX_WS_MESSAGE_SIZE:
                self.connected = False
                return None

            if mask:
                mask_key = await self.reader.read(4)
                data = await self.reader.read(length)
                if len(data) < length:
                    self.connected = False
                    return None
                message = bytes(data[i] ^ mask_key[i % 4] for i in range(length))
            else:
                message = await self.reader.read(length)

            if message:
                try:
                    return message.decode()
                except Exception:
                    return message
            return None
        except Exception:
            self.connected = False
            return None

    async def ping(self):
        if self.connected:
            try:
                self.writer.write(b'\x89\x00')
                await self.writer.drain()
            except Exception:
                self.connected = False

    async def pong(self):
        if self.connected:
            try:
                self.writer.write(b'\x8a\x00')
                await self.writer.drain()
            except Exception:
                self.connected = False

    async def close(self, code=1000, reason=""):
        if self.connected:
            try:
                reason_bytes = reason.encode()[:123]
                payload = code.to_bytes(2, 'big') + reason_bytes
                length = len(payload)
                frame = b'\x88'
                if length <= 125:
                    frame += bytes([length])
                else:
                    frame += b'\x7e' + length.to_bytes(2, 'big')
                frame += payload
                self.writer.write(frame)
                await self.writer.drain()
            except Exception:
                pass
            self.connected = False

# ============================================
# MAIN APPLICATION
# ============================================
class UWeb:
    def __init__(self, secret_key=None, rate_limit=DEFAULT_RATE_LIMIT,
                 templates_dir='templates', static_dir='static',
                 media_dir='media', debug=False):

        self.routes = {
            'GET': {}, 'POST': {}, 'PUT': {}, 'DELETE': {},
            'PATCH': {}, 'OPTIONS': {}, 'HEAD': {}, 'WS': {}
        }
        self.middlewares = []
        self.websocket_handlers = {}
        self.ws_manager = WebSocketManager()

        self.secret_key = secret_key or self._generate_secret_key()
        self.auth = Auth(self.secret_key)
        self.rate_limit = rate_limit
        self.request_count = DefaultDict(int)
        self.request_timestamp = DefaultDict(int)
        self.blacklisted_ips = set()

        self.fs = FileSystemManager(templates_dir, static_dir, media_dir)
        self.debug = debug
        self.max_request_size = MAX_REQUEST_SIZE
        self.response_headers = {}

        self.security_headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache'
        }

        self.cors_enabled = False
        self.cors_allowed_origins = ['*']
        self.cors_allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        self.cors_allowed_headers = ['Content-Type', 'Authorization', 'X-API-Key']

        self._register_static_routes()

    def _generate_secret_key(self):
        entropy = str(sys.implementation) + str(machine.unique_id()) + str(time.time_ns())
        return hashlib.sha256(entropy.encode()).hexdigest()

    def _register_static_routes(self):
        @self.route('/static/<path:path>', methods=['GET', 'HEAD'])
        def serve_static_route(req, path):
            content, mime = self.fs.serve_file(path, 'static')
            if content is None:
                return self.error(404, "Static file not found")
            return Response(content, 200, content_type=mime)

        @self.route('/media/<path:path>', methods=['GET', 'HEAD'])
        def serve_media_route(req, path):
            content, mime = self.fs.serve_file(path, 'media')
            if content is None:
                return self.error(404, "Media file not found")
            return Response(content, 200, content_type=mime)

        @self.route('/assets/<path:path>', methods=['GET', 'HEAD'])
        def serve_assets_route(req, path):
            content, mime = self.fs.serve_file(path, 'static')
            if content is None:
                return self.error(404, "Asset not found")
            return Response(content, 200, content_type=mime)

    def route(self, path, methods=None):
        if methods is None:
            methods = ['GET']
        def decorator(handler):
            for method in methods:
                if method == 'WS':
                    self.websocket_handlers[path] = handler
                else:
                    self.routes[method][path] = handler
            return handler
        return decorator

    def get(self, path):
        return self.route(path, ['GET'])

    def post(self, path):
        return self.route(path, ['POST'])

    def put(self, path):
        return self.route(path, ['PUT'])

    def delete(self, path):
        return self.route(path, ['DELETE'])

    def patch(self, path):
        return self.route(path, ['PATCH'])

    def ws(self, path):
        return self.route(path, ['WS'])

    def use(self, middleware):
        self.middlewares.append(middleware)
        return self

    def enable_cors(self, origins=None, methods=None, headers=None):
        self.cors_enabled = True
        if origins:
            self.cors_allowed_origins = origins if isinstance(origins, list) else [origins]
        if methods:
            self.cors_allowed_methods = methods if isinstance(methods, list) else [methods]
        if headers:
            self.cors_allowed_headers = headers if isinstance(headers, list) else [headers]
        return self

    def require_auth(self, req):
        token = req.header('Authorization', '')
        if token.startswith('Bearer '):
            token = token[7:]
        if not token:
            return self.error(401, "Authentication required")
        payload = self.auth.verify_token(token)
        if not payload:
            return self.error(401, "Invalid or expired token")
        req.user = payload
        return True

    def require_role(self, req, roles):
        result = self.require_auth(req)
        if isinstance(result, Response):
            return result
        user_roles = req.user.get('data', {}).get('roles', [])
        if not any(r in user_roles for r in roles):
            return self.error(403, "Insufficient permissions")
        return True

    def login(self, user_id, extra_data=None, create_session=True):
        access = self.auth.generate_token(user_id, extra_data)
        refresh = self.auth.generate_refresh_token(user_id)
        data = {
            'access_token': access,
            'refresh_token': refresh,
            'token_type': 'Bearer',
            'expires_in': self.auth.token_expiry,
            'user_id': user_id
        }
        if create_session:
            data['session_id'] = self.auth.create_session(user_id, extra_data)
        return data

    def logout(self, token=None, session_id=None):
        if token:
            self.auth.revoke_token(token)
        if session_id:
            self.auth.delete_session(session_id)
        return True

    def refresh_token(self, refresh_token):
        return self.auth.refresh_access_token(refresh_token)

    def _check_rate_limit(self, client_id):
        current_minute = int(time.time() // 60)
        key = client_id + ":" + str(current_minute)

        if len(self.request_count) > 150:
            cutoff = current_minute - 8
            to_del = [k for k, ts in self.request_timestamp.items() if ts < cutoff]
            for k in to_del:
                self.request_count.pop(k, None)
                self.request_timestamp.pop(k, None)

        if key not in self.request_count:
            self.request_count[key] = 0
            self.request_timestamp[key] = current_minute

        if self.request_count[key] >= self.rate_limit:
            return False
        self.request_count[key] += 1
        return True

    def json(self, data, status=200, headers=None):
        return Response(json.dumps(data), status, headers, "application/json")

    def html(self, content, status=200, headers=None):
        return Response(content, status, headers, "text/html")

    def text(self, content, status=200, headers=None):
        return Response(content, status, headers, "text/plain")

    def file(self, content, filename=None, status=200, headers=None):
        h = headers or {}
        if filename:
            h['Content-Disposition'] = 'attachment; filename="' + filename + '"'
        return Response(content, status, h, "application/octet-stream")

    def redirect(self, url, status=302):
        return Response("", status, {"Location": url}, "text/plain")

    def error(self, status, message="Error"):
        return Response(
            json.dumps({"error": message, "status": status}),
            status, content_type="application/json"
        )

    def render_template(self, name, context=None, status=200):
        content = self.fs.render_template(name, context)
        if content is None:
            return self.error(404, "Template not found")
        return self.html(content, status)

    def serve_static(self, path):
        content, mime = self.fs.serve_file(path, 'static')
        if content is None:
            return None
        return Response(content, 200, content_type=mime)

    def serve_media(self, path):
        content, mime = self.fs.serve_file(path, 'media')
        if content is None:
            return None
        return Response(content, 200, content_type=mime)

    def upload_media(self, filename, data):
        return self.fs.upload_media(filename, data)

    def delete_media(self, filename):
        return self.fs.delete_media(filename)

    def list_media(self, pattern=None):
        return self.fs.list_directory(self.fs.media_dir, pattern)

    def _parse_request(self, data):
        try:
            if isinstance(data, bytes):
                sep = data.find(b'\r\n\r\n')
                if sep == -1:
                    header_part = data.decode('utf-8', 'ignore')
                    body = b''
                else:
                    header_part = data[:sep].decode('utf-8', 'ignore')
                    body = data[sep + 4:]
            else:
                header_part = data
                body = ''

            lines = header_part.split('\r\n')
            if not lines:
                return None

            parts = lines[0].split(' ')
            if len(parts) < 3:
                return None
            method, path, version = parts[0], parts[1], parts[2]

            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.lower().strip()] = v.strip()

            query_params = {}
            if '?' in path:
                path, qs = path.split('?', 1)
                for pair in qs.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        query_params[k] = v

            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body,
                'query_params': query_params
            }
        except Exception:
            return None

    def _match_route(self, method, path):
        routes = self.routes.get(method, {})

        # Exact match
        if path in routes:
            return routes[path], {}

        path_parts = path.strip('/').split('/') if path != '/' else []
        if path == '/':
            path_parts = []

        for route_path, handler in routes.items():
            route_parts = route_path.strip('/').split('/') if route_path != '/' else []
            if route_path == '/':
                route_parts = []

            params = {}
            matched = True
            i = 0
            j = 0

            while i < len(route_parts) and j < len(path_parts):
                part = route_parts[i]
                if part.startswith('<') and part.endswith('>'):
                    inner = part[1:-1]
                    if ':' in inner:
                        pname, ptype = inner.split(':', 1)
                    else:
                        pname, ptype = inner, 'str'

                    if ptype == 'path':
                        # catch remaining path
                        remaining = '/'.join(path_parts[j:])
                        try:
                            params[pname] = Validator.path(remaining)
                        except Exception:
                            matched = False
                            break
                        j = len(path_parts)
                        i += 1
                        break
                    else:
                        try:
                            if ptype == 'int':
                                params[pname] = Validator.integer(path_parts[j])
                            elif ptype == 'float':
                                params[pname] = float(path_parts[j])
                            else:
                                params[pname] = Validator.string(path_parts[j], max_len=200)
                        except Exception:
                            matched = False
                            break
                        i += 1
                        j += 1
                else:
                    if part != path_parts[j]:
                        matched = False
                        break
                    i += 1
                    j += 1

            if matched and i == len(route_parts) and j == len(path_parts):
                return handler, params

            # special case: path param at end consumed everything
            if matched and i == len(route_parts) and 'path' in str(route_parts):
                return handler, params

        return None, {}

    def _get_cors_headers(self, req):
        origin = req.header('Origin', '')
        allowed = '*'
        if '*' not in self.cors_allowed_origins:
            allowed = origin if origin in self.cors_allowed_origins else ''
        return {
            'Allow-Origin': allowed,
            'Allow-Methods': ', '.join(self.cors_allowed_methods),
            'Allow-Headers': ', '.join(self.cors_allowed_headers),
            'Expose-Headers': 'Authorization, Content-Type',
            'Max-Age': '86400'
        }

    async def _send_response(self, writer, response):
        try:
            for k, v in self.security_headers.items():
                if k not in response.headers:
                    response.headers[k] = v
            for k, v in self.response_headers.items():
                if k not in response.headers:
                    response.headers[k] = v
            writer.write(response.to_bytes())
            await writer.drain()
        except Exception as e:
            if self.debug:
                print("Error sending response:", e)

    async def _handle_request(self, reader, writer):
        try:
            data = await reader.read(self.max_request_size)
            if not data:
                await writer.aclose()
                return

            request_data = self._parse_request(data)
            if not request_data:
                await self._send_response(writer, self.error(400, "Invalid request"))
                return

            method = request_data['method']
            path = request_data['path']
            headers = request_data['headers']
            body = request_data['body']
            query_params = request_data['query_params']

            client_ip = '0.0.0.0'
            try:
                peer = writer.get_extra_info('peername')
                if peer and isinstance(peer, tuple):
                    client_ip = peer[0]
                else:
                    client_ip = headers.get('x-forwarded-for', '').split(',')[0].strip() or \
                                headers.get('x-real-ip', '0.0.0.0')
            except Exception:
                pass

            if client_ip in self.blacklisted_ips:
                await self._send_response(writer, self.error(403, "IP blocked"))
                return

            if not self._check_rate_limit(client_ip):
                await self._send_response(writer, self.error(429, "Rate limit exceeded"))
                return

            req = Request(reader, headers, method, path, query_params, body)
            req.client_ip = client_ip

            if method == 'GET' and headers.get('upgrade', '').lower() == 'websocket':
                await self._handle_websocket(reader, writer, req)
                return

            if method == 'OPTIONS' and self.cors_enabled:
                response = Response(status=204)
                for k, v in self._get_cors_headers(req).items():
                    response.cors_headers[k] = v
                await self._send_response(writer, response)
                return

            handler, params = self._match_route(method, path)
            if not handler:
                await self._send_response(writer, self.error(404, "Not found"))
                return

            for mw in self.middlewares:
                result = mw(req, self)
                if isinstance(result, Response):
                    await self._send_response(writer, result)
                    return

            try:
                result = handler(req, **params)
                if isinstance(result, Response):
                    response = result
                else:
                    response = self.json(result)
            except Exception as e:
                if self.debug:
                    sys.print_exception(e)
                    response = self.error(500, str(e))
                else:
                    response = self.error(500, "Internal server error")

            if self.cors_enabled:
                for k, v in self._get_cors_headers(req).items():
                    response.cors_headers[k] = v

            await self._send_response(writer, response)

        except Exception as e:
            if self.debug:
                print("Error:", e)
                sys.print_exception(e)
            try:
                await self._send_response(writer, self.error(500, "Internal server error"))
            except Exception:
                pass
        finally:
            try:
                await writer.aclose()
            except Exception:
                pass
            gc.collect()

    async def _handle_websocket(self, reader, writer, req):
        handler = self.websocket_handlers.get(req.path)
        if not handler:
            await self._send_response(writer, self.error(404, "WebSocket endpoint not found"))
            return

        key = req.header('sec-websocket-key')
        if not key:
            await self._send_response(writer, self.error(400, "Missing WebSocket key"))
            return

        accept = ubinascii.b2a_base64(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode().strip()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
        )
        writer.write(response.encode())
        await writer.drain()

        ws = WebSocket(req, reader, writer)
        client_id = req.client_ip + ":" + str(time.time_ns())
        ws.client_id = client_id

        if not self.ws_manager.add(client_id, ws):
            await ws.close()
            return

        try:
            await handler(ws, req)
        except Exception as e:
            if self.debug:
                print("WebSocket error:", e)
        finally:
            self.ws_manager.remove(client_id)
            try:
                await ws.close()
            except Exception:
                pass

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(30)
            await self.ws_manager.heartbeat()
            gc.collect()

    async def run(self, host="0.0.0.0", port=80, backlog=8):
        print("\n" + "=" * 60)
        print("UWeb v" + VERSION + " - Final Production Ready")
        print("=" * 60)
        print("http://" + host + ":" + str(port))
        print("Static  → /static/<path>")
        print("Media   → /media/<path>")
        print("Assets  → /assets/<path>")
        print("Rate Limit:", self.rate_limit, "req/min")
        print("CORS:", "Enabled" if self.cors_enabled else "Disabled")
        print("=" * 60 + "\n")

        asyncio.create_task(self._heartbeat_loop())
        server = await asyncio.start_server(
            self._handle_request, host, port, backlog=backlog
        )
        await server.wait_closed()
