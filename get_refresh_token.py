#!/usr/bin/env python3
"""
Microsoft OAuth2认证脚本
用于获取Microsoft的access_token和refresh_token
支持使用系统浏览器或无浏览器模式
"""

import requests
import webbrowser
import logging
import configparser
import time
from datetime import datetime
import base64
import hashlib
import secrets
import string
import sys
from urllib.parse import quote, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

def load_config():
    config = configparser.ConfigParser()
    config.read('config.txt', encoding='utf-8')
    return config

def save_config(config):
    with open('config.txt', 'w', encoding='utf-8') as f:
        config.write(f)

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 加载配置
config = load_config()
microsoft_config = config['microsoft']

CLIENT_ID = microsoft_config['client_id']
REDIRECT_URI = microsoft_config['redirect_uri']

# API端点
AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

# 全局变量用于存储验证码
global_code_verifier = None
auth_code_received = None

# 权限范围
SCOPES = [
    'offline_access',
    'https://graph.microsoft.com/Mail.ReadWrite',
    'https://graph.microsoft.com/Mail.Send',
    'https://graph.microsoft.com/User.Read'
]

def generate_code_verifier(length=128) -> str:
    """生成PKCE验证码"""
    alphabet = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_code_challenge(code_verifier: str) -> str:
    """生成PKCE挑战码"""
    sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode().rstrip('=')

def get_auth_url():
    """生成授权URL"""
    global global_code_verifier
    global_code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(global_code_verifier)
    
    scope = ' '.join(SCOPES)
    auth_params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': scope,
        'response_mode': 'query',
        'prompt': 'select_account',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    params = '&'.join([f'{k}={quote(v)}' for k, v in auth_params.items()])
    return f'{AUTH_URL}?{params}'

def get_tokens(auth_code: str, code_verifier: str):
    """使用授权码获取访问令牌和刷新令牌"""
    token_params = {
        'client_id': CLIENT_ID,
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'scope': ' '.join(SCOPES),
        'code_verifier': code_verifier
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        response = requests.post(TOKEN_URL, data=token_params, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"获取令牌失败: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"响应内容: {e.response.text}")
        raise

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code_received
        
        if '/?code=' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            query_components = parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            if 'code' in query_components:
                auth_code_received = query_components['code'][0]
                
                response_html = """
                <html>
                <head><title>Authorization Successful</title></head>
                <body>
                <h1>Authorization Successful</h1>
                <p>You can close this window and return to the application.</p>
                </body>
                </html>
                """
                self.wfile.write(response_html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    server = HTTPServer(('localhost', 8000), OAuthHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def main():
    global auth_code_received, global_code_verifier
    
    # 启动本地服务器接收回调
    server = start_server()
    
    # 获取授权URL
    auth_url = get_auth_url()
    
    # 根据命令行参数决定使用哪种方式打开URL
    if len(sys.argv) > 1 and sys.argv[1] == '--no-browser':
        # 无浏览器模式
        print("\n请手动访问以下URL进行授权:")
        print(f"\n{auth_url}\n")
        print("授权后，您将被重定向到一个本地页面。\n")
    else:
        # 使用系统默认浏览器
        print("正在使用系统浏览器打开授权页面...")
        webbrowser.open(auth_url)
    
    # 等待授权码
    print("等待用户授权...")
    timeout = 300  # 5分钟超时
    start_time = time.time()
    
    while auth_code_received is None:
        if time.time() - start_time > timeout:
            print("授权超时，请重试")
            sys.exit(1)
        time.sleep(0.5)
    
    print("成功获取授权码！")
    
    try:
        # 获取令牌
        tokens = get_tokens(auth_code_received, global_code_verifier)
        
        if 'refresh_token' in tokens:
            print("成功获取refresh_token！")
            if 'tokens' not in config:
                config.add_section('tokens')
                
            config['tokens']['refresh_token'] = tokens['refresh_token']
            if 'access_token' in tokens:
                config['tokens']['access_token'] = tokens['access_token']
                expires_at = time.time() + tokens['expires_in']
                expires_at_str = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')
                config['tokens']['expires_at'] = expires_at_str
            save_config(config)
            print("令牌已保存到配置文件")
    except Exception as e:
        logger.error(f"获取令牌时出错: {e}")
        sys.exit(1)
    finally:
        # 停止服务器
        server.shutdown()

if __name__ == '__main__':
    main()