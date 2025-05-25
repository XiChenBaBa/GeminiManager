import json
import requests
import random
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
import threading
import os
import hashlib

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-this-in-production'

CONFIG_FILE = 'config.json'
GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/openai'

# 检查SOCKS支持
try:
    import socks
    SOCKS_AVAILABLE = True
    logger.info("SOCKS支持已加载")
except ImportError:
    SOCKS_AVAILABLE = False
    logger.warning("未安装SOCKS支持，代理功能将被禁用。请运行 'pip install requests[socks]' 安装支持。")

class ConfigManager:
    def __init__(self):
        self.config = self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        default_config = {
            'access_key': 'default-access-key',
            'admin_password': self.hash_password('admin123'),  # 默认密码
            'session_timeout': 3600,  # 会话超时时间（秒）
            'api_keys': [],
            'proxies': [],
            'key_proxy_mapping': {},
            'disabled_keys': [],
            'api_key_stats': {}
        }
        
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 确保所有必要的键都存在
                    for key in default_config:
                        if key not in config:
                            config[key] = default_config[key]
                    
                    # 如果密码未加密，则加密它
                    if 'admin_password' in config and not config['admin_password'].startswith('sha256:'):
                        config['admin_password'] = self.hash_password(config['admin_password'])
                    
                    # 为现有API密钥初始化统计信息
                    for api_key in config['api_keys']:
                        if api_key not in config['api_key_stats']:
                            config['api_key_stats'][api_key] = {
                                'call_count': 0,
                                'success_count': 0,
                                'error_count': 0,
                                'last_used': None,
                                'created_at': datetime.now().isoformat()
                            }
                    
                    logger.info(f"配置文件加载成功，共有 {len(config['api_keys'])} 个API密钥")
                    return config
            except Exception as e:
                logger.error(f"加载配置文件失败: {e}")
                return default_config
        else:
            logger.info("配置文件不存在，使用默认配置")
            return default_config
    
    def hash_password(self, password):
        """加密密码"""
        return 'sha256:' + hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def verify_password(self, password, hashed_password):
        """验证密码"""
        if not hashed_password.startswith('sha256:'):
            # 兼容旧的未加密密码
            return password == hashed_password
        
        expected_hash = hashed_password[7:]  # 移除 'sha256:' 前缀
        actual_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return actual_hash == expected_hash
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.info("配置文件保存成功")
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
    
    def add_api_key(self, api_key):
        """添加API密钥"""
        if api_key not in self.config['api_keys']:
            self.config['api_keys'].append(api_key)
            # 初始化统计信息
            self.config['api_key_stats'][api_key] = {
                'call_count': 0,
                'success_count': 0,
                'error_count': 0,
                'last_used': None,
                'created_at': datetime.now().isoformat()
            }
            self.save_config()
            logger.info(f"API密钥已添加: {api_key[:10]}...")
            return True
        return False
    
    def remove_api_key(self, api_key):
        """删除API密钥"""
        if api_key in self.config['api_keys']:
            self.config['api_keys'].remove(api_key)
            # 同时删除相关的代理映射、禁用状态和统计信息
            if api_key in self.config['key_proxy_mapping']:
                del self.config['key_proxy_mapping'][api_key]
            if api_key in self.config['disabled_keys']:
                self.config['disabled_keys'].remove(api_key)
            if api_key in self.config['api_key_stats']:
                del self.config['api_key_stats'][api_key]
            self.save_config()
            logger.info(f"API密钥已删除: {api_key[:10]}...")
            return True
        return False
    
    def add_proxy(self, proxy_url):
        """添加代理"""
        if proxy_url not in self.config['proxies']:
            self.config['proxies'].append(proxy_url)
            self.save_config()
            logger.info(f"代理已添加: {proxy_url}")
            return True
        return False
    
    def remove_proxy(self, proxy_url):
        """删除代理"""
        if proxy_url in self.config['proxies']:
            self.config['proxies'].remove(proxy_url)
            # 删除使用此代理的映射
            keys_to_update = []
            for key, proxy in self.config['key_proxy_mapping'].items():
                if proxy == proxy_url:
                    keys_to_update.append(key)
            
            for key in keys_to_update:
                del self.config['key_proxy_mapping'][key]
            
            self.save_config()
            logger.info(f"代理已删除: {proxy_url}")
            return True
        return False
    
    def set_key_proxy(self, api_key, proxy_url):
        """设置API密钥的代理"""
        if proxy_url == '':
            # 删除代理映射
            if api_key in self.config['key_proxy_mapping']:
                del self.config['key_proxy_mapping'][api_key]
                logger.info(f"API密钥 {api_key[:10]}... 的代理映射已删除")
        else:
            self.config['key_proxy_mapping'][api_key] = proxy_url
            logger.info(f"API密钥 {api_key[:10]}... 已设置代理: {proxy_url}")
        self.save_config()
    
    def disable_key(self, api_key):
        """禁用API密钥"""
        if api_key not in self.config['disabled_keys']:
            self.config['disabled_keys'].append(api_key)
            self.save_config()
            logger.warning(f"API密钥已禁用: {api_key[:10]}...")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] API密钥已禁用: {api_key[:10]}...")
    
    def enable_key(self, api_key):
        """启用API密钥"""
        if api_key in self.config['disabled_keys']:
            self.config['disabled_keys'].remove(api_key)
            self.save_config()
            logger.info(f"API密钥已重新启用: {api_key[:10]}...")
    
    def get_available_keys(self):
        """获取可用的API密钥"""
        available = [key for key in self.config['api_keys'] if key not in self.config['disabled_keys']]
        logger.debug(f"可用API密钥数量: {len(available)}/{len(self.config['api_keys'])}")
        return available
    
    def set_access_key(self, access_key):
        """设置访问密钥"""
        self.config['access_key'] = access_key
        self.save_config()
        logger.info("访问密钥已更新")
    
    def set_admin_password(self, password):
        """设置管理员密码"""
        self.config['admin_password'] = self.hash_password(password)
        self.save_config()
        logger.info("管理员密码已更新")
    
    def check_admin_password(self, password):
        """检查管理员密码"""
        return self.verify_password(password, self.config['admin_password'])
    
    def increment_api_call(self, api_key, success=True):
        """增加API调用统计"""
        if api_key not in self.config['api_key_stats']:
            self.config['api_key_stats'][api_key] = {
                'call_count': 0,
                'success_count': 0,
                'error_count': 0,
                'last_used': None,
                'created_at': datetime.now().isoformat()
            }
        
        stats = self.config['api_key_stats'][api_key]
        stats['call_count'] += 1
        stats['last_used'] = datetime.now().isoformat()
        
        if success:
            stats['success_count'] += 1
        else:
            stats['error_count'] += 1
        
        self.save_config()
        logger.debug(f"API密钥 {api_key[:10]}... 调用统计已更新: 总计{stats['call_count']}, 成功{stats['success_count']}, 失败{stats['error_count']}")
    
    def get_api_key_stats(self, api_key):
        """获取API密钥统计信息"""
        return self.config['api_key_stats'].get(api_key, {
            'call_count': 0,
            'success_count': 0,
            'error_count': 0,
            'last_used': None,
            'created_at': datetime.now().isoformat()
        })
    
    def reset_api_key_stats(self, api_key):
        """重置API密钥统计信息"""
        if api_key in self.config['api_key_stats']:
            stats = self.config['api_key_stats'][api_key]
            stats['call_count'] = 0
            stats['success_count'] = 0
            stats['error_count'] = 0
            stats['last_used'] = None
            self.save_config()
            logger.info(f"API密钥 {api_key[:10]}... 的统计信息已重置")

config_manager = ConfigManager()

class GeminiProxy:
    def __init__(self):
        self.last_used_index = -1
        self.lock = threading.Lock()
    
    def get_next_api_key(self):
        """轮询获取下一个可用的API密钥"""
        available_keys = config_manager.get_available_keys()
        if not available_keys:
            logger.warning("没有可用的API密钥")
            return None
        
        with self.lock:
            self.last_used_index = (self.last_used_index + 1) % len(available_keys)
            selected_key = available_keys[self.last_used_index]
            logger.debug(f"选择API密钥: {selected_key[:10]}... (索引: {self.last_used_index})")
            return selected_key
    
    def get_proxy_for_key(self, api_key):
        """获取指定API密钥的代理配置"""
        if not SOCKS_AVAILABLE:
            return None
            
        proxy_url = config_manager.config['key_proxy_mapping'].get(api_key)
        if proxy_url:
            logger.debug(f"API密钥 {api_key[:10]}... 使用代理: {proxy_url}")
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        return None
    
    def make_request(self, api_key, data, max_retries=3):
        """使用指定的API密钥发送请求"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
        
        proxies = self.get_proxy_for_key(api_key)
        url = f"{GEMINI_BASE_URL}/chat/completions"
        
        # 如果配置了代理但没有SOCKS支持，给出警告
        if not SOCKS_AVAILABLE and api_key in config_manager.config['key_proxy_mapping']:
            logger.warning(f"API密钥 {api_key[:10]}... 配置了代理但SOCKS支持未安装，将直接连接")
        
        logger.info(f"发送请求到Gemini API，使用密钥: {api_key[:10]}...")
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json=data,
                    proxies=proxies,
                    timeout=30
                )
                
                logger.debug(f"收到响应，状态码: {response.status_code}")
                
                if response.status_code == 200:
                    logger.info(f"请求成功，使用密钥: {api_key[:10]}...")
                    # 记录成功调用
                    config_manager.increment_api_call(api_key, success=True)
                    return response.json(), None
                elif response.status_code == 401:
                    # 标准的未授权错误
                    config_manager.disable_key(api_key)
                    # 记录失败调用
                    config_manager.increment_api_call(api_key, success=False)
                    logger.error(f"API密钥无效(401)，已禁用: {api_key[:10]}...")
                    return None, f"API密钥无效: {api_key[:10]}..."
                elif response.status_code == 400:
                    # 检查是否为API密钥无效的400错误
                    try:
                        error_response = response.json()
                        error_message = ""
                        
                        # 检查多种可能的错误格式
                        if isinstance(error_response, list) and len(error_response) > 0:
                            error_data = error_response[0]
                        else:
                            error_data = error_response
                        
                        if 'error' in error_data:
                            error_message = error_data['error'].get('message', '')
                        
                        # 检查是否为API密钥相关错误
                        if any(keyword in error_message.lower() for keyword in [
                            'api key not valid', 
                            'invalid api key', 
                            'api_key_invalid',
                            'authentication failed'
                        ]):
                            config_manager.disable_key(api_key)
                            # 记录失败调用
                            config_manager.increment_api_call(api_key, success=False)
                            logger.error(f"API密钥无效(400)，已禁用: {api_key[:10]}... - {error_message}")
                            return None, f"API密钥无效: {api_key[:10]}..."
                        else:
                            # 记录失败调用（非密钥问题）
                            config_manager.increment_api_call(api_key, success=False)
                            logger.error(f"请求参数错误: {error_message}")
                            return None, f"请求参数错误: {error_message}"
                            
                    except (json.JSONDecodeError, KeyError):
                        # 记录失败调用
                        config_manager.increment_api_call(api_key, success=False)
                        logger.error(f"无法解析错误响应: {response.text}")
                        return None, f"请求失败: {response.status_code} - {response.text}"
                elif response.status_code == 429:
                    # 速率限制，等待后重试
                    wait_time = 2 ** attempt
                    logger.warning(f"速率限制，等待 {wait_time} 秒后重试... (尝试 {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    # 记录失败调用
                    config_manager.increment_api_call(api_key, success=False)
                    logger.error(f"请求失败: {response.status_code} - {response.text}")
                    return None, f"请求失败: {response.status_code} - {response.text}"
                    
            except requests.exceptions.ProxyError as e:
                # 记录失败调用
                config_manager.increment_api_call(api_key, success=False)
                logger.error(f"代理连接失败: {proxies} - {str(e)}")
                return None, f"代理连接失败: {proxies} - {str(e)}"
            except requests.exceptions.Timeout:
                # 记录失败调用
                config_manager.increment_api_call(api_key, success=False)
                logger.error("请求超时")
                return None, "请求超时"
            except Exception as e:
                if "Missing dependencies for SOCKS support" in str(e):
                    logger.error("缺少SOCKS支持依赖")
                    return None, "缺少SOCKS支持依赖，请运行: pip install requests[socks]"
                if attempt == max_retries - 1:
                    # 记录失败调用
                    config_manager.increment_api_call(api_key, success=False)
                    logger.error(f"请求异常: {str(e)}")
                    return None, f"请求异常: {str(e)}"
                time.sleep(1)
        
        # 记录失败调用
        config_manager.increment_api_call(api_key, success=False)
        logger.error("请求失败，已达到最大重试次数")
        return None, "请求失败，已达到最大重试次数"
    
    def proxy_request(self, data):
        """代理请求到Gemini API"""
        available_keys = config_manager.get_available_keys()
        if not available_keys:
            logger.error("没有可用的API密钥")
            return None, "没有可用的API密钥"
        
        # 尝试所有可用的API密钥
        for attempt in range(len(available_keys)):
            api_key = self.get_next_api_key()
            if api_key:
                result, error = self.make_request(api_key, data)
                if result:
                    return result, None
                elif "API密钥无效" in error:
                    # 继续尝试下一个密钥
                    logger.warning(f"API密钥无效，尝试下一个密钥...")
                    continue
                else:
                    return None, error
        
        logger.error("所有API密钥都不可用")
        return None, "所有API密钥都不可用"

gemini_proxy = GeminiProxy()

def verify_access_key(request):
    """验证访问密钥"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    
    token = auth_header[7:]  # 移除 "Bearer " 前缀
    return token == config_manager.config['access_key']

def require_admin_login(f):
    """装饰器：要求管理员登录"""
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('login'))
        
        # 检查会话是否过期
        login_time = session.get('login_time')
        if login_time:
            login_datetime = datetime.fromisoformat(login_time)
            timeout = config_manager.config.get('session_timeout', 3600)
            if datetime.now() - login_datetime > timedelta(seconds=timeout):
                session.clear()
                flash('会话已过期，请重新登录', 'warning')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """管理员登录"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if config_manager.check_admin_password(password):
            session['admin_logged_in'] = True
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            logger.info(f"管理员登录成功，IP: {request.remote_addr}")
            flash('登录成功', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"管理员登录失败，IP: {request.remote_addr}")
            flash('密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """管理员登出"""
    session.clear()
    flash('已安全登出', 'success')
    return redirect(url_for('login'))

@app.route('/')
@require_admin_login
def index():
    """管理界面"""
    return render_template('index.html', config=config_manager.config)

@app.route('/add_api_key', methods=['POST'])
@require_admin_login
def add_api_key():
    """添加API密钥"""
    api_key = request.form.get('api_key', '').strip()
    if api_key:
        if config_manager.add_api_key(api_key):
            flash('API密钥添加成功', 'success')
        else:
            flash('API密钥已存在', 'warning')
    else:
        flash('请输入有效的API密钥', 'error')
    
    return redirect(url_for('index'))

@app.route('/remove_api_key', methods=['POST'])
@require_admin_login
def remove_api_key():
    """删除API密钥"""
    api_key = request.form.get('api_key')
    if config_manager.remove_api_key(api_key):
        flash('API密钥删除成功', 'success')
    else:
        flash('API密钥删除失败', 'error')
    
    return redirect(url_for('index'))

@app.route('/add_proxy', methods=['POST'])
@require_admin_login
def add_proxy():
    """添加代理"""
    proxy_url = request.form.get('proxy_url', '').strip()
    if proxy_url:
        if config_manager.add_proxy(proxy_url):
            flash('代理添加成功', 'success')
        else:
            flash('代理已存在', 'warning')
    else:
        flash('请输入有效的代理URL', 'error')
    
    return redirect(url_for('index'))

@app.route('/remove_proxy', methods=['POST'])
@require_admin_login
def remove_proxy():
    """删除代理"""
    proxy_url = request.form.get('proxy_url')
    if config_manager.remove_proxy(proxy_url):
        flash('代理删除成功', 'success')
    else:
        flash('代理删除失败', 'error')
    
    return redirect(url_for('index'))

@app.route('/set_key_proxy', methods=['POST'])
@require_admin_login
def set_key_proxy():
    """设置API密钥的代理"""
    api_key = request.form.get('api_key')
    proxy_url = request.form.get('proxy_url', '')
    
    config_manager.set_key_proxy(api_key, proxy_url)
    flash('代理映射设置成功', 'success')
    
    return redirect(url_for('index'))

@app.route('/toggle_key', methods=['POST'])
@require_admin_login
def toggle_key():
    """启用/禁用API密钥"""
    api_key = request.form.get('api_key')
    action = request.form.get('action')
    
    if action == 'disable':
        config_manager.disable_key(api_key)
        flash('API密钥已禁用', 'success')
    elif action == 'enable':
        config_manager.enable_key(api_key)
        flash('API密钥已启用', 'success')
    
    return redirect(url_for('index'))

@app.route('/set_access_key', methods=['POST'])
@require_admin_login
def set_access_key():
    """设置访问密钥"""
    access_key = request.form.get('access_key', '').strip()
    if access_key:
        config_manager.set_access_key(access_key)
        flash('访问密钥设置成功', 'success')
    else:
        flash('请输入有效的访问密钥', 'error')
    
    return redirect(url_for('index'))

@app.route('/set_admin_password', methods=['POST'])
@require_admin_login
def set_admin_password():
    """设置管理员密码"""
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    if not new_password:
        flash('请输入新密码', 'error')
    elif new_password != confirm_password:
        flash('两次输入的密码不一致', 'error')
    elif len(new_password) < 6:
        flash('密码长度至少6位', 'error')
    else:
        config_manager.set_admin_password(new_password)
        flash('管理员密码设置成功', 'success')
    
    return redirect(url_for('index'))

@app.route('/test_api_key', methods=['POST'])
@require_admin_login
def test_api_key():
    """测试API密钥有效性"""
    api_key = request.form.get('api_key')
    
    test_data = {
        "model": "gemini-2.0-flash-lite",
        "messages": [{"role": "user", "content": "Hello"}]
    }
    
    result, error = gemini_proxy.make_request(api_key, test_data)
    
    if result:
        flash(f'API密钥 {api_key[:10]}... 测试成功', 'success')
    else:
        flash(f'API密钥 {api_key[:10]}... 测试失败: {error}', 'error')
    
    return redirect(url_for('index'))

@app.route('/reset_stats', methods=['POST'])
@require_admin_login
def reset_stats():
    """重置API密钥统计信息"""
    api_key = request.form.get('api_key')
    config_manager.reset_api_key_stats(api_key)
    flash(f'API密钥 {api_key[:10]}... 的统计信息已重置', 'success')
    return redirect(url_for('index'))

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    """Gemini API代理端点"""
    # 验证访问密钥
    if not verify_access_key(request):
        logger.warning("未授权的访问尝试")
        return jsonify({'error': '未授权访问'}), 401
    
    try:
        # 添加请求日志
        logger.info(f"收到聊天完成请求，Content-Type: {request.content_type}")
        
        data = request.get_json()
        if not data:
            logger.error("请求数据无效")
            return jsonify({'error': '请求数据无效，请确保Content-Type为application/json且数据格式正确'}), 400
        
        # 验证必要字段
        if 'model' not in data:
            logger.error("缺少必要字段: model")
            return jsonify({'error': '缺少必要字段: model'}), 400
        if 'messages' not in data:
            logger.error("缺少必要字段: messages")
            return jsonify({'error': '缺少必要字段: messages'}), 400
        
        logger.info(f"处理模型 {data.get('model')} 的请求")
        
        # 代理请求到Gemini API
        result, error = gemini_proxy.proxy_request(data)
        
        if result:
            logger.info("请求处理成功")
            return jsonify(result)
        else:
            logger.error(f"请求处理失败: {error}")
            return jsonify({'error': error}), 500
            
    except Exception as e:
        logger.error(f"处理请求时发生错误: {str(e)}")
        return jsonify({'error': f'服务器内部错误: {str(e)}'}), 500

@app.route('/status')
def status():
    """获取服务状态（无需认证）"""
    available_keys = config_manager.get_available_keys()
    
    # 计算总调用次数
    total_calls = sum(stats.get('call_count', 0) for stats in config_manager.config['api_key_stats'].values())
    total_success = sum(stats.get('success_count', 0) for stats in config_manager.config['api_key_stats'].values())
    total_errors = sum(stats.get('error_count', 0) for stats in config_manager.config['api_key_stats'].values())
    
    status_info = {
        'total_keys': len(config_manager.config['api_keys']),
        'available_keys': len(available_keys),
        'disabled_keys': len(config_manager.config['disabled_keys']),
        'proxies': len(config_manager.config['proxies']),
        'socks_support': SOCKS_AVAILABLE,
        'total_calls': total_calls,
        'total_success': total_success,
        'total_errors': total_errors,
        'success_rate': round((total_success / total_calls * 100) if total_calls > 0 else 0, 2),
        'timestamp': datetime.now().isoformat()
    }
    logger.info(f"状态查询: {status_info}")
    return jsonify(status_info)

if __name__ == '__main__':
    logger.info("启动Gemini API代理服务...")
    logger.info(f"SOCKS支持: {'已启用' if SOCKS_AVAILABLE else '未启用'}")
    logger.info(f"可用API密钥: {len(config_manager.get_available_keys())}")
    logger.info("默认管理员密码: admin123 (请及时修改)")
    app.run(host='0.0.0.0', port=80, debug=False)
