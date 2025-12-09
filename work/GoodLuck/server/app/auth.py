# 导入日期时间处理模块
import datetime
# 导入哈希加密模块
import hashlib

# 导入Flask核心模块及相关功能
from flask import Flask, request, jsonify, Blueprint
# 导入JWT相关功能（生成令牌、验证令牌、获取身份信息等）
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
# 导入JWT异常类
from jwt import ExpiredSignatureError, InvalidTokenError

# 导入自定义工具函数（错误/成功响应、密码加密）
from .api.tools import error_response, success_response, hash_password
# 导入数据库相关模块
from .database import get_db
# 导入配置文件
from . import config

# 创建认证蓝图，前缀为/auth，所有路由都以/auth开头
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
# 初始化数据库连接，指定数据库名称
system = get_db(config.DataBase_Name)


@auth_bp.route('/login', methods=['GET', 'POST', 'OPTIONS'])
def login():
    """
    用户登录接口
    支持OPTIONS（预检请求）、POST/GET方法
    功能：验证用户名密码，生成JWT令牌，记录登录信息
    """
    # 处理跨域预检请求，直接返回200
    if request.method == 'OPTIONS':
        return '', 200

    try:
        # 获取请求的JSON数据
        data = request.get_json()

        # 校验请求数据是否为空
        if not data:
            return error_response('请求数据不能为空')

        # 提取并清理用户名和密码（去除首尾空格）
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        # 校验用户名和密码是否为空
        if not username or not password:
            return error_response('用户名和密码不能为空')

        # 根据用户名查询用户信息
        user = system.user_manager.get_user_by_username(username)
        # 用户不存在则返回错误
        if not user:
            return error_response('用户不存在', 400)

        # 对输入密码进行哈希加密（与数据库存储的加密方式一致）
        hashed_password = hash_password(password)
        # 校验密码是否匹配
        if user['password'] != hashed_password:
            return error_response('密码错误', 401)

        # 记录用户登录日志
        system.login_manager.add_login_record(user['id'])

        # 生成JWT访问令牌，将用户ID作为身份标识
        access_token = create_access_token(identity=str(user['id']))

        # 返回登录成功响应，包含令牌和用户基本信息
        return success_response(
            data={
                'token': access_token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'height': user['height'],
                    'weight': user['weight']
                }
            },
            message='登录成功'
        )

    # 捕获所有异常，返回服务器错误
    except Exception as e:
        return error_response(f'登录失败: {str(e)}', 500)


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    用户注册接口
    方法：POST
    功能：校验注册信息，创建新用户（密码加密存储）
    """
    try:
        # 获取请求JSON数据
        data = request.get_json()

        # 校验请求数据是否为空
        if not data:
            return error_response('请求数据不能为空')

        # 提取注册信息
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        height = data.get('height')
        weight = data.get('weight')

        # 校验必填字段（用户名/密码）
        if not username or not password:
            return error_response('用户名和密码不能为空')

        # 校验用户名长度（至少3位）
        if len(username) < 3:
            return error_response('用户名至少3位')

        # 校验密码长度（至少6位）
        if len(password) < 6:
            return error_response('密码至少6位')

        # 检查用户名是否已存在
        existing_user = system.user_manager.get_user_by_username(username)
        if existing_user:
            return error_response('用户名已存在')

        # 密码哈希加密
        hashed_password = hash_password(password)
        # 创建新用户，成功则返回注册成功，失败则返回错误
        if system.user_manager.add_user(username, hashed_password, height, weight):
            return success_response(message='注册成功')
        else:
            return error_response('注册失败')

    # 捕获异常，返回注册失败信息
    except Exception as e:
        return error_response(f'注册失败: {str(e)}', 500)


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()  # 需要JWT令牌验证才能访问
def get_profile():
    """
    获取用户个人信息接口
    方法：GET
    权限：需要登录（JWT验证）
    功能：根据令牌中的用户ID查询并返回用户信息
    """
    try:
        # 从JWT令牌中获取当前用户ID
        user_id = get_jwt_identity()

        # 获取所有用户列表，根据ID匹配当前用户
        users = system.user_manager.get_all_users()
        user = None
        for u in users:
            if int(u['id']) == int(user_id):
                user = u
                break

        # 用户不存在返回404错误
        if not user:
            return error_response('用户不存在', 404)

        # 返回用户信息
        return success_response(
            data={
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'height': user['height'],
                'weight': user['weight']
            }
        )

    # 捕获异常，返回获取信息失败
    except Exception as e:
        return error_response(f'获取用户信息失败: {str(e)}', 500)


@auth_bp.route('/change_password', methods=['PUT'])
@jwt_required()  # 需要JWT令牌验证
def change_password():
    """
    修改密码接口
    方法：PUT
    权限：需要登录（JWT验证）
    功能：根据用户ID更新密码（密码加密后存储）
    """
    try:
        # 从JWT令牌中获取当前用户ID
        user_id = get_jwt_identity()
        # 获取请求JSON数据
        data = request.get_json()
        if not data:
            return error_response('请求数据不能为空')

        # 根据ID查询用户信息（使用生成器表达式简化查找）
        users = system.user_manager.get_all_users()
        user = next((u for u in users if int(u['id']) == int(user_id)), None)
        if not user:
            return error_response('用户不存在', 404)

        # 提取新密码并加密
        password = data.get('password')
        hashed_password = hash_password(password)

        # 定义无需更新的字段为None（仅更新密码）
        username = None
        height = None
        weight = None

        # 调用更新用户方法，仅更新密码字段
        if system.user_manager.update_user(user['id'], username, hashed_password, height, weight):
            return success_response(message='更新成功')
        return error_response('更新失败')

    # 捕获异常，返回更新失败
    except Exception as e:
        return error_response(f'更新失败: {str(e)}', 500)


@auth_bp.route('/update_simple_profile', methods=['PUT'])
@jwt_required()  # 需要JWT令牌验证
def update_simple_profile():
    """
    更新用户基本信息接口
    方法：PUT
    权限：需要登录（JWT验证）
    功能：更新用户名、身高、体重（不修改密码）
    """
    try:
        # 从JWT令牌中获取当前用户ID
        user_id = get_jwt_identity()
        # 获取请求JSON数据
        data = request.get_json()
        if not data:
            return error_response('请求数据不能为空')

        # 根据ID查询用户信息
        users = system.user_manager.get_all_users()
        user = next((u for u in users if int(u['id']) == int(user_id)), None)
        if not user:
            return error_response('用户不存在', 404)

        # 定义无需更新的字段为None（仅更新基本信息）
        password = None
        # 提取更新的信息，未传则使用原信息
        username = data.get('username', user['username']).strip()
        height = data.get('height')
        weight = data.get('weight')

        # 调用更新用户方法，仅更新基本信息字段
        if system.user_manager.update_user(user['id'], username, password, height, weight):
            return success_response(message='更新成功')
        return error_response('更新失败')

    # 捕获异常，返回更新失败
    except Exception as e:
        return error_response(f'更新失败: {str(e)}', 500)


@auth_bp.route('/refresh', methods=['GET'])
@jwt_required()  # 需要JWT令牌验证
def refresh():
    """
    刷新JWT令牌接口
    方法：GET
    权限：需要登录（JWT验证）
    功能：根据当前令牌的用户ID生成新的访问令牌
    """
    try:
        # 从JWT令牌中获取当前用户ID
        user_id = get_jwt_identity()

        # 根据ID查询用户信息
        users = system.user_manager.get_all_users()
        user = None
        for u in users:
            if int(u['id']) == int(user_id):
                user = u
                break

        # 用户不存在返回404错误
        if not user:
            return error_response('用户不存在', 404)

        # 生成新的JWT访问令牌
        access_token = create_access_token(identity=str(user['id']))
        # 返回新令牌
        return success_response(
            data={
                'token': access_token,
            },
            message='刷新token'
        )

    # 捕获异常，返回服务器错误
    except Exception as e:
        return error_response(f'服务错误: {str(e)}', 500)
