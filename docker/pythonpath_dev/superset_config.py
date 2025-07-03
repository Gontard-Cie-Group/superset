import base64
import logging
import os
import requests
import socket
import fcntl
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import g
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.sqla.models import User
from flask_consulate import Consul
from superset.security import SupersetSecurityManager

from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache

from flask import Flask

from flask_appbuilder.security.views import AuthOAuthView
from flask import redirect, request
from flask_login import login_user
from superset import security_manager

STATIC_FOLDER = "/app/static"
app = Flask(__name__, static_folder=STATIC_FOLDER)

# logger = logging.getLogger()
#
# try:
#     import superset_config_docker
#     from superset_config_docker import *  # noqa
#
#     logger.info(
#         f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
#     )
# except ImportError:
#     logger.info("Using default Docker config...")


# Security
SECRET_KEY = os.environ.get('SUPERSET_SECRET_KEY')

# Database
DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

# Redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "1")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "2")
REDIS_CACHE_DB = os.getenv("CACHE_REDIS_DB", "0")

# Auth
KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL')
KEYCLOAK_CLIENT_ID = os.environ.get('KEYCLOAK_CLIENT_ID')
KEYCLOAK_CLIENT_SECRET = os.environ.get('KEYCLOAK_CLIENT_SECRET')
POST_LOGOUT_REDIRECT_URL = os.environ.get('POST_LOGOUT_REDIRECT_URL')

# Consul
CONSUL_SERVICE_NAME = os.environ.get('CONSUL_SERVICE_NAME')

# ######################### Security ######################### #
def jwk_to_pem(jwk):
    n_b64 = jwk["n"]
    e_b64 = jwk["e"]
    n_bytes = base64.urlsafe_b64decode(n_b64 + '=' * (4 - len(n_b64) % 4))
    e_bytes = base64.urlsafe_b64decode(e_b64 + '=' * (4 - len(e_b64) % 4))

    n = int.from_bytes(n_bytes, byteorder='big')
    e = int.from_bytes(e_bytes, byteorder='big')
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem.decode()


def get_public_key():
    jwks_url = f'{KEYCLOAK_URL}/protocol/openid-connect/certs'
    jwks = requests.get(jwks_url).json()
    if "keys" not in jwks or len(jwks["keys"]) == 0:
        raise ValueError("No keys found in JWKS.")

    for jwk in jwks["keys"]:
        if jwk.get("kty") == "RSA":
            return jwk_to_pem(jwk)

    raise ValueError("No RSA key found in JWKS.")


class CustomOIDCSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super().__init__(appbuilder)

    def oauth_user_info(self, provider, response=None):
        user_info = response.get("userinfo", {})
        # userinfo = self._get_oauth_token(provider).userinfo()
        # Получаем объект OAuth клиента для keycloak
        # client = self.appbuilder.sm.oauth._clients[provider]
        # Запрашиваем userinfo endpoint
        # userinfo = client.get('userinfo').json()
        resource_access = user_info.get("resource_access", {})
        roles = resource_access.get(f"{KEYCLOAK_CLIENT_ID}", {}).get("roles", [])

        return {
            "name": user_info.get("name", ""),
            "username": user_info.get("preferred_username"),
            "email": user_info.get("email"),
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
            "role_keys": roles,
        }

    def load_user_jwt(self, _jwt_header, jwt_data):
        # print(jwt_data)
        username = jwt_data['preferred_username']
        session = self.get_session()
        user = session.query(User).filter(User.username == username).first()
        if user.is_active:
            g.user = user
            return user


JWT_ALGORITHM = 'RS256'
JWT_PUBLIC_KEY = get_public_key()

def init_consul(app):
    """
    Initialize flask-consulate for service discovery.
    """
    consul = Consul(app=app)

    def get_ip_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])

    def register_service():
        # service_address = socket.gethostbyname(socket.gethostname())
        service_address = get_ip_address('eth0')
        service_port = 8088

        consul.register_service(
            name=f'{CONSUL_SERVICE_NAME}',
            service_id=f'{CONSUL_SERVICE_NAME}',
            address=service_address,
            port=service_port,
            interval='10s',
            httpcheck=f"http://{service_address}:{service_port}/health",
        )
        logging.debug("Superset service registered!")

    with app.app_context():
        register_service()


FLASK_APP_MUTATOR = init_consul

AUTH_TYPE = AUTH_OAUTH
CUSTOM_SECURITY_MANAGER = CustomOIDCSecurityManager
LOGOUT_REDIRECT_URL = POST_LOGOUT_REDIRECT_URL
AUTH_USER_REGISTRATION = True
AUTH_ROLES_SYNC_AT_LOGIN = True

AUTH_ROLES_MAPPING = {
    "Admin": ["Admin"],
    "Alpha": ["Gamma"],
    "Embedder": ["Embedder"],
    "Gamma": ["Gamma"],
}
OAUTH_PROVIDERS = [
    {
        'name': 'gcie-keycloak',
        'icon': 'fa-key',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET,
            'client_kwargs': {
                'scope': 'openid profile email',
            },
            'server_metadata_url': f'{KEYCLOAK_URL}/.well-known/openid-configuration',
        },
        # 'user_info': lambda token: {
        #     "username": token["preferred_username"],
        #     "email": token["email"],
        #     "first_name": token.get("given_name", ""),
        #     "last_name": token.get("family_name", ""),
        # },
    }
]
GUEST_ROLE_NAME = 'Embedder'
GUEST_TOKEN_JWT_SECRET = os.environ.get('GUEST_TOKEN_JWT_SECRET')
GUEST_TOKEN_JWT_EXP_SECONDS = int(os.environ.get('GUEST_TOKEN_JWT_EXP_SECONDS'))
FEATURE_FLAGS = {
    "ALERT_REPORTS": True,
    "DATAPANEL_CLOSED_BY_DEFAULT": True,
    "DASHBOARD_VIRTUALIZATION": True,
    "DASHBOARD_RBAC": True,
    "ENABLE_TEMPLATE_PROCESSING": True,
    "ESCAPE_MARKDOWN_HTML": True,
    "LISTVIEWS_DEFAULT_CARD_VIEW": True,
    "THUMBNAILS": True,
    "DRILL_BY": True,
    "DRILL_TO_DETAIL": True,
    "HORIZONTAL_FILTER_BAR": True,
    "ESTIMATE_QUERY_COST": True,
    "TAGGING_SYSTEM": True,
    "HTML_SANITIZATION": False,
    "EMBEDDED_SUPERSET": True,
    "DASHBOARD_CACHE": True,
    "ENABLE_CACHING": True, # Charts cache
    "EXPLORE_FORM_DATA_CACHE": True,
    "ENABLE_OAUTH": False,
}
WTF_CSRF_ENABLED = False

TALISMAN_ENABLED = True
TALISMAN_CONFIG = {
    "content_security_policy": {
        'default-src': "'self'",
        'frame-ancestors': ["'self'", "*"],
        "base-uri": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://ows.terrestris.de",
            "https://tile.openstreetmap.org"
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}
TALISMAN_DEV_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        'frame-ancestors': ["'self'", "*"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
            "https://avatars.slack-edge.com",
            "https://ows.terrestris.de",
            "https://tile.openstreetmap.org"
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}

# class CustomAuthOAuthView(AuthOAuthView):
#     @app.route('/api/v1/security/login/keycloak/', methods=['POST'])
#     def login_with_token():
#         from flask import jsonify
# 
#         access_token = request.json.get("access_token")
#         if not access_token:
#             return jsonify({"error": "Missing token"}), 400
# 
#         # Получаем user_info через introspection или OIDC userinfo endpoint
#         # Например:
#         user_info = security_manager.oauth_remote_apps['gcie-keycloak'].userinfo(token={"access_token": access_token})
#         username = user_info["preferred_username"]
#        	user = security_manager.find_user(username=username)
#         if not user:
#             user = security_manager.add_user(
#                 username=username,
#                 first_name=user_info.get("first_name", ""),
#                 last_name=user_info.get("last_name", ""),
#                 email=user_info.get("email", ""),
#                 role=security_manager.find_role("Gamma")
#             )
#         login_user(user)
#         return jsonify({"message": f"Logged in as {username}"})

# ######################### Security ######################### #

# ######################### DB ######################### #
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 30,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
}
# ######################### DB ######################### #

# ######################### Cache ######################### #
CACHE_NO_NULL_WARNING = True
CACHE_CONFIG = {
    'CACHE_TYPE': "RedisCache",
    'CACHE_DEFAULT_TIMEOUT': 60 * 60 * 1,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_HOST': REDIS_HOST,
    'CACHE_REDIS_PORT': REDIS_PORT,
    'CACHE_REDIS_DB': REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = {
    'CACHE_TYPE': "RedisCache",
    'CACHE_DEFAULT_TIMEOUT': 60 * 60 * 1, # 1 hour default (in secs)
    'CACHE_KEY_PREFIX': 'data_',
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_CACHE_DB,
}
# ######################### Cache ######################### #

# ######################### Async ######################### #
GLOBAL_ASYNC_QUERIES = True
SQLLAB_ASYNC_TIME_LIMIT_SEC = 60 * 60 * 1 # 1 hour
SQLLAB_BACKEND_PERSISTENCE = True  # Включает хранение результатов запросов
SQLLAB_ASYNC_MODE = True

CELERYD_CONCURRENCY = 3

class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    imports = (
        "superset.sql_lab",
        "superset.tasks.scheduler",
        "superset.tasks.thumbnails",
        "superset.tasks.cache",
    )
    CELERY_IMPORTS = ('superset.sql_lab',
                      'superset.tasks'
    )
    worker_prefetch_multiplier = 1 # workers take only one tasks
    task_acks_late = True # False # workers apruve that task was done
    worker_concurrency = 1 # number of tasks on a worker
    broker_connection_retry_on_startup = True
    CELERYD_LOG_LEVEL = 'DEBUG'
    CONCURRENCY = 3
    GLOBAL_ASYNC_QUERIES = True

    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
        "cleanup_logs": {
            "task": "superset.tasks.cleanup_logs",
            "schedule": crontab(hour=0, minute=0),
        },
    }
    # Queues
    task_queues = {
        # "celery": {"exchange": "celery"},
        "queue_sql": {"exchange": "sql_tasks"},
        "queue_reports": {"exchange": "reports_tasks"},
        "queue_cache": {"exchange": "cache_tasks"},
        # "dashboards": {"exchange": "dashboards", "routing_key": "dashboards"},
    }
    # Marshrutirization tasks on queues
    task_routes = {
        "superset.sql_lab.*": {"queue": "queue_sql"},
        "superset.tasks.thumbnails.*": {"queue": "queue_reports"},
        "superset.tasks.cache.*": {"queue": "queue_cache"},
        "superset.tasks.cleanup_logs": {"queue": "queue_cache"},
        "*": {"queue": "queue_sql"},
    }
    task_annotations = {
        "sql_lab.get_sql_results": {
            "rate_limit": "100/s",
        },
        "superset.sql_lab.*": {
            "rate_limit": "100/s",
        },
        'email_reports.send': {
            'rate_limit': '1/s',
            'time_limit': 120,
            'soft_time_limit': 150,
            'ignore_result': True,
        },
        "tasks.*": {"rate_limit": "100/s",},

        "get_sql_results": {
            "rate_limit": "100/s",
        },
        "sql_lab.*": {
            "rate_limit": "100/s",
        },
   }

CELERY_CONFIG = CeleryConfig
# import redis
CACHE_DEFAULT_TIMEOUT = 21600 # Default timeout

GLOBAL_ASYNC_QUERIES_JWT_SECRET = os.getenv('GLOBAL_ASYNC_QUERIES_JWT_SECRET', 'default_secret_key') 
GLOBAL_ASYNC_QUERIES_POLLING_DELAY = 4000

GLOBAL_ASYNC_QUERIES_REDIS_CONFIG = {
    "port": REDIS_PORT,
    "host": REDIS_HOST,
    "password": "",
    "db": REDIS_CELERY_DB,
    "ssl": False,
    "GLOBAL_ASYNC_QUERIES": True,
}

# Persisting results from running query handling using Celery workers
from cachelib.redis import RedisCache
RESULTS_BACKEND = RedisCache(host=REDIS_HOST, port=REDIS_PORT, key_prefix='superset_results')

# Disable MessagePack and PyArrow for results serialization
RESULTS_BACKEND_USE_MSGPACK = False
# ######################### Async ######################### #


# ######################### UI ######################### #
APP_NAME = "Gontard & Cie Group"
APP_ICON = "/static/assets/images/GCG-WhiteBG-Logo.png"
LOGO_TARGET_PATH = '/'
LOGO_TOOLTIP = "Go Home"
FAVICONS = [{"href": "/static/assets/images/GCG-WhiteBG-Icon.png"}]
MAPBOX_API_KEY = 'pk.eyJ1IjoiZ2FyaXNvdiIsImEiOiJjam5hNW11a3owbnJvM3FvZHdkMXI0NnhlIn0.xigeTRVuccbyzXhkOv1TqQ'
FAB_API_SWAGGER_UI = True

# ######################### COLOR SCHEMES ######################### #
EXTRA_CATEGORICAL_COLOR_SCHEMES = [{
         "id": 'GontardAndCieMainColors',
         "description": 'Main colors',
         "label": 'Gontard & Cie - main colors',
         "isDefault": True,
         "colors": ["#3568AD", "#4D84CA", "#81A8D9", "#817EB8", "#625FA7", "#4B4884",  "#35A8B6", "#41A66E", "#63C18C", "#99D6B4", "#DB2D57", "#E36280", "#E2B700", "#EACF60"]
     },
     {
         "id": 'GontardAndCieDark',
         "description": 'Main colors dark',
         "label": 'Gontard & Cie - main colors dark',
         "isDefault": True,
         "colors": ["#1A3457", "#20416B", "#285185", "#393764", "#302E55", "#262442", "#1A545B", "#205337", "#2A6845", "#358357", "#71132A", "#8A1933", "#715C00", "#927913"]
     },
     {
         "id": 'GontardAndCieLite',
         "description": 'Main colors lite',
         "label": 'Gontard & Cie - main colors lite',
         "isDefault": True,
         "colors": ["#A8C2E4", "#B8CEEA", "#CDDCF0", "#CDCBE3", "#C0BFDC", "#B2B0D4", "#AAE0E6", "#AFE0C5", "#C1E6D1", "#D6EFE1", "#F1ABBC", "#F4C0CC", "#FFE98D", "#F7ECBF"]
     }]

EXTRA_SEQUENTIAL_COLOR_SCHEMES = [
        {
         "id": 'GontardAndCie',
         "description": 'Main colors',
         "isDiverging": True,
         "label": 'Gontard & Cie main colors',
         "isDefault": True,
         "colors": ["#3568AD", "#4D84CA", "#81A8D9", "#817EB8", "#625FA7", "#4B4884",  "#35A8B6", "#41A66E", "#63C18C", "#99D6B4", "#DB2D57", "#E36280", "#E2B700", "#EACF60"]
        },
        {
         "id": 'GontardAndCieDark',
         "description": 'Main colors dark',
         "isDiverging": True,
         "label": 'Gontard & Cie main colors dark',
         "isDefault": True,
         "colors": ["#1A3457", "#20416B", "#285185", "#393764", "#302E55", "#262442", "#1A545B", "#205337", "#2A6845", "#358357", "#71132A", "#8A1933", "#715C00", "#927913"]
        },
        {
         "id": 'GontardAndCieLite',
         "description": 'Main colors lite',
         "isDiverging": True,
         "label": 'Gontard & Cie main colors lite',
         "isDefault": True,
         "colors": ["#A8C2E4", "#B8CEEA", "#CDDCF0", "#CDCBE3", "#C0BFDC", "#B2B0D4", "#AAE0E6", "#AFE0C5", "#C1E6D1", "#D6EFE1", "#F1ABBC", "#F4C0CC", "#FFE98D", "#F7ECBF"]
        }]
# ######################### COLOR SCHEMES ######################### #

# ######################### Misc ######################### #
SUPERSET_DASHBOARD_POSITION_DATA_LIMIT = 196605 # just x3

# RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")
SUPERSET_WEBSERVER_TIMEOUT = 3600
ROW_LIMIT = 50000000
VIZ_ROW_LIMIT = 50000000
SAMPLES_ROW_LIMIT = 50000000
FILTER_SELECT_ROW_LIMIT = 50000000
QUERY_SEARCH_LIMIT = 50000000
SQL_MAX_ROW = 500000000
DISPLAY_MAX_ROW = 50000000
DEFAULT_SQLLAB_LIMIT = 50000000
# ######################### Misc ######################### #


from flask_appbuilder.views import expose
from flask_appbuilder.security.views import AuthOAuthView
from flask import jsonify, request
from flask_login import login_user
from superset import app, security_manager


class CustomAuthOAuthView(AuthOAuthView):
    @expose('/login/keycloak/', methods=['POST'])
    def login_with_token(self):
        access_token = request.json.get("access_token")
        if not access_token:
            return jsonify({"error": "Missing token"}), 400

        # user_info = security_manager.oauth_remote_apps['gcie-keycloak'].userinfo(token={"access_token": access_token})
        user_info = security_manager.appbuilder.sm.oauth_remotes['gcie-keycloak'].userinfo(token={"access_token": access_token}).json()
        username = user_info["preferred_username"]
        user = security_manager.find_user(username=username)
        if not user:
            user = security_manager.add_user(
                username=username,
                first_name=user_info.get("given_name", ""),
                last_name=user_info.get("family_name", ""),
                email=user_info.get("email", ""),
                role=security_manager.find_role("Gamma"),
            )
        login_user(user)
        return jsonify({"message": f"Logged in as {username}"}), 200

def custom_app_mutator(app):
    """Объединяет регистрацию Consul и кастомной аутентификации."""
    # 🔹 Consul (оставим как было)
    consul = Consul(app=app)
    def register_service():
        ...
    with app.app_context():
        register_service()

    # 🔹 Регистрируем кастомную OAuth ручку
    from flask_appbuilder.views import expose
    from flask_appbuilder.security.views import AuthOAuthView
    from flask import jsonify, request
    from flask_login import login_user
    from superset import appbuilder, security_manager

    class CustomAuthOAuthView(AuthOAuthView):
        @expose('/login/keycloak/', methods=['POST'])
        def login_with_token(self):
            access_token = request.json.get("access_token")
            if not access_token:
                return jsonify({"error": "Missing token"}), 400

            # user_info = security_manager.oauth_remote_apps['gcie-keycloak'].userinfo(token={"access_token": access_token})
            print("DEBUG:", dir(security_manager.appbuilder.sm))
            user_info = security_manager.appbuilder.sm.oauth_remotes['gcie-keycloak'].userinfo(token={"access_token": access_token}).json()
            username = user_info["preferred_username"]
            user = security_manager.find_user(username=username)
            if not user:
                user = security_manager.add_user(
                    username=username,
                    first_name=user_info.get("given_name", ""),
                    last_name=user_info.get("family_name", ""),
                    email=user_info.get("email", ""),
                    role=security_manager.find_role("Gamma"),
                )
            login_user(user)
            return jsonify({"message": f"Logged in as {username}"}), 200

    appbuilder.add_view_no_menu(CustomAuthOAuthView())

# Привязываем
FLASK_APP_MUTATOR = custom_app_mutator

# Привязываем к Flask
# appbuilder.add_view_no_menu(CustomAuthOAuthView())
