"""
Implementa los apartados 2 y 3 de la práctica:
- Apartado 2: Cifrado/descifrado simétrico con AES
- Apartado 3: Generación/verificación de etiquetas de autenticación (HMAC)
"""

import os
import base64
import secrets
import hmac
import hashlib
import json
from typing import Dict, Tuple, Optional, Any
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class CriptografiaManager:
    """Gestiona las operaciones criptográficas de la aplicación."""
    
    
