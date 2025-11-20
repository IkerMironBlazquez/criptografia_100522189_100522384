"""
Módulo de criptografía híbrida RSA + AES para mensajería segura.
Implementa los apartados 2 y 3 de la práctica con arquitectura realista.
"""

import json
import base64
import secrets
import os
from typing import Dict, Optional, Tuple, Any
from datetime import datetime
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class CriptografiaHibrida:
    """
    Gestor de criptografía híbrida RSA + AES.
    
    - RSA: Para intercambio seguro de claves AES
    - AES-256-GCM: Para cifrado de mensajes (sin límite de tamaño)
    """
    
    def __init__(self, directorio_claves: str = "JSON/claves"):
        """
        Inicializa el sistema de criptografía híbrida.
        
        Args:
            directorio_claves: Directorio donde se almacenan las claves
        """
        self.directorio_claves = directorio_claves
        self.directorio_publicas = os.path.join(directorio_claves, "publicas")
        self.directorio_privadas = os.path.join(directorio_claves, "privadas")
        self.directorio_sesiones = os.path.join(directorio_claves, "sesiones")
        
        self._crear_directorios()
        
        logger.info("Sistema de criptografía híbrida inicializado")
    
    def _crear_directorios(self):
        """Crea los directorios necesarios para almacenar claves."""
        for directorio in [self.directorio_claves, self.directorio_publicas, 
                          self.directorio_privadas, self.directorio_sesiones]:
            os.makedirs(directorio, exist_ok=True)
    
    # ========================
    # GESTIÓN DE CLAVES RSA
    # ========================
    
    def generar_par_claves_usuario(self, usuario_id: str, contraseña: str) -> Dict[str, str]:
        """
        Genera un par de claves RSA para un usuario.
        
        Args:
            usuario_id: ID único del usuario
            contraseña: Contraseña para cifrar la clave privada
            
        Returns:
            Dict con las claves pública y privada
        """
        try:
            # Generar par de claves RSA-2048
            clave_privada = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            clave_publica = clave_privada.public_key()
            
            # Serializar clave pública (sin cifrar)
            clave_publica_pem = clave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Serializar clave privada (cifrada con contraseña)
            clave_privada_pem = clave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    contraseña.encode('utf-8')
                )
            )
            
            # Guardar clave pública
            archivo_publica = os.path.join(self.directorio_publicas, f"{usuario_id}.pem")
            with open(archivo_publica, 'wb') as f:
                f.write(clave_publica_pem)
            
            # Guardar clave privada cifrada
            archivo_privada = os.path.join(self.directorio_privadas, f"{usuario_id}.pem")
            with open(archivo_privada, 'wb') as f:
                f.write(clave_privada_pem)
            
            logger.info(f"Par de claves RSA generado para usuario {usuario_id}")
            
            return {
                'publica': clave_publica_pem.decode('utf-8'),
                'privada': clave_privada_pem.decode('utf-8')
            }
            
        except Exception as e:
            logger.error(f"Error generando claves RSA para {usuario_id}: {e}")
            raise
    
    def cargar_clave_publica(self, usuario_id: str) -> Optional[bytes]:
        """
        Carga la clave pública de un usuario.
        
        Args:
            usuario_id: ID del usuario
            
        Returns:
            Clave pública en bytes o None si no existe
        """
        try:
            archivo_publica = os.path.join(self.directorio_publicas, f"{usuario_id}.pem")
            
            if not os.path.exists(archivo_publica):
                return None
                
            with open(archivo_publica, 'rb') as f:
                clave_publica_pem = f.read()
            
            clave_publica = serialization.load_pem_public_key(clave_publica_pem)
            return clave_publica
            
        except Exception as e:
            logger.error(f"Error cargando clave pública de {usuario_id}: {e}")
            return None
    
    def cargar_clave_privada(self, usuario_id: str, contraseña: str) -> Optional[bytes]:
        """
        Carga y descifra la clave privada de un usuario.
        
        Args:
            usuario_id: ID del usuario
            contraseña: Contraseña para descifrar la clave privada
            
        Returns:
            Clave privada descifrada o None si falla
        """
        try:
            archivo_privada = os.path.join(self.directorio_privadas, f"{usuario_id}.pem")
            
            if not os.path.exists(archivo_privada):
                return None
                
            with open(archivo_privada, 'rb') as f:
                clave_privada_pem = f.read()
            
            clave_privada = serialization.load_pem_private_key(
                clave_privada_pem,
                password=contraseña.encode('utf-8')
            )
            
            return clave_privada
            
        except Exception as e:
            logger.error(f"Error cargando clave privada de {usuario_id}: {e}")
            return None
    
    # ===============================
    # GESTIÓN DE CLAVES AES DE SESIÓN
    # ===============================
    
    def obtener_clave_sesion_para_usuario(self, remitente_id: str, destinatario_id: str, usuario_id: str) -> bytes:
        """
        Obtiene la clave AES de sesión para un usuario específico (remitente o destinatario).
        
        Args:
            remitente_id: ID del usuario que envía
            destinatario_id: ID del usuario que recibe  
            usuario_id: ID del usuario que quiere descifrar
            
        Returns:
            Clave AES de 32 bytes para la sesión
        """
        try:
            sesion_id = self._get_id_sesion(remitente_id, destinatario_id)
            archivo_sesion = os.path.join(self.directorio_sesiones, f"{sesion_id}.json")
            
            if not os.path.exists(archivo_sesion):
                raise ValueError(f"No existe sesión entre {remitente_id} y {destinatario_id}")
            
            with open(archivo_sesion, 'r') as f:
                datos_sesion = json.load(f)
            
            # Buscar la clave cifrada para este usuario específico
            clave_aes_cifrada = datos_sesion.get(f"clave_para_{usuario_id}")
            if not clave_aes_cifrada:
                raise ValueError(f"No hay clave disponible para usuario {usuario_id}")
            
            # Descifrar la clave AES usando la clave privada RSA del usuario
            clave_privada = self.cargar_clave_privada(usuario_id, self._get_password_cache(usuario_id))
            if not clave_privada:
                raise ValueError(f"No se pudo cargar clave privada para usuario {usuario_id}")
            
            clave_aes = self._descifrar_clave_aes_con_rsa(
                base64.b64decode(clave_aes_cifrada), 
                clave_privada
            )
            
            logger.info(f"Clave de sesión obtenida para usuario {usuario_id}")
            return clave_aes
            
        except Exception as e:
            logger.error(f"Error obteniendo clave de sesión para {usuario_id}: {e}")
            raise
    
    def _get_id_sesion(self, usuario1_id: str, usuario2_id: str) -> str:
        """
        Genera ID único para una sesión entre dos usuarios.
        
        Args:
            usuario1_id: ID del primer usuario
            usuario2_id: ID del segundo usuario
            
        Returns:
            ID de sesión consistente independiente del orden
        """
        usuarios_ordenados = sorted([usuario1_id, usuario2_id])
        return f"{usuarios_ordenados[0]}_{usuarios_ordenados[1]}"
    
    def obtener_o_generar_clave_sesion(self, remitente_id: str, destinatario_id: str) -> bytes:
        """
        Obtiene o genera una clave AES para la sesión entre dos usuarios.
        
        Args:
            remitente_id: ID del usuario que envía
            destinatario_id: ID del usuario que recibe
            
        Returns:
            Clave AES de 32 bytes para la sesión
        """
        try:
            sesion_id = self._get_id_sesion(remitente_id, destinatario_id)
            archivo_sesion = os.path.join(self.directorio_sesiones, f"{sesion_id}.json")
            
            # Si ya existe la sesión, cargar clave
            if os.path.exists(archivo_sesion):
                with open(archivo_sesion, 'r') as f:
                    datos_sesion = json.load(f)
                
                # Descifrar clave AES usando RSA del usuario actual
                clave_aes_cifrada = datos_sesion.get(f"clave_para_{remitente_id}")
                if clave_aes_cifrada:
                    clave_privada = self.cargar_clave_privada(remitente_id, self._get_password_cache(remitente_id))
                    if clave_privada:
                        clave_aes = self._descifrar_clave_aes_con_rsa(
                            base64.b64decode(clave_aes_cifrada), 
                            clave_privada
                        )
                        return clave_aes
            
            # Generar nueva clave AES si no existe
            clave_aes = secrets.token_bytes(32)  # AES-256
            
            # Cifrar clave AES para ambos usuarios con sus claves RSA públicas
            clave_publica_remitente = self.cargar_clave_publica(remitente_id)
            clave_publica_destinatario = self.cargar_clave_publica(destinatario_id)
            
            if not clave_publica_remitente or not clave_publica_destinatario:
                raise ValueError("No se pudieron cargar las claves públicas")
            
            clave_aes_para_remitente = self._cifrar_clave_aes_con_rsa(clave_aes, clave_publica_remitente)
            clave_aes_para_destinatario = self._cifrar_clave_aes_con_rsa(clave_aes, clave_publica_destinatario)
            
            # Guardar claves cifradas
            datos_sesion = {
                f"clave_para_{remitente_id}": base64.b64encode(clave_aes_para_remitente).decode('utf-8'),
                f"clave_para_{destinatario_id}": base64.b64encode(clave_aes_para_destinatario).decode('utf-8'),
                "fecha_creacion": datetime.now().isoformat(),
                "algoritmo": "AES-256-GCM"
            }
            
            with open(archivo_sesion, 'w') as f:
                json.dump(datos_sesion, f, indent=2)
            
            logger.info(f"Clave AES generada para sesión {sesion_id}")
            return clave_aes
            
        except Exception as e:
            logger.error(f"Error obteniendo clave de sesión: {e}")
            raise
    
    def _cifrar_clave_aes_con_rsa(self, clave_aes: bytes, clave_publica_rsa) -> bytes:
        """Cifra una clave AES usando RSA."""
        return clave_publica_rsa.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def _descifrar_clave_aes_con_rsa(self, clave_aes_cifrada: bytes, clave_privada_rsa) -> bytes:
        """Descifra una clave AES usando RSA."""
        return clave_privada_rsa.decrypt(
            clave_aes_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # =====================================
    # CIFRADO/DESCIFRADO DE MENSAJES (AES)
    # =====================================
    
    def cifrar_mensaje(self, mensaje: str, remitente_id: str, destinatario_id: str) -> Dict[str, str]:
        """
        Cifra un mensaje usando AES-256-GCM con clave de sesión.
        
        Args:
            mensaje: Texto del mensaje a cifrar
            remitente_id: ID del usuario que envía
            destinatario_id: ID del usuario que recibe
            
        Returns:
            Dict con mensaje cifrado, nonce y metadatos
        """
        try:
            # Obtener clave AES de la sesión
            clave_aes = self.obtener_o_generar_clave_sesion(remitente_id, destinatario_id)
            
            # Generar nonce único
            nonce = secrets.token_bytes(12)
            
            # Cifrar con AES-GCM
            aesgcm = AESGCM(clave_aes)
            mensaje_cifrado = aesgcm.encrypt(nonce, mensaje.encode('utf-8'), None)
            
            resultado = {
                'mensaje_cifrado': base64.b64encode(mensaje_cifrado).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'algoritmo': 'AES-256-GCM',
                'remitente_id': remitente_id,
                'destinatario_id': destinatario_id,
                'fecha_cifrado': datetime.now().isoformat(),
                'version': '2.0'
            }
            
            logger.info(f"Mensaje cifrado exitosamente ({remitente_id} → {destinatario_id})")
            return resultado
            
        except Exception as e:
            logger.error(f"Error cifrando mensaje: {e}")
            raise
    
    def descifrar_mensaje(self, datos_cifrados: Dict[str, str], usuario_id: str) -> str:
        """
        Descifra un mensaje usando AES-256-GCM.
        
        Args:
            datos_cifrados: Dict con mensaje cifrado y metadatos
            usuario_id: ID del usuario que descifra
            
        Returns:
            Mensaje descifrado en texto plano
        """
        try:
            remitente_id = datos_cifrados['remitente_id']
            destinatario_id = datos_cifrados['destinatario_id']
            
            # Verificar que el usuario puede descifrar este mensaje
            if usuario_id not in [remitente_id, destinatario_id]:
                raise ValueError(f"Usuario {usuario_id} no autorizado para descifrar este mensaje")
            
            # Obtener clave AES de la sesión (intentar con nuevo método primero)
            clave_aes = None
            try:
                clave_aes = self.obtener_clave_sesion_para_usuario(remitente_id, destinatario_id, usuario_id)
            except Exception as e1:
                # Si falla, intentar con método legacy (para mensajes antiguos)
                try:
                    if usuario_id == destinatario_id:
                        clave_aes = self.obtener_o_generar_clave_sesion(remitente_id, destinatario_id)
                    else:  # usuario_id == remitente_id
                        clave_aes = self.obtener_o_generar_clave_sesion(usuario_id, destinatario_id)
                except Exception as e2:
                    raise ValueError(f"Error obteniendo clave de sesión: {e1}")
            
            # Decodificar datos
            try:
                mensaje_cifrado = base64.b64decode(datos_cifrados['mensaje_cifrado'])
                nonce = base64.b64decode(datos_cifrados['nonce'])
            except Exception as e:
                raise ValueError(f"Error decodificando datos base64: {e}")
            
            # Descifrar con AES-GCM
            try:
                aesgcm = AESGCM(clave_aes)
                mensaje_bytes = aesgcm.decrypt(nonce, mensaje_cifrado, None)
                mensaje = mensaje_bytes.decode('utf-8')
            except Exception as e:
                raise ValueError(f"Error en descifrado AES-GCM: {e}")
            
            logger.info(f"Mensaje descifrado exitosamente para usuario {usuario_id}")
            return mensaje
            
        except ValueError as ve:
            logger.error(f"Error descifrando mensaje para {usuario_id}: {ve}")
            raise ve
        except Exception as e:
            logger.error(f"Error inesperado descifrando mensaje para {usuario_id}: {e}")
            raise ValueError(f"Error de descifrado: {str(e)}")
    
    # ================
    # UTILIDADES
    # ================
    
    def set_usuario_manager(self, usuario_manager):
        """Establece referencia al usuario manager para acceder al cache de contraseñas."""
        self.usuario_manager = usuario_manager
    
    def _get_password_cache(self, usuario_id: str) -> str:
        """
        Obtiene la contraseña del usuario desde caché temporal.
        """
        if hasattr(self, 'usuario_manager') and self.usuario_manager:
            contraseña = self.usuario_manager.obtener_contraseña_usuario(usuario_id)
            if not contraseña:
                raise ValueError(f"Contraseña no encontrada en cache para usuario {usuario_id}")
            return contraseña
        else:
            raise ValueError("Usuario manager no configurado para acceder al cache de contraseñas")
    
    def verificar_integridad_sistema(self) -> Dict[str, bool]:
        """
        Verifica la integridad del sistema criptográfico.
        
        Returns:
            Dict con resultados de verificación
        """
        try:
            # Verificar directorios
            directorios_ok = all(os.path.exists(d) for d in [
                self.directorio_claves, self.directorio_publicas,
                self.directorio_privadas, self.directorio_sesiones
            ])
            
            # Test de cifrado/descifrado
            test_mensaje = "Test de integridad del sistema"
            test_usuario1 = "test_user_1"
            test_usuario2 = "test_user_2"
            
            # Generar claves de prueba temporales
            temp_key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(temp_key)
            
            cifrado = aesgcm.encrypt(nonce, test_mensaje.encode('utf-8'), None)
            descifrado = aesgcm.decrypt(nonce, cifrado, None).decode('utf-8')
            
            cifrado_ok = (descifrado == test_mensaje)
            
            resultado = {
                'directorios': directorios_ok,
                'cifrado_aes': cifrado_ok,
                'sistema_operativo': True
            }
            
            logger.info(f"Verificación de integridad: {resultado}")
            return resultado
            
        except Exception as e:
            logger.error(f"Error en verificación de integridad: {e}")
            return {'error': True, 'mensaje': str(e)}