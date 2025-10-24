"""
Implementa los apartados 2 y 3 de la práctica:
- Apartado 2: Cifrado/descifrado simétrico con AES-256-GCM
- Apartado 3: Generación/verificación de etiquetas de autenticación integradas en GCM
"""

import os
import base64
import secrets
import json
from typing import Dict, Tuple, Optional, Any
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class CriptografiaManager:
    """Gestiona las operaciones criptográficas de la aplicación usando AES-256-GCM."""
    
    def __init__(self, archivo_claves: str = "JSON/claves_sistema.json"):
        """
        Inicializa el gestor criptográfico.
        
        Args:
            archivo_claves: Ruta al archivo de claves del sistema
        """
        self.archivo_claves = archivo_claves
        self.logger = logging.getLogger(__name__)
        
        # Cargar o generar claves del sistema
        self.claves_sistema = self.cargar_o_generar_claves()
        
        self.logger.info("CriptografiaManager inicializado correctamente")
    
    def cargar_o_generar_claves(self) -> Dict[str, str]:
        """
        Carga las claves del sistema desde archivo o las genera si no existen.
        
        Returns:
            Dict con las claves del sistema en base64
        """
        try:
            if os.path.exists(self.archivo_claves):
                with open(self.archivo_claves, 'r', encoding='utf-8') as f:
                    claves = json.load(f)
                self.logger.info("Claves del sistema cargadas desde archivo")
                return claves
            else:
                # Generar nuevas claves
                claves = self.generar_claves_sistema()
                self.guardar_claves_sistema(claves)
                self.logger.info("Nuevas claves del sistema generadas y guardadas")
                return claves
        except Exception as e:
            self.logger.error(f"Error manejando claves del sistema: {e}")
            # En caso de error, generar claves temporales
            return self.generar_claves_sistema()
    
    def generar_claves_sistema(self) -> Dict[str, str]:
        """
        Genera nuevas claves criptográficas para el sistema.
        
        Returns:
            Dict con claves en formato base64
        """
        # Generar clave AES-256 (32 bytes)
        clave_aes = secrets.token_bytes(32)
        
        # Generar sal para PBKDF2 (16 bytes)
        salt = secrets.token_bytes(16)
        
        claves = {
            'clave_aes': base64.b64encode(clave_aes).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'version': '1.0',
            'algoritmo': 'AES-256-GCM'
        }
        
        self.logger.info("Claves del sistema generadas")
        return claves
    
    def guardar_claves_sistema(self, claves: Dict[str, str]) -> None:
        """
        Guarda las claves del sistema en archivo JSON.
        
        Args:
            claves: Diccionario con las claves a guardar
        """
        try:
            # Crear directorio JSON si no existe
            os.makedirs(os.path.dirname(self.archivo_claves), exist_ok=True)
            
            with open(self.archivo_claves, 'w', encoding='utf-8') as f:
                json.dump(claves, f, indent=4, ensure_ascii=False)
            
            self.logger.info("Claves del sistema guardadas en archivo")
        except Exception as e:
            self.logger.error(f"Error guardando claves del sistema: {e}")
            raise
    
    def obtener_clave_aes(self) -> bytes:
        """
        Obtiene la clave AES-256 del sistema.
        
        Returns:
            Clave AES en formato bytes
        """
        clave_b64 = self.claves_sistema.get('clave_aes')
        if not clave_b64:
            raise ValueError("Clave AES no encontrada en el sistema")
        return base64.b64decode(clave_b64)
    
    def generar_nonce(self) -> bytes:
        """
        Genera un nonce único para GCM (12 bytes recomendados).
        
        Returns:
            Nonce aleatorio de 12 bytes
        """
        return secrets.token_bytes(12)
    
    def cifrar_mensaje(self, mensaje: str) -> Dict[str, str]:
        """
        Cifra un mensaje usando AES-256-GCM.
        
        Args:
            mensaje: Texto plano a cifrar
            
        Returns:
            Dict con mensaje cifrado, nonce y metadatos
        """
        try:
            # Obtener clave del sistema
            clave = self.obtener_clave_aes()
            
            # Generar nonce único
            nonce = self.generar_nonce()
            
            # Crear instancia AES-GCM
            aesgcm = AESGCM(clave)
            
            # Cifrar mensaje (incluye autenticación automática)
            mensaje_cifrado = aesgcm.encrypt(nonce, mensaje.encode('utf-8'), None)
            
            # Preparar resultado en formato base64 para JSON
            resultado = {
                'mensaje_cifrado': base64.b64encode(mensaje_cifrado).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'algoritmo': 'AES-256-GCM',
                'version': '1.0'
            }
            
            self.logger.debug(f"Mensaje cifrado correctamente (tamaño: {len(mensaje)} chars)")
            return resultado
            
        except Exception as e:
            self.logger.error(f"Error cifrando mensaje: {e}")
            raise
    
    def descifrar_mensaje(self, datos_cifrados: Dict[str, str]) -> str:
        """
        Descifra un mensaje usando AES-256-GCM.
        
        Args:
            datos_cifrados: Dict con mensaje cifrado y nonce
            
        Returns:
            Mensaje en texto plano
        """
        try:
            # Obtener clave del sistema
            clave = self.obtener_clave_aes()
            
            # Decodificar datos de base64
            mensaje_cifrado = base64.b64decode(datos_cifrados['mensaje_cifrado'])
            nonce = base64.b64decode(datos_cifrados['nonce'])
            
            # Crear instancia AES-GCM
            aesgcm = AESGCM(clave)
            
            # Descifrar mensaje (verifica autenticación automáticamente)
            mensaje_bytes = aesgcm.decrypt(nonce, mensaje_cifrado, None)
            mensaje = mensaje_bytes.decode('utf-8')
            
            self.logger.debug(f"Mensaje descifrado correctamente (tamaño: {len(mensaje)} chars)")
            return mensaje
            
        except Exception as e:
            self.logger.error(f"Error descifrando mensaje: {e}")
            # En GCM, cualquier error puede indicar manipulación
            raise ValueError("Error de descifrado o mensaje manipulado")
    
    def cifrar_para_almacenamiento(self, texto: str) -> str:
        """
        Cifra texto y lo convierte a formato JSON para almacenamiento.
        
        Args:
            texto: Texto a cifrar
            
        Returns:
            String JSON con datos cifrados
        """
        datos_cifrados = self.cifrar_mensaje(texto)
        return json.dumps(datos_cifrados)
    
    def descifrar_desde_almacenamiento(self, json_cifrado: str) -> str:
        """
        Descifra texto desde formato JSON almacenado.
        
        Args:
            json_cifrado: String JSON con datos cifrados
            
        Returns:
            Texto descifrado
        """
        try:
            datos_cifrados = json.loads(json_cifrado)
            return self.descifrar_mensaje(datos_cifrados)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decodificando JSON cifrado: {e}")
            raise ValueError("Formato de datos cifrados inválido")
    
    def verificar_integridad_sistema(self) -> bool:
        """
        Verifica que el sistema criptográfico esté funcionando correctamente.
        
        Returns:
            True si el sistema funciona correctamente
        """
        try:
            # Mensaje de prueba
            mensaje_prueba = "Prueba de integridad del sistema criptográfico"
            
            # Cifrar y descifrar
            datos_cifrados = self.cifrar_mensaje(mensaje_prueba)
            mensaje_descifrado = self.descifrar_mensaje(datos_cifrados)
            
            # Verificar que coincidan
            if mensaje_prueba == mensaje_descifrado:
                self.logger.info("Sistema criptográfico verificado correctamente")
                return True
            else:
                self.logger.error("Fallo en la verificación del sistema criptográfico")
                return False
                
        except Exception as e:
            self.logger.error(f"Error en verificación de integridad: {e}")
            return False
    
    def obtener_informacion_sistema(self) -> Dict[str, Any]:
        """
        Obtiene información sobre el sistema criptográfico.
        
        Returns:
            Dict con información del sistema
        """
        return {
            'algoritmo': 'AES-256-GCM',
            'tamaño_clave': '256 bits',
            'tamaño_nonce': '96 bits (12 bytes)',
            'autenticacion': 'Integrada (GCM)',
            'version': self.claves_sistema.get('version', '1.0'),
            'archivo_claves': self.archivo_claves,
            'claves_cargadas': bool(self.claves_sistema)
        }

