"""
Módulo de modelo de datos para la aplicación de quedadas de perros.
Define las estructuras de datos para usuarios, perros y mensajes.
"""

import json
import os
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging


class Perro:
    """Clase que representa un perro en el sistema."""
    
    def __init__(self, id_perro: str, nombre: str, identificador_oficial: str, descripcion: str = ""):
        """
        Inicializa un perro con sus datos básicos.
        
        Args:
            id_perro: ID único generado por el manager
            nombre: Nombre del perro
            identificador_oficial: Número de microchip, pedigree, o identificación oficial
            descripcion: Descripción del perro (raza, color, características, etc.)
        """
        self.id = id_perro
        self.nombre = nombre
        self.identificador_oficial = identificador_oficial
        self.descripcion = descripcion
        self.fecha_registro = datetime.now().isoformat()
        self.publico = True  # Si la descripción es pública o privada
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el perro a diccionario para almacenamiento."""
        return{"id": self.id,
            "nombre": self.nombre,
            "identificador_oficial": self.identificador_oficial,
            "descripcion": self.descripcion,
            "fecha_registro": self.fecha_registro,
            "publico": self.publico
            }
    
    @classmethod
    def from_dict(cls, datos: Dict[str, Any]) -> 'Perro':
        """Crea un perro desde un diccionario."""
        return cls(
            id_perro=datos.get('id', ''),
            nombre=datos.get('nombre', ''),
            identificador_oficial=datos.get('identificador_oficial', ''),
            descripcion=datos.get('descripcion', '')
        )


class Mensaje:
    """Clase que representa un mensaje entre usuarios."""
    
    def __init__(self, id_mensaje: str, remitente_id: str, destinatario_id: str, contenido: str):
        """
        Inicializa un mensaje.
        
        Args:
            id_mensaje: ID único generado por el manager
            remitente_id: ID del usuario que envía el mensaje
            destinatario_id: ID del usuario que recibe el mensaje
            contenido: Contenido del mensaje (se cifrará automáticamente)
        """
        self.id = id_mensaje
        self.remitente_id = remitente_id
        self.destinatario_id = destinatario_id
        self.contenido_original = contenido  # Contenido en texto plano (antes de cifrar)
        self.contenido_cifrado = ""  # Contenido cifrado (se llenará en criptografía.py)
        self.fecha_envio = datetime.now().isoformat()
        self.leido = False  # Si el destinatario ha leído el mensaje
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el mensaje a diccionario para almacenamiento."""
        return {"id": self.id,
            "remitente_id": self.remitente_id,
            "destinatario_id": self.destinatario_id,
            "contenido_original": self.contenido_original,
            "contenido_cifrado": self.contenido_cifrado,
            "fecha_envio": self.fecha_envio,
            "leido": self.leido
            }
    
    @classmethod
    def from_dict(cls, datos: Dict[str, Any]) -> 'Mensaje':
        """Crea un mensaje desde un diccionario."""
        mensaje = cls(
            id_mensaje=datos.get('id', ''),
            remitente_id=datos.get('remitente_id', ''),
            destinatario_id=datos.get('destinatario_id', ''),
            contenido=datos.get('contenido_original', '')
        )
        # Restaurar propiedades adicionales
        mensaje.contenido_cifrado = datos.get('contenido_cifrado', '')
        mensaje.fecha_envio = datos.get('fecha_envio', '')
        mensaje.leido = datos.get('leido', False)
        return mensaje


class PerroManager:
    """Gestiona los perros registrados en el sistema."""
    
    def __init__(self, archivo_perros: str = "perros.json"):
        self.archivo_perros = archivo_perros
        self.perros: Dict[str, Dict[str, Any]] = {}  # usuario_id -> [perros]
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Cargar perros después de configurar logger
        self.cargar_perros()
    
    def cargar_perros(self) -> None:
        """Carga los perros desde el archivo JSON."""
        
    
    def guardar_perros(self) -> None:
        """Guarda los perros en el archivo JSON."""


    def registrar_perro(self, usuario_id: str, nombre: str, identificador_oficial: str, descripcion: str = "") -> Perro:
        """
        Registra un nuevo perro para un usuario.
        
        Args:
            usuario_id: ID del usuario propietario
            nombre: Nombre del perro
            identificador_oficial: Identificación oficial del perro
            descripcion: Descripción del perro (opcional)
        
        Returns:
            Perro: El perro registrado
        """
        
    
    def obtener_perros_usuario(self, usuario_id: str) -> List[Perro]:
        """Obtiene todos los perros de un usuario."""
        
    
    def obtener_perros_publicos(self) -> List[Dict[str, Any]]:
        """Obtiene todos los perros con fotos públicas."""
        
    
    def buscar_perro_por_id(self, perro_id: str) -> Optional[Dict[str, Any]]:
        """Busca un perro por su ID y retorna el perro con el ID del propietario."""
        


class MensajeManager:
    """Gestiona los mensajes entre usuarios."""
    
    def __init__(self, archivo_mensajes: str = "mensajes.json"):
        self.archivo_mensajes = archivo_mensajes
        self.mensajes: List[Dict[str, Any]] = []
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Cargar mensajes después de configurar logger
        self.cargar_mensajes()
    
    def cargar_mensajes(self) -> None:
        """Carga los mensajes desde el archivo JSON."""
        
    
    def guardar_mensajes(self) -> None:
        """Guarda los mensajes en el archivo JSON."""
        
    
    def enviar_mensaje(self, remitente_id: str, destinatario_id: str, contenido: str) -> Mensaje:
        """
        Crea un nuevo mensaje (se cifrará en criptografía.py).
        
        Args:
            remitente_id: ID del usuario que envía
            destinatario_id: ID del usuario que recibe
            contenido: Contenido del mensaje
        
        Returns:
            Mensaje: El mensaje creado
        """
    
    def obtener_mensajes_usuario(self, usuario_id: str) -> List[Mensaje]:
        """Obtiene todos los mensajes enviados y recibidos por un usuario."""
        
    
    def marcar_como_leido(self, mensaje_id: str, usuario_id: str) -> bool:
        """Marca un mensaje como leído si el usuario es el destinatario."""
        

