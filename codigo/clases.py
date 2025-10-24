"""
Módulo de modelo de datos para la aplicación de quedadas de perros.
Define las estructuras de datos para usuarios, perros y mensajes.
"""

import json
import os
import secrets
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from criptografia import CriptografiaManager


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

    def validar_identificador(self) -> bool:
        """
        Valida el identificador oficial del perro.
        Acepta microchip numérico de 15 dígitos o identificadores alfanuméricos razonables.
        """
        if not getattr(self, "identificador_oficial", None):
            return False

        id_str = str(self.identificador_oficial).strip()

        # Microchip: exactamente 15 dígitos
        if re.fullmatch(r"\d{15}", id_str):
            return True

        # Otros identificadores alfanuméricos razonables (4-32 chars)
        if re.fullmatch(r"[A-Za-z0-9\-\_]{4,32}", id_str):
            return True

        return False

    def generar_id_publico(self) -> str:
        """
        Genera un id público no sensible para mostrar en la app.
        Construye un 'slug' corto del nombre y añade un token aleatorio.
        """
        nombre = getattr(self, "nombre", "") or ""
        slug = re.sub(r"[^a-z0-9]+", "-", nombre.lower()).strip("-")
        slug = slug[:20] or "perro"

        token = secrets.token_hex(4)  # 8 hex chars
        id_publico = f"{slug}-{token}"
        setattr(self, "id_publico", id_publico)
        return id_publico


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
    
    def __init__(self, archivo_perros: str = "JSON/perros.json"):
        self.archivo_perros = archivo_perros
        self.perros: Dict[str, List[Dict[str, Any]]] = {}  # usuario_id -> [perros]
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Cargar perros después de configurar logger
        self.cargar_perros()
    
    def cargar_perros(self) -> None:
        """Carga los perros desde el archivo JSON."""
        if os.path.exists(self.archivo_perros):
            with open(self.archivo_perros, "r", encoding="utf-8") as f:
                self.perros = json.load(f)
            self.logger.info(f"Perros cargados: {sum(len(v) for v in self.perros.values())}")
        else:
            self.perros = {}
    
    def guardar_perros(self) -> None:
        """Guarda los perros en el archivo JSON."""
        try:
            with open(self.archivo_perros, "w", encoding="utf-8") as f:
                json.dump(self.perros, f, indent=4, ensure_ascii=False)

            self.logger.info(f"Perros guardados en disco: {sum(len(v) for v in self.perros.values())} perros")

        except Exception as e:
            self.logger.error(f"Error guardando perros: {e}")
            raise
    
    
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
        id_perro = secrets.token_hex(8)
        perro_a_registrar = Perro(id_perro, nombre, identificador_oficial, descripcion)
        if usuario_id not in self.perros:
            self.perros[usuario_id] = []
        self.perros[usuario_id].append(perro_a_registrar.to_dict())
        self.guardar_perros()
        self.logger.info(f"Perro registrado: {nombre} para usuario {usuario_id}")
        return perro_a_registrar
    
    def obtener_perros_usuario(self, usuario_id: str) -> List[Perro]:
        """Obtiene todos los perros de un usuario."""
        perros_obtenidos = self.perros.get(usuario_id, [])
        return [Perro.from_dict(p) for p in perros_obtenidos]
    
    def obtener_perros_publicos(self) -> List[Dict[str, Any]]:
        """Obtiene todos los perros con fotos públicas."""
        perros_publicos = []
        for usuario_id, perro_list in self.perros.items():
            for perro in perro_list:
                if perro.get("publico", True):
                    # Convertir el dict almacenado a objeto Perro para la UI
                    perro_obj = Perro.from_dict(perro)
                    perros_publicos.append({"perro": perro_obj, "propietario_id": usuario_id})
        return perros_publicos
    
    def buscar_perro_por_id(self, perro_id: str) -> Optional[Dict[str, Any]]:
        """Busca un perro por su ID y retorna el perro con el ID del propietario."""
        for usuario_id, perros_list in self.perros.items():
            for perro in perros_list:
                if perro.get("id") == perro_id:
                    # Devolver objeto Perro junto con el propietario
                    perro_obj = Perro.from_dict(perro)
                    return {"perro": perro_obj, "propietario_id": usuario_id}
        return None

    def borrar_perro(self, usuario_id: str, perro_id: str) -> bool:
        """Elimina un perro registrado para un usuario. Devuelve True si se borró."""
        if usuario_id not in self.perros:
            return False

        perros_list = self.perros[usuario_id]
        for i, perro in enumerate(perros_list):
            if perro.get("id") == perro_id:
                # eliminar y persistir
                del perros_list[i]
                # si la lista queda vacía, eliminar la clave del usuario
                if not perros_list:
                    del self.perros[usuario_id]
                else:
                    self.perros[usuario_id] = perros_list
                self.guardar_perros()
                self.logger.info(f"Perro {perro_id} eliminado para usuario {usuario_id}")
                return True

        return False


class MensajeManager:
    """Gestiona los mensajes entre usuarios del sistema con cifrado automático."""
    
    def __init__(self, archivo_mensajes: str = "JSON/mensajes.json"):
        self.archivo_mensajes = archivo_mensajes
        self.mensajes: List[Dict[str, Any]] = []
        
        # Configurar logging
        self.logger = logging.getLogger(__name__)
        
        # Inicializar gestor criptográfico
        try:
            self.crypto_manager = CriptografiaManager()
            self.logger.info("Sistema de cifrado inicializado correctamente")
        except Exception as e:
            self.logger.error(f"Error inicializando sistema de cifrado: {e}")
            raise
        
        # Cargar mensajes después de configurar logger
        self.cargar_mensajes()
    
    def cargar_mensajes(self) -> None:
        """Carga los mensajes desde el archivo JSON."""
        try:
            if os.path.exists(self.archivo_mensajes):
                with open(self.archivo_mensajes, "r", encoding="utf-8") as f:
                    self.mensajes = json.load(f)
                self.logger.info(f"Mensajes cargados desde disco: {len(self.mensajes)} mensajes")
            else:
                self.mensajes = []
                self.logger.info("Archivo de mensajes no existe, iniciando con base vacía")
        except Exception as e:
            # En caso de error dejamos la lista vacía y registramos el fallo
            self.mensajes = []
            self.logger.error(f"Error cargando mensajes: {e}")
    
    def guardar_mensajes(self) -> None:
        """Guarda los mensajes en el archivo JSON."""
        try:
            with open(self.archivo_mensajes, "w", encoding="utf-8") as f:
                json.dump(self.mensajes, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Mensajes guardados en disco: {len(self.mensajes)} mensajes")
        except Exception as e:
            self.logger.error(f"Error guardando mensajes: {e}")
            raise
    
    def enviar_mensaje(self, remitente_id: str, destinatario_id: str, contenido: str) -> Mensaje:
        """
        Crea un nuevo mensaje y lo cifra automáticamente usando AES-256-GCM.
        
        Args:
            remitente_id: ID del usuario que envía
            destinatario_id: ID del usuario que recibe
            contenido: Contenido del mensaje (se cifrará automáticamente)
        
        Returns:
            Mensaje: El mensaje creado con contenido cifrado
        """
        try:
            # Generar ID único para el mensaje
            id_mensaje = secrets.token_hex(8)
            
            # Crear objeto mensaje
            mensaje = Mensaje(id_mensaje, remitente_id, destinatario_id, contenido)
            
            # CIFRAR EL CONTENIDO automáticamente
            datos_cifrados = self.crypto_manager.cifrar_mensaje(contenido)
            mensaje.contenido_cifrado = json.dumps(datos_cifrados)
            
            # Guardar en la lista y persistir
            self.mensajes.append(mensaje.to_dict())
            self.guardar_mensajes()
            
            self.logger.info(f"Mensaje enviado y cifrado: {id_mensaje} de {remitente_id} a {destinatario_id}")
            return mensaje
            
        except Exception as e:
            self.logger.error(f"Error enviando mensaje cifrado: {e}")
            raise
    
    def obtener_mensajes_usuario(self, usuario_id: str) -> List[Mensaje]:
        """
        Obtiene todos los mensajes enviados y recibidos por un usuario.
        Los mensajes se descifran automáticamente para mostrar el contenido.
        """
        try:
            # Filtrar mensajes del usuario
            mensajes_filtrados = [
                m for m in self.mensajes
                if m.get("remitente_id") == usuario_id or m.get("destinatario_id") == usuario_id
            ]
            
            resultados = []
            for m in mensajes_filtrados:
                # Crear objeto mensaje
                mensaje = Mensaje.from_dict(m)
                
                # DESCIFRAR EL CONTENIDO automáticamente si está cifrado
                if mensaje.contenido_cifrado:
                    try:
                        mensaje.contenido_original = self.crypto_manager.descifrar_desde_almacenamiento(
                            mensaje.contenido_cifrado
                        )
                        self.logger.debug(f"Mensaje {mensaje.id} descifrado correctamente")
                    except Exception as e:
                        self.logger.error(f"Error descifrando mensaje {mensaje.id}: {e}")
                        mensaje.contenido_original = "[ERROR: Mensaje no pudo ser descifrado]"
                
                resultados.append(mensaje)
            
            return resultados
            
        except Exception as e:
            self.logger.error(f"Error obteniendo mensajes de usuario {usuario_id}: {e}")
            return []
    
    def marcar_como_leido(self, mensaje_id: str, usuario_id: str) -> bool:
        """Marca un mensaje como leído si el usuario es el destinatario."""
        for m in self.mensajes:
            if m.get("id") == mensaje_id and m.get("destinatario_id") == usuario_id:
                m["leido"] = True                        # marcar en el dict en memoria
                self.guardar_mensajes()                  # persistir cambio
                self.logger.info(f"Mensaje {mensaje_id} marcado como leído por {usuario_id}")
                return True
        return False
    
    def verificar_sistema_cifrado(self) -> bool:
        """
        Verifica que el sistema de cifrado de mensajes funcione correctamente.
        
        Returns:
            True si el cifrado/descifrado funciona correctamente
        """
        try:
            # Usar el verificador interno del crypto_manager
            return self.crypto_manager.verificar_integridad_sistema()
        except Exception as e:
            self.logger.error(f"Error verificando sistema de cifrado: {e}")
            return False
    
    def obtener_estadisticas_cifrado(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas sobre el cifrado de mensajes.
        
        Returns:
            Dict con estadísticas del sistema de cifrado
        """
        try:
            total_mensajes = len(self.mensajes)
            mensajes_cifrados = sum(1 for m in self.mensajes if m.get('contenido_cifrado'))
            
            return {
                'total_mensajes': total_mensajes,
                'mensajes_cifrados': mensajes_cifrados,
                'mensajes_texto_plano': total_mensajes - mensajes_cifrados,
                'porcentaje_cifrado': (mensajes_cifrados / total_mensajes * 100) if total_mensajes > 0 else 0,
                'sistema_criptografico': self.crypto_manager.obtener_informacion_sistema()
            }
        except Exception as e:
            self.logger.error(f"Error obteniendo estadísticas de cifrado: {e}")
            return {'error': str(e)}
    
    def borrar_mensajes_de_usuario(self, usuario_id: str) -> int:
        """
        Elimina todos los mensajes enviados y recibidos por un usuario.
        
        Args:
            usuario_id: ID del usuario cuyos mensajes se van a eliminar
            
        Returns:
            int: Número de mensajes eliminados
        """
        try:
            # Contar mensajes antes de borrar
            mensajes_iniciales = len(self.mensajes)
            
            # Filtrar mensajes que NO son del usuario
            self.mensajes = [
                m for m in self.mensajes
                if m.get("remitente_id") != usuario_id and m.get("destinatario_id") != usuario_id
            ]
            
            # Calcular cuántos se eliminaron
            mensajes_eliminados = mensajes_iniciales - len(self.mensajes)
            
            # Guardar cambios
            if mensajes_eliminados > 0:
                self.guardar_mensajes()
                self.logger.info(f"Eliminados {mensajes_eliminados} mensajes del usuario {usuario_id}")
            
            return mensajes_eliminados
            
        except Exception as e:
            self.logger.error(f"Error eliminando mensajes del usuario {usuario_id}: {e}")
            return 0

