"""
Módulo de autenticación de usuarios para la aplicación de quedadas de perros.
Implementa el apartado 1 de la práctica: Registro y autenticación de usuarios.
"""

import bcrypt
import secrets
import json
import os
import re
from typing import Dict, Optional, Any
from datetime import datetime
import logging
from criptografia_hibrida import CriptografiaHibrida

class Usuario:
    """Representa un usuario del sistema con sus datos y métodos asociados."""
    
    def __init__(self, id_usuario: str, nombre_usuario: str, hash_contraseña: str, email: str = "", fecha_registro: str = ""):
        self.id = id_usuario
        self.nombre_usuario = nombre_usuario
        self.hash_contraseña = hash_contraseña
        self.email = email
        self.fecha_registro = fecha_registro
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el usuario a diccionario para serialización JSON."""
        return{"id": self.id,
            "nombre_usuario": self.nombre_usuario,
            "hash_contraseña": self.hash_contraseña,
            "email": self.email,
            "fecha_registro": self.fecha_registro
            }
    
    @classmethod
    def from_dict(cls, datos: Dict[str, Any]) -> 'Usuario':
        """Crea un usuario desde un diccionario."""
        return cls(
            id_usuario=datos.get('id', ''),
            nombre_usuario=datos.get('nombre_usuario', ''),
            hash_contraseña=datos.get('hash_contraseña', ''),
            email=datos.get('email', ''),
            fecha_registro=datos.get('fecha_registro', '')
        )

class UsuarioManager:
    """Gestiona el registro y autenticación de usuarios de forma segura."""
    
    def __init__(self, archivo_usuarios: str = "JSON/usuarios.json"):
        self.archivo_usuarios = archivo_usuarios
        self.usuarios: Dict[str, Dict[str, Any]] = {}
        self.crypto_hibrida = CriptografiaHibrida()
        self.crypto_hibrida.set_usuario_manager(self)  # Configurar referencia circular
        self._cache_contraseñas = {}  # Cache temporal de contraseñas para sesión
        
        # Configurar logging para mostrar operaciones criptográficas
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Cargar usuarios después de configurar el logger
        self.cargar_usuarios()
    
    def cargar_usuarios(self) -> None:
        """Carga usuarios desde el archivo JSON si existe."""
        try:
            # Verificar si el archivo existe
            if os.path.exists(self.archivo_usuarios):
                # Abrir archivo en modo lectura con codificación UTF-8
                with open(self.archivo_usuarios, "r", encoding="utf-8") as f:
                    # Cargar JSON y convertir a diccionario Python
                    datos = json.load(f)
                    # Asignar a la variable de instancia
                    self.usuarios = datos
                    # Log de éxito
                    self.logger.info(f"Usuarios cargados desde disco: {len(self.usuarios)}  usuarios")
            else:
                # Si no existe el archivo, inicializar diccionario vacío
                self.usuarios = {}
                self.logger.info("Archivo de usuarios no existe, iniciando con base vacía")

        except Exception as e:
            # Log de error
            self.usuarios = {}
            self.logger.error(f"Error cargando usuarios: {e}")

    def guardar_usuarios(self) -> None:
        """Guarda usuarios en el archivo JSON."""   
        try:
            # Abrir archivo en modo escritura con codificación UTF-8
            with open(self.archivo_usuarios, "w", encoding="utf-8") as f:
                # Convertir diccionario a JSON con formato bonito
                json.dump(self.usuarios, f, indent=4, ensure_ascii=False)
            
            # Log de éxito
            self.logger.info(f"Usuarios guardados en disco: {len(self.usuarios)} usuarios")
            
        except Exception as e:
            # Log de error
            self.logger.error(f"Error guardando usuarios: {e}")
            raise
    
    def validar_contraseña_robusta(self, contraseña: str) -> bool:
        """
        Valida que la contraseña sea robusta según criterios de seguridad.
        Debe tener al menos 8 caracteres, mayúsculas, minúsculas, números y símbolos.
        """
        # Verificar longitud mínima de 8 caracteres
        if len(contraseña) < 8:
            self.logger.warning("Contraseña demasiado corta (menos de 8 caracteres)")
            return False

        # Al menos una mayúscula (A-Z)
        if not re.search(r"[A-Z]", contraseña):
            self.logger.warning("Contraseña sin mayúsculas")
            return False

        # Al menos una minúscula (a-z)
        if not re.search(r"[a-z]", contraseña):
            self.logger.warning("Contraseña sin minúsculas")
            return False

        # Al menos un número (0-9)
        if not re.search(r"\d", contraseña):
            self.logger.warning("Contraseña sin números")
            return False

        # Al menos un símbolo especial (!@#$%^&*()_+{}[]|;':\",./<>?)
        if not re.search(r"[^\w\s]", contraseña):
            self.logger.warning("Contraseña sin símbolos especiales")
            return False

        # Si pasa todas las validaciones
        self.logger.info("Contraseña validada como robusta")
        return True
    
    def hash_contraseña(self, contraseña: str) -> str:
        """
        Genera hash seguro de la contraseña usando bcrypt con salt automático.
        bcrypt incorpora salt automáticamente y es resistente a ataques de fuerza bruta.
        """
        try:
            # Convertimos la contraseña a bytes
            contraseña_bytes = contraseña.encode("utf-8")

            # Generamos un salt aleatorio y único para la contraseña con gensalt(), hacemos el hash y lo convertimos a string para almaacenarlo en JSON
            hash_bytes = bcrypt.hashpw(contraseña_bytes, bcrypt.gensalt())
            hash_string = hash_bytes.decode("utf-8")

            # Log de operación exitosa 
            self.logger.info("Hash de contraseña generado correctamente")

            #Retornamos el hash
            return hash_string
        
        except Exception as e:
            # Si algo falla, loguear error y lanzar excepción
            self.logger.error(f"Error generando hash: {e}")
            raise
            
    
    def verificar_contraseña(self, contraseña: str, hash_almacenado: str) -> bool:
        """
        Verifica si la contraseña proporcionada coincide con el hash almacenado.
        """
        try:
            # Convertir contraseña a bytes
            contraseña_bytes = contraseña.encode("utf-8")

            # Convertir hash almacenado a bytes
            hash_bytes = hash_almacenado.encode("utf-8")

            # checkpw() se encarga de extraer el salt del hash almacenado, hashear la nueva contraseña con ese salt y comprobar si los hashes coinciden
            resultado = bcrypt.checkpw(contraseña_bytes, hash_bytes)

            if resultado:
                self.logger.info("Contraseña verificada correctamente")
            else:
                self.logger.warning("Contraseña incorrecta")

            return resultado

        except Exception as e:
            # Si hay error en la verificación, devolver False
            self.logger.error(f"Error verificando contraseña: {e}")
            return False
    
    def registrar_usuario(self, nombre_usuario: str, contraseña: str, email: str = "") -> bool:
        """
        Registra un nuevo usuario con contraseña segura y claves RSA.
        
        Args:
            nombre_usuario: Nombre único del usuario
            contraseña: Contraseña en texto plano (se hashea automáticamente)
            email: Email opcional del usuario
        
        Returns:
            bool: True si el registro fue exitoso, False si el usuario ya existe o la contraseña no es robusta
        """
        #Comprobar que no exista el nombre de usuario
        if nombre_usuario in self.usuarios:
            self.logger.warning(f"Intento de registro de usuario existente: {nombre_usuario}")
            return False
        
        #Comprobar que la contraseña sea robusta
        if not self.validar_contraseña_robusta(contraseña):
            self.logger.warning(f"Registro fallido por contraseña débil: {nombre_usuario}")
            return False
        
        #si se cumple generamos ID único, hash, timestamp del registro, creamos el usuario y lo almacenamos
        try:
            id_usuario = secrets.token_hex(8) # Genera string aleatorio de 16 caracteres
            hash_contraseña = self.hash_contraseña(contraseña)
            fecha_registro = datetime.now().isoformat()
            
            print("Generando par de claves RSA (esto puede tomar unos segundos)...")
            
            # Generar par de claves RSA para el usuario
            try:
                claves_rsa = self.crypto_hibrida.generar_par_claves_usuario(id_usuario, contraseña)
                print("Par de claves RSA generado exitosamente")
            except Exception as e:
                print(f"Error generando claves RSA: {e}")
                return False
            
            usuario = Usuario(id_usuario=id_usuario,
                            nombre_usuario=nombre_usuario,
                            hash_contraseña=hash_contraseña,
                            email=email,
                            fecha_registro=fecha_registro)
            self.usuarios[nombre_usuario] = usuario.to_dict()
            self.guardar_usuarios()
            self.logger.info(f"Usuario registrado exitosamente con claves RSA: {nombre_usuario}")
            print(f"Usuario '{nombre_usuario}' registrado exitosamente con criptografia RSA.")
            return True
        
        #en caso de fallo
        except Exception as e:
            self.logger.error(f"Error registrando usuario {nombre_usuario}: {e}")
            return False
    def autenticar_usuario(self, nombre_usuario: str, contraseña: str) -> Optional[Dict[str, Any]]:
        """
        Autentica un usuario verificando sus credenciales y cacheando la contraseña.
        
        Args:
            nombre_usuario: Nombre del usuario
            contraseña: Contraseña en texto plano
        
        Returns:
            Dict con información del usuario si la autenticación es exitosa, None en caso contrario
        """
        #buscamos el usuario en el diccionario de usuarios, extraemos hash y verificamos la contraseña
        usuario_autenticar = self.usuarios.get(nombre_usuario)

        if not usuario_autenticar:
            self.logger.warning(f"Intento de login con usuario inexistente: {nombre_usuario}")
            return None
        
        hash_extraido = usuario_autenticar["hash_contraseña"]

        if self.verificar_contraseña(contraseña, hash_extraido):
            # Cachear contraseña para uso en criptografía (temporal para sesión)
            usuario_id = usuario_autenticar.get('id')
            if usuario_id:
                self._cache_contraseñas[usuario_id] = contraseña
            
            self.logger.info(f"Autenticación exitosa: {nombre_usuario}")
            return usuario_autenticar
        
        else:
            self.logger.warning(f"Intento de login con contraseña incorrecta: {nombre_usuario}")
            return None
    def listar_usuarios(self) -> list:
        """Retorna lista de nombres de usuarios registrados (para pruebas)."""
        return list(self.usuarios.keys())
    
    def eliminar_usuario(self, nombre_usuario: str, perro_manager=None, mensaje_manager=None) -> bool:
        """Elimina un usuario del sistema y, opcionalmente, sus recursos asociados.

        Si se proporciona `perro_manager` se recorrerán los perros del usuario y se
        llamará a `perro_manager.borrar_perro(usuario_id, perro_id)` para cada uno.
        Si se proporciona `mensaje_manager` y tiene el método
        `borrar_mensajes_de_usuario(usuario_id)` se intentará borrar los mensajes
        asociados también.
        """
        usuario = self.usuarios.get(nombre_usuario)
        if not usuario:
            return False

        usuario_id = usuario.get("id")

        # Eliminar el usuario de la colección y persistir
        try:
            del self.usuarios[nombre_usuario]
            self.guardar_usuarios()
            self.logger.info(f"Usuario {nombre_usuario} eliminado (id={usuario_id})")
        except Exception as e:
            logging.error(f"Error eliminando usuario {nombre_usuario}: {e}")
            return False
    
        # Borrar perros asociados (si se proporciona el manager)
        if perro_manager is not None:
            try:
                # Tomar una copia de los ids para no mutar la lista mientras iteramos
                perros_list = perro_manager.perros.get(usuario_id, [])
                perro_ids = [p.get("id") for p in perros_list]
                for pid in perro_ids:
                    try:
                        perro_manager.borrar_perro(usuario_id, pid)
                    except Exception as e:
                        # No abortamos si falla un borrado individual
                        self.logger.warning(f"Error borrando perro {pid} de {usuario_id}: {e}")
            except Exception as e:
                self.logger.warning(f"No se pudieron borrar perros de {usuario_id}: {e}")

        # Borrar mensajes asociados (si se proporciona el manager y tiene el método)
        if mensaje_manager is not None and hasattr(mensaje_manager, "borrar_mensajes_de_usuario"):
            try:
                mensaje_manager.borrar_mensajes_de_usuario(usuario_id)
            except Exception as e:
                self.logger.warning(f"No se pudieron borrar mensajes de {usuario_id}: {e}")

        return True
    
    def obtener_contraseña_usuario(self, usuario_id: str) -> Optional[str]:
        """Obtiene la contraseña cacheada de un usuario para operaciones criptográficas."""
        return self._cache_contraseñas.get(usuario_id)
    
    def obtener_usuario_por_id(self, usuario_id: str) -> Optional[Usuario]:
        """Obtiene un objeto Usuario por su ID."""
        for usuario_data in self.usuarios.values():
            if usuario_data.get('id') == usuario_id:
                return Usuario.from_dict(usuario_data)
        return None
    
    def limpiar_cache_contraseñas(self):
        """Limpia el cache de contraseñas al cerrar sesión."""
        self._cache_contraseñas.clear()
        logging.info("Cache de contraseñas limpiado")