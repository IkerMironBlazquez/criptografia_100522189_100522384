"""
Aplicación de Mensajería Híbrida para Quedadas de Perros
Práctica de Criptografía y Seguridad Informática

Implementa los apartados 1, 2 y 3 de la práctica con arquitectura realista:
1. Registro y autenticación de usuarios (bcrypt) + Generación de claves RSA
2. Cifrado híbrido: RSA-2048 para intercambio de claves + AES-256-GCM para mensajes
3. Autenticación integrada: GCM para integridad de mensajes + RSA para integridad de claves

Arquitectura:
- Cada usuario tiene par de claves RSA (pública/privada)
- Cada conversación usa clave AES única intercambiada vía RSA
- Los mensajes se cifran con AES-256-GCM (sin límite de tamaño)
- La autenticación es automática (GCM incluye MAC)
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

# Importar nuestros módulos
from autenticacion import UsuarioManager
from clases import PerroManager, MensajeManager, Mensaje


class AplicacionQuedadasPerros:
    
    def __init__(self):
        """Inicializa la aplicación y sus componentes."""
        # Configurar logging para archivo en lugar de consola
        self._configurar_logging()
        self.logger = logging.getLogger(__name__)
        
        # Inicializar gestores
        self.usuario_manager = UsuarioManager()
        self.perro_manager = PerroManager()
        # MensajeManager necesita referencia al usuario_manager para criptografía híbrida
        self.mensaje_manager = MensajeManager(usuario_manager=self.usuario_manager)
        
        # Usuario actualmente logueado
        self.usuario_actual = None
        self.logger.info("Aplicación iniciada correctamente")
    
    def _configurar_logging(self):
        """Configura el sistema de logging profesional - logs van a archivos, NO a consola."""
        from datetime import datetime
        import glob
        
        # Crear directorio de logs si no existe
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        # BORRAR LOGS ANTERIORES al iniciar la aplicación
        try:
            archivos_log = glob.glob(os.path.join(log_dir, "*.log"))
            for archivo in archivos_log:
                os.remove(archivo)
        except Exception:
            pass  # Silenciar errores de borrado de logs
        
        # Fecha actual para nombres de archivo
        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        
        # Limpiar configuración previa
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Configurar root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Evitar propagación para evitar duplicados
        root_logger.propagate = False
        
        # Formato detallado para archivos
        formatter_archivo = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Formato simple para errores críticos en consola
        formatter_consola = logging.Formatter('❌ ERROR: %(message)s')
        
        # 1. Handler para archivo general (SOLO INFO y WARNING, NO ERRORES)
        class InfoWarningFilter(logging.Filter):
            def filter(self, record):
                return logging.INFO <= record.levelno < logging.ERROR
        
        handler_archivo = logging.FileHandler(
            filename=os.path.join(log_dir, f'app_{fecha_hoy}.log'),
            mode='a',
            encoding='utf-8'
        )
        handler_archivo.setLevel(logging.INFO)
        handler_archivo.addFilter(InfoWarningFilter())
        handler_archivo.setFormatter(formatter_archivo)
        root_logger.addHandler(handler_archivo)
        
        # 2. Handler específico SOLO para errores reales
        class ErrorFilter(logging.Filter):
            def filter(self, record):
                return record.levelno >= logging.ERROR
        
        handler_errores = logging.FileHandler(
            filename=os.path.join(log_dir, f'errores_{fecha_hoy}.log'),
            mode='a',
            encoding='utf-8'
        )
        handler_errores.setLevel(logging.ERROR)
        handler_errores.addFilter(ErrorFilter())
        handler_errores.setFormatter(formatter_archivo)
        root_logger.addHandler(handler_errores)
        
        # 3. Handler para consola (SOLO ERRORES CRÍTICOS)
        handler_consola = logging.StreamHandler()
        handler_consola.setLevel(logging.CRITICAL)  # Solo errores muy graves
        handler_consola.setFormatter(formatter_consola)
        root_logger.addHandler(handler_consola)
        

    
    def mostrar_banner(self):
        """Muestra el banner de la aplicación."""
        print("\n" + "=" * 70)
        print("     QUEDADAS DE PERROS")
        print("=" * 70)
        
        # Verificar que el sistema de cifrado funciona
        if not self.mensaje_manager.verificar_sistema_cifrado():
            raise RuntimeError("Error crítico en la inicialización del sistema")
    
    def mostrar_menu_principal(self):
        """Muestra el menú principal de la aplicación."""
        print("\nMENÚ PRINCIPAL")
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Salir")
        print("-" * 30)
    
    def mostrar_menu_usuario(self):
        """Muestra el menú para usuario logueado."""
        nombre_usuario = self.usuario_actual.get('nombre_usuario', 'Usuario') if self.usuario_actual else 'Usuario'
        print(f"\nBienvenido, {nombre_usuario}!")
        print("1. Registrar mi perro")
        print("2. Ver mis perros")
        print("3. Explorar perros y contactar propietarios")
        print("4. Borrar mi perro")
        print("5. Ver mis mensajes")
        print("6. Borrar mi cuenta")
        print("7. Cerrar sesión")
        print("-" * 40)

    
    def registrar_usuario(self):
        """Registra un nuevo usuario en el sistema."""
        print("\nREGISTRO DE USUARIO")
        print("Criterios de contraseña segura:")
        print("- Al menos 8 caracteres")
        print("- Mayúsculas y minúsculas")
        print("- Números y símbolos")
        print()
        
        nombre_usuario = input("Nombre de usuario: ").strip()
        if not nombre_usuario:
            print("Error: El nombre de usuario no puede estar vacío")
            return
        
        contraseña = input("Contraseña: ").strip()
        email = input("Email (opcional): ").strip()
        
        try:
            # Intentar registrar usuario
            if self.usuario_manager.registrar_usuario(nombre_usuario, contraseña, email):
                print(f"¡Usuario '{nombre_usuario}' registrado exitosamente!")
                print("Ya puedes iniciar sesión con tus credenciales.")
            else:
                print("❌ Error: No se pudo registrar el usuario.")
                print("Verifica que el nombre no exista y la contraseña sea robusta.")
        except Exception as e:
            print(f"Error en el sistema de autenticación: {e}")
    
    def iniciar_sesion(self):
        """Autentica un usuario en el sistema."""
        print("\nINICIAR SESIÓN")
        
        nombre_usuario = input("Nombre de Usuario: ").strip()
        contraseña = input("Contraseña: ").strip()
        
        try:
            # Intentar autenticación
            usuario = self.usuario_manager.autenticar_usuario(nombre_usuario, contraseña)
            
            if usuario:
                self.usuario_actual = usuario
                print(f"¡Bienvenido, {usuario['nombre_usuario']}!")
                return True
            else:
                print("Error: Credenciales incorrectas")
                return False
        except Exception as e:
            print(f"Error en el sistema de autenticación: {e}")
            return False
    
    def registrar_perro(self):
        """Registra un nuevo perro para el usuario actual."""
        if not self.usuario_actual:
            print("Error: Debes iniciar sesión primero")
            return
            
        print("\nREGISTRAR PERRO")
        
        nombre = input("Nombre del perro: ").strip()
        if not nombre:
            print("Error: El nombre no puede estar vacío")
            return
        
        identificador = input("Número de microchip/pedigree: ").strip()
        if not identificador:
            print("Error: El identificador es obligatorio")
            return
        
        print("\nDescripción del perro:")
        descripcion = input("Descripción: ").strip()
        
        try:
            # Registrar perro
            perro = self.perro_manager.registrar_perro(self.usuario_actual['id'], nombre, identificador, descripcion)
            
            print(f"¡Perro '{nombre}' registrado exitosamente!")
            print(f"ID del perro: {perro.id}")
        except Exception as e:
            print(f"Error en el sistema de perros: {e}")
    
    def ver_mis_perros(self):
        """Muestra los perros del usuario actual."""
        if not self.usuario_actual:
            print("Error: Debes iniciar sesión primero")
            return
            
        print("\nMIS PERROS")
        
        try:
            perros = self.perro_manager.obtener_perros_usuario(self.usuario_actual['id'])
            
            if not perros:
                print("No tienes perros registrados aún.")
                return
            
            for i, perro in enumerate(perros, 1):
                print(f"\n{i}.  {perro.nombre}")
                print(f"   ID: {perro.id}")
                print(f"   Identificador: {perro.identificador_oficial}")
                print(f"   Público: {'Sí' if perro.publico else 'No'}")
                if perro.descripcion:
                    print(f"   Descripción: {perro.descripcion}")
        except Exception as e:
            print(f"Error en el sistema de perros: {e}")

    def eliminar_perro(self):
        """Interfaz para eliminar un perro del usuario actual."""
        if not self.usuario_actual:
            print("Error: Debes iniciar sesión primero")
            return

        try:
            perros = self.perro_manager.obtener_perros_usuario(self.usuario_actual['id'])

            if not perros:
                print("No tienes perros registrados para eliminar.")
                return

            print("\nELIMINAR PERRO - Tus perros:")
            for i, perro in enumerate(perros, 1):
                print(f"{i}. {perro.nombre} - ID: {perro.id}")

            perro_id = input("Ingresa el ID del perro que quieres eliminar: ").strip()
            if not perro_id:
                print("No se proporcionó ID. Operación cancelada.")
                return

            # Comprobación extra: obtener el perro y validar propietario
            info = self.perro_manager.buscar_perro_por_id(perro_id)
            if not info:
                print("Perro no encontrado con ese ID.")
                return

            if info.get('propietario_id') != self.usuario_actual['id']:
                print("No tienes permiso para eliminar ese perro (no eres el propietario).")
                return

            # Llamada al manager para borrar el perro (ya sabemos que somos propietarios)
            borrado = self.perro_manager.borrar_perro(self.usuario_actual['id'], perro_id)

            perro_nombre = info['perro'].nombre
            if borrado:
                print(f"Perro {perro_nombre} eliminado correctamente.")
            else:
                print(f"No se pudo eliminar el perro ({perro_nombre}).")

        except Exception as e:
            print(f"Error eliminando perro: {e}")
            self.logger.error(f"Error en eliminar_perro: {e}", exc_info=True)
    
    def explorar_perros_publicos(self):
        """Muestra perros públicos de otros usuarios."""
        print("\nPERROS PÚBLICOS")
        
        try:
            perros_publicos = self.perro_manager.obtener_perros_publicos()
            
            if not perros_publicos:
                print("No hay perros públicos disponibles.")
                return
            
            print(f"Encontrados {len(perros_publicos)} perros disponibles para quedadas:\n")
            
            for i, info in enumerate(perros_publicos, 1):
                perro = info['perro']
                propietario_id = info['propietario_id']
                
                # No mostrar nuestros propios perros
                if self.usuario_actual and propietario_id == self.usuario_actual['id']:
                    continue
                
                print(f"{i}.  {perro.nombre}")
                print(f"   ID del perro: {perro.id}")
                # Intentar resolver el nombre de usuario a partir del id del propietario
                owner_name = None
                for uname, udata in self.usuario_manager.usuarios.items():
                    if udata.get('id') == propietario_id:
                        owner_name = uname
                        break
                owner_display = owner_name if owner_name else f"{propietario_id[:8]}..."
                print(f"   Propietario: {owner_display}")
                if hasattr(perro, 'descripcion') and perro.descripcion:
                    print(f"   Descripción: {perro.descripcion}")
                print()
            
            # Opción para enviar mensaje
            perro_id = input("¿Te interesa alguno? Ingresa el ID del perro para contactar: ").strip()
            if perro_id:
                self.enviar_mensaje_a_propietario(perro_id)
                
        except Exception as e:
            print(f"Error en el sistema de perros: {e}")
    
    def enviar_mensaje_a_propietario(self, perro_id: str):
        """Envía un mensaje al propietario de un perro específico."""
        if not self.usuario_actual:
            print("Error: Debes iniciar sesión primero")
            return
            
        try:
            # Buscar el perro y su propietario
            info_perro = self.perro_manager.buscar_perro_por_id(perro_id)
            
            if not info_perro:
                print("Error: Perro no encontrado")
                return
            
            perro = info_perro['perro']
            propietario_id = info_perro['propietario_id']
            
            # No enviar mensaje a uno mismo
            if propietario_id == self.usuario_actual['id']:
                print("No puedes enviarte un mensaje a ti mismo")
                return
            
            print(f"\nContactando al propietario de {perro.nombre}...")
            
            mensaje = input("Escribe tu mensaje sobre la quedada: ").strip()
            if not mensaje:
                print("El mensaje no puede estar vacío")
                return
            
            # Crear el mensaje
            mensaje_obj = self.mensaje_manager.enviar_mensaje(
                self.usuario_actual['id'],
                propietario_id,
                mensaje
            )
                
        except Exception as e:
            print(f"Error en el sistema de mensajes: {e}")
    
    def ver_mensajes(self):
        """Muestra los mensajes del usuario actual."""
        if not self.usuario_actual:
            print("Error: Debes iniciar sesión primero")
            return
            
        print("\nMIS MENSAJES")
        
        try:
            mensajes = self.mensaje_manager.obtener_mensajes_usuario(self.usuario_actual['id'])
            
            if not mensajes:
                print("No tienes mensajes")
                return
            
            print(f"Total de mensajes: {len(mensajes)}\n")
            
            for i, mensaje in enumerate(mensajes, 1):
                # Determinar dirección del mensaje
                if mensaje.remitente_id == self.usuario_actual['id']:
                    direccion = "ENVIADO"
                    otro_usuario_id = mensaje.destinatario_id
                else:
                    direccion = "RECIBIDO"
                    otro_usuario_id = mensaje.remitente_id
                
                # Obtener el nombre de usuario usando el método existente
                usuario_obj = self.usuario_manager.obtener_usuario_por_id(otro_usuario_id)
                nombre_otro_usuario = usuario_obj.nombre_usuario if usuario_obj else otro_usuario_id[:8] + "..."
                
                print(f"{i}. {direccion} - {nombre_otro_usuario}")
                print(f"   Fecha: {mensaje.fecha_envio[:19] if hasattr(mensaje, 'fecha_envio') else 'N/A'}")
                print(f"   Leído: {'Sí' if mensaje.leido else 'No'}")
                
                # Mostrar mensaje descifrado automáticamente
                contenido = getattr(mensaje, 'contenido_original', 'Contenido no disponible')
                
                # Mostrar el mensaje
                print(f"   Mensaje:")
                # Mostrar el mensaje por lineas
                for linea in [contenido[i:i+80] for i in range(0, len(contenido), 80)]:
                    print(f"      {linea}")
                
                # Marcar como leido el mensaje si lo vemos
                if not mensaje.leido and mensaje.destinatario_id == self.usuario_actual['id']:
                    try:
                        if self.mensaje_manager.marcar_como_leido(mensaje.id, self.usuario_actual['id']):
                            mensaje.leido = True  # Actualizar también el objeto en memoria
                    except Exception as e:
                        self.logger.error(f"Error marcando mensaje {mensaje.id} como leído: {e}")
                
                print()
                
        except Exception as e:
            print(f"Error cargando mensajes: {e}")
    
    def borrar_cuenta(self):
        """Permite al usuario borrar su cuenta y todos sus datos asociados."""
        if not self.usuario_actual:
            print("Error: No hay usuario autenticado")
            return
        
        nombre_usuario = self.usuario_actual.get('nombre_usuario')
        print(f"\n  BORRAR CUENTA: {nombre_usuario}")
        print("   ADVERTENCIA: Esta acción eliminará permanentemente:")
        print("   • Tu cuenta de usuario")
        print("   • Todos tus perros registrados")
        print("   • Todos tus mensajes")
        print("   • No se puede deshacer")
        print()
        
        # Confirmación 1
        confirmar1 = input("¿Estás seguro de que quieres borrar tu cuenta? (escribe 'BORRAR'): ").strip()
        if confirmar1 != "BORRAR":
            print("Cancelado. Tu cuenta está segura.")
            return
        
        # Confirmación 2 - verificar contraseña
        print("\nPor seguridad, confirma tu contraseña:")
        contraseña = input("Contraseña actual: ").strip()
        
        if not self.usuario_manager.autenticar_usuario(nombre_usuario, contraseña):
            print("Contraseña incorrecta. Operación cancelada.")
            return
        
        # Confirmación 3 - última oportunidad
        print(f"\n  ÚLTIMA CONFIRMACIÓN:")
        print(f"Se va a eliminar PERMANENTEMENTE la cuenta '{nombre_usuario}' y todos sus datos.")
        confirmar_final = input("Escribe 'CONFIRMO' para proceder: ").strip()
        
        if confirmar_final != "CONFIRMO":
            print("Operación cancelada. Tu cuenta está segura.")
            return
        
        try:
            # Usar la función de eliminar_usuario que ya existe
            exito = self.usuario_manager.eliminar_usuario(
                nombre_usuario,
                perro_manager=self.perro_manager,
                mensaje_manager=self.mensaje_manager
            )
            
            if exito:
                print("Cuenta eliminada exitosamente.")
                print("Gracias por usar nuestra aplicación.")
                
                # Cerrar sesión automáticamente
                self.usuario_actual = None
                
                print("\nPresiona Enter para volver al menú principal...")
                input()
            else:
                print("Error: No se pudo eliminar la cuenta.")
                
        except Exception as e:
            print(f"Error eliminando cuenta: {e}")
            self.logger.error(f"Error eliminando cuenta de {nombre_usuario}: {e}")
    

    
    def ejecutar(self):
        """Ejecuta el bucle principal de la aplicación."""
        self.mostrar_banner()
        
        while True:
            try:
                if not self.usuario_actual:
                    # Menú principal para usuarios no autenticados
                    self.mostrar_menu_principal()
                    opcion = input("Selecciona una opción: ").strip()
                    
                    if opcion == "1":
                        self.registrar_usuario()
                    elif opcion == "2":
                        self.iniciar_sesion()
                    elif opcion == "3":
                        print("\n¡Hasta luego! Gracias por usar la aplicación.")
                        break
                    else:
                        print("Opción inválida")
                        
                else:
                    # Menú para usuario autenticado
                    self.mostrar_menu_usuario()
                    opcion = input("Selecciona una opción: ").strip()
                    
                    if opcion == "1":
                        self.registrar_perro()
                    elif opcion == "2":
                        self.ver_mis_perros()
                    elif opcion == "3":
                        self.explorar_perros_publicos()
                    elif opcion == "4":
                        self.eliminar_perro()
                    elif opcion == "5":
                        self.ver_mensajes()
                    elif opcion == "6":
                        self.borrar_cuenta()
                    elif opcion == "7":
                        self.usuario_actual = None
                        print("Sesión cerrada exitosamente")
                    else:
                        print("Opción inválida")
                        
            except KeyboardInterrupt:
                print("\n\n Aplicación interrumpida por el usuario")
                break
            except Exception as e:
                print(f"\n Error inesperado: {e}")
                self.logger.error(f"Error en aplicación: {e}", exc_info=True)
                print(" Continuando ejecución...")

def main():
    """Función principal de la aplicación."""
    try:
        app = AplicacionQuedadasPerros()
        app.ejecutar()
    except Exception as e:
        print(f" Error iniciando aplicación: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
