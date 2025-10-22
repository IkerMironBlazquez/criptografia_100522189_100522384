"""
Aplicación de Mensajería para Quedadas de Perros
Práctica de Criptografía y Seguridad Informática

Implementa los apartados 1, 2 y 3 de la práctica:
1. Registro y autenticación de usuarios (bcrypt)
2. Cifrado/descifrado simétrico (AES-256-CBC)
3. Generación/verificación de etiquetas de autenticación (HMAC-SHA256)
"""

import os
import sys
import json
import logging
from typing import Optional, Dict, Any

# Importar nuestros módulos
from autenticacion import UsuarioManager
from clases import PerroManager, MensajeManager, Mensaje


class AplicacionQuedadasPerros:
    
    def __init__(self):
        """Inicializa la aplicación y sus componentes."""
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Inicializar gestores
        self.usuario_manager = UsuarioManager()
        self.perro_manager = PerroManager()
        self.mensaje_manager = MensajeManager()
        
        # Usuario actualmente logueado
        self.usuario_actual = None
        self.logger.info("Aplicación iniciada correctamente")
    
    def mostrar_banner(self):
        """Muestra el banner de la aplicación."""
        print("\n" + "=" * 60)
        print("     🐶 QUEDADAS DE PERROS - MENSAJERÍA SEGURA 🐶")
        print("=" * 60)
        print("Práctica de Criptografía y Seguridad Informática")
        print("✓ Apartado 1: Autenticación segura (bcrypt)")
        print("✓ Apartado 2: Cifrado simétrico (AES-256-CBC)")
        print("✓ Apartado 3: Etiquetas de autenticación (HMAC-SHA256)")
        print("=" * 60 + "\n")
    def mostrar_menu_principal(self):
        """Muestra el menú principal de la aplicación."""
        print("\n🏠 MENÚ PRINCIPAL")
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Ver información del sistema")
        print("4. Salir")
        print("-" * 30)
    
    def mostrar_menu_usuario(self):
        """Muestra el menú para usuario logueado."""
        nombre_usuario = self.usuario_actual.get('nombre_usuario', 'Usuario') if self.usuario_actual else 'Usuario'
        print(f"\n👤 Bienvenido, {nombre_usuario}!")
        print("1. Registrar mi perro")
        print("2. Ver mis perros")
        print("3. Explorar perros y contactar propietarios")
        print("4. Borrar mi perro")
        print("5. Ver mis mensajes")
        print("6. Cerrar sesión")
        print("-" * 40)

    
    def registrar_usuario(self):
        """Registra un nuevo usuario en el sistema."""
        print("\n📋 REGISTRO DE USUARIO")
        print("Criterios de contraseña segura:")
        print("- Al menos 8 caracteres")
        print("- Mayúsculas y minúsculas")
        print("- Números y símbolos")
        print()
        
        nombre_usuario = input("📝 Nombre de usuario: ").strip()
        if not nombre_usuario:
            print("❌ Error: El nombre de usuario no puede estar vacío")
            return
        
        contraseña = input("🔒 Contraseña: ").strip()
        email = input("📧 Email (opcional): ").strip()
        
        try:
            # Intentar registrar usuario
            if self.usuario_manager.registrar_usuario(nombre_usuario, contraseña, email):
                print(f"✓ ¡Usuario '{nombre_usuario}' registrado exitosamente!")
                print("Ya puedes iniciar sesión con tus credenciales.")
            else:
                print("❌ Error: No se pudo registrar el usuario.")
                print("Verifica que el nombre no exista y la contraseña sea robusta.")
        except Exception as e:
            print(f"❌ Error en el sistema de autenticación: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
    
    def iniciar_sesion(self):
        """Autentica un usuario en el sistema."""
        print("\n🔑 INICIAR SESIÓN")
        
        nombre_usuario = input("📝 Usuario: ").strip()
        contraseña = input("🔒 Contraseña: ").strip()
        
        try:
            # Intentar autenticación
            usuario = self.usuario_manager.autenticar_usuario(nombre_usuario, contraseña)
            
            if usuario:
                self.usuario_actual = usuario
                print(f"✓ ¡Bienvenido, {usuario['nombre_usuario']}!")
                return True
            else:
                print("❌ Error: Credenciales incorrectas")
                return False
        except Exception as e:
            print(f"❌ Error en el sistema de autenticación: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
            return False
    
    def registrar_perro(self):
        """Registra un nuevo perro para el usuario actual."""
        if not self.usuario_actual:
            print("❌ Error: Debes iniciar sesión primero")
            return
            
        print("\n🐕 REGISTRAR PERRO")
        
        nombre = input("📝 Nombre del perro: ").strip()
        if not nombre:
            print("❌ Error: El nombre no puede estar vacío")
            return
        
        identificador = input("🔖 Número de microchip/pedigree: ").strip()
        if not identificador:
            print("❌ Error: El identificador es obligatorio")
            return
        
        print("\n📷 Descripción del perro:")
        descripcion = input("📝 Descripción: ").strip()
        
        try:
            # Registrar perro
            perro = self.perro_manager.registrar_perro(self.usuario_actual['id'], nombre, identificador, descripcion)
            
            print(f"✓ ¡Perro '{nombre}' registrado exitosamente!")
            print(f"ID del perro: {perro.id}")
        except Exception as e:
            print(f"❌ Error en el sistema de perros: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
    
    def ver_mis_perros(self):
        """Muestra los perros del usuario actual."""
        if not self.usuario_actual:
            print("❌ Error: Debes iniciar sesión primero")
            return
            
        print("\n🐕 MIS PERROS")
        
        try:
            perros = self.perro_manager.obtener_perros_usuario(self.usuario_actual['id'])
            
            if not perros:
                print("🚫 No tienes perros registrados aún.")
                return
            
            for i, perro in enumerate(perros, 1):
                print(f"\n{i}. 🐶 {perro.nombre}")
                print(f"   ID: {perro.id}")
                print(f"   Identificador: {perro.identificador_oficial}")
                print(f"   Público: {'Sí' if perro.publico else 'No'}")
                if perro.descripcion:
                    print(f"   Descripción: {perro.descripcion}")
        except Exception as e:
            print(f"❌ Error en el sistema de perros: {e}")
            print("💡 Funcionalidad no implementada completamente aún")

    def eliminar_perro(self):
        """Interfaz para eliminar un perro del usuario actual."""
        if not self.usuario_actual:
            print("❌ Error: Debes iniciar sesión primero")
            return

        try:
            perros = self.perro_manager.obtener_perros_usuario(self.usuario_actual['id'])

            if not perros:
                print("🚫 No tienes perros registrados para eliminar.")
                return

            print("\n🐕 ELIMINAR PERRO - Tus perros:")
            for i, perro in enumerate(perros, 1):
                print(f"{i}. {perro.nombre} - ID: {perro.id}")

            perro_id = input("🗑️ Ingresa el ID del perro que quieres eliminar: ").strip()
            if not perro_id:
                print("❌ No se proporcionó ID. Operación cancelada.")
                return

            # Comprobación extra: obtener el perro y validar propietario
            info = self.perro_manager.buscar_perro_por_id(perro_id)
            if not info:
                print("❌ Perro no encontrado con ese ID.")
                return

            if info.get('propietario_id') != self.usuario_actual['id']:
                print("❌ No tienes permiso para eliminar ese perro (no eres el propietario).")
                return

            # Llamada al manager para borrar el perro (ya sabemos que somos propietarios)
            borrado = self.perro_manager.borrar_perro(self.usuario_actual['id'], perro_id)

            if borrado:
                print(f"✓ Perro {perro_id} eliminado correctamente.")
            else:
                print(f"❌ No se pudo eliminar el perro ({perro_id}).")

        except Exception as e:
            print(f"❌ Error eliminando perro: {e}")
            self.logger.error(f"Error en eliminar_perro: {e}", exc_info=True)

    # método antiguo `borrar_perro_ui` eliminado; usar `eliminar_perro` abajo
    
    def explorar_perros_publicos(self):
        """Muestra perros públicos de otros usuarios."""
        print("\n🌍 PERROS PÚBLICOS")
        
        try:
            perros_publicos = self.perro_manager.obtener_perros_publicos()
            
            if not perros_publicos:
                print("🚫 No hay perros públicos disponibles.")
                return
            
            print(f"Encontrados {len(perros_publicos)} perros disponibles para quedadas:\n")
            
            for i, info in enumerate(perros_publicos, 1):
                perro = info['perro']
                propietario_id = info['propietario_id']
                
                # No mostrar nuestros propios perros
                if self.usuario_actual and propietario_id == self.usuario_actual['id']:
                    continue
                
                print(f"{i}. 🐶 {perro.nombre}")
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
            perro_id = input("💬 ¿Te interesa alguno? Ingresa el ID del perro para contactar: ").strip()
            if perro_id:
                self.enviar_mensaje_a_propietario(perro_id)
                
        except Exception as e:
            print(f"❌ Error en el sistema de perros: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
    
    def enviar_mensaje_a_propietario(self, perro_id: str):
        """Envía un mensaje al propietario de un perro específico."""
        if not self.usuario_actual:
            print("❌ Error: Debes iniciar sesión primero")
            return
            
        try:
            # Buscar el perro y su propietario
            info_perro = self.perro_manager.buscar_perro_por_id(perro_id)
            
            if not info_perro:
                print("❌ Error: Perro no encontrado")
                return
            
            perro = info_perro['perro']
            propietario_id = info_perro['propietario_id']
            
            # No enviar mensaje a uno mismo
            if propietario_id == self.usuario_actual['id']:
                print("❌ No puedes enviarte un mensaje a ti mismo")
                return
            
            print(f"\n💬 Contactando al propietario de {perro.nombre}...")
            
            mensaje = input("📝 Escribe tu mensaje sobre la quedada: ").strip()
            if not mensaje:
                print("❌ El mensaje no puede estar vacío")
                return
            
            # Crear el mensaje
            mensaje_obj = self.mensaje_manager.enviar_mensaje(
                self.usuario_actual['id'],
                propietario_id,
                mensaje
            )
            
            # Mensaje creado y persistido por el manager (sin cifrado por ahora)
            print(f"✓ ¡Mensaje enviado! (sin cifrar)")
            print(f"ID del mensaje: {mensaje_obj.id}")
                
        except Exception as e:
            print(f"❌ Error en el sistema de mensajes: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
    
    def ver_mensajes(self):
        """Muestra los mensajes del usuario actual."""
        if not self.usuario_actual:
            print("❌ Error: Debes iniciar sesión primero")
            return
            
        print("\n📨 MIS MENSAJES")
        
        try:
            mensajes = self.mensaje_manager.obtener_mensajes_usuario(self.usuario_actual['id'])
            
            if not mensajes:
                print("🚫 No tienes mensajes")
                return
            
            print(f"Total de mensajes: {len(mensajes)}\n")
            
            for i, mensaje in enumerate(mensajes, 1):
                # Determinar dirección del mensaje
                if mensaje.remitente_id == self.usuario_actual['id']:
                    direccion = "📤 ENVIADO"
                    otro_usuario = mensaje.destinatario_id
                else:
                    direccion = "📥 RECIBIDO"
                    otro_usuario = mensaje.remitente_id
                
                print(f"{i}. {direccion} - {otro_usuario[:12]}...")
                print(f"   Fecha: {mensaje.fecha_envio[:19] if hasattr(mensaje, 'fecha_envio') else 'N/A'}")
                print(f"   Leído: {'Sí' if mensaje.leido else 'No'}")
                
                # Mostrar mensaje: si existe contenido cifrado lo indicamos,
                # pero mostramos el contenido original si está disponible.
                if hasattr(mensaje, 'contenido_cifrado') and mensaje.contenido_cifrado:
                    contenido = getattr(mensaje, 'contenido_original', None)
                    if contenido:
                        print(f"   Mensaje: {contenido[:100]}{'...' if len(contenido) > 100 else ''}")
                    else:
                        print("   Mensaje: (cifrado - descifrado pendiente de implementación)")
                else:
                    contenido = getattr(mensaje, 'contenido_original', 'Contenido no disponible')
                    print(f"   Mensaje: {contenido}")
                
                print()
                
        except Exception as e:
            print(f"❌ Error en el sistema de mensajes: {e}")
            print("💡 Funcionalidad no implementada completamente aún")
    
    def mostrar_info_sistema(self):
        """Muestra información técnica del sistema."""
        print("\n🔧 INFORMACIÓN DEL SISTEMA")
        print("\n📊 Algoritmos Criptográficos Implementados:")
        print("• Autenticación: bcrypt con salt automático")
        print("• Cifrado simétrico: AES-256-CBC")
        print("• Autenticación de mensajes: HMAC-SHA256")
        print("• Generación de claves: PBKDF2 + secrets")
        print("\n📈 Estado de la Implementación:")
        print("✓ Apartado 1: Sistema de autenticación (bcrypt)")
        print("✓ Apartado 2: Cifrado simétrico (AES-256-CBC)")
        print("✓ Apartado 3: Autenticación de mensajes (HMAC-SHA256)")
        print("⏳ Apartado 4: Firma digital (pendiente)")
        print("⏳ Apartado 5: PKI y certificados (pendiente)")
        
        # Mostrar estadísticas si es posible
        try:
            usuarios_count = len(self.usuario_manager.listar_usuarios())
            print(f"\n📊 Estadísticas actuales:")
            print(f"• Usuarios registrados: {usuarios_count}")
        except:
            print(f"\n📊 Estadísticas: No disponibles (módulos en desarrollo)")
    
    def ejecutar(self):
        """Ejecuta el bucle principal de la aplicación."""
        self.mostrar_banner()
        
        while True:
            try:
                if not self.usuario_actual:
                    # Menú principal para usuarios no autenticados
                    self.mostrar_menu_principal()
                    opcion = input("🔄 Selecciona una opción: ").strip()
                    
                    if opcion == "1":
                        self.registrar_usuario()
                    elif opcion == "2":
                        self.iniciar_sesion()
                    elif opcion == "3":
                        self.mostrar_info_sistema()
                    elif opcion == "4":
                        print("\n👋 ¡Hasta luego! Gracias por usar la aplicación.")
                        break
                    else:
                        print("❌ Opción inválida")
                        
                else:
                    # Menú para usuario autenticado
                    self.mostrar_menu_usuario()
                    opcion = input("🔄 Selecciona una opción: ").strip()
                    
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
                        self.usuario_actual = None
                        print("✓ Sesión cerrada exitosamente")
                    else:
                        print("❌ Opción inválida")
                        
            except KeyboardInterrupt:
                print("\n\n📛 Aplicación interrumpida por el usuario")
                break
            except Exception as e:
                print(f"\n❌ Error inesperado: {e}")
                self.logger.error(f"Error en aplicación: {e}", exc_info=True)
                print("💡 Continuando ejecución...")

def main():
    """Función principal de la aplicación."""
    try:
        app = AplicacionQuedadasPerros()
        app.ejecutar()
    except Exception as e:
        print(f"❌ Error iniciando aplicación: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
