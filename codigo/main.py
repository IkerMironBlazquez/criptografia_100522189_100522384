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
from criptografia import CriptografiaManager


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
        self.crypto_manager = CriptografiaManager()
        
        # Usuario actualmente logueado
        self.usuario_actual = None
        self.logger.info("Aplicación iniciada correctamente")
    
    def mostrar_banner(self):
        """Muestra el banner de la aplicación."""

        
    def mostrar_menu_principal(self):
        """Muestra el menú principal de la aplicación."""
        
    
    def mostrar_menu_usuario(self):
        """Muestra el menú para usuario logueado."""
        
    
    def registrar_usuario(self):
        """Registra un nuevo usuario en el sistema."""
        
    
    def iniciar_sesion(self):
        """Autentica un usuario en el sistema."""
        
    
    def registrar_perro(self):
        """Registra un nuevo perro para el usuario actual."""
        
    
    def ver_mis_perros(self):
        """Muestra los perros del usuario actual."""
        
    
    def explorar_perros_publicos(self):
        """Muestra perros públicos de otros usuarios."""
        
    
    def enviar_mensaje_a_propietario(self, perro_id: str):
        """Envía un mensaje al propietario de un perro específico."""
        
    
    def ver_mensajes(self):
        """Muestra los mensajes del usuario actual."""
        
    
    def ejecutar(self):
        """Ejecuta el bucle principal de la aplicación."""
        

def main():
    """Función principal de la aplicación."""
    try:
        app = AplicacionQuedadasPerros()
        app.ejecutar()
    except Exception as e:
        print(f"❌ Error iniciando aplicación: {e}")



if __name__ == "__main__":
    sys.exit(main())
