from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import sys


def encrypt_file(file_path, rsa_public_key_pem, output_dir):
    try:
        # Asegurar que el directorio de salida exista
        os.makedirs(output_dir, exist_ok=True)

        # Paso 1: Extraer la extensión del archivo
        filename = os.path.basename(file_path)
        extension = os.path.splitext(filename)[1]
        extension_bytes = extension.encode('utf-8')
        extension_length = len(extension_bytes)
        extension_length_bytes = extension_length.to_bytes(4, byteorder='big')

        # Paso 2: Leer el contenido del archivo
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Paso 3: Generar clave AES e IV
        aes_key = os.urandom(32)  # Clave de 256 bits
        iv = os.urandom(16)  # IV de 16 bytes

        # Paso 4: Encriptar archivo con AES-256-CBC
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_content) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

        # Paso 5: Combinar elementos
        final_encrypted_file = extension_length_bytes + extension_bytes + iv + encrypted_content

        # Paso 6: Encriptar clave AES con RSA
        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode('utf-8'), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Paso 7: Guardar archivos encriptados
        relative_path = os.path.relpath(file_path, os.path.dirname(file_path))
        encrypted_file_path = os.path.join(output_dir, f"{relative_path}.enc")
        key_file_path = os.path.join(output_dir, f"{relative_path}.key")
        os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
        with open(encrypted_file_path, 'wb') as f:
            f.write(final_encrypted_file)
        with open(key_file_path, 'wb') as f:
            f.write(encrypted_aes_key)

        return encrypted_file_path, key_file_path, None
    except Exception as e:
        return None, None, str(e)


def encrypt_folder(folder_path, rsa_public_key_pem, output_dir):
    results = []
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"🔄 Procesando: {file_path}")
            encrypted_file, key_file, error = encrypt_file(file_path, rsa_public_key_pem, output_dir)
            results.append((file_path, encrypted_file, key_file, error))
    return results


def main():
    print("🔒 Herramienta de Encriptación de Carpetas 🗂️")

    # Solicitar rutas al usuario
    folder_path = input("📁 Ingrese la ruta de la carpeta a encriptar: ").strip()
    if not os.path.isdir(folder_path):
        print("❌ Error: La ruta de la carpeta no es válida.")
        return

    output_dir = input("📂 Ingrese la ruta del directorio de salida: ").strip()
    if not output_dir:
        print("❌ Error: Debe especificar un directorio de salida.")
        return

    rsa_key_path = input("🔑 Ingrese la ruta del archivo de clave pública RSA (.pem): ").strip()
    if not os.path.isfile(rsa_key_path) or not rsa_key_path.endswith('.pem'):
        print("❌ Error: La ruta del archivo de clave RSA no es válida o no es un archivo .pem.")
        return

    # Leer la clave RSA
    try:
        with open(rsa_key_path, 'r') as f:
            rsa_public_key_pem = f.read()
    except Exception as e:
        print(f"❌ Error al leer el archivo de clave RSA: {str(e)}")
        return

    # Encriptar carpeta
    print("\n🚀 Iniciando encriptación...")
    results = encrypt_folder(folder_path, rsa_public_key_pem, output_dir)

    # Mostrar resultados
    success_count = 0
    error_messages = []
    for file_path, encrypted_file, key_file, error in results:
        if error:
            error_messages.append(f"❌ Error al encriptar {file_path}: {error}")
        else:
            success_count += 1
            print(f"✅ Éxito: {file_path} -> {encrypted_file}, clave: {key_file}")

    if error_messages:
        print(f"\n🎉 Encriptados {success_count} archivos con éxito.")
        print("⚠️ Errores encontrados:")
        for error in error_messages:
            print(error)
    else:
        print(f"\n🎉 ¡Éxito! Se encriptaron {success_count} archivos correctamente.")


if __name__ == "__main__":
    main()