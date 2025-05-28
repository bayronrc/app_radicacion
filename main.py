import flet as ft
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_file(file_path, rsa_public_key_pem, output_dir="C:\\Users\\PROGRAMADOR\\Documents\\EncryptedFiles"):
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Step 1: Extract file extension
        filename = os.path.basename(file_path)
        extension = os.path.splitext(filename)[1]  # e.g., '.pdf'
        extension_bytes = extension.encode('utf-8')
        extension_length = len(extension_bytes)
        extension_length_bytes = extension_length.to_bytes(4, byteorder='big')

        # Step 2: Read file content
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Step 3: Generate AES key and IV
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)       # 16-byte IV

        # Step 4: Encrypt file with AES-256-CBC
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_content) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

        # Step 5: Combine elements
        final_encrypted_file = extension_length_bytes + extension_bytes + iv + encrypted_content

        # Step 6: Encrypt AES key with RSA
        public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode('utf-8'), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Step 7: Save encrypted files
        encrypted_file_path = os.path.join(output_dir, f"{filename}.enc")
        key_file_path = os.path.join(output_dir, f"{filename}.key")
        with open(encrypted_file_path, 'wb') as f:
            f.write(final_encrypted_file)
        with open(key_file_path, 'wb') as f:
            f.write(encrypted_aes_key)

        return encrypted_file_path, key_file_path, None
    except Exception as e:
        return None, None, str(e)

def main(page: ft.Page):
    page.window_width = 400  # Reducido a 400 píxeles para un ancho más estrecho
    page.title = "File Encryption Tool"
    page.padding = 20
    page.bgcolor = ft.Colors.BLACK
    page.window_height = 600  # Ajustado para mantener proporcionalidad

    # UI Elements
    file_path_label = ft.Text("No file selected", color=ft.Colors.WHITE, size=14)  # Cambiado a blanco para contraste
    rsa_key_input = ft.TextField(label="RSA Public Key (PEM)", multiline=True, height=150, width=350, max_lines=10, min_lines=5, color=ft.Colors.GREEN, border_color=ft.Colors.GREEN)
    status_label = ft.Text("", color=ft.Colors.RED)
    pick_file_button = ft.ElevatedButton("Select File", color=ft.Colors.BLUE, icon=ft.Icons.FILE_OPEN_SHARP, width=120, height=40, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)))
    encrypt_button = ft.ElevatedButton("Encriptar Archivo", disabled=True, color=ft.Colors.GREEN, icon=ft.Icons.LOCK, width=250, height=40, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)))

    # File Picker
    file_picker = ft.FilePicker()

    def on_file_picked(e: ft.FilePickerResultEvent):
        if e.files:
            file_path_label.value = e.files[0].path
            encrypt_button.disabled = not (file_path_label.value and rsa_key_input.value)
        else:
            file_path_label.value = "No file selected"
            encrypt_button.disabled = True
        page.update()

    file_picker.on_result = on_file_picked
    pick_file_button.on_click = lambda e: file_picker.pick_files(allow_multiple=False)

    def on_encrypt_click(e):
        if file_path_label.value == "No file selected" or not rsa_key_input.value:
            status_label.value = "Por favor, selecciona un archivo y proporciona una clave pública RSA."
            page.update()
            return

        encrypted_file, key_file, error = encrypt_file(file_path_label.value, rsa_key_input.value)
        if error:
            status_label.value = f"Error al encriptar: {error}"
            status_label.color = ft.Colors.RED
        else:
            status_label.value = f"¡Éxito! Archivos guardados:\n{encrypted_file}\n{key_file}"
            status_label.color = ft.Colors.GREEN
        page.update()

    def on_rsa_key_change(e):
        encrypt_button.disabled = not (file_path_label.value != "No file selected" and rsa_key_input.value)
        page.update()

    rsa_key_input.on_change = on_rsa_key_change
    encrypt_button.on_click = on_encrypt_click

    # Add FilePicker to page overlay
    page.overlay.append(file_picker)

    # Layout
    page.add(
        
        ft.Column(
            controls=[
                ft.Text("Herramienta de Encriptación de Archivos", color=ft.Colors.WHITE, size=20, weight=ft.FontWeight.BOLD),
                pick_file_button,
                file_path_label,
                rsa_key_input,
                encrypt_button,
                status_label
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
    )

if __name__ == "__main__":
    ft.app(target=main)