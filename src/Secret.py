import numpy as np
from PIL import Image, ImageFilter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import secrets
from typing import Tuple, Optional

img_path = os.path.join('src', 'itr4.png')


class AdvancedCipher:
    def __init__(self, key: Optional[str] = None):
        self.salt = secrets.token_bytes(16)
        self.key = self._derive_key(key) if key else Fernet.generate_key()
        self.fernet = Fernet(self.key)
        # Ограничиваем seed до 32 бит
        self.permutation_seed = int.from_bytes(self.key[:4], 'big') % (2**32)

    def _derive_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        derived = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(derived[:32])

    def _generate_permutation(self, size: int) -> np.ndarray:
        np.random.seed(self.permutation_seed)
        return np.random.permutation(size)

    def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self.fernet.decrypt(ciphertext.encode()).decode()

class SteganographyEngine:
    def __init__(self, dimensions: Tuple[int, int] = (512, 512)):
        self.width, self.height = dimensions
        self._generate_noise_pattern()

    def _generate_noise_pattern(self):
        self.noise = np.random.randint(0, 64, (self.height, self.width, 3), dtype=np.uint8)

    def _embed_data(self, pixels: np.ndarray, bits: list) -> np.ndarray:
        perm = AdvancedCipher()._generate_permutation(len(bits))
        scrambled_bits = [bits[i] for i in perm]
        
        for idx, bit in enumerate(scrambled_bits):
            x = (idx * 997) % self.width
            y = (idx * 991) % self.height
            r, g, b = pixels[y, x]
            pixels[y, x] = (
                (r & 0xFE) | bit,
                (g & 0xFE) | ((bit + (x % 2)) % 2),
                (b & 0xFE) | ((bit + (y % 2)) % 2)
            )
        return pixels

    def _extract_data(self, pixels: np.ndarray, length: int) -> list:
        bits = []
        for idx in range(length * 8):
            x = (idx * 997) % self.width
            y = (idx * 991) % self.height
            r, g, b = pixels[y, x]
            bits.append((r & 1) | (g & 1) | (b & 1) & 1)
        
        perm = AdvancedCipher()._generate_permutation(len(bits))
        inverse_perm = np.argsort(perm)
        return [bits[i] for i in inverse_perm]

    def encode(self, message: str, output_path: str, cipher: AdvancedCipher) -> None:
        encrypted = cipher.encrypt(message)
        bits = [int(b) for byte in encrypted.encode() for b in f"{byte:08b}"]
        length_bits = [int(b) for b in f"{len(bits):032b}"]
        full_bits = length_bits + bits

        img = Image.new('RGB', (self.width, self.height))
        pixels = np.array(img, dtype=np.uint16)
        
        pixels = np.clip(pixels + self.noise, 0, 255).astype(np.uint8)
        pixels = self._embed_data(pixels, full_bits)
        
        final_img = Image.fromarray(pixels)
        final_img = final_img.filter(ImageFilter.GaussianBlur(radius=0.5))
        final_img.save(img_path, format='PNG', compress_level=9)

    def decode(self, image_path: str, cipher: AdvancedCipher) -> str:
        img = Image.open(image_path)
        pixels = np.array(img)
        
        length_bits = self._extract_data(pixels, 4)
        message_length = int(''.join(map(str, length_bits)), 2)
        
        message_bits = self._extract_data(pixels, 4 + message_length // 8)[32:]
        byte_array = bytearray()
        
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) < 8:
                byte += [0] * (8 - len(byte))
            byte_array.append(int(''.join(map(str, byte)), 2))
        
        return cipher.decrypt(byte_array.decode())

def main_interface():
    print("\n=== Стеганографическая система с усиленным шифрованием ===")
    cipher = None
    
    while True:
        print("\n1. Закодировать сообщение в изображение")
        print("2. Декодировать сообщение из изображения")
        print("3. Выход")
        choice = input("Выберите действие: ")
        
        if choice == "1":
            message = input("Введите секретное сообщение: ")
            password = input("Введите пароль (оставьте пустым для автоматической генерации): ")
            cipher = AdvancedCipher(password)
            
            engine = SteganographyEngine()
            engine.encode(message, "hidden_message.png", cipher)
            
            if not password:
                print(f"Сгенерированный ключ: {cipher.key.decode()}")
        
        elif choice == "2":
            password = input("Введите пароль: ")
            
            try:
                cipher = AdvancedCipher(password)
                engine = SteganographyEngine()
                message = engine.decode(img_path, cipher)
                
                print(f"\nИзвлеченное сообщение:\n{message}")
            except Exception as e:
                print(f"Ошибка при декодировании: {e}")
        
        elif choice == "3":
            print("Завершение работы.")
            break
        
        else:
            print("Неверный выбор. Пожалуйста, попробуйте снова.")

if __name__ == "__main__":
    main_interface()