from PIL import Image
import numpy as np
import os
import random
from cryptography.fernet import Fernet
import base64


img_path = os.path.join('src', 'itr3.png')

class SecretImage:
    def __init__(self, img_size=(100, 100), key=None):
        self.img_size = img_size
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    @staticmethod
    def _text_to_bits(text):
        return [int(bit) for byte in text.encode('utf-8') for bit in f"{byte:08b}"]
    
    @staticmethod
    def _bits_to_text(bits):
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) < 8:
                byte += [0] * (8 - len(byte))
            bytes_list.append(int(''.join(map(str, byte)), 2))
        return bytes(bytes_list).decode('utf-8', errors='ignore').strip('\x00')
    
    def _encrypt(self, text):
        return self.cipher.encrypt(text.encode()).decode()
    
    def _decrypt(self, text):
        return self.cipher.decrypt(text.encode()).decode()
    
    def _generate_noise_pattern(self, width, height):
        return np.random.randint(0, 50, (height, width), dtype=np.uint8)
    
    def encode(self, message, output_path=img_path, encrypt=True):
        if encrypt:
            message = self._encrypt(message)
        
        bits = self._text_to_bits(message)
        width, height = self.img_size
        
        required_pixels = len(bits) + 32
        if width * height < required_pixels:
            width = height = int(np.ceil(np.sqrt(required_pixels)))
        
        img = Image.new('L', (width, height), color=255)
        pixels = np.array(img)
        
        noise = self._generate_noise_pattern(width, height)
        pixels = np.clip(pixels.astype(np.int16) - noise, 0, 255).astype(np.uint8)
        
        length_bits = [int(b) for b in f"{len(bits):032b}"]
        for i, bit in enumerate(length_bits + bits):
            x, y = i % width, i // width
            if y >= height:
                break
            pixels[y, x] = 0 if bit else 255
        
        img = Image.fromarray(pixels)
        img.save(output_path, optimize=True)
        return f"Сообщение скрыто в {output_path} (Ключ: {self.key.decode()})"
    
    def decode(self, image_path=img_path, encrypted=True):
        img = Image.open(image_path)
        pixels = np.array(img)
        
        width, height = img.size
        flat_pixels = [1 if p < 128 else 0 for p in pixels.flatten()]
        
        length_bits = flat_pixels[:32]
        message_length = int(''.join(map(str, length_bits)), 2)
        
        message_bits = flat_pixels[32:32 + message_length]
        message = self._bits_to_text(message_bits)
        
        return self._decrypt(message) if encrypted else message

if __name__ == "__main__":
    secret = SecretImage()
    
    print("1. Закодировать сообщение")
    print("2. Декодировать сообщение")
    choice = input("Выберите действие: ")
    
    if choice == "1":
        message = input("Введите секретное сообщение: ")
        password = input("Введите пароль (опционально): ") or None
        if password:
            secret = SecretImage(key=base64.urlsafe_b64encode(password.ljust(32)[:32].encode()))
        result = secret.encode(message)
        print(result)
    elif choice == "2":
        image_path = input("Введите путь к изображению: ")
        password = input("Введите пароль (если требуется): ") or None
        if password:
            secret = SecretImage(key=base64.urlsafe_b64encode(password.ljust(32)[:32].encode()))
        try:
            print("Расшифрованное сообщение:", secret.decode(image_path))
        except Exception:
            print("Не удалось расшифровать. Проверьте пароль и изображение.")