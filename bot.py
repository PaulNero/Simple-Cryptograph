from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.contrib.middlewares.logging import LoggingMiddleware
from aiogram.utils import executor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

API_TOKEN = os.getenv("TOKEN")

bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot)
dp.middleware.setup(LoggingMiddleware())

# Кнопки
button_encrypt = KeyboardButton('Зашифровать')
button_decrypt = KeyboardButton('Расшифровать')
button_about = KeyboardButton('О боте')

markup = ReplyKeyboardMarkup(resize_keyboard=True).add(button_encrypt).add(button_decrypt).add(button_about)

# Создаем словарь для хранения состояний
user_data = {}

def encrypt(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(salt + iv + encryptor.tag + ciphertext).decode()

def decrypt(token, password):
    data = base64.urlsafe_b64decode(token)
    salt, iv, tag, ciphertext = data[:16], data[16:28], data[28:44], data[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

@dp.message_handler(commands=['start'])
async def send_welcome(message: types.Message):
    await message.reply("Привет! Выберите действие:", reply_markup=markup)

@dp.message_handler(lambda message: message.text == "Зашифровать")
async def encrypt_start(message: types.Message):
    await message.reply("Введите строку для шифрования:")
    user_data[message.from_user.id] = {'action': 'encrypt'}

@dp.message_handler(lambda message: message.text == "Расшифровать")
async def decrypt_start(message: types.Message):
    await message.reply("Введите зашифрованную строку:")
    user_data[message.from_user.id] = {'action': 'decrypt'}

@dp.message_handler(lambda message: message.text == "О боте")
async def about_bot(message: types.Message):
    description = (
        """Этот бот позволяет шифровать и расшифровывать данные с использованием AES-GCM шифрования. 
        \n Вы можете ввести строку для шифрования, и бот вернет зашифрованный текст и ключ, который 
        необходим для расшифровки. 
        \n * Используйте кнопку 'Зашифровать' для шифрования данных и кнопку 
        \n * 'Расшифровать' для расшифровки данных с использованием предоставленного ключа."""
    )
    await message.reply(description)

@dp.message_handler(lambda message: message.from_user.id in user_data and user_data[message.from_user.id]['action'] == 'encrypt')
async def process_encrypt(message: types.Message):
    text_to_encrypt = message.text
    password = os.urandom(16).hex()
    encrypted_text = encrypt(text_to_encrypt, password)
    await message.reply(f"Зашифрованный текст: \n{encrypted_text}\n\nКлюч: \n{password} \n\nРекомендуем передавать текст и ключ адресанту через разные каналы связи.", reply_markup=markup)
    user_data.pop(message.from_user.id, None)

@dp.message_handler(lambda message: message.from_user.id in user_data and user_data[message.from_user.id]['action'] == 'decrypt' and 'encrypted_text' not in user_data[message.from_user.id])
async def process_decrypt_text(message: types.Message):
    user_data[message.from_user.id]['encrypted_text'] = message.text
    await message.reply("Введите ключ для расшифрования:")

@dp.message_handler(lambda message: message.from_user.id in user_data and 'encrypted_text' in user_data[message.from_user.id])
async def process_decrypt_key(message: types.Message):
    try:
        encrypted_text = user_data[message.from_user.id]['encrypted_text']
        password = message.text
        decrypted_text = decrypt(encrypted_text, password).decode()
        await message.reply(f"Расшифрованный текст: \n\n{decrypted_text}", reply_markup=markup)
    except Exception as e:
        await message.reply(f"Ошибка расшифрования: {str(e)}", reply_markup=markup)
    user_data.pop(message.from_user.id, None)  # Удаляем данные пользователя после завершения

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
