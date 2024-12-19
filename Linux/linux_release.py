import subprocess
import sys
import os
import platform
import requests
import logging
import time
import asyncio
import aiohttp
import threading
from dotenv import load_dotenv
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip39WordsNum,
)

# Constants
LOG_FILE_NAME = "logfile.log"
WALLETS_FILE_NAME = "wallets_with_balance.txt"
NUMBER_OF_THREADS = 5

# Global counters
wallets_scanned = 0
total_balance = 0
counter_lock = threading.Lock()
log_lock = threading.Lock()  # Для обеспечения атомарности логирования

# Get the absolute path of the directory where the script is located
directory = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(directory, LOG_FILE_NAME)
wallets_file_path = os.path.join(directory, WALLETS_FILE_NAME)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler(sys.stdout),
    ],
)

def update_cmd_title():
    """Обновляет заголовок CMD с текущим количеством сканированных кошельков и найденным балансом."""
    if platform.system() == "Windows":
        with counter_lock:
            title = f"Wallets Scanned: {wallets_scanned}, Balance Found: {total_balance} BTC"
        os.system(f"title {title}")

def bip():
    """Генерирует 12-словную BIP39 мнемоническую фразу."""
    return Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)

def bip44_BTC_seed_to_address(seed):
    """Генерирует Bitcoin адрес из BIP44 seed."""
    # Генерация seed из мнемонической фразы
    seed_bytes = Bip39SeedGenerator(seed).Generate()

    # Генерация Bip44 объекта
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

    # Генерация Bip44 адреса (аккаунт 0, изменение 0, адрес 0)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)

    # Возвращаем адрес
    return bip44_addr_ctx.PublicKey().ToAddress()

def write_to_file(seed, BTC_address, BTC_balance):
    """Записывает seed, адрес и баланс в файл."""
    log_message = f"Seed: {seed}\nAddress: {BTC_address}\nBalance: {BTC_balance} BTC\n\n"
    with log_lock:  # Обеспечиваем, что запись в файл и логирование атомарны
        with open(wallets_file_path, "a") as f:
            f.write(log_message)
        logging.info(f"Written to file: Seed: {seed}, Address: {BTC_address}, Balance: {BTC_balance} BTC")

async def check_BTC_balance(session, address, retries=3, delay=5):
    """Асинхронно проверяет баланс BTC для заданного адреса, используя несколько API."""
    urls = [
        f"https://blockchain.info/balance?active={address}",
        f"https://blockstream.info/api/address/{address}",
    ]
    for attempt in range(retries):
        for url_index, url in enumerate(urls):
            try:
                if "blockchain.info" in url:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 429:
                            logging.error(f"Received 429 Too Many Requests from Blockchain.info. Switching API.")
                            continue  # Переключаемся на следующий URL
                        elif response.status != 200:
                            raise Exception(f"HTTP status {response.status}")
                        data = await response.json()
                        balance = data[address]["final_balance"]
                        return balance / 100000000  # Конвертация сатоши в биткоины

                elif "blockstream.info" in url:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 429:
                            logging.error(f"Received 429 Too Many Requests from Blockstream.info. Switching API.")
                            continue
                        elif response.status != 200:
                            raise Exception(f"HTTP status {response.status}")
                        data = await response.json()
                        balance = data["chain_stats"]["funded_txo_sum"] - data["chain_stats"]["spent_txo_sum"]
                        return balance / 100000000

                elif "sochain.com" in url:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 429:
                            logging.error(f"Received 429 Too Many Requests from SoChain.com. Switching API.")
                            continue
                        elif response.status != 200:
                            raise Exception(f"HTTP status {response.status}")
                        data = await response.json()
                        balance = float(data["data"]["confirmed_balance"])
                        return balance
            except Exception as e:
                if attempt < retries - 1:
                    logging.error(f"Error with {url} for address {address}, retrying: {str(e)}")
                    await asyncio.sleep(delay)
                else:
                    logging.error(f"Error with {url} for address {address}: {str(e)}")
    return 0

async def process_wallets(thread_id, session):
    """Асинхронно обрабатывает бесконечный поток кошельков."""
    global wallets_scanned
    global total_balance

    while True:
        seed = bip()
        BTC_address = bip44_BTC_seed_to_address(seed)
        BTC_balance = await check_BTC_balance(session, BTC_address)

        if BTC_balance > 0:
            write_to_file(seed, BTC_address, BTC_balance)
            with counter_lock:
                total_balance += BTC_balance
            log_msg = (
                f"Thread {thread_id} - (!) Wallet with balance found!\n"
                f"Seed: {seed}\n"
                f"BTC Address: {BTC_address}\n"
                f"BTC Balance: {BTC_balance} BTC\n"
            )
            with log_lock:
                logging.info(log_msg)

        with counter_lock:
            wallets_scanned += 1

        # Логирование информации о кошельке
        log_info = (
            f"Thread {thread_id} - Seed: {seed}\n"
            f"Thread {thread_id} - BTC Address: {BTC_address}\n"
            f"Thread {thread_id} - BTC Balance: {BTC_balance} BTC\n"
        )
        with log_lock:
            logging.info(log_info)

        # Обновляем заголовок CMD после каждой проверки
        update_cmd_title()

async def worker_async(thread_id):
    """Асинхронный рабочий поток."""
    async with aiohttp.ClientSession() as session:
        await process_wallets(thread_id, session)

def worker(thread_id):
    """Функция работника, запускаемая в каждом потоке."""
    asyncio.run(worker_async(thread_id))

def update_title_periodically(interval=5):
    """Периодически обновляет заголовок CMD."""
    while True:
        update_cmd_title()
        time.sleep(interval)

def main():
    """Главная функция для запуска потоков и управления работниками."""
    threads = []

    # Запуск обновления заголовка в отдельном потоке
    title_thread = threading.Thread(target=update_title_periodically, daemon=True)
    title_thread.start()

    # Запуск рабочих потоков
    for i in range(NUMBER_OF_THREADS):
        t = threading.Thread(target=worker, args=(i+1,), daemon=True)
        t.start()
        threads.append(t)
        logging.info(f"Started thread {i+1}")

    # Основной поток остаётся живым, чтобы рабочие потоки продолжали работу
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Program interrupted by user. Exiting...")

if __name__ == "__main__":
    main()
