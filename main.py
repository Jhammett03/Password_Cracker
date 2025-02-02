import hashlib
import bcrypt
import random
import time
import nltk
import multiprocessing
from collections import defaultdict
import matplotlib.pyplot as plt

#takes string data input and returns its SHA256 hash in hexadecimal format
def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

# Crack password in a given chunk, stopping if another process finds it
def crack_password_chunk(chunk, stored_hash, result_dict, progress_queue, user, stop_event):
    for idx, word in enumerate(chunk):
        if stop_event.is_set():  # Check if another process found the password
            return
        if bcrypt.checkpw(word.encode(), stored_hash.encode()):
            result_dict[user] = word
            print(f"[SUCCESS] User '{user}' cracked! Password: {word}")
            stop_event.set()  # Notify all other processes to stop
            return
        if idx % 1000 == 0: # helpful for showing progress of how many attempts
            progress_queue.put((user, idx))


def crack_bcrypt_passwords_parallel(shadow_file, wordlist, num_processes=4):
    """Crack bcrypt passwords using multiprocessing with an early stop mechanism."""
    cracked_passwords = {}
    with open(shadow_file, 'r') as file:
        for line in file:
            user, hash_str = line.strip().split(':', 1)
            _, algo, workfactor, salt_hash = hash_str.split('$')
            salt = salt_hash[:22]
            stored_hash = f"$2b${workfactor}${salt}{salt_hash[22:]}"

            chunk_size = len(wordlist) // num_processes
            chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

            manager = multiprocessing.Manager()
            result_dict = manager.dict()
            progress_queue = multiprocessing.Queue()
            stop_event = multiprocessing.Event()  # New event for early stopping

            processes = []
            for chunk in chunks:
                p = multiprocessing.Process(target=crack_password_chunk,
                                            args=(chunk, stored_hash, result_dict, progress_queue, user, stop_event))
                processes.append(p)
                p.start()

            total_checked = 0
            while any(p.is_alive() for p in processes):
                while not progress_queue.empty():
                    user, checked = progress_queue.get()
                    total_checked += checked
                    print(f"[STATUS] Cracking '{user}': Checked {total_checked}/{len(wordlist)} passwords...")

            for p in processes:
                p.join()

            if user in result_dict:
                cracked_passwords[user] = result_dict[user]

    return cracked_passwords


if __name__ == "__main__":
    #Task 1: Part a
    print("-------------- Task 1: Part a --------------")
    print(f'hello SHA256 hash: {sha256_hash("hello")}')
    print(f'world SHA256 hash: {sha256_hash("world")}')


    print('\n-------------- Task 2 --------------')
    nltk.download('words') #note: if words is already downloaded it will show an error message, but will keep running
    wordlist = [w for w in nltk.corpus.words.words() if 6 <= len(w) <= 10]

    shadow_file = 'shadow.txt'  # Change to actual shadow file path
    # Safe number of processes; Note: I'm impatient and made this
    # number probably larger than it shouldve been, made using the computer nearly impossible, but it didnt crash
    num_processes = max(1, multiprocessing.cpu_count() - 1)
    print(f"Using {num_processes} processes for password cracking...")

    cracked_passwords = crack_bcrypt_passwords_parallel(shadow_file, wordlist, num_processes=num_processes)
    print(cracked_passwords)