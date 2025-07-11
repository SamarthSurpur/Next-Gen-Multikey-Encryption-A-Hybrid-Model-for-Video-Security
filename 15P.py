import os
import time
import logging
import hashlib
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CHUNK_SIZE = 1024 * 1024
NUM_KEYS = 5
KEY_FILE = "aes_keys.bin"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def save_keys(keys):
    with open(KEY_FILE, 'wb') as f:
        for key in keys:
            f.write(key)

def load_keys():
    if not os.path.exists(KEY_FILE):
        return None
    with open(KEY_FILE, 'rb') as f:
        data = f.read()
        return [data[i*16:(i+1)*16] for i in range(NUM_KEYS)]

def generate_keys():
    keys = [get_random_bytes(16) for _ in range(NUM_KEYS)]
    save_keys(keys)
    return keys

def encrypt_chunk(chunk, key, start_time=None):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_chunk = pad(chunk, AES.block_size)
    encrypted_chunk = cipher.iv + cipher.encrypt(padded_chunk)
    if start_time:
        encryption_time = time.time() - start_time
        return encrypted_chunk, encryption_time
    return encrypted_chunk

def decrypt_chunk(encrypted_chunk, key):
    iv = encrypted_chunk[:AES.block_size]
    ciphertext = encrypted_chunk[AES.block_size:]
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext size is incorrect. Possible corruption.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_chunk = cipher.decrypt(ciphertext)
    return unpad(decrypted_chunk, AES.block_size)

def encrypt_file_parallel(input_file, output_file, keys):
    encryption_times = []
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out, ThreadPoolExecutor() as executor:
        futures = []
        chunk_num = 0
        while chunk := f_in.read(CHUNK_SIZE):
            key = keys[chunk_num % len(keys)]
            start_time = time.time()
            future = executor.submit(encrypt_chunk, chunk, key, start_time)
            futures.append((future, chunk_num))
            chunk_num += 1

        for future, _ in futures:
            encrypted_chunk, encryption_time = future.result()
            f_out.write(len(encrypted_chunk).to_bytes(4, 'big'))
            f_out.write(encrypted_chunk)
            encryption_times.append(encryption_time)

    return encryption_times

def decrypt_file(input_file, output_file, keys):
    decryption_times = []
    chunk_num = 0
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            length_bytes = f_in.read(4)
            if not length_bytes:
                break
            chunk_size = int.from_bytes(length_bytes, 'big')
            encrypted_chunk = f_in.read(chunk_size)
            if not encrypted_chunk:
                break
            key = keys[chunk_num % len(keys)]
            start_time = time.time()
            try:
                decrypted_chunk = decrypt_chunk(encrypted_chunk, key)
                end_time = time.time()
                decryption_times.append(end_time - start_time)
                f_out.write(decrypted_chunk)
            except ValueError as e:
                logging.error(f"Decryption error in chunk {chunk_num}: {e}")
                break
            chunk_num += 1
    logging.info(f"Decrypted video saved to {output_file}")
    return decryption_times

def generate_graphs(enc_times, dec_times, total_chunks, input_file, ecc_sign_time, ecc_verify_time):
    if not enc_times or not dec_times or len(enc_times) != len(dec_times):
        logging.error("Skipping graph generation due to mismatched data lengths.")
        return

    plt.figure(figsize=(10, 8))

    plt.subplot(2, 2, 1)
    plt.plot(range(total_chunks), enc_times, marker='x', linestyle='-', color='blue')
    plt.xlabel("Chunk Number")
    plt.ylabel("Time (s)")
    plt.title("Encryption Time per Chunk")
    plt.grid(True)

    plt.subplot(2, 2, 2)
    plt.plot(range(total_chunks), dec_times, marker='x', linestyle='-', color='red')
    plt.xlabel("Chunk Number")
    plt.ylabel("Time (s)")
    plt.title("Decryption Time per Chunk")
    plt.grid(True)

    plt.subplot(2, 2, 3)
    plt.bar(["Encryption", "Decryption", "ECC Sign", "ECC Verify"],
            [sum(enc_times), sum(dec_times), ecc_sign_time, ecc_verify_time],
            color=['blue', 'red', 'green', 'purple'])
    plt.ylabel("Time (s)")
    plt.title("Total Processing Times")
    plt.grid(True)

    plt.subplot(2, 2, 4)
    plt.plot(range(total_chunks), [sum(enc_times[:i+1]) for i in range(total_chunks)], label="Encryption", color='blue')
    plt.plot(range(total_chunks), [sum(dec_times[:i+1]) for i in range(total_chunks)], label="Decryption", color='red')
    plt.xlabel("Chunk Number")
    plt.ylabel("Cumulative Time (s)")
    plt.title("Cumulative Time")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(f"{input_file}_graph_output.png")
    plt.show()

def calculate_checksum(filename):
    hash_sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(65536):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def ecc_sign_verify(data_bytes):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    start_sign = time.time()
    signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    end_sign = time.time()
    sign_time = end_sign - start_sign

    start_verify = time.time()
    try:
        public_key.verify(signature, data_bytes, ec.ECDSA(hashes.SHA256()))
        verify_success = True
    except Exception:
        verify_success = False
    end_verify = time.time()
    verify_time = end_verify - start_verify

    if verify_success:
        logging.info("✅ ECC Signature verified successfully.")
    else:
        logging.error("❌ ECC Signature verification failed.")

    return sign_time, verify_time

if __name__ == "__main__":
    input_file = 'input_video2.mp4'
    encrypted_file = 'encrypted_input_video2.mp4'
    decrypted_file = 'decrypted_input_video2.mp4'

    if not os.path.exists(input_file):
        print(f"Input file '{input_file}' not found. Please place it in the folder and retry.")
        exit()

    keys = generate_keys()
    original_checksum = calculate_checksum(input_file)
    logging.info(f"Original checksum: {original_checksum}")

    enc_times = encrypt_file_parallel(input_file, encrypted_file, keys)

    keys = load_keys()
    if not keys:
        logging.error("AES keys could not be loaded. Aborting.")
        exit()

    dec_times = decrypt_file(encrypted_file, decrypted_file, keys)
    decrypted_checksum = calculate_checksum(decrypted_file)
    logging.info(f"Decrypted checksum: {decrypted_checksum}")

    if original_checksum == decrypted_checksum:
        logging.info("✅ Decryption successful. File integrity maintained.")
    else:
        logging.error("❌ Decryption failed. File integrity compromised.")

    ecc_sign_time, ecc_verify_time = ecc_sign_verify(original_checksum.encode())
    generate_graphs(enc_times, dec_times, len(enc_times), input_file, ecc_sign_time, ecc_verify_time)
