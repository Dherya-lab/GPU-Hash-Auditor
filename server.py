import socket
import ctypes
import os

dll_path = os.path.abspath("hasher.dll")

try:
    gpu_engine = ctypes.CDLL(dll_path)
    # Added a 5th argument: algo_flag (int)
    gpu_engine.findMatch.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    gpu_engine.findMatch.restype = ctypes.c_int
except Exception as e:
    print(f"FATAL ERROR: {e}")
    exit()

def run_gpu_audit(conn, algo_str, target_hash_hex):
    file_path = "dictionary.txt" 
    word_length = 32  
    chunk_size = 100000 
    
    # 0 = MD5, 1 = SHA-256
    algo_flag = 0 if algo_str == "MD5" else 1
    
    try:
        target_bytes = bytes.fromhex(target_hash_hex)
    except ValueError:
        conn.sendall(b"DONE: ERROR: Invalid Hex String.\n")
        return

    total_size = os.path.getsize(file_path)
    processed_size = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            chunk_bytes = []
            original_words = [] 
            
            for line in file:
                word = line.strip()
                processed_size += len(line.encode('utf-8')) 
                
                if not word: continue
                    
                raw_bytes = word.encode('utf-8', errors='ignore')
                chunk_bytes.append(raw_bytes[:word_length].ljust(word_length, b' '))
                original_words.append(word) 
                
                if len(chunk_bytes) == chunk_size:
                    percent = int((processed_size / total_size) * 100)
                    conn.sendall(f"PROG:{percent}\n".encode('utf-8'))
                    
                    dict_buffer = b"".join(chunk_bytes)
                    # Pass the algo_flag to C++
                    match_index = gpu_engine.findMatch(dict_buffer, target_bytes, word_length, chunk_size, algo_flag)
                    
                    if match_index != -1:
                        conn.sendall(f"DONE: CRITICAL MATCH -> '{original_words[match_index]}'\n".encode('utf-8'))
                        return
                    
                    chunk_bytes = [] 
                    original_words = []
            
            if chunk_bytes:
                dict_buffer = b"".join(chunk_bytes)
                match_index = gpu_engine.findMatch(dict_buffer, target_bytes, word_length, len(chunk_bytes), algo_flag)
                if match_index != -1:
                    conn.sendall(f"DONE: CRITICAL MATCH -> '{original_words[match_index]}'\n".encode('utf-8'))
                    return
                    
    except FileNotFoundError:
        conn.sendall(b"DONE: ERROR: dictionary.txt not found.\n")
        return

    conn.sendall(b"DONE: SECURE: No Match Found in entire dictionary.\n")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    server.bind(('127.0.0.1', 5000))
    server.listen(1)
    
    print("PYTHON ORCHESTRATOR ONLINE: Listening on port 5000...")
    
    while True:
        conn, addr = server.accept()
        data = conn.recv(1024).decode('utf-8').strip()
        if data:
            # Parse the incoming message: "ALGORITHM:HASH"
            algo_str, target_hash = data.split(":", 1)
            print(f"Auditing Hash: {target_hash} using {algo_str}")
            conn.sendall(f"MSG: Target acquired. Spinning up CUDA cores for {algo_str}...\n".encode('utf-8'))
            
            run_gpu_audit(conn, algo_str, target_hash)
        conn.close()

if __name__ == "__main__":
    start_server()