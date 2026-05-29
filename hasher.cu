#include <iostream>
#include <cuda_runtime.h>

// --- MD5 CONSTANTS & FUNCTION (Kept exactly the same) ---
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
__constant__ uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
__constant__ uint32_t r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

__device__ void md5_hash(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
    uint8_t msg[64] = {0}; 
    for (size_t i = 0; i < initial_len; i++) msg[i] = initial_msg[i];
    msg[initial_len] = 0x80; 
    uint64_t bits_len = 8 * initial_len;
    for (size_t i = 0; i < 8; i++) msg[56 + i] = (bits_len >> (i * 8)) & 0xFF;
    uint32_t *w = (uint32_t *)msg;
    uint32_t a = h0, b = h1, c = h2, d = h3;
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | (~d)); g = (7 * i) % 16; }
        uint32_t temp = d; d = c; c = b; b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]); a = temp;
    }
    h0 += a; h1 += b; h2 += c; h3 += d;
    digest[0] = h0 & 0xFF; digest[1] = (h0 >> 8) & 0xFF; digest[2] = (h0 >> 16) & 0xFF; digest[3] = (h0 >> 24) & 0xFF;
    digest[4] = h1 & 0xFF; digest[5] = (h1 >> 8) & 0xFF; digest[6] = (h1 >> 16) & 0xFF; digest[7] = (h1 >> 24) & 0xFF;
    digest[8] = h2 & 0xFF; digest[9] = (h2 >> 8) & 0xFF; digest[10] = (h2 >> 16) & 0xFF; digest[11] = (h2 >> 24) & 0xFF;
    digest[12] = h3 & 0xFF; digest[13] = (h3 >> 8) & 0xFF; digest[14] = (h3 >> 16) & 0xFF; digest[15] = (h3 >> 24) & 0xFF;
}

// --- NEW: SHA-256 CONSTANTS & FUNCTION ---
#define EP0(x) (RIGHTROTATE(x,2) ^ RIGHTROTATE(x,13) ^ RIGHTROTATE(x,22))
#define EP1(x) (RIGHTROTATE(x,6) ^ RIGHTROTATE(x,11) ^ RIGHTROTATE(x,25))
#define SIG0(x) (RIGHTROTATE(x,7) ^ RIGHTROTATE(x,18) ^ ((x) >> 3))
#define SIG1(x) (RIGHTROTATE(x,17) ^ RIGHTROTATE(x,19) ^ ((x) >> 10))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))

__constant__ uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ void sha256_hash(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t msg[64] = {0}; 
    
    for (size_t i = 0; i < initial_len; i++) msg[i] = initial_msg[i];
    msg[initial_len] = 0x80; 
    uint64_t bits_len = 8 * initial_len;
    
    // SHA256 stores the length in big-endian at the end of the block
    for (size_t i = 0; i < 8; i++) msg[63 - i] = (bits_len >> (i * 8)) & 0xFF;

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (msg[i*4] << 24) | (msg[i*4+1] << 16) | (msg[i*4+2] << 8) | (msg[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp1 = h + EP1(e) + ch + sha256_k[i] + w[i];
        uint32_t temp2 = EP0(a) + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    // Convert state back to big-endian bytes
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (state[i] >> 24) & 0xFF;
        digest[i*4+1] = (state[i] >> 16) & 0xFF;
        digest[i*4+2] = (state[i] >> 8) & 0xFF;
        digest[i*4+3] = (state[i]) & 0xFF;
    }
}

// --- THE MASTER KERNEL ---
__global__ void checkPasswords(char* dict, char* target, int* resultIndex, int wordLength, int numWords, int algoFlag) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx < numWords && *resultIndex == -1) {
        int len = 0;
        for (int i = 0; i < wordLength; i++) {
            if (dict[idx * wordLength + i] == ' ') break;
            len++;
        }

        bool match = true;
        
        if (algoFlag == 0) {
            // MD5
            uint8_t hash_result[16];
            md5_hash((uint8_t*)&dict[idx * wordLength], len, hash_result);
            for (int i = 0; i < 16; i++) {
                if (hash_result[i] != (uint8_t)target[i]) { match = false; break; }
            }
        } else {
            // SHA-256
            uint8_t hash_result[32];
            sha256_hash((uint8_t*)&dict[idx * wordLength], len, hash_result);
            for (int i = 0; i < 32; i++) {
                if (hash_result[i] != (uint8_t)target[i]) { match = false; break; }
            }
        }

        if (match) {
            *resultIndex = idx; 
        }
    }
}

extern "C" {
    // Added algoFlag to the DLL export
    __declspec(dllexport) int findMatch(char* dict, char* target, int wordLength, int numWords, int algoFlag) {
        char *d_dict, *d_target;
        int *d_resultIndex;
        int resultIndex = -1; 
        
        cudaSetDevice(0);
        cudaMalloc((void**)&d_dict, numWords * wordLength * sizeof(char));
        // Allocate 32 bytes for the target regardless (covers both 16-byte MD5 and 32-byte SHA256)
        cudaMalloc((void**)&d_target, 32 * sizeof(char)); 
        cudaMalloc((void**)&d_resultIndex, sizeof(int));

        cudaMemcpy(d_dict, dict, numWords * wordLength * sizeof(char), cudaMemcpyHostToDevice);
        cudaMemcpy(d_target, target, 32 * sizeof(char), cudaMemcpyHostToDevice);
        cudaMemcpy(d_resultIndex, &resultIndex, sizeof(int), cudaMemcpyHostToDevice);

        int threadsPerBlock = 256;
        int blocksPerGrid = (numWords + threadsPerBlock - 1) / threadsPerBlock;
        // Pass algoFlag to the kernel
        checkPasswords<<<blocksPerGrid, threadsPerBlock>>>(d_dict, d_target, d_resultIndex, wordLength, numWords, algoFlag);

        cudaDeviceSynchronize();
        cudaMemcpy(&resultIndex, d_resultIndex, sizeof(int), cudaMemcpyDeviceToHost);

        cudaFree(d_dict); cudaFree(d_target); cudaFree(d_resultIndex);
        return resultIndex;
    }
}