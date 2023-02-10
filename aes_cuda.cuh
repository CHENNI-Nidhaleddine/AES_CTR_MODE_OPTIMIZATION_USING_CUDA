#include <stddef.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#define AES_BLOCK_SIZE 16              

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD;             // 32-bit word
typedef unsigned long long int BIGWORD;

/*********************** FUNCTIONS **********************/

// Key setup must be done before any AES en/de-cryption functions can be used.
void keyExpansion(const BYTE key[],          // The key, must be 128, 192, or 256 bits
    WORD w[],                  // Output key schedule to be used later
    int keysize);              // Bit length of the key, 128, 192, or 256

__device__ void encrypt(const BYTE in[],             // 16 bytes of plaintext
    BYTE out[],                  // 16 bytes of ciphertext
    const WORD key[],            // all round kets, returned from keyExpansion
    int keysize);                // length of the key: 128, 192, or 256 bits

__device__ void decrypt(const BYTE in[],             // 16 bytes of ciphertext(text cryptee)
    BYTE out[],                  // 16 bytes of plaintext
    const WORD key[],            // From the key setup
    int keysize);                // Bit length of the key, 128, 192, or 256


///////////////////
// AES - CTR
///////////////////
__device__ void increment_ctr(BYTE ctr[],                  // Must be a multiple of AES_BLOCK_SIZE
    int counter_size,         // Bytes of the IV used for counting (low end)
    int step);                //Step of incrementation
__global__ void aes_encrypt_ctr(const BYTE in[],         // Plaintext
    size_t in_len,           // Any byte length
    BYTE out[],              // Ciphertext, same length as plaintext
    const WORD key[],        // From the key setup
    int keysize,             // Bit length of the key, 128, 192, or 256
    const BYTE ctr[]);        // IV, must be AES_BLOCK_SIZE bytes long
