
#include "aes_cuda.cuh"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <stdint.h>


#define NUM_BLOCKS 1024
#define NUM_THREADS 2048


void print_hex(BYTE str[], int len)
{
    int idx;

    for (idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

int read_file(char* filename, char** text) {
    FILE* textfile;
    long long numbytes;
    textfile = fopen(filename, "rb");
    if (textfile == NULL)
        return 1;

    fseek(textfile, 0L, SEEK_END);
    numbytes = ftell(textfile);
    fseek(textfile, 0L, SEEK_SET);

    *text = (char*)calloc(numbytes, sizeof(char));
    if (*text == NULL)
        return 1;

    fread(*text, sizeof(char), numbytes, textfile);
    fclose(textfile);
    return numbytes;

}

void write_file(char* filename, BYTE* text, long long numbytes) {
    FILE* textfile;
    textfile = fopen(filename, "wb");
    fwrite(text, sizeof(BYTE), numbytes, textfile);
    fclose(textfile);
}

int main(int argc, char* argv[])
{
    clock_t start, end;
    double cpu_time_used;
    start = clock();
    char* text;

    char* fileToEncrypt = "archive.zip";
    char* newFile = "sarra.zip";

    long long numbytes = read_file(fileToEncrypt, &text);

     BYTE *plaintext = (BYTE*)malloc(numbytes * sizeof(BYTE));
     memcpy(plaintext, text, numbytes); 
    
    BYTE* plaintext2;
    cudaMalloc(&plaintext2, numbytes * sizeof(BYTE));
    cudaMemcpy(plaintext2, plaintext, numbytes * sizeof(BYTE), cudaMemcpyHostToDevice);

    WORD key_schedule[60];
    WORD *key_schedule2= (WORD*)malloc(numbytes * sizeof(WORD));;
    BYTE* ciphertext = (BYTE*)malloc(numbytes * sizeof(BYTE));
    BYTE* enc_buf = (BYTE*)malloc(numbytes * sizeof(BYTE));
    int keysize = 128;
    //BYTE *ciphertext=(BYTE*)malloc(numbytes * sizeof(BYTE));
    BYTE iv[1][16] = { {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff} };
    BYTE key[1][16] = { 0x2b,0x7e,0x15,0x16,0x27,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    BYTE* ctrs = (BYTE*)malloc((numbytes / AES_BLOCK_SIZE + 1) * 16 * sizeof(BYTE));
    memcpy(&ctrs[0], iv[0], AES_BLOCK_SIZE);
    for (int i = 1; i < numbytes / AES_BLOCK_SIZE + 1; i++) {
        memcpy(&ctrs[i * AES_BLOCK_SIZE], &ctrs[(i - 1) * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        increment_ctr(&ctrs[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
    }    
   


    keyExpansion(key[0], key_schedule, keysize);
   
   
   
    cudaMalloc(&key_schedule2, 60 * sizeof(WORD));
    cudaMemcpy(key_schedule2,key_schedule, 60 * sizeof(WORD), cudaMemcpyHostToDevice);
    BYTE* enc_buf2;
    cudaMalloc(&enc_buf2, numbytes * sizeof(BYTE));
    BYTE* ctrs2;
    cudaMalloc(&ctrs2, (numbytes / AES_BLOCK_SIZE + 1) * 16 * sizeof(BYTE));
    cudaMemcpy(ctrs2, ctrs, (numbytes / AES_BLOCK_SIZE + 1) * 16 * sizeof(BYTE), cudaMemcpyHostToDevice);

    BYTE* iv2;
    cudaMalloc(&iv2,  16 * sizeof(BYTE));
    cudaMemcpy(iv2, iv,  16 * sizeof(BYTE), cudaMemcpyHostToDevice);

    aes_encrypt_ctr<<<NUM_BLOCKS,NUM_THREADS>>>(&plaintext2[0], numbytes, enc_buf2, key_schedule2, keysize, iv2);

    cudaMemcpy(enc_buf, enc_buf2, numbytes * sizeof(BYTE), cudaMemcpyDeviceToHost);
    printf("\n");
    //for (int i = 0; i < numbytes; i++) printf("%x ", enc_buf[i]);
    //return 0;
   
    aes_encrypt_ctr << <NUM_BLOCKS, NUM_THREADS >> > (&enc_buf2[0], numbytes, plaintext2, key_schedule2, keysize, iv2);
    cudaMemcpy(plaintext, plaintext2, numbytes * sizeof(BYTE), cudaMemcpyDeviceToHost);

    write_file(newFile, plaintext, numbytes);

    cudaFree(plaintext2);
    cudaFree(enc_buf2);
    cudaFree(ctrs2);

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("time to encrypt and decrypt : %f s\n", cpu_time_used);

    return 0;
}
