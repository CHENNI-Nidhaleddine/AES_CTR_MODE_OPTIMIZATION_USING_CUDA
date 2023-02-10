
#include "aes_cuda.cuh"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <stdint.h>


#define NUM_BLOCKS 16
#define NUM_THREADS 512


/********************************** UTILITIES FUNCTIONS *****************************************/

//Print the content of str of length len in hexadecimal values
void print_hex(BYTE str[], int len)
{
    int idx;

    for (idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

//Reads the content of filename into text and returns numbers of bytes
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

//writes text of length numbytes into filename
void write_file(char* filename, BYTE* text, long long numbytes) {
    FILE* textfile;
    textfile = fopen(filename, "wb");
    fwrite(text, sizeof(BYTE), numbytes, textfile);
    fclose(textfile);
}

/********************************** MAIN PROGRAM *****************************************/
int main(int argc, char* argv[])
{
    //Name of files
    char* fileToEncrypt = "archive.zip";
    char* newFile = "newnew.zip";

    //To calculate processing time
    clock_t start, end;
    double cpu_time_used;
    start = clock();


    //CPU Variables:
    int keysize = 128;
    BYTE iv[1][16] = { {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff} };
    BYTE key[1][16]={ 0x2b,0x7e,0x15,0x16,0x27,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };

    char* text;    
    long long numbytes = read_file(fileToEncrypt, &text);//reading file
    BYTE* plaintext = (BYTE*)malloc(numbytes * sizeof(BYTE));
    memcpy(plaintext, text, numbytes);
    BYTE* enc_buf = (BYTE*)malloc(numbytes * sizeof(BYTE));

    WORD key_schedule[60];//round keys
    //Calculate round keys
    keyExpansion(key[0], key_schedule, keysize);

    //GPU Variables
    BYTE* gpu_plaintext;
    cudaMalloc(&gpu_plaintext, numbytes * sizeof(BYTE));
    cudaMemcpy(gpu_plaintext, plaintext, numbytes * sizeof(BYTE), cudaMemcpyHostToDevice);

  
    WORD* gpu_key_schedule = (WORD*)malloc(numbytes * sizeof(WORD));;
    cudaMalloc(&gpu_key_schedule, 60 * sizeof(WORD));
    cudaMemcpy(gpu_key_schedule, key_schedule, 60 * sizeof(WORD), cudaMemcpyHostToDevice);
    BYTE* gpu_enc_buf;
    cudaMalloc(&gpu_enc_buf, numbytes * sizeof(BYTE));
   
    BYTE* gpu_iv;
    cudaMalloc(&gpu_iv, 16 * sizeof(BYTE));
    cudaMemcpy(gpu_iv, iv, 16 * sizeof(BYTE), cudaMemcpyHostToDevice);
   
    //Start AES
//    printf("Start Encryption:\n");
    aes_encrypt_ctr << <NUM_BLOCKS, NUM_THREADS >> > (&gpu_plaintext[0], numbytes, &gpu_plaintext[0], gpu_key_schedule, keysize, gpu_iv);
    cudaMemcpy(enc_buf, gpu_plaintext, numbytes * sizeof(BYTE), cudaMemcpyDeviceToHost);
   // printf("Done with Encryption\n");

    cudaMemcpy(gpu_plaintext, enc_buf, numbytes * sizeof(BYTE), cudaMemcpyHostToDevice);
 
  //  printf("Start Decryption:\n");
    aes_encrypt_ctr << <NUM_BLOCKS, NUM_THREADS >> > (&gpu_plaintext[0], numbytes, gpu_plaintext, gpu_key_schedule, keysize, gpu_iv);
    cudaMemcpy(plaintext, gpu_plaintext, numbytes * sizeof(BYTE), cudaMemcpyDeviceToHost);
 //   printf("Done with Decryption\n");
    write_file(newFile, plaintext, numbytes);

    //Calculate stop time
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("time to encrypt and decrypt : %f s\n", cpu_time_used);
   

    //Free all gpu allocated memory
    cudaDeviceReset();
    return 0;
}