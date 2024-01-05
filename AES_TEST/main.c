#include <stdio.h>
#include <aes.h>
#include <string.h>
#include <stdint.h>
uint8_t key[] = {0x41, 0x71, 0x4F, 0x46, 0x33, 0x73, 0x56, 0x31, 0x4D, 0x76, 0x51, 0x66, 0x43, 0x4B, 0x5A, 0x34, 0x41, 0x71, 0x4F, 0x46, 0x33, 0x73, 0x56, 0x31, 0x4D, 0x76, 0x51, 0x66, 0x43, 0x4B, 0x5A, 0x34};
const uint8_t iv[] = {0x41, 0x71, 0x4F, 0x46, 0x33, 0x73, 0x56, 0x31, 0x4D, 0x76, 0x51, 0x66, 0x43, 0x4B, 0x5A, 0x35};
uint8_t Buffer[128] = {0};
uint8_t RecBuf[64] = {0};
aes_context ctx;
int main()
{
    /*Tx Part*/
    snprintf(Buffer, sizeof(Buffer), "%s", "LoRa Easy AES");
    printf("Input Encrypt: %s\r\n", Buffer);
    aes_set_key(key, 32, &ctx);
    int plaintext_len = strlen((char *)Buffer);
    uint32_t out_size = plaintext_len + (16 - (plaintext_len % 16));
    if (out_size == 0)
    {
        printf("Input is not a string\r\n");
        return -1;
    }
    uint8_t OutBufffer[out_size];
    uint8_t ec_iv[16] = {0};
    memcpy(ec_iv, iv, sizeof(ec_iv));
    aes_cbc_encrypt(Buffer, OutBufffer, out_size / 16, ec_iv, &ctx);
    printf("Encrypt data as hex type:\r\n");
    for (uint8_t i = 0; i < out_size; i++)
    {
        printf("0x%02x\r\n", OutBufffer[i]);
    }
    printf("\r\n");
     /*Rx Part Pointer IV is change after aes_cbc_decrypt -> Must Restore the IV*/
    uint8_t my_iv[16] = {0};
    memcpy(my_iv, iv, sizeof(my_iv));
    aes_cbc_decrypt(OutBufffer, RecBuf, out_size / 16, my_iv, &ctx);
    printf("Output decrypt: %s\r\n", RecBuf);
}
