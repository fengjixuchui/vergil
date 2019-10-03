#pragma once
#include "base.h"

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0
typedef struct{
    int mode;
    unsigned long sk[32];
}sm4_context;
__attribute__((visibility("hidden"))) extern unsigned char SboxTable[16][16];
__attribute__((visibility("hidden"))) extern unsigned long FK[4];
__attribute__((visibility("hidden"))) extern unsigned long CK[32];
__attribute__((visibility("hidden"))) unsigned char sm4Sbox(unsigned char inch);
__attribute__((visibility("hidden"))) unsigned long sm4Lt(unsigned long ka);
__attribute__((visibility("hidden"))) unsigned long sm4F(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, unsigned long rk);
__attribute__((visibility("hidden"))) unsigned long sm4CalciRK(unsigned long ka);
__attribute__((visibility("hidden"))) void sm4_setkey( unsigned long SK[32], unsigned char key[16] );
__attribute__((visibility("hidden"))) void sm4_one_round( unsigned long sk[32], unsigned char input[16], unsigned char output[16] );
__attribute__((visibility("hidden"))) void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );
__attribute__((visibility("hidden"))) void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );
__attribute__((visibility("hidden"))) void sm4_crypt_ecb( sm4_context *ctx, int mode, int length, unsigned char *input, unsigned char *output);
__attribute__((visibility("hidden"))) void sm4_crypt_cbc( sm4_context *ctx, int mode, int length, unsigned char iv[16], unsigned char *input, unsigned char *output );

namespace tokza{
    STRUCT SM4INFO{
        SM4INFO();
        ~SM4INFO();
        u8 key[16];     // KEY
        u8 iv[16];      // 备份的向量
        u8 tmpiv[16];   // 运行加解密后会被更新
        u32 old_sz;     // 长度(原始长度,没有对齐)
        u32 input_sz;   // 输入长度(==16*n)
        u32 output_sz;  // 输出长度(==16*n)
        u8* input;      // 输入内容
        u8* output;     // 输出内容
    }SM4INFO;

    class SM4 {
    public:
        SM4();
        ~SM4();
    public:
        SM4INFO* enc(u8 *input__, u32 inputsz__, u8(&key)[16]);
        SM4INFO* dec(u8 *input__, u32 inputsz__, u8(&key)[16]);
        void cleankey();
    private:
        SM4INFO* get_key(u8 *input__, u32 inputsz__, u8(&key)[16]);
        vector<SM4INFO*> m;
    };
}


/*
 * OK!
    SM4 sm4;
    char* input = (char*)"123456789";
    u32 size = strlen(input);
    u8 key[] = {1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0};
    SM4INFO* info1 = sm4.enc((u8*)input,size,key);
    SM4INFO* info2 = sm4.dec(info1->output,info1->output_sz,key);
 */