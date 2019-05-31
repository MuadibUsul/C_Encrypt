#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../Tools/md5.c"
#include "../Tools/aes.c"
// #include "../Tools/timestamp.c"
#define BUFFERSIZE 1000000
#define ATTESTATION_SUCCESS 0;
#define ATTESTATION_FAIL -1;
/*
    * md5  MD5_ABSTRACT(message, md5ctx);
    * AES  AES_ENCRYPT_MESSAGE(message, ciphertext);
    * RSA  RSA_public_encrypt(strlen(message_in), (const unsigned char*)message_in, (unsigned char*)message_out, server_pub_key, RSA_PKCS1_PADDING);     
*/

int DECODE_AES_KEY(unsigned char message[]){
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量
    int ret;
    unsigned char md5ctx_out[128];
    unsigned char message_out[128];
    /****************************************************************************
     ****************************************************************************
    // 分离字段
    *****************************************************************************
    ****************************************************************************/
    for(int i=0; i<128; i++){
        md5ctx_out[i] = message[i];
    }

    for(int i=0, j=128; j<256; i++, j++){
        message_out[i] = message[j];
    }
    /****************************************************************************
     ****************************************************************************
    // 解密摘要
    *****************************************************************************
    ****************************************************************************/
        // 读取client_public_key.pem
    FILE *fp_client_pub_key = fopen("./client_public_key.pem", "r");
    RSA *client_pub_key;
    client_pub_key = RSA_new();
    if (fp_client_pub_key == NULL) {
        printf("ERROR: 无法打开发送方私钥文件！");
        exit(0);
    }
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量
    PEM_read_RSA_PUBKEY(fp_client_pub_key, &client_pub_key, 0, 0);
    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey, client_pub_key) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }
    unsigned char msg_md5ctx[16];
    // 使用公钥对摘要验证签名
    ret = RSA_public_decrypt(128, (const unsigned char*)md5ctx_out, (unsigned char*)msg_md5ctx, client_pub_key, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("AES密码摘要的公钥验证签名失败！");
        exit(0);
    }
    printf("\n\n解密后的摘要为： \n");
    for(int i=0; i < 16; i++){
        printf("%02x ", msg_md5ctx[i]);
    }

    /***********************************************************************************
     * *********************************************************************************
    // 解密AES_KEY
    ************************************************************************************
    ************************************************************************************/
    // 使用接收方的私钥对AES秘钥进行解密
    unsigned char AES_KEY[32];
    // 读取server_private_key.pem
    RSA *server_pvt_key;
    FILE *fp_server_pvt_key = fopen("../server/server_private_key.pem", "r");
 
    server_pvt_key = RSA_new();
    if (fp_server_pvt_key == NULL) {
    printf("ERROR: 无法打开发送方私钥文件！");
    exit(0);
    }
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量
    PEM_read_RSAPrivateKey(fp_server_pvt_key, &server_pvt_key, 0, 0);
    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey, server_pvt_key) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }
    ret = RSA_private_decrypt(128, (const unsigned char*)message_out, (unsigned char*)AES_KEY, server_pvt_key, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("AES密码的私钥解密失败！");
        exit(0);
    }
    printf("\n\n解密后的AES_key: \n");
    for(int i=0; i < 32; i++){
        printf("%x", AES_KEY[i]);
    }
    printf("\n\n");
    /****************************************************************************
     ****************************************************************************
    // 对AES_KEY计算摘要
    *****************************************************************************
    ****************************************************************************/
    unsigned char md5ctx[16]; //加密结果
    MD5_ABSTRACT(AES_KEY, md5ctx);
    for(int i=0;i<16;i++)  
    {
        printf("%02x ",md5ctx[i]);  //02x前需要加上%      
    }
    printf("\n\n");
    /****************************************************************************
     ****************************************************************************
    // 检验完整性
    *****************************************************************************
    ****************************************************************************/
    for(int i=0; i < 16; i++){
        if(md5ctx[i]==msg_md5ctx[i]){
            continue;
        }
        else{
            printf("验证签名失败,消息失效!");
            return ATTESTATION_FAIL;
        }
    }
    // 解密成功
    printf("验证成功");
    return ATTESTATION_SUCCESS;
}

// void DECODE_MESSAGE(unsigned char message[], unsigned char send_message[]){
//     // 分离字段

//     // 验证时间戳

//     // 解密摘要, 验证client身份

//     // 使用AES_KEY解密密文

//     // 对明文计算摘要

//     // 对比摘要
// }

// // int main(int argc, char **argv) {
    
// // }