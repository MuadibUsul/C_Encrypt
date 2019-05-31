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
#include "../Tools/timestamp.c"
/*gcc encode_client.c  -lcrypto -lssl 

    * md5  MD5_ABSTRACT(message, md5ctx);
    * AES  AES_ENCRYPT_MESSAGE(message, ciphertext);
    * RSA  RSA_public_encrypt(strlen(message_in), (const unsigned char*)message_in, (unsigned char*)message_out, server_pub_key, RSA_PKCS1_PADDING);    
*/
#define ATTESTATION_FAIL -1;
#define ATTESTATION_SUCCESS -1;
int ENCODE_AES_KEY(unsigned char key_message[256]){
    RSA* server_pub_key;
    RSA* client_pvt_key;
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量
    int ret;
    unsigned char message_out[128];
    unsigned char md5ctx_out[128];

    unsigned char AES_KEY[] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f};
    printf("\n输出AES_key: \n");
    for(int i=0; i<32; i++){
        printf("%x", AES_KEY[i]);
    }
    printf("\n");

    /**************************************************************************************
    
            对明文计算MD5摘要

    ****************************************************************************************/

    unsigned char md5ctx[16]; //加密结果
    MD5_ABSTRACT(AES_KEY, md5ctx);
    for(int i=0;i<16;i++)  
    {
        printf("%02x ",md5ctx[i]);  //02x前需要加上%      
    }
    printf("\n\n");

    /**************************************************************************************
    
    使用client私钥对摘要进行签名
    
    **************************************************************************************/
    // 读取client_private_key.pem
    FILE *fp_client_pvt_key = fopen("./client_private_key.pem", "r");
 
    client_pvt_key = RSA_new();
    if (fp_client_pvt_key == NULL) {
        printf("ERROR: 无法打开发送方私钥文件！");
        exit(0);
    }
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量
    PEM_read_RSAPrivateKey(fp_client_pvt_key, &client_pvt_key, 0, 0);
    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey, client_pvt_key) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }

    // 使用私钥对摘要签名
    ret = RSA_private_encrypt(16, (const unsigned char*)md5ctx, (unsigned char*)md5ctx_out, client_pvt_key, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("AES密码摘要的私钥签名失败！");
        exit(0);
    }
    printf("签名后的摘要为： \n");
    for(int i=0; i < 128; i++){
        printf("%x", md5ctx_out[i]);
    }

    /*********************************************************************************
    
    使用server的公钥加密AES_KEy

    *********************************************************************************/
    // // 读取server_public_key.pem
    FILE *fp_server_pub_key = fopen("./server_pub_key/server_public_key.pem", "r");
    server_pub_key = RSA_new();
    if (fp_server_pub_key == NULL) {
        printf("ERROR: 无法打开接收方的公钥文件！");
        exit(0);
    }
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量
    PEM_read_RSA_PUBKEY(fp_server_pub_key, &server_pub_key, 0, 0);
    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey, server_pub_key) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }

    /*
    // 使用接收方公钥对AES秘钥加密
    */
    ret = RSA_public_encrypt(32, (const unsigned char*)AES_KEY, (unsigned char*)message_out, server_pub_key, RSA_PKCS1_PADDING);
    if(ret < 0){
        printf("AES密码的公钥加密失败！");
        exit(0);
    }
    printf("\n\n加密后的AES_KEY为: \n");

    for(int i=0; i < 128; i++){
        printf("%x", message_out[i]);
    }
    printf("\n\n");
    /****************************************************************************
     
    // 组合字段

    *****************************************************************************/
    for(int i=0; i<128; i++){
        key_message[i] = md5ctx_out[i];
        // printf("%x", key_message[i]);
    }
    printf("\n\n");

    for(int i=128,j=0; i<256; i++, j++){
        key_message[i] = message_out[j];
        // printf("%x", key_message[i]);
    }
    printf("\n\n");
    // 加密成功
    printf("");
    return 0;
}






void ENCODE_MESSAGE(unsigned char message[], unsigned char send_message[]){
    unsigned char ciphertext[32];
     // 明文MD5摘要
    unsigned char md5ctx[16]; //加密结果
    unsigned char md5ctx_out[128];
    char message_in[128];
    char message_out[128];

    long ret;
    int len;
    RSA* client_pub_key;
    RSA* client_pvt_key;
    RSA* server_pub_key;
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量

    /***************************************************************************
     * 
    // 对原文计算摘要

    ****************************************************************************/

    MD5_ABSTRACT(message, md5ctx);
    for(int i=0;i<16;i++)  
    {
        printf("%02x ",md5ctx[i]);  //02x前需要加上%      
    }
    printf("\n\n");


    // 读取server_pub_key与client_pvt_key
    FILE *fp_server_pub_key = fopen("./server_pub_key/server_public_key.pem", "r");
    FILE *fp_client_pvt_key = fopen("./client_private_key.pem", "r");

    // srand(time(NULL));
    // OpenSSL_add_all_algorithms();

    client_pvt_key = RSA_new();
    server_pub_key = RSA_new();
    evpKey = EVP_PKEY_new();//新建一个EVP_PKEY变量

    if (fp_client_pvt_key == NULL) {
        printf("ERROR: 无法打开A的私钥文件！");
        exit(0);
    }
    if (fp_server_pub_key == NULL) {
        printf("ERROR: 无法打开B的公钥文件！");
        exit(0);
    }

    PEM_read_RSAPrivateKey(fp_client_pvt_key, &client_pvt_key, 0, 0);
    PEM_read_RSA_PUBKEY(fp_server_pub_key, &server_pub_key, 0, 0);

    if(evpKey == NULL)
    {
        printf("EVP_PKEY_new err\n");
        exit(0);
    }
    if(EVP_PKEY_set1_RSA(evpKey,client_pvt_key) != 1)  //保存RSA结构体到EVP_PKEY结构体
    {
        printf("EVP_PKEY_set1_RSA err\n");
        exit(0);
    }

    /*********************************************************************************
    
    // AES对明文 message 进行对称加密
    
    ***********************************************************************************/
    
    AES_ENCRYPT_MESSAGE(message, ciphertext);
    printf("加密后密文:\n");
	for (int i = 0; i < 32; i++) {
        printf("%02x ", ciphertext[i]);
		// printf("%02x %02x %02x %02x", ciphertext[4*i+0], ciphertext[4*i+1], ciphertext[4*i+2], ciphertext[4*i+3]);
	}
	printf("\n\n");


    /************************************************************************************
    
    // 使用RSA私钥对MD5摘要签名 
    
    ************************************************************************************/
    
    ret = RSA_private_encrypt(32, md5ctx, md5ctx_out, client_pvt_key, RSA_PKCS1_PADDING);
     if(ret < 0){
        printf("AES密码摘要的私钥签名失败！");
        exit(0);
    }
    printf("签名后的摘要为：　\n");
    for(int i=0; i<128; i++){
        printf("%02x ", md5ctx_out[i]);
    }
    

    /************************************************************************************
    
    // 获取当前时间戳

    ************************************************************************************/
    int time = time_stamp();
    unsigned char time_stamp_value[10];
    printf("\n\n时间戳为：　\n%d", time);
    for (int i=9; i>=0; i--){
        time_stamp_value[i] = time % 10;
        time = time / 10;
        printf("%c ", time_stamp_value[i]);
    }
    printf("\n\n");
    /************************************************************************************
    // 组合字段
    *************************************************************************************/
    for(int i=0; i<128; i++){
        send_message[i] = md5ctx_out[i];
        // printf("%02x ", send_message[i]);
    }

    for(int i=128, j=0; i<160; i++, j++){
        send_message[i] = ciphertext[j];
        // printf("%02x ", send_message[i]);
    }

    for(int i=160, j=0; i<170; i++, j++){
        send_message[i] = time_stamp_value[j];
        // printf("%02x ", send_message[i]);
    }


    /***********************************************************************************
    // 释放资源
    *************************************************************************************/
    RSA_free(server_pub_key);
    RSA_free(client_pvt_key);

    // 关闭文件流
    fclose(fp_client_pvt_key);
    fclose(fp_server_pub_key);

}

int DECODE_MESSAGE(unsigned char message[]){
    unsigned char md5ctx_out[128];
    unsigned char ciphertext[32];
    unsigned char msg_ciphertext[32];
    unsigned char time_stamp_value[10];
    unsigned char time_stamp_native[10];
    EVP_PKEY *evpKey=NULL;      //EVP KEY结构体变量
    int ret;

    printf("加密后的摘要：\n");
    for(int i=0; i<128; i++){
        md5ctx_out[i] = message[i];
        printf("%02x ", md5ctx_out[i]);
    }
    printf("\n\n");
    printf("加密后的明文：\n");
    for(int i=128, j=0; i<160; i++, j++){
        ciphertext[j] = message[i];
        printf("%02x ", ciphertext[j]);
    }
    printf("\n\n");
    printf("时间戳：\n");
    for(int i=160, j=0; i<170; i++, j++){
        time_stamp_value[j] = message[i];
        printf("%02x ", time_stamp_value[i]);
    }

    /************************************************************************************
    
    // 获取当前时间戳

    ************************************************************************************/
    int time = time_stamp();
    printf("\n\n时间戳为：　\n%d", time);
    for (int i=9; i>=0; i--){
        time_stamp_native[i] = time % 10;
        time = time / 10;
        printf("%c ", time_stamp_native[i]);
        if (time_stamp_value[i]==time_stamp_native[i]){
            continue;
        }
        else{
            printf("消息已过期");
        }
    }
    printf("\n时间戳验证通过");

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
        printf("明文密码摘要的公钥验证签名失败！");
        exit(0);
    }
    printf("\n\n解密后的摘要msg_md5ctx为： \n");
    for(int i=0; i < 16; i++){
        printf("%02x ", msg_md5ctx[i]);
    }
    printf("\n");
    /***********************************************************************************
     * *********************************************************************************
    // 解密密文获取明文
    ************************************************************************************
    ************************************************************************************/
    AES_DECRYPT_MESSAGE(ciphertext, msg_ciphertext);
    for(int i=0;i<32;i++)  
    {
        printf("%02x ",msg_ciphertext[i]);  //02x前需要加上%      
    }
    
    /****************************************************************************
     ****************************************************************************
    // 对明文计算摘要
    *****************************************************************************
    ****************************************************************************/
    unsigned char msg_ciphertext_md5ctx[16]; //加密结果
    MD5_ABSTRACT(msg_ciphertext, msg_ciphertext_md5ctx);
    for(int i=0;i<16;i++)  
    {
        printf("%02x ",msg_ciphertext_md5ctx[i]);  //02x前需要加上%      
    }
    printf("\n\n");
    /****************************************************************************
     ****************************************************************************
    // 检验完整性
    *****************************************************************************
    ****************************************************************************/
    for(int i=0; i < 16; i++){
        if(msg_ciphertext_md5ctx[i]==msg_md5ctx[i]){
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


int main(int argc, char **argv) {
    // unsigned char key_message[256];
    // ENCODE_AES_KEY(key_message);
    // DECODE_AES_KEY(key_message);
    unsigned char message[32] = "suchensuchensuchensuchensuchensu";
    unsigned char send_message[170];
    ENCODE_MESSAGE(message, send_message);
    DECODE_MESSAGE(send_message);
    return 0;
}