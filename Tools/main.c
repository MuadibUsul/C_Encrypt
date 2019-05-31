#include "aes.c"
#include "md5.c"
#include <stdio.h>

int main(){
    // 明文MD5摘要
    unsigned char encrypt[] = "";
    printf("请输入需要传输的数据: ");
    scanf("%s", encrypt);
    unsigned char md5ctx[16]; //加密结果
    MD5_ABSTRACT(encrypt, md5ctx);
    for(int i=0;i<16;i++)  
    {
        printf("%02x",md5ctx[i]);  //02x前需要加上%      
    }
    printf("\n\n");


    // 对明文 encrypt 进行对称加密
    unsigned char ciphertext[16];
    AES_ENCRYPT_MESSAGE(encrypt, ciphertext);
    printf("加密后密文:\n");
	for (int i = 0; i < 4; i++) {
		printf("%x%x%x%x", ciphertext[4*i+0], ciphertext[4*i+1], ciphertext[4*i+2], ciphertext[4*i+3]);
	}
	printf("\n\n");


    // 对密文 ciphertext 进行解密
    unsigned char message[16];
    AES_DECRYPT_MESSAGE(ciphertext, message);
    printf("解密后明文:\n");
    for (int i = 0; i < 4; i++) {
        printf("%x%x%x%x", message[4*i+0], message[4*i+1], message[4*i+2], message[4*i+3]);
    }
    
    return 0;
}