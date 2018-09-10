#define _CRT_SECURE_NO_DEPRECATE
#pragma warning( disable : 4996)

#include <stdio.h>
#include <string.h>
//#include <cstring>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/comp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#include "improveSpn/improveSpn.h"
#include "overall.h"


/*************************SPN参数声明**************************/
#define Nr 16

int File_read();
char * Hash_sha1(char * P);
int Len;              //填充后几位
int Padding;             //填充几位
char *P;              //导出的明文
char Hash1[SHA_DIGEST_LENGTH * 2 + 1];     //存储加密时的hash
char Hash2[SHA_DIGEST_LENGTH * 2 + 1];     //存储解密时的hashֵ
char testHash1[SHA_DIGEST_LENGTH * 2 + 1];

int main()
{
	char *q;
	File_read();
	return 0;

}



int File_read() {
	char filename[20];
	FILE *fq,*fp;
	char * Plain, *t;                  //char 一个字节
	unsigned long long * temp;
	unsigned long long * cipher;
	unsigned long long * Cipher;        //64位， 加/解密后存储
	unsigned char digest[SHA_DIGEST_LENGTH], Digest[SHA_DIGEST_LENGTH]; //hash使用
	int block, Num, i, m, z, Len;
//	printf("请输入明文名称\n");
	int fileLength;
//	scanf("%s", filename);
	printf("开始读入文件......\n");
	if ((fq = fopen("test.txt" ,"r")) == NULL) {
		printf("打开文件时%s出错\n", filename);
		return 0;
	}
	fseek(fq, 0, SEEK_END);
	i = ftell(fq); //文件长度
	fileLength = i;
	Plain = (char *)malloc(sizeof(char)*(i + 1));
	rewind(fq);
	fread(Plain, 1, i, fq);//读取文件
	Plain[i] = '\0';
	block = 8;//分组8个字节
	Num = i / block;   //一共Num块
	Padding = i % block;
	printf("Padding = %d, i = %d\n", Padding, i);
	Padding= block - Padding;    // fill 为需要填充多少字节，每块必须8字节
	P = (char *)malloc(sizeof(char)*(i + Padding)); //填充后的长度

	cipher = (unsigned long long *)malloc(sizeof(unsigned long long)*(Num + 1));
	Cipher = (unsigned long long *)malloc(sizeof(unsigned long long)*(Num + 1));
	for (z = 0; z<i; z++) {//明文填充
		P[z] = Plain[z];
	}
	for (; z<i + Padding; z++) {
		P[z] = Padding + '0';
	}
	P[z] = '\0';


	t = (char *)malloc(sizeof(char)*(i + Padding));   // 注意地址的连续性

	// todo: 这里有问题，怎么能直接操作地址呢？
//	for (int k = 0; k < z; k++) {
//		t[k] = P[k];
//	}
	strcpy(t, P);
	t[z] = '\0';
//	t = P;
	printf("t = %s, P = %s, sizeof(t) = %d\n", t, P, sizeof(t));

	Len = z;


/************************SHA1 hash   得到hash值  ************************/
	// 进行hash

//	SHA1((unsigned char*)P, Len, (unsigned char*)&digest);
	SHA1((unsigned char*)P, Len, (unsigned char*)&digest);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		Digest[i] = digest[i];
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(&Hash1[i * 2], "%02x", (unsigned int)Digest[i]);
		sprintf(&testHash1[i * 2], "%02x", (unsigned int)digest[i]);
	}
	printf("\nSHA1 Digest: %s\n", Hash1);
	printf("\nSHA1 digest: %s\n", testHash1);
	printf("\n对明文P：%s  \n进行加密：digest=%s\n", P, digest);
	// 获得Hash后的值

/************************SHA1 hash************************/





//	printf("HASH后初始密文 = %s\n", cipher);

/*************************  椭圆曲线算法 签名 使用A的私钥进行签名。 *************/
	EC_KEY *key1,*key2;
	const EC_POINT *pubkey1,*pubkey2;
	EC_GROUP *group1,*group2;
	unsigned int ret,nid,size,sig_len;
	unsigned char *signature;
	BIO *berr;
	EC_builtin_curve *curves;
	int crv_len;
	char shareKey1[128],shareKey2[128];
	int len1,len2;
	/* 构造 EC_KEY 数据结构 */
	key1=EC_KEY_new();
	if(key1==NULL)
	{
		printf("EC_KEY_new err!\n");
		return -1;
	}
	key2=EC_KEY_new();
	if(key2==NULL)
	{
		printf("EC_KEY_new err!\n");
		return -1;
	}
	/* 获取实现的椭圆曲线个数 */
	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	/* 获取椭圆曲线列表 */
	EC_get_builtin_curves(curves, crv_len);
	/*
    nid=curves[0].nid;会有错误，原因是密钥太短
    */
	/* 选取一种椭圆曲线 */
	nid=curves[25].nid;
//    printf("%d\n", nid);
	/* 根据选择的椭圆曲线生成s密钥参数 group */
	group1=EC_GROUP_new_by_curve_name(nid);
	if(group1==NULL) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		return -1;
	}
	group2=EC_GROUP_new_by_curve_name(nid);
    if(group2==NULL) {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
	/* 设置密钥参数 */
	/*Sets the EC_GROUP of a EC_KEY object.*/
	ret=EC_KEY_set_group(key1,group1);
	if(ret!=1) {
		printf("EC_KEY_set_group err.\n");
		return -1;
	}
	/* 设置Key2 */
	ret=EC_KEY_set_group(key2,group2);
	if(ret!=1) {
		printf("EC_KEY_set_group err.\n");
		return -1;
	}
	/* 生成密钥 */
	ret=EC_KEY_generate_key(key1);
	if(ret!=1) {
		printf("EC_KEY_generate_key err.\n");
		return -1;
	}
	ret=EC_KEY_generate_key(key2);
	if(ret!=1) {
		printf("EC_KEY_generate_key err.\n");
		return -1;
	}
	/* 检查密钥 */
	ret=EC_KEY_check_key(key1);
	if(ret!=1) {
		printf("check key err.\n");
		return -1;
	}
	/* 获取密钥大小 */
	size=ECDSA_size(key1);
	printf("size %d \n",size);
	for(i=0;i<20;i++)
		memset(&digest[i],i+1,1);
	signature= (unsigned char*)malloc(size);
	ERR_load_crypto_strings();
	berr=BIO_new(BIO_s_file());
	//BIO_set_fp(berr,stdout,BIO_NOCLOSE);
	/* 签名数据，本例未做摘要，可将 digest 中的数据看作是 sha1 摘要结果 */
	ret=ECDSA_sign(0,Digest,20,signature,&sig_len,key1);
	if(ret!=1) {
		ERR_print_errors(berr);
		printf("sign err!\n");
		return -1;
	}


	/* 获取对方公钥，不能直接引用 */
	pubkey2 = EC_KEY_get0_public_key(key2);
	/* 生成一方的共享密钥 */
	len1= ECDH_compute_key(shareKey1, 128, pubkey2, key1, NULL);
	pubkey1 = EC_KEY_get0_public_key(key1);
	/* 生成另一方共享密钥 */
	len2= ECDH_compute_key(shareKey2, 128, pubkey1, key2, NULL);
	if(len1!=len2)
	{
		printf("err\n");
	}
	else
	{
//		char ddd[128];
		ret=memcmp(shareKey1,shareKey2,len1);
		if(ret==0) {
			printf("生成共享密钥成功\n");
			printf("共享密钥key = %llx, %d\n", shareKey1, strlen(shareKey1));
		} else {
			printf("生成共享密钥失败\n");
		}
	}
//	for (int i = 0; i < 64; i++){
//		printf("%s", &shareKey1[i]);
//	}
//	printf("\n\n");
	unsigned long long arrForShareKey;
	unsigned long long * arrForShareKey0, * arrForShareKey1;
	arrForShareKey0 = arrForShareKey1 = (unsigned long long *)malloc(sizeof(unsigned long long));
	arrForShareKey0 = (unsigned long long *)shareKey1;
	arrForShareKey1 = (unsigned long long *)shareKey2;

	arrForShareKey = arrForShareKey0[0];
//	printf("sharekey = %llx\n", shareKey1);
//	for (int i = 0; i < 64; i++) {
//		printf("%d", i);
//		sprintf(&shareKey1[i * 2], "%02x", (unsigned int)arrForShareKey[i]);
//	}
//
//	printf("\nshareKey in arr = %llx\n", arrForShareKey);
/**************************************************************/


//
//
/*************************SPN对称加密   利用k 加密明文和hash值**************************/
	printf("HASH前P = %s\n", P);
	// todo: what use for it?????

	for (z = 0; z <= Num; z++){
		temp = (unsigned long long *)(t);
		printf("temp = %s\n", temp);
//		strncpy(cipher[z], temp, 8);
		cipher[z] = *temp;
		printf("cipher[%d] = %s\n", z, temp);
		t += 8;
	}
//	cipher[Num+1] = "\0";
	printf("cipher = %s\n", cipher);

	// 将从文件中读取的明文放入数组中

	// 此处对文件进行spn的加密
	Cipher[0] = spn_encode(cipher[0] ^ iv, arrForShareKey);//明文加密，放入Cipher中，cbc模式
	for (z = 1; z <= Num; z++)
		Cipher[z] = spn_encode(Cipher[z - 1] ^ cipher[z], arrForShareKey);
	if ((fp = fopen("encryptTest.txt", "w+")) == NULL) {
		printf("打开文件%s出现错误\n", filename);
		return 0;
	}
	for (i = 0; i < Num+1 ; i++)
		fwrite(&Cipher[i], sizeof(unsigned long long), 1, fp); // 将密文写入文件中
	fclose(fp);
	fclose(fq);
/*************************SPN对称加密************************/


/*************************SPN 对称解密**************************/
	if ((fq = fopen("encryptTest.txt", "r")) == NULL) {    // 打开文件
		printf("打开文件%s时出现错误\n", filename);
		return 0;
	}
	fseek(fq, 0, SEEK_END);
	i = ftell(fq);   // 文件长度
	unsigned long long *Cip;
	block = 8;
	Num = i / block;
	Cip = (unsigned long long *)malloc(sizeof(unsigned long long)*Num);
	rewind(fq);
	fread(Cip, 1, i, fq);

	cipher = (unsigned long long *)malloc(sizeof(unsigned long long)*(Num + 1));
	Cipher = (unsigned long long *)malloc(sizeof(unsigned long long)*(Num + 1));
	for (z = 0; z <Num; z++)
		cipher[z] = Cip[z];
	Cipher[0] = spn_decode(cipher[0], arrForShareKey) ^ iv;
	// 此处进行解密
	for (z = 1; z < Num; z++)
		Cipher[z] = spn_decode(cipher[z], arrForShareKey) ^ cipher[z - 1];
	printf("Cipher = %s\n", Cipher);
//	Cipher[]
	if ((fp = fopen("output.txt", "w+")) == NULL) {
		printf("打开文件%s时出现错误\n", filename);
		return 0;
	}


	P =(char *) Cipher;


	SHA1((unsigned char*)P, Len, (unsigned char*)&digest);
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&Hash1[i * 2], "%02x", (unsigned int)Digest[i]);
	printf("\nSHA1 digest: %s\n", Hash1);

	printf("\ndigest=%s\n", digest);


	// 此处在处理解密后显示的值
	P[Num * block - Padding] = '\0';
	printf("解密后 P = %s\n", P);
	printf("Num = %d\n", Num);
	int tempTick;
	int k;
	for (k = 0, tempTick = 0; k < Num; k++) {
		printf("P[%d] = %s\n", k, &P[k]);
		fwrite(&P[tempTick], sizeof(unsigned long long), 1, fp);
		tempTick+=8;
	}
	printf("tempTick = %d, fileLength = %d\n", tempTick, fileLength);

	// todo: 处理一下padding后多添加的值
//	for (; tempTick < fileLength; tempTick++) {
//		fwrite(&P[tempTick], sizeof(unsigned long long), 1, fp);
//	}
//	for (i = 0; i < 1; i++) {
//		printf("P[%d] = %s\n", i, &P[i]);
//
//	}

	fclose(fp);
	fclose(fq);
	/*************************SPN对称解密**************************/


	printf("处理椭圆曲线前，digest = %s\n", digest);
/**************************椭圆曲线验签***********************/

	/* 验证签名 */
	ret=ECDSA_verify(0,digest,20,signature,sig_len,key1);
	if(ret!=1)
	{
		ERR_print_errors(berr);
		printf("ECDSA_verify err!\n");
		return -1;
	}

	printf("test ok!\n");
	BIO_free(berr);
	EC_KEY_free(key1);
	EC_KEY_free(key2);
	free(signature);
	free(curves);
/**************************椭圆曲线验签************************/

	return 0;
}

