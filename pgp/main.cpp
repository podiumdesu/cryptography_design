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
/*************************SPN参数声明**************************/
#define Nr 16
int  S[16][16] = {
	{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};
int Pbox[16] = { 0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15 };
int  S_inverse[16][16] = { 0 };
long long key[Nr + 1] = { 0 };
long long w = 0;
long long u = 0;
long long v = 0;
unsigned long long K = 0x123ab25df686c124;
unsigned long long iv = 0x3a94d63f12345678;
/**********************SPN增强加密************************/
long long s_arrange(long long u, int S[16][16]);
long long p_arrange(long long u);
long long p_spn(int  u);
long long spn_encryption(long long x, long long K);
/**********************SPN************************/

/**********************SPN增强解密*************************/
void sbox_inverse(int S[16][16], int S_inverse[16][16]);
long long p_inverse(long long u);
long long spn_dncryption(long long y, long long K);
/**********************SPN��ǿ����*************************/

/************************��Կ����**************************/
unsigned long long KL_LShift(unsigned long long KL, int t);
unsigned long long KR_LShift(unsigned long long KR, int t);
void k_arrange(long long K, long long key[Nr + 1]);
/************************��Կ����**************************/

/************************����ת��**************************/
long long bit_to_num1(int  bit[64]);
void num_to_bit1(int  bit[64], long long u);
int  bit_to_num(int  bit[16]);
void num_to_bit(int  bit[16], int u);
long long char_to_hex(char x_128[32], int m);
/************************����ת��**************************/

/*************************SPN参数声明*************************/

int File_read();
char * Hash_sha1(char * P);
int Len;              //填充后几位
int Padding;             //填充几位
char *P;              //导出的明文
char Hash1[SHA_DIGEST_LENGTH * 2 + 1];     //存储加密时的hash
char Hash2[SHA_DIGEST_LENGTH * 2 + 1];     //存储解密时的hashֵ
char testHash1[SHA_DIGEST_LENGTH * 2 + 1];
long long spn_encryption(long long x, long long K);


int main()
{
	char *q;
	File_read();
//	printf("AA%s11111%llx", q,k1);

//	printf("请按任意键继续...");
//	getchar();
//	getchar();
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
	if ((fq = fopen("11.txt" ,"r")) == NULL) {
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
	if(group1==NULL)
	{
		printf("EC_GROUP_new_by_curve_name err!\n");
		return -1;
	}
	group2=EC_GROUP_new_by_curve_name(nid);
    if(group2==NULL)
    {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }
	/* 设置密钥参数 */
	/*Sets the EC_GROUP of a EC_KEY object.*/
	ret=EC_KEY_set_group(key1,group1);
	if(ret!=1)
	{
		printf("EC_KEY_set_group err.\n");
		return -1;
	}
	/* 设置Key2 */
	ret=EC_KEY_set_group(key2,group2);
	if(ret!=1)
	{
		printf("EC_KEY_set_group err.\n");
		return -1;
	}
	/* 生成密钥 */
	ret=EC_KEY_generate_key(key1);
	if(ret!=1)
	{
		printf("EC_KEY_generate_key err.\n");
		return -1;
	}
	ret=EC_KEY_generate_key(key2);
	if(ret!=1)
	{
		printf("EC_KEY_generate_key err.\n");
		return -1;
	}
	/* 检查密钥 */
	ret=EC_KEY_check_key(key1);
	if(ret!=1)
	{
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
	if(ret!=1)
	{
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
		ret=memcmp(shareKey1,shareKey2,len1);
		if(ret==0)
			printf("生成共享密钥成功\n");
		else
			printf("生成共享密钥失败\n");
	}
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
	Cipher[0] = spn_encryption(cipher[0] ^ iv, K);//明文加密，放入Cipher中，cbc模式
	for (z = 1; z <= Num; z++)
		Cipher[z] = spn_encryption(Cipher[z - 1] ^ cipher[z], K);
	if ((fp = fopen("111.txt", "w+")) == NULL) {
		printf("打开文件%s出现错误\n", filename);
		return 0;
	}
	for (i = 0; i < Num+1 ; i++)
		fwrite(&Cipher[i], sizeof(unsigned long long), 1, fp); // 将密文写入文件中
	fclose(fp);
	fclose(fq);
/*************************SPN对称加密************************/


//
///************************ 椭圆曲线加密key  *************************/
//	//加密操作，对点M1（此处以G为例）加密，C2=rG，C1=G+rK，
//
////其中K为B的公钥。
//
////OpenSSL里的函数功能：EC_POINT_mul是点乘，EC—POINT_
//
////add是点加。
//	EC_GROUP * encryptKeyGroup;
//	const EC_POINT * encryptKeyC1, encryptKeyC2, encryptKeyB;
//	const EC_POINT * encryptKeyQ, encryptKeyK;
//	const BIGNUM * encryptKeyM;
//	const BN_CTX * encryptKeyCtx;
//
//
//	encryptKeyK = EC_KEY_new();
//
//	/* 获取实现的椭圆曲线个数 */
//	crv_len = EC_get_builtin_curves(NULL, 0);
//	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
//	/* 获取椭圆曲线列表 */
//	EC_get_builtin_curves(curves, crv_len);
//	/*
//    nid=curves[0].nid;会有错误，原因是密钥太短
//    */
//	/* 选取一种椭圆曲线 */
//	nid=curves[25].nid;
////    printf("%d\n", nid);
//	/* 根据选择的椭圆曲线生成s密钥参数 group */
//	encryptKeyGroup = EC_GROUP_new_by_curve_name(nid);
//
//	/* 设置密钥参数 */
//	/*Sets the EC_GROUP of a EC_KEY object.*/
//	ret=EC_KEY_set_group(encryptKeyK ,encryptKeyGroup);
//	if(ret!=1) {
//		printf("EC_KEY_set_group err.\n");
//		return -1;
//	}
//	/* 生成公钥和私钥 */
//	ret = EC_KEY_generate_key(encryptKeyK);
//	if (ret != 1) {
//		printf("EC_KEY_generate_key err.\n");
//		return -1;
//	}
//	int KEYLen = i2o_ECPublicKey()
//
//
//
//	/** Computes r = generator * n + q * m
//645  *  \param  group  underlying EC_GROUP object
//646  *  \param  r      EC_POINT object for the result
//647  *  \param  n      BIGNUM with the multiplier for the group generator (optional)
//648  *  \param  q      EC_POINT object with the first factor of the second summand
//649  *  \param  m      BIGNUM with the second factor of the second summand
//650  *  \param  ctx    BN_CTX object (optional)
//651  *  \return 1 on success and 0 if an error occured
//652  */
////	int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
////	EC_POINT_mul( group, C2, NULL,G,r,ctx);
////	EC_POINT_mul(group,B,NULL,K,r,ctx);
////	EC_POINT_add( group, C1,G,B,ctx);
//
////	C2=MQ，C1=Q+MK，
////其中K为B的公钥。
//	EC_POINT_mul(encryptKeyGroup, encryptKeyC2, NULL, encryptKeyQ ,encryptKeyM,encryptKeyCtx);
//
//	EC_POINT_mul(encryptKeyGroup, encryptKeyB, NULL, encryptKeyK, encryptKeyM, encryptKeyCtx);
//
//	EC_POINT_add(encryptKeyGroup, encryptKeyC1, encryptKeyQ , encryptKeyB, encryptKeyCtx);
//
//
///************************ 椭圆曲线加密key  *************************/
//
//
///************************ 椭圆曲线解密key  *************************/
////解密操作，对得到的(C1，C2)解密得到M2=Cl-kC2
//
//	EC_POINT_mul(group,R,NULL, C2,k,ctx);
//
//	EC_POINT_invert( group,R,ctx);
//
//	EC_POINT_add( group, M2, Cl,R,ctx);
//
///************************ 椭圆曲线解密key  *************************/
//
//




/*************************SPN 对称解密**************************/
	if ((fq = fopen("111.txt", "r")) == NULL) {    // 打开文件
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
	Cipher[0] = spn_dncryption(cipher[0], K) ^ iv;
	// 此处进行解密
	for (z = 1; z < Num; z++)
		Cipher[z] = spn_dncryption(cipher[z], K) ^ cipher[z - 1];
	printf("Cipher = %s\n", Cipher);
//	Cipher[]
	if ((fp = fopen("1111.txt", "w+")) == NULL) {
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
/**************************椭圆曲线算法************************/

/************************SHA1 hash************************/

/****************************压缩******************************/
//	COMP_CTX          *ctx;
//	int                  len=0, olen = 100, ilen = 50,  total =0;
//	unsigned char in[100], out[100];
//	unsigned char expend[200];
//#ifdef      _WIN32
//	ctx = COMP_CTX_new(COMP_rle());
//#else
//	/* for linux */
//	ctx = COMP_CTX_new(COMP_zlib());
//#endif
//	for (i = 0; i<100; i++)
//		memset(&out[i], i, 1);
//	total = COMP_compress_block(ctx, in, 50, out, 100);
////	total = COMP_compress_block(ctx, out,100, in, 100);
//	for (i = 0; i < 50; i++)
//		printf("%d ", in[i]);
//	printf("\n");
//	len = COMP_expand_block(ctx, expend, 200, out, total);
//	printf("\n");
//	for (i = 0; i < 200; i++)
//		printf("%d ", expend[i]);
//	printf("len=%d,to=%d", len, total);
//	COMP_CTX_free(ctx);
/****************************ѹ��******************************/

	return 0;
}

/*************************SPN�ԳƼ���**************************/

/************************��Կ����**************************/
/*��Կ����ʱKLѭ������*/
unsigned long long KL_LShift(unsigned long long KL, int t) {
	unsigned long long k;
	k = KL >> (32 - t);
	KL = (KL << t) | k;
	return KL;
}
/*��Կ����ʱKLѭ������*/
unsigned long long KR_LShift(unsigned long long KR, int t) {
	unsigned long long k;
	k = KR >> (32 - t);
	KR = (KR << t) | k;
	KR = KR & 0x00000000ffffffff;
	return KR;
}
/*����DES����Կ����*/
void k_arrange(long long K, long long key[Nr + 1]) {
	int i, j;
	int  P_K[64] = { 57,49,41,33,25,17,9,8,1,58,50,42,34,26,18,16,
		10,2,59,51,43,35,27,24,19,11,3,60,52,44,36,32,
		63,55,47,39,31,23,15,40,7,62,54,46,38,30,22,48,
		14,6,61,53,45,37,29,56,21,13,5,28,20,12,4,64 };
	unsigned long long KL, KR;
	int  P_temp[64] = { 0 };
	int  p_bit[64] = { 0 };
	num_to_bit1(P_temp, K);         //��������Կ���64��������
	for (i = 0; i<64; i++)
		p_bit[i] = P_temp[P_K[i] - 1]; //�û�
	K = bit_to_num1(p_bit);          //���û����64λ�����ƴ���Ϊʮ����K,��ʼ�û�
	KL = K & 0xffffffff00000000;
	KR = K & 0x00000000ffffffff;       //��K��Ϊ����������
	KL = KL_LShift(KL, 1);
	KR = KR_LShift(KR, 1);            //�ֱ�ѭ������һλ
	key[0] = KL | KR;                  //��һ����Կ
	KL = KL_LShift(KL, 1);
	KR = KR_LShift(KR, 1);
	key[1] = KL | KR;
	for (i = 2; i <= 8; i++) {
		KL = KL_LShift(KL, 1);
		KR = KR_LShift(KR, 1);
		key[i] = KL | KR;
	}
	for (i = 9; i <= 15; i++) {
		KL = KL_LShift(KL, 2);
		KR = KR_LShift(KR, 2);
		key[i] = KL | KR;
	}
	key[16] = K;                   //���һ��
}
/************************��Կ����**************************/

/************************����ת��**************************/
/*16����2���ƴ�ת��Ϊ10������*/
int  bit_to_num(int  bit[16]) {
	int  num = 0;
	int i;
	for (i = 0; i<16; i++)
		num = num * 2 + bit[i];
	return num;
}
/*16���س�10������ת��Ϊ16λ2���ƴ�*/
void num_to_bit(int  bit[16], int  u) {
	int i, con = u;
	for (i = 0; i<16; i++)
		bit[i] = 0;
	for (i = 15; i >= 0; i--) {
		bit[i] = con % 2;
		con = con / 2;
	}
}
/*64����2���ƴ�ת��Ϊ10������*/
long long bit_to_num1(int bit[64]) {
	long long num = 0;
	int i;
	for (i = 0; i<64; i++)
		num = num * 2 + bit[i];
	return num;
}
/*64���س�10������ת��Ϊ64λ2���ƴ�*/
void num_to_bit1(int  bit[64], long long u) {
	int i;
	for (i = 0; i<64; i++)
		bit[i] = 0;
	long long  con;
	con = u;
	for (i = 63; i >= 0; i--) {
		bit[i] = con % 2;
		con = con / 2;
	}
}
/*�ַ���ת��Ϊ16λ16����*/
long long char_to_hex(char x_128[32], int m) {
	int i, temp[32];
	long long x = 0;
	for (i = 0; i<16; i++) {
		if (x_128[i + m] >= '0'&&x_128[i + m] <= '9')
			temp[i] = x_128[i + m] - '0';
		else temp[i] = x_128[i + m] - 87;
		x = temp[i] + x * 16;
	}
	return x;
}
/************************����ת��**************************/

/**********************SPN��ǿ����*************************/
/*64�������ļӡ�����s��(�棩����*/
long long s_arrange(long long u, int S[16][16]) {   //����ʱ��S��������S_inverse
	int i;
	long long v = 0;
	long long t0[8] = { 0xff00000000000000,0x00ff000000000000,0x0000ff0000000000,0x000000ff00000000,
		0x00000000ff000000,0x0000000000ff0000,0x000000000000ff00,0x00000000000000ff };//һ��64λ���ģ���Ϊ8��
	long long t[8];
	int  low, high, swap;
	for (i = 0; i<8; i++)
		t[i] = (u & t0[i]) >> (56 - i * 8);       //��u�е�ÿ16λ�����t[i]�У���λ��������Ҫ����56λ���Դ�����
	for (i = 0; i<8; i++) {
		low = (t[i] & 0x0f);
		high = (t[i] & 0xf0) >> 4;
		swap = S[high][low];                //��t[i]������16����������ΪS��������н����滻
		t[i] = (long)swap;
		t[i] = t[i] << (56 - i * 8);            //��t[i]���ӳ�64����
		v = v | t[i];                         //������ӣ�t[i]ÿһ������λ�ò�ͬ����򼴿�����
	}
	return v;
}
/*����p�û�*/
long long p_arrange(long long v) {    //p���û�����64λ���ݷ�Ϊ8��
	unsigned long long b[4];
	unsigned long long t[8];                  //��v��Ϊ8�飬ÿһ�����ֵ���������t��
	t[0] = 0xff00000000000000 & v; t[4] = 0x00000000ff000000 & v;
	t[1] = 0x00ff000000000000 & v; t[5] = 0x0000000000ff0000 & v;
	t[2] = 0x0000ff0000000000 & v; t[6] = 0x000000000000ff00 & v;
	t[3] = 0x000000ff00000000 & v; t[7] = 0x00000000000000ff & v;
	v = (t[0] >> 56) | (t[1] >> 24) | (t[2] >> 8) | (t[3] << 24) | (t[4] >> 16) | (t[5]) | (t[6] << 32) | (t[7] << 48);
	//��8�����ݰ���p�й��򽻻�λ�ã��û�,v�������
	b[0] = (0x000000000000ffff & v);
	b[1] = (0x00000000ffff0000 & v) >> 16;
	b[2] = (0x0000ffff00000000 & v) >> 32;
	b[3] = (0xffff000000000000 & v) >> 48;
	v = (p_spn(b[3]) << 48) | (p_spn(b[2]) << 32) | (p_spn(b[1]) << 16) | p_spn(b[0]);
	//��8���û���ķ�Ϊ4�飬һ��16���أ�ÿһ�����ԭʼspn���û�
	return v;
}
/*ԭʼP���û�*/
long long p_spn(int u) {
	int i;
	int P_temp[16] = { 0 };
	int p_bit[16] = { 0 };
	num_to_bit(P_temp, u);         //u���16λ������
	for (i = 0; i<16; i++)
		p_bit[i] = P_temp[Pbox[i]]; //16λ�û�������Pbox�Ĺ���
	u = bit_to_num(p_bit);          //�û����16λ�����Ʊ�Ϊu
	u = (long)u;
	return u;
}
/*spn��ǿ����*/
long long spn_encryption(long long x, long long K) {
	long long y;
	int i;
	k_arrange(K, key);      //��Կ����
	w = x;
	for (i = 0; i<Nr - 1; i++) {   //ǰNr-1��
		u = key[i] ^ w;        //�׻�
		v = s_arrange(u, S);  //����
		w = p_arrange(v);    //�û�
	}
	u = key[Nr - 1] ^ w;
	v = s_arrange(u, S);
	y = key[Nr] ^ v;       //���һ����򣬲��û�
	return y;
}
/**********************SPN��ǿ����*************************/

/**********************SPN��ǿ����*************************/
/*����ʹ��s�е���*/
void sbox_inverse(int S[16][16], int S_inverse[16][16]) {
	int  i, j, temp, th, tl;
	for (i = 0; i<16; i++)
		for (j = 0; j<16; j++) {
			temp = S[i][j];
			th = (temp & 0xf0) >> 4;    //thΪ����λ
			tl = temp & 0x0f;         //tlΪ����λ
			temp = (i << 4) | j;          //i��Ϊ����λ��j��Ϊ����λ����Ϊs���Ԫ��
			S_inverse[th][tl] = temp; //th��tlΪtemp��λ��
		}       //���ܴ���ʱ����u�����ݱ��s����Ȼ����s�����ݴ���������ʱ��s���б��s_inverse���ݣ�s�е����ݱ�Ϊ����
}
/*64bit���Ľ���p�����û�*/
long long p_inverse(long long u) {  //p�����û�����64λ���ݷ�Ϊ8��
	unsigned long long b[4];
	unsigned long long t[8];
	b[0] = (0x000000000000ffff & u);
	b[1] = (0x00000000ffff0000 & u) >> 16;
	b[2] = (0x0000ffff00000000 & u) >> 32;
	b[3] = (0xffff000000000000 & u) >> 48;
	u = (p_spn(b[3]) << 48) | (p_spn(b[2]) << 32) | (p_spn(b[1]) << 16) | p_spn(b[0]);
	//��8���û���ķ�Ϊ4�飬һ��16���أ�ÿһ�����ԭʼspn�����û������û����û���ͬ
	t[0] = 0xff00000000000000 & u; t[4] = 0x00000000ff000000 & u;
	t[1] = 0x00ff000000000000 & u; t[5] = 0x0000000000ff0000 & u;
	t[2] = 0x0000ff0000000000 & u; t[6] = 0x000000000000ff00 & u;
	t[3] = 0x000000ff00000000 & u; t[7] = 0x00000000000000ff & u;
	u = (t[0] >> 24) | (t[1] >> 48) | (t[2] >> 32) | (t[3] << 8) | (t[4] << 24) | (t[5]) | (t[6] << 16) | (t[7] << 56);
	//��8�����ݰ���p�й��򽻻�λ�ã����û�
	return u;
}
/*spn��ǿ����*/
long long spn_dncryption(long long y, long long K) {
	long long x;
	int i;
	k_arrange(K, key);
	sbox_inverse(S, S_inverse);//�����
	v = key[16] ^ y;              //��Կ���
	u = s_arrange(v, S_inverse); //�����
	w = key[15] ^ u;              //�׻�
	for (i = 0; i<Nr - 1; i++) {
		v = p_inverse(w);       //���û�
		u = s_arrange(v, S_inverse);
		w = key[Nr - i - 2] ^ u;
	}
	x = w;
	return x;
}
/**********************SPN��ǿ����*************************/

/*************************SPN�ԳƼ���**************************/
