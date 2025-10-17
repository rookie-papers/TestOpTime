#include "benchmark/benchmark.h"
#include "Tools.h"

#include <iostream>
#include "core.h"
#include "rsa_RSA3072.h"
#include <cstdlib>  // for rand()

using namespace std;
using namespace RSA3072;



gmp_randstate_t state_BM;
csprng rng;

const mpz_class q("0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001");


void GMP_add(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        a + b;
    }
}

void GMP_sub(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        a - b;
    }
}

void GMP_mul(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        a * b;
    }
}


void GMP_div(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        a / b;
    }
}


void GMP_modadd(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        (a + b) % q;
    }
}

void GMP_modsub(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        (a - b) % q;
    }
}

void GMP_modmul(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        (a * b) % q;
    }
}


void GMP_moddiv(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    for (auto _: state1) {
        (a / b) % q;
    }
}


void GMP_inv(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    for (auto _: state1) {
        invert_mpz(a, q);
    }
}


void GMP_pow(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    mpz_class b = rand_mpz(state_BM);
    mpz_class c = rand_mpz(state_BM);
    for (auto _: state1) {
        pow_mpz(a, b, q);
    }
}


void Miracl_add(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    for (auto _: state1) {
        BIG_add(a, a, b);
    }
}

void Miracl_sub(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    for (auto _: state1) {
        BIG_sub(a, a, b);
    }
}

void Miracl_mul(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    for (auto _: state1) {
        BIG_mul(a, a, b);
    }
}


void Miracl_modadd(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b, order;
    randBig(a, rng);
    randBig(b, rng);
    BIG_rcopy(order, CURVE_Order);
    for (auto _: state1) {
        BIG_modadd(a, a, b, order);
    }
}

void Miracl_modsub(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b, order;
    randBig(a, rng);
    randBig(b, rng);
    BIG_rcopy(order, CURVE_Order);
    for (auto _: state1) {
        BIG_sub(a, a, b);
        BIG_mod(a, order);
    }
}


void Miracl_modmul(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b, order;
    randBig(a, rng);
    randBig(b, rng);
    BIG_rcopy(order, CURVE_Order);
    for (auto _: state1) {
        BIG_modmul(a, a, b, order);
    }
}


void Miracl_inv(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b, order;
    randBig(a, rng);
    BIG_rcopy(order, CURVE_Order);
    for (auto _: state1) {
        BIG_invmodp(a, b, order);
    }
}

void Miracl_ECP_add(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP P1, P2;
    ECP_generator(&P1);
    ECP_generator(&P2);
    ECP_mul(&P1, a);
    ECP_mul(&P2, b);
    for (auto _: state1) {
        ECP_add(&P1, &P2);
    }
}

void Miracl_ECP_mul(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP P1, P2;
    ECP_generator(&P1);
    ECP_generator(&P2);
    ECP_mul(&P1, a);
    ECP_mul(&P2, b);
    for (auto _: state1) {
        ECP_mul(&P1, a);
    }
}

void Miracl_ECP2_add(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP2 P1, P2;
    ECP2_generator(&P1);
    ECP2_generator(&P2);
    ECP2_mul(&P1, a);
    ECP2_mul(&P2, b);
    for (auto _: state1) {
        ECP2_add(&P1, &P2);
    }
}

void Miracl_ECP2_mul(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP2 P1, P2;
    ECP2_generator(&P1);
    ECP2_generator(&P2);
    ECP2_mul(&P1, a);
    ECP2_mul(&P2, b);
    for (auto _: state1) {
        ECP2_mul(&P1, a);
    }
}


void Miracl_pair(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP P1;
    ECP2 P2;
    ECP_generator(&P1);
    ECP2_generator(&P2);
    for (auto _: state1) {
        e(P1, P2);
    }
}


void Miracl_GT_mul(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP P1;
    ECP2 P2;
    ECP_generator(&P1);
    ECP2_generator(&P2);
    FP12 gt1 = e(P1, P2);
    ECP_mul(&P1, a);
    ECP2_mul(&P2, b);
    FP12 gt2 = e(P1, P2);
    for (auto _: state1) {
        FP12_mul(&gt1, &gt2);
    }
}

void Miracl_GT_pow(benchmark::State &state1) {
    initRNG(&rng);
    BIG a, b;
    randBig(a, rng);
    randBig(b, rng);
    ECP P1;
    ECP2 P2;
    ECP_generator(&P1);
    ECP2_generator(&P2);
    FP12 gt = e(P1, P2);
    for (auto _: state1) {
        FP12_pow(&gt, &gt, a);
    }
}

void Miracl_hash(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    for (auto _: state1) {
        hashToZp256(a, q);
    }
}

void Miracl_hashToPoint(benchmark::State &state1) {
    initState(state_BM);
    mpz_class a = rand_mpz(state_BM);
    for (auto _: state1) {
        hashToPoint(a, q);
    }
}


void Miracl_AES_Enc(benchmark::State &state) {
    int KK = 32;
    int i;
    aes a;
    char key[KK];
    char block[16]; // 加密16字节 16Bytes
    char iv[16];
    for (i = 0; i < KK; i++) key[i] = 5;
    key[0] = 1;
    for (i = 0; i < 16; i++) iv[i] = i;
    for (i = 0; i < 16; i++) block[i] = i;

    AES_init(&a, CTR16, KK, key, iv);
    AES_encrypt(&a, block);
    for (auto _: state) {
        AES_encrypt(&a, block);
    }
    AES_end(&a);
}

void Miracl_AES_Dec(benchmark::State &state) {

    int KK = 32;
    int i;
    aes a;

    char key[KK];
    char block[16];
    char iv[16];
    for (i = 0; i < KK; i++) key[i] = 5;
    key[0] = 1;
    for (i = 0; i < 16; i++) iv[i] = i;
    for (i = 0; i < 16; i++) block[i] = i;
    AES_init(&a, CTR16, KK, key, iv);
    AES_encrypt(&a, block);
    AES_reset(&a, CTR16, iv);
    for (auto _: state) {
        AES_decrypt(&a, block);
    }
    AES_end(&a);

}






bool pkcs1_v15_pad(const char* message, octet* padded) {
    size_t mlen = strlen(message);

    if (mlen > RFS_RSA3072 - 11) {
        cout << "消息太长，不能填充" << endl;
        return false;
    }

    static char buffer[RFS_RSA3072];
    buffer[0] = 0x00;
    buffer[1] = 0x02;

    int ps_len = RFS_RSA3072 - mlen - 3;
    for (int i = 0; i < ps_len; i++) {
        char rnd = 0;
        while (rnd == 0) rnd = rand() % 0xFF + 1;  // 非零填充
        buffer[2 + i] = rnd;
    }

    buffer[2 + ps_len] = 0x00;
    memcpy(buffer + 3 + ps_len, message, mlen);

    padded->len = RFS_RSA3072;
    padded->max = RFS_RSA3072;
    padded->val = buffer;

    return true;
}


bool pkcs1_v15_unpad(octet* decrypted, char* output, int max_output_len) {
    if (decrypted->len < 11 || decrypted->val[0] != 0x00 || decrypted->val[1] != 0x02) {
        cout << "解密数据格式错误" << endl;
        return false;
    }

    // 找分隔符 0x00
    int i = 2;
    while (i < decrypted->len && decrypted->val[i] != 0x00) {
        i++;
    }

    i++;  // 跳过 0x00
    if (i >= decrypted->len) {
        cout << "格式错误，找不到分隔符" << endl;
        return false;
    }

    int msg_len = decrypted->len - i;
    if (msg_len >= max_output_len) msg_len = max_output_len - 1;

    memcpy(output, decrypted->val + i, msg_len);
    output[msg_len] = '\0';

    return true;
}

void Miracl_RSA_Enc(benchmark::State &state) {
    char pr[100];
    csprng RNG;
    time_t t;
    time(&t);
    for (int i = 0; i < 100; i++) pr[i] = i + t % 256;
    RAND_seed(&RNG, 100, pr);

    rsa_private_key PRIV;
    rsa_public_key PUB;
    sign32 e = 65537;
    RSA_KEY_PAIR(&RNG, e, &PRIV, &PUB, NULL, NULL);

    const char* message ="Hello, MIRACL RSA! Hello, MIRACL RSA!";
    octet M;
    if (!pkcs1_v15_pad(message, &M)) {
        cout << "填充失败：消息太长或格式错误" << endl;
        return;
    }

    char enc[RFS_RSA3072], dec[RFS_RSA3072];
    octet C = {0, sizeof(enc), enc};
    octet D = {0, sizeof(dec), dec};

    for (auto _: state) {
        RSA_ENCRYPT(&PUB, &M, &C);
    }
    RSA_PRIVATE_KEY_KILL(&PRIV);
}

void Miracl_RSA_Dec(benchmark::State &state) {
    char pr[100];
    csprng RNG;
    time_t t;
    time(&t);
    for (int i = 0; i < 100; i++) pr[i] = i + t % 256;
    RAND_seed(&RNG, 100, pr);

    rsa_private_key PRIV;
    rsa_public_key PUB;
    sign32 e = 65537;
    RSA_KEY_PAIR(&RNG, e, &PRIV, &PUB, NULL, NULL);

    const char* message ="Hello, MIRACL RSA! Hello, MIRACL RSA!";
    octet M;
    if (!pkcs1_v15_pad(message, &M)) {
        cout << "填充失败：消息太长或格式错误" << endl;
        return;
    }

    char enc[RFS_RSA3072], dec[RFS_RSA3072];
    octet C = {0, sizeof(enc), enc};
    octet D = {0, sizeof(dec), dec};

    RSA_ENCRYPT(&PUB, &M, &C);

    for (auto _: state) {
        RSA_DECRYPT(&PRIV, &C, &D);
    }
    RSA_PRIVATE_KEY_KILL(&PRIV);
}



// 注册基准测试
BENCHMARK(GMP_add);
BENCHMARK(GMP_sub);
BENCHMARK(GMP_mul);
BENCHMARK(GMP_div);
BENCHMARK(GMP_modadd);
BENCHMARK(GMP_modsub);
BENCHMARK(GMP_modmul);
BENCHMARK(GMP_moddiv);
BENCHMARK(GMP_inv);
BENCHMARK(GMP_pow);
// miracl 库
BENCHMARK(Miracl_add);
BENCHMARK(Miracl_sub);
BENCHMARK(Miracl_mul);
BENCHMARK(Miracl_modadd);
BENCHMARK(Miracl_modsub);
BENCHMARK(Miracl_modmul);
BENCHMARK(Miracl_inv);
// ECC
BENCHMARK(Miracl_ECP_add);
BENCHMARK(Miracl_ECP_mul);
BENCHMARK(Miracl_ECP2_add);
BENCHMARK(Miracl_ECP2_mul);
BENCHMARK(Miracl_pair);
BENCHMARK(Miracl_GT_mul);
BENCHMARK(Miracl_GT_pow);
// hash & AES
BENCHMARK(Miracl_hash);
BENCHMARK(Miracl_hashToPoint);
BENCHMARK(Miracl_AES_Enc);
BENCHMARK(Miracl_AES_Dec);
BENCHMARK(Miracl_RSA_Enc);
BENCHMARK(Miracl_RSA_Dec);

// 基准测试的入口
BENCHMARK_MAIN();


//int main() {
//    // 初始化随机数生成器
//    char pr[100];
//    csprng RNG;
//    time_t t;
//    time(&t);
//    for (int i = 0; i < 100; i++) pr[i] = i + t % 256;
//    RAND_seed(&RNG, 100, pr);
//
//    // 密钥对
//    rsa_private_key PRIV;
//    rsa_public_key PUB;
//
//    // 公钥指数
//    sign32 e = 65537;
//
//    // 生成密钥对
//    RSA_KEY_PAIR(&RNG, e, &PRIV, &PUB, NULL, NULL);
//
//    // 消息内容（确保不超过最大可填充长度）
//    const char* message ="Hello, MIRACL RSA! Hello, MIRACL RSA!";
//
//    // 填充
//    octet M;
//    if (!pkcs1_v15_pad(message, &M)) {
//        cout << "填充失败：消息太长或格式错误" << endl;
//        return 1;
//    }
//
//    // 显示填充结果
//    showOctet(&M);
//
//    // 准备加解密缓冲区
//    char enc[RFS_RSA3072], dec[RFS_RSA3072];
//    octet C = {0, sizeof(enc), enc};
//    octet D = {0, sizeof(dec), dec};
//
//
//    RSA_ENCRYPT(&PUB, &M, &C);
//    RSA_DECRYPT(&PRIV, &C, &D);
//
//    // 去填充并提取明文
//    char recovered[RFS_RSA3072];
//    if (!pkcs1_v15_unpad(&D, recovered, sizeof(recovered))) {
//        cout << "解密填充去除失败" << endl;
//        return 1;
//    }
//
//// 输出结果
//    cout << "原始明文: " << message << endl;
//    cout << "解密结果: " << recovered << endl;
//
//
//    // 清理
//    RSA_PRIVATE_KEY_KILL(&PRIV);
//
//    return 0;
//}
