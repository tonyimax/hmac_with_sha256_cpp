#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
//for macos setup openssl :brew install openssl
#include <cstring>
#include <openssl/sha.h> // 需要OpenSSL库支持

// 辅助函数：将字节数组转换为十六进制字符串
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// 辅助函数：字符串转字节向量
std::vector<unsigned char> string_to_bytes(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}


// 辅助函数：打印十六进制
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}


// 定义常量
#define SM3_DIGEST_SIZE 32    // 摘要长度(字节)

// SM3上下文结构
typedef struct {
    uint32_t state[8];      // 中间状态
    uint64_t count;         // 已处理消息长度(位)
    uint8_t buffer[64];     // 当前分组
} SM3_CTX;

void sm3_init(SM3_CTX* ctx);
void sm3_update(SM3_CTX* ctx, const uint8_t* data, size_t len);
void sm3_final(SM3_CTX* ctx, uint8_t digest[SM3_DIGEST_SIZE]);


#define SM3_BLOCK_SIZE 64     // 分组长度(字节)

// 初始向量IV (大端序)
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 循环左移
static uint32_t ROTL(uint32_t X, int n) {
    return (X << n) | (X >> (32 - n));
}

// 布尔函数FFj
static uint32_t FFj(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
}

// 布尔函数GGj
static uint32_t GGj(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (~X & Z));
}

// 置换函数P0
static uint32_t P0(uint32_t X) {
    return X ^ ROTL(X, 9) ^ ROTL(X, 17);
}

// 置换函数P1
static uint32_t P1(uint32_t X) {
    return X ^ ROTL(X, 15) ^ ROTL(X, 23);
}

// 常量Tj
static uint32_t Tj(int j) {
    return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
}

// 初始化上下文
void sm3_init(SM3_CTX* ctx) {
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->count = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

// 处理单个512位分组
static void sm3_compress(SM3_CTX* ctx, const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68];  // 消息扩展后的字
    uint32_t W1[64]; // 用于压缩的字
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;

    // 1. 消息扩展 (手动解析大端序)
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
            ((uint32_t)block[i * 4 + 1] << 16) |
            ((uint32_t)block[i * 4 + 2] << 8) |
            (uint32_t)block[i * 4 + 3];
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15))
            ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 2. 压缩函数
    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];

    for (int j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj(j), j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FFj(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GGj(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 3. 更新状态
    ctx->state[0] ^= A; ctx->state[1] ^= B;
    ctx->state[2] ^= C; ctx->state[3] ^= D;
    ctx->state[4] ^= E; ctx->state[5] ^= F;
    ctx->state[6] ^= G; ctx->state[7] ^= H;
}

// 更新消息数据
void sm3_update(SM3_CTX* ctx, const uint8_t* data, size_t len) {
    size_t left = ctx->count / 8 % SM3_BLOCK_SIZE;
    size_t fill = SM3_BLOCK_SIZE - left;

    ctx->count += len * 8; // 更新位计数

    // 处理不完整缓冲区
    if (left && len >= fill) {
        memcpy(ctx->buffer + left, data, fill);
        sm3_compress(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        left = 0;
    }

    // 处理完整分组
    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(ctx, data);
        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    // 存储剩余数据
    if (len) {
        memcpy(ctx->buffer + left, data, len);
    }
}

// 生成最终摘要
void sm3_final(SM3_CTX* ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    size_t last = (ctx->count / 8) % SM3_BLOCK_SIZE;
    size_t padn = (last < 56) ? (56 - last) : (120 - last);

    // 填充数据: 0x80 + 0x00... + 消息长度(64位大端序)
    uint8_t footer[64] = { 0x80 };
    uint64_t bit_count = ctx->count;
    uint8_t len_bytes[8];

    // 手动构造大端序长度
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (bit_count >> (56 - 8 * i)) & 0xFF;
    }

    sm3_update(ctx, footer, padn);
    sm3_update(ctx, len_bytes, 8);

    // 输出大端序摘要
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (ctx->state[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[4 * i + 3] = ctx->state[i] & 0xFF;
    }
}

void SM3_HASH(const char* to_sm3_hash_string,uint8_t* sm3_hash_result)
{
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx,reinterpret_cast<const uint8_t*>(to_sm3_hash_string),strlen(to_sm3_hash_string));
    sm3_final(&ctx, sm3_hash_result);
}

// HMAC-SHA256实现
std::vector<unsigned char> hmac_sha256(
        const std::vector<unsigned char>& key,    //密钥
        const std::vector<unsigned char>& message //消息
        )
{

    const size_t block_size = 64; // SHA-256的块大小是64字节  64*8=512 bit

    std::cout<<"===>原始密钥字节:"<<bytes_to_hex(key)<<std::endl;
    std::cout<<"===>原始消息字节:"<<bytes_to_hex(message)<<std::endl;

    // 1. 如果密钥长度大于块大小，先对密钥进行哈希
    std::vector<unsigned char> adjusted_key = key;//存储原来密钥
    //如果密钥长度大于64字节
    if (adjusted_key.size() > block_size) {
        std::cout << "===>密钥长度大于64字节，需要使用HASH算法取一个32字节新密钥"<<std::endl;
        unsigned char hash[SHA256_DIGEST_LENGTH];//创建一个32字节长度的哈希
        //replace to SM3
        SHA256(adjusted_key.data(), adjusted_key.size(), hash);//使用SHA256哈希算法将传入密钥生成哈希值
        adjusted_key = std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);//复制32字节哈希值到新密钥变量
        std::cout<<"===>SHA256哈希算法计算生成的密钥:"<<bytes_to_hex(adjusted_key)<<std::endl;
    }

    // 2. 如果密钥长度小于块大小(密钥长度小于64字节)，用0填充到块大小
    if (adjusted_key.size() < block_size) {
        std::cout << "===>密钥长度小于64字节，需要在密钥后面填充0x00,并满足长度64"<<std::endl;
        //如果是HASH计算后的密钥，在后面填充32个0
        //如果不是HASH计算的密钥，
        adjusted_key.resize(block_size, 0x00);
        std::cout<<"===>在密钥后面填充0x00的最终64字节密钥:"<<bytes_to_hex(adjusted_key)<<std::endl;
    }

    // 3. 创建内部填充键和外部填充键
    std::vector<unsigned char> o_key_pad(block_size, 0x5c);//外部填充
    std::vector<unsigned char> i_key_pad(block_size, 0x36);//内部填充
    std::cout<<"===>初始化外部填充:"<<bytes_to_hex(o_key_pad)<<std::endl;
    std::cout<<"===>初始化内部填充:"<<bytes_to_hex(i_key_pad)<<std::endl;

    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] ^= adjusted_key[i];
        i_key_pad[i] ^= adjusted_key[i];
    }
    std::cout<<"===>外部填充XOR结果:"<<bytes_to_hex(o_key_pad)<<std::endl;
    std::cout<<"===>内部填充XOR结果:"<<bytes_to_hex(i_key_pad)<<std::endl;

    // 4. 计算内部哈希
    std::vector<unsigned char> inner_message = i_key_pad;
    inner_message.insert(inner_message.end(), message.begin(), message.end());

    std::cout<<"===>计算内部哈希(公式：内部填充XOR字节＋原始消息字节)  内填充＋消息拼接-->:"<<bytes_to_hex(inner_message)<<std::endl;

    unsigned char inner_hash[SHA256_DIGEST_LENGTH];
    //replace to SM3
    SHA256(inner_message.data(), inner_message.size(), inner_hash);

    std::cout<<"===>计算内部哈希(公式：内部填充XOR字节＋原始消息字节):  （内填充＋消息拼接）32字节HASH--->";
    print_hex(inner_hash, SHA256_DIGEST_LENGTH);
    std::cout<<std::endl;

    // 5. 计算外部哈希
    std::vector<unsigned char> outer_message = o_key_pad;
    outer_message.insert(outer_message.end(), inner_hash, inner_hash + SHA256_DIGEST_LENGTH);

    std::cout<<"===>计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  外填充＋内部HASH值拼接-->:"<<bytes_to_hex(outer_message)<<std::endl;

    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    //replace to SM3
    SHA256(outer_message.data(), outer_message.size(), hmac_result);

    std::cout<<"===>计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  (外填充＋内部HASH值拼接) 32字节HASH--->最终的HMAC_SHA256 HASH:";
    print_hex(hmac_result, SHA256_DIGEST_LENGTH);
    std::cout<<std::endl;

    return std::vector<unsigned char>(hmac_result, hmac_result + SHA256_DIGEST_LENGTH);
}

// HMAC-SM3实现
std::vector<unsigned char> hmac_sm3(
        const std::vector<unsigned char>& key,    //密钥
        const std::vector<unsigned char>& message //消息
        )
{

    const size_t block_size = 64; // SHA-256的块大小是64字节  64*8=512 bit

    std::cout<<"===>SM3原始密钥字节:"<<bytes_to_hex(key)<<std::endl;
    std::cout<<"===>SM3原始消息字节:"<<bytes_to_hex(message)<<std::endl;

    // 1. 如果密钥长度大于块大小，先对密钥进行哈希
    std::vector<unsigned char> adjusted_key = key;//存储原来密钥
    //如果密钥长度大于64字节
    if (adjusted_key.size() > block_size) {
        std::cout << "===>SM3密钥长度大于64字节，需要使用HASH算法取一个32字节新密钥"<<std::endl;
        unsigned char hash[SHA256_DIGEST_LENGTH];//创建一个32字节长度的哈希
        //replace to SM3
        SM3_HASH(reinterpret_cast<const char *>(adjusted_key.data()),hash);
        //SHA256(adjusted_key.data(), adjusted_key.size(), hash);//使用SHA256哈希算法将传入密钥生成哈希值
        adjusted_key = std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);//复制32字节哈希值到新密钥变量
        std::cout<<"===>SM3哈希算法计算生成的密钥:";
        print_hex(hash, SHA256_DIGEST_LENGTH);
        std::cout<<"\n";
    }

    // 2. 如果密钥长度小于块大小(密钥长度小于64字节)，用0填充到块大小
    if (adjusted_key.size() < block_size) {
        std::cout << "===>SM3密钥长度小于64字节，需要在密钥后面填充0x00,并满足长度64"<<std::endl;
        //如果是HASH计算后的密钥，在后面填充32个0
        //如果不是HASH计算的密钥，
        adjusted_key.resize(block_size, 0x00);
        std::cout<<"===>SM3在密钥后面填充0x00的最终64字节密钥:"<<bytes_to_hex(adjusted_key)<<std::endl;
    }

    // 3. 创建内部填充键和外部填充键
    std::vector<unsigned char> o_key_pad(block_size, 0x5c);//外部填充
    std::vector<unsigned char> i_key_pad(block_size, 0x36);//内部填充
    std::cout<<"===>SM3初始化外部填充:"<<bytes_to_hex(o_key_pad)<<std::endl;
    std::cout<<"===>SM3初始化内部填充:"<<bytes_to_hex(i_key_pad)<<std::endl;

    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] ^= adjusted_key[i];
        i_key_pad[i] ^= adjusted_key[i];
    }
    std::cout<<"===>SM3外部填充XOR结果:"<<bytes_to_hex(o_key_pad)<<std::endl;
    std::cout<<"===>SM3内部填充XOR结果:"<<bytes_to_hex(i_key_pad)<<std::endl;

    // 4. 计算内部哈希
    std::vector<unsigned char> inner_message = i_key_pad;
    inner_message.insert(inner_message.end(), message.begin(), message.end());

    std::cout<<"===>SM3计算内部哈希(公式：内部填充XOR字节＋原始消息字节)  内填充＋消息拼接-->:"<<bytes_to_hex(inner_message)<<std::endl;

    unsigned char inner_hash[SHA256_DIGEST_LENGTH];
    //replace to SM3
    SM3_HASH(reinterpret_cast<const char *>(inner_message.data()),inner_hash);
    //SHA256(inner_message.data(), inner_message.size(), inner_hash);

    std::cout<<"===>SM3计算内部哈希(公式：内部填充XOR字节＋原始消息字节):  （内填充＋消息拼接）32字节HASH--->";
    print_hex(inner_hash, SHA256_DIGEST_LENGTH);
    std::cout<<std::endl;

    // 5. 计算外部哈希
    std::vector<unsigned char> outer_message = o_key_pad;
    outer_message.insert(outer_message.end(), inner_hash, inner_hash + SHA256_DIGEST_LENGTH);

    std::cout<<"===>SM3计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  外填充＋内部HASH值拼接-->:"<<bytes_to_hex(outer_message)<<std::endl;

    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    //replace to SM3
    SM3_HASH(reinterpret_cast<const char *>(outer_message.data()),hmac_result);
    //SHA256(outer_message.data(), outer_message.size(), hmac_result);

    std::cout<<"===>SM3计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  (外填充＋内部HASH值拼接) 32字节HASH--->最终的HMAC_SM3 HASH:";
    print_hex(hmac_result, SHA256_DIGEST_LENGTH);
    std::cout<<std::endl;

    return std::vector<unsigned char>(hmac_result, hmac_result + SHA256_DIGEST_LENGTH);
}

int main() {
    // 示例使用
    std::string key = "secretKey_secretKey_secretKey_secretKey_secretKey_secretKey_secretKey";
    std::string message = "Hello, HMAC-SHA256!";
    std::cout <<"===>原始密钥字符串:"<<key<<std::endl;
    std::cout <<"===>原始消息字符串:"<<message<<std::endl;

    auto hmac_result = hmac_sha256(string_to_bytes(key), string_to_bytes(message));

    std::cout << "HMAC-SHA256 of \"" << message << "\" with key \"" << key << "\":\n";
    std::cout << bytes_to_hex(hmac_result) << std::endl;

    std::cout << "HMAC-SM3 TEST:\n";
    uint8_t hash_result[32]{0};
    SM3_HASH(key.c_str(),hash_result);
    print_hex(hash_result, 32);
    //a1bd67ceb9c76d9b1f3a8b161a0ef48478b851709403d5faa0189cb76ce9fd0d   --sm3
    //a1bd67ceb9c76d9b1f3a8b161a0ef48478b851709403d5faa0189cb76ce9fd0d   --online
    auto hmac_sm3_result = hmac_sm3(string_to_bytes(key), string_to_bytes("Hello, HMAC-SM3!"));


    return 0;
}