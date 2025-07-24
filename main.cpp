#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
//for macos setup openssl :brew install openssl
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
    SHA256(inner_message.data(), inner_message.size(), inner_hash);

    std::cout<<"===>计算内部哈希(公式：内部填充XOR字节＋原始消息字节):  （内填充＋消息拼接）32字节HASH--->";
    print_hex(inner_hash, SHA256_DIGEST_LENGTH);
    std::cout<<std::endl;

    // 5. 计算外部哈希
    std::vector<unsigned char> outer_message = o_key_pad;
    outer_message.insert(outer_message.end(), inner_hash, inner_hash + SHA256_DIGEST_LENGTH);

    std::cout<<"===>计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  外填充＋内部HASH值拼接-->:"<<bytes_to_hex(outer_message)<<std::endl;

    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    SHA256(outer_message.data(), outer_message.size(), hmac_result);

    std::cout<<"===>计算外部哈希(公式：外部填充XOR字节＋内部HASH值)  (外填充＋内部HASH值拼接) 32字节HASH--->最终的HMAC_SHA256 HASH:";
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

    return 0;
}