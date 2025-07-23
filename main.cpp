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

// HMAC-SHA256实现
std::vector<unsigned char> hmac_sha256(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& message) {

    const size_t block_size = 64; // SHA-256的块大小是64字节

    // 1. 如果密钥长度大于块大小，先对密钥进行哈希
    std::vector<unsigned char> adjusted_key = key;
    if (adjusted_key.size() > block_size) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(adjusted_key.data(), adjusted_key.size(), hash);
        adjusted_key = std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
    }

    // 2. 如果密钥长度小于块大小，用0填充到块大小
    if (adjusted_key.size() < block_size) {
        adjusted_key.resize(block_size, 0x00);
    }

    // 3. 创建内部填充键和外部填充键
    std::vector<unsigned char> o_key_pad(block_size, 0x5c);
    std::vector<unsigned char> i_key_pad(block_size, 0x36);

    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] ^= adjusted_key[i];
        i_key_pad[i] ^= adjusted_key[i];
    }

    // 4. 计算内部哈希
    std::vector<unsigned char> inner_message = i_key_pad;
    inner_message.insert(inner_message.end(), message.begin(), message.end());

    unsigned char inner_hash[SHA256_DIGEST_LENGTH];
    SHA256(inner_message.data(), inner_message.size(), inner_hash);

    // 5. 计算外部哈希
    std::vector<unsigned char> outer_message = o_key_pad;
    outer_message.insert(outer_message.end(), inner_hash, inner_hash + SHA256_DIGEST_LENGTH);

    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    SHA256(outer_message.data(), outer_message.size(), hmac_result);

    return std::vector<unsigned char>(hmac_result, hmac_result + SHA256_DIGEST_LENGTH);
}

int main() {
    // 示例使用
    std::string key = "secretKey";
    std::string message = "Hello, HMAC-SM3!";

    auto hmac_result = hmac_sha256(string_to_bytes(key), string_to_bytes(message));

    std::cout << "HMAC-SHA256 of \"" << message << "\" with key \"" << key << "\":\n";
    std::cout << bytes_to_hex(hmac_result) << std::endl;

    return 0;
}