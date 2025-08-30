#pragma once

#include <vector>
#include <cstdint>

/**
 * @brief 주어진 바이트 벡터를 키 벡터(key_vector)로 XOR 연산합니다.
 *        키가 데이터보다 짧을 경우, 키는 순환하여 사용됩니다 (Repeating Key XOR).
 *        입력받은 data 벡터가 이 함수 내에서 직접 수정됩니다.
 * @param data 암호화 또는 복호화할 데이터. 함수 종료 후 내용이 변경됩니다.
 * @param key_vector XOR 연산에 사용할 키 벡터. 비어있으면 안됩니다.
 */
void xor_cipher_repeating_key(std::vector<uint8_t>& data, const std::vector<uint8_t>& key_vector);

/**
 * @brief 주어진 바이트 벡터의 각 바이트를 왼쪽으로 회전(rotate left)시킵니다.
 *        예: 0b11010010 를 2만큼 rotl -> 0b01001011
 *        입력받은 data 벡터가 이 함수 내에서 직접 수정됩니다.
 * @param data 회전시킬 데이터. 함수 종료 후 내용이 변경됩니다.
 * @param shift 회전시킬 비트 수.
 */
void rotl(std::vector<uint8_t>& data, int shift);

/**
 * @brief 주어진 바이트 벡터의 각 바이트를 오른쪽으로 회전(rotate right)시킵니다.
 *        예: 0b11010010 를 2만큼 rotr -> 0b10110100
 *        입력받은 data 벡터가 이 함수 내에서 직접 수정됩니다.
 * @param data 회전시킬 데이터. 함수 종료 후 내용이 변경됩니다.
 * @param shift 회전시킬 비트 수.
 */
void rotr(std::vector<uint8_t>& data, int shift);
