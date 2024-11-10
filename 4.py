from S_AES import *  # 导入S_AES模块
import time  # 导入时间模块


# 中间相遇攻击
def hack(plaintext_group, ciphertext_group):
    # 重置密钥
    Key1 = "0000000000000000"  # 初始化第一个密钥
    Key2 = "0000000000000000"  # 初始化第二个密钥
    # 密钥空间
    fre = 2 ** len(Key1)  # 计算密钥空间大小
    key_group = []  # 存储找到的密钥对
    plaintext_dic = {}  # 存储明文到中间文本的映射
    ciphertext_dic = {}  # 存储密文到中间文本的映射

    for i in range(fre):  # 遍历所有可能的Key1
        middle_text_encode = encode(plaintext_group[0], Key1)  # 对第一个明文分组进行编码
        if middle_text_encode in plaintext_dic:  # 如果中间结果已经存在
            plaintext_dic[middle_text_encode].append(Key1)  # 添加当前Key1到映射
        else:
            plaintext_dic[middle_text_encode] = [Key1]  # 新建映射条目

        # 更新Key1
        Key1_int = int(Key1, 2) + 1  # 将二进制字符串转换为整数并加1
        Key1 = format(Key1_int, '016b')  # 更新为新的二进制字符串

        middle_text_decode = decode(ciphertext_group[0], Key2)  # 对第一个密文分组进行解码
        if middle_text_decode in ciphertext_dic:  # 如果中间结果已经存在
            ciphertext_dic[middle_text_decode].append(Key2)  # 添加当前Key2到映射
        else:
            ciphertext_dic[middle_text_decode] = [Key2]  # 新建映射条目

        # 更新Key2
        Key2_int = int(Key2, 2) + 1  # 将二进制字符串转换为整数并加1
        Key2 = format(Key2_int, '016b')  # 更新为新的二进制字符串

    # 遍历第一个字典的键
    for key in plaintext_dic:
        # 检查第二个字典是否有相同的键
        if key in ciphertext_dic:
            for K1 in plaintext_dic[key]:  # 遍历所有Key1
                for K2 in ciphertext_dic[key]:  # 遍历所有Key2
                    flag = 0  # 标记用于检查是否匹配
                    for i in range(len(plaintext_group)):  # 对所有明文分组进行验证
                        middle_text_encode = encode(plaintext_group[i], K1)  # 编码
                        middle_text_decode = decode(ciphertext_group[i], K2)  # 解码
                        if middle_text_encode != middle_text_decode:  # 如果不匹配
                            flag = 1  # 标记不匹配
                            break  # 跳出循环
                    if flag == 0:  # 如果所有都匹配
                        key_group.append([K1, K2])  # 添加找到的密钥对

    return key_group  # 返回找到的所有密钥对


if __name__ == '__main__':
    # 新的测试样例
    plaintext1 = "1100100101000111"
    ciphertext1 = "1001010011000101"

    plaintext2 = "1110100010010111"
    ciphertext2 = "1011011110100110"

    plaintext3 = "0101101101100101"
    ciphertext3 = "0111110001000111"

    Key_1 = "0010110101010101"
    Key_2 = "0101011010101001"
    print(f"原始密钥对{[Key_1, Key_2]}")

    plaintext_group_1 = [plaintext1]
    ciphertext_group_1 = [ciphertext1]

    plaintext_group_2 = [plaintext1, plaintext2]
    ciphertext_group_2 = [ciphertext1, ciphertext2]

    plaintext_group_3 = [plaintext1, plaintext2, plaintext3]
    ciphertext_group_3 = [ciphertext1, ciphertext2, ciphertext3]

    # 得到一对明密文对
    print("得到一对明密文对时")
    time_start_1 = time.time()
    key_group_1 = hack(plaintext_group_1, ciphertext_group_1)
    time_end_1 = time.time()
    print(key_group_1)
    print(f"解密得到的密钥数量:{len(key_group_1)}, 共用时:{time_end_1 - time_start_1}s")
    # 得到两对明密文对
    print("得到两对明密文对时")
    time_start_2 = time.time()
    key_group_2 = hack(plaintext_group_2, ciphertext_group_2)
    time_end_2 = time.time()
    print(key_group_2)
    print(f"解密得到的密钥数量:{len(key_group_2)}, 共用时:{time_end_2 - time_start_2}s")
    # 得到三对明密文对
    print("得到三对明密文对时")
    time_start_3 = time.time()
    key_group_3 = hack(plaintext_group_3, ciphertext_group_3)
    time_end_3 = time.time()
    print(key_group_3)
    print(f"解密得到的密钥数量:{len(key_group_3)}, 共用时:{time_end_3 - time_start_3}s")

