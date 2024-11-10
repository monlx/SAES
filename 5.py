from SAES import *  # 导入S_AES模块
import random  # 导入随机模块
# 分组函数，将明文分成16位一组
def plaintext2P(plain_text):
    P = []  # 初始化分组列表
    for i in range(len(plain_text) // 16):  # 每16位分一组
        P.append(plain_text[i * 16:i * 16 + 16])  # 添加分组到列表
    return P  # 返回分组列表
# 生成随机数C0的函数
def get_C0(seed):
    random.seed(seed)  # 使用给定的种子初始化随机数生成器
    temp = [random.randint(0, 15) for _ in range(4)]  # 生成4个0到15之间的随机数
    C0 = ''.join(bin(t)[2:].zfill(4) for t in temp)  # 将每个随机数转换为4位二进制字符串并连接
    return C0  # 返回初始向量C0
# CBC模式加密函数
def CBC_encode(plain_text, K, C0):
    P = plaintext2P(plain_text)  # 将明文分组
    C = [C0]  # 初始化密文列表，添加初始向量C0
    for i in range(len(P)):  # 遍历每个明文分组
        temp = xor(P[i], C[i])  # 与前一个密文分组异或
        temp = encode(temp, K)  # 使用密钥K加密
        C.append(temp)  # 添加加密后的密文分组
    return C[1:]  # 返回除初始向量外的密文列表
# CBC模式解密函数
def CBC_decode(C, K, C0):
    p = ''  # 初始化明文字符串
    for i in range(len(C)):  # 遍历每个密文分组
        temp = decode(C[i], K)  # 解密当前密文分组
        if i == 0:  # 如果是第一个分组
            temp = xor(C0, temp)  # 与初始向量异或
        else:
            temp = xor(C[i - 1], temp)  # 与前一个密文分组异或
        p += temp  # 拼接解密后的明文
    return p  # 返回完整明文

# 自然语言转unicode明文串的函数
def language2plaintext(language):
    p = ''  # 初始化明文字符串
    for char in language:  # 遍历每个字符
        unicode_value = ord(char)  # 获取字符的Unicode整数值
        bin_text = bin(unicode_value)[2:]  # 转换为二进制字符串
        p += bin_text.zfill(16)  # 将二进制字符串填充至16位并拼接
    return p  # 返回完整的明文串

# unicode明文串转自然语言的函数
def plaintext2language(plain_text):
    p = ''  # 初始化字符串
    for i in range(len(plain_text) // 16):  # 每16位转换为一个字符
        temp = plain_text[i * 16:i * 16 + 16]  # 获取当前16位二进制
        p += chr(int(temp, 2))  # 将二进制转为字符并拼接
    return p  # 返回生成的自然语言字符串

if __name__ == '__main__':  # 主程序入口
    # 长明文加解密
    print("长明文加解密")
    # 新的测试样例
    plain_text = 'Hello, World! This is a test of CBC encryption.'  # 使用新的明文
    plain_text = language2plaintext(plain_text)  # 转换为16位二进制串
    K = '0101010101010101'  # 定义密钥
    C0 = get_C0(2023)  # 生成初始向量
    print(f"长明文P = {plain_text}")  # 输出明文
    print(f"密钥K = {K}")  # 输出密钥
    print(f"初始向量C0 = {C0}")  # 输出初始向量
    C = CBC_encode(plain_text, K, C0)  # 对明文进行CBC加密
    cipher_text = "".join(C)  # 将密文分组拼接
    print(f"加密后得到的密文C = {cipher_text}")  # 输出密文
    new_p = CBC_decode(C, K, C0)  # 对密文进行CBC解密
    print(f"解密后得到的明文P = {new_p}")  # 输出解密后的明文
    print(f"解密后得到的明文与原始明文是否相等: {new_p == plain_text}")  # 比较解密结果与原始明文
    print("篡改密文分组")
    # 密文篡改
    attacked_C = C.copy()  # 复制密文分组
    # 将倒数第二分组中三个二进制位取反
    for i in range(3):
        attacked_C[2] = attacked_C[2][:i] + ('1' if attacked_C[2][i] == '0' else '0') + attacked_C[2][i + 1:]

    attacked_p = CBC_decode(attacked_C, K, C0)  # 对篡改后的密文进行解密
    for i in range(len(plain_text)):  # 遍历并比较
        if attacked_p[i] != plain_text[i]:  # 检查每位是否变化
            print(f"第{i}位变化")  # 输出变化位置
    print(f"篡改密文前: {plain_text}")  # 输出篡改前的明文
    print(f"篡改密文后: {attacked_p}")  # 输出篡改后的解密结果
    # 不定长文字加密总流程
    long_plain_text = language2plaintext('All the splendor in the world is not worth a good friend!')  # 使用新的长文本
    K = '0101010101010101'  # 定义密钥
    C0 = get_C0(20231106)  # 生成新的初始向量
    C = CBC_encode(long_plain_text, K, C0)  # 对长明文进行CBC加密
    new_plain_text = CBC_decode(C, K, C0)  # 对密文进行CBC解密
    print(f"解密后的长明文: {plaintext2language(new_plain_text)}")  # 输出解密后的自然语言
