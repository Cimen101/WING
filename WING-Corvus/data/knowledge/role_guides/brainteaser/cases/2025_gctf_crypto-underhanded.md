# 后门 AES (2025_gctf_crypto-underhanded)

## 基本信息
- 题型: crypto
- 难度: hard
- 判断结果: ✅ 脑洞题
- 解题结果: ❌ 未解出

## 脑洞特征
- 看似正确的 AES 但隐藏后门
- 题目名 'underhanded' 暗示隐蔽缺陷
- 标准 AES 解密出乱码

## 卡住点
- 3 路被函数命名误导(key_expansion→expand_key)
- 未实际运行 chall.py 与 oracle 交互

## 下次改进方向
- AES 后门检测: 逐函数对比标准实现
- 利用 oracle 收集选择明文密文对
- 先运行 chall.py 了解交互再分析
