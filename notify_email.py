import json

# 假设 original_data 是从缓存中获取的数据
original_data = b'\x80\x03c__main__\nMyClass\nq\x00)\x81q\x01}q\x02(X\x04\x00\x00\x00fooX\x05\x00\x00\x00baru.'

# 替换为 JSON 序列化
decoded_data = json.loads(original_data.decode('latin1'))

print(decoded_data)