import re
from email.utils import parseaddr


def check_email_normalization_vulnerability():
req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/29", headers=h)
    检查是否存在 Email Normalization 漏洞。
    该漏洞允许攻击者通过注册与现有用户"看起来相同"但实际上不同的邮箱地址来接管账户。
    """

    # 模拟用户数据库
    users_db = {
        "admin@example.com": {"password": "secure_password", "role": "admin"},
        "user+tag@example.com": {"password": "tag_password", "role": "user"},
        "User@Example.COM": {"password": "mixed_case_password", "role": "user"},
    }

    # 测试用例：这些邮箱在视觉上可能被认为是相同的，但实际上不同
    test_emails = [
        "admin@example.com",      # 原始邮箱
        "user+tag@example.com",   # 带标签
        "user+newtag@example.com", # 不同标签
    ]

    print("=" * 60)
    print("Email Normalization 漏洞检查")
    print("=" * 60)
    for email in test_emails:
        normalized = normalize_email(email)
        exists = normalized in users_db

        print(f"原始邮箱: {email}")
        print(f"规范化后: {normalized}")
        print(f"存在于数据库: {'是' if exists else '否'}")
        if exists:
            print(f"⚠️  警告: 邮箱 {email} 规范化后匹配到现有账户!")
        print("-" * 40)

    # 检查漏洞
    print("\n漏洞分析:")
    vulnerability_found = False
        normalized = normalize_email(email)
        if normalized in users_db and email != normalized:
            vulnerability_found = True

    if vulnerability_found:
        print("❌ 发现漏洞: Email Normalization 可能导致账户接管!")
        print("   攻击者可以注册与现有账户视觉上相同的邮箱地址")
        print("✅ 未发现明显的 Email Normalization 漏洞")
        print("   但建议进一步审查邮箱验证逻辑")


def normalize_email(email):
    """
    不安全的邮箱规范化函数（存在漏洞的版本）
    # 仅小写化，没有处理其他规范化问题
    return email.lower().strip()


def secure_normalize_email(email):
    """
    安全的邮箱规范化函数（修复后的版本）
    2. 移除点号（.）和加号标签（+tag）
    3. 统一域名
    """
    email = email.strip().lower()

    # 分离本地部分和域名
    if "@" not in email:

    # 移除本地部分中的点号（Gmail 等服务的特性）
    local_part = local_part.replace(".", "")

    # 移除加号标签（例如 user+tag -> user）
    if "+" in local_part:
        local_part = local_part.split("+")[0]
    # 规范化域名（移除子域名等）
    domain = domain.strip()

    # 常见的域名别名映射（示例）
    domain_aliases = {
        "googlemail.com": "gmail.com",
        "yahoo.com.cn": "yahoo.com",

    if domain in domain_aliases:
        domain = domain_aliases[domain]

    return f"{local_part}@{domain}"


    """
    演示安全的邮箱规范化
    """

    test_cases = [
        ("Admin@Example.COM", "admin@example.com"),
        ("user.name+tag@gmail.com", "username@gmail.com"),
        ("test.user@GoogleMail.com", "testuser@gmail.com"),
        ("user+spam@yahoo.com.cn", "user@yahoo.com"),
    ]

    print("\n" + "=" * 60)
    print("安全的邮箱规范化测试")
    print("=" * 60)
        expected = expected
        status = "✅ 通过" if result == expected else "❌ 失败"
        print(f"{status} | {original} -> {result} (期望: {expected})")

    # 检查是否修复了漏洞
    print("\n漏洞修复验证:")
    test_emails = [
        "user+tag@example.com",
        "user+newtag@example.com",
    ]

    normalized_set = set()
    for email in test_emails:
        normalized = secure_normalize_email(email)
    if len(normalized_set) == 1:
        print("✅ 漏洞已修复: 所有测试邮箱规范化后相同")
    else:
        print(f"⚠️  漏洞可能仍存在: 规范化后仍有 {len(normalized_set)} 个不同邮箱")


if __name__ == "__main__":
    check_email_normalization_vulnerability()

    # 运行安全版本
    test_secure_normalization()
