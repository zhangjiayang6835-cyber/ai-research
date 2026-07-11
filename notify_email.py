zone:
    allow-transfer:
        - 192.168.1.0/24
    key-table: tsig_keys
    notify: yes

keytable tsig_keys {
    key "tsig_key" {
        algorithm hmac-md5;
        secret "your_secret_key_here";
    };
}