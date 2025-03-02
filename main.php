<?php

class SecureCrypto {
    private const AES_METHOD = 'AES-256-CBC';

    public static function generateRSAKeys(): array {
        $config = [
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey);
        $publicKey = openssl_pkey_get_details($res)["key"];
        return ["private" => $privateKey, "public" => $publicKey];
    }

    public static function encryptAES(string $plaintext, string &$key, string &$iv): string {
        $key = random_bytes(32);
        $iv = random_bytes(16);
        return base64_encode(openssl_encrypt($plaintext, self::AES_METHOD, $key, OPENSSL_RAW_DATA, $iv));
    }

    public static function decryptAES(string $encrypted, string $key, string $iv): string {
        return openssl_decrypt(base64_decode($encrypted), self::AES_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    }

    public static function encryptRSA(string $data, string $publicKey): string {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }

    public static function decryptRSA(string $encrypted, string $privateKey): string {
        openssl_private_decrypt(base64_decode($encrypted), $decrypted, $privateKey);
        return $decrypted;
    }
}

// Generate RSA keys
$rsaKeys = SecureCrypto::generateRSAKeys();
$publicKey = $rsaKeys['public'];
$privateKey = $rsaKeys['private'];

// Encrypt message using AES-256-CBC
$plaintext = "Hello, AES-256-CBC with RSA!";
$aesKey = $aesIV = "";
$encryptedMessage = SecureCrypto::encryptAES($plaintext, $aesKey, $aesIV);

// Encrypt AES key using RSA
$encryptedAESKey = SecureCrypto::encryptRSA($aesKey, $publicKey);
$encryptedAESIV = SecureCrypto::encryptRSA($aesIV, $publicKey);

// Decrypt AES key using RSA
$decryptedAESKey = SecureCrypto::decryptRSA($encryptedAESKey, $privateKey);
$decryptedAESIV = SecureCrypto::decryptRSA($encryptedAESIV, $privateKey);

// Decrypt message using AES-256-CBC
$decryptedMessage = SecureCrypto::decryptAES($encryptedMessage, $decryptedAESKey, $decryptedAESIV);

// Output Results
echo "Original Message: $plaintext\n";
echo "Encrypted Message: $encryptedMessage\n";
echo "Decrypted Message: $decryptedMessage\n";

?>
