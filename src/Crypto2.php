<?php
//namespace Sniper\EfrisLib;
//class Crypto
//{
//    private const cipherAlgorithm = "aes-128-ecb";
//    public static string $privateKeyPath;
//    public static string $privateKeyPassword;
//
//
//    private static function getPrivateKey(): mixed
//    {
//        $cert_store = file_get_contents(Crypto::$privateKeyPath);
//        $isRead = openssl_pkcs12_read($cert_store, $cert_info, Crypto::$privateKeyPassword);
//        return $cert_info['pkey'];
//    }
//    public static function rsaDecrypt($encryptedData): string
//    {
//        $privateKey = self::getPrivateKey();
//        openssl_private_decrypt($encryptedData, $decryptedData, $privateKey, OPENSSL_PKCS1_PADDING);
//        return $decryptedData;
//    }
//
//    public static function aesEncrypt(string $data, string $aesKey): bool|string
//    {
//        if ($data) {
//            return openssl_encrypt($data, Crypto::cipherAlgorithm, $aesKey);
//        }
//        return $data;
//    }
//
//    public static function aesDecrypt(string $encryptedData, string $aesKey): bool|string
//    {
//        return openssl_decrypt($encryptedData, Crypto::cipherAlgorithm, $aesKey);
//    }
//
//    public static function rsaSign(string $data): bool|string
//    {
//        $pKey = Crypto::getPrivateKey();
//        $isSigned = openssl_sign($data, $signature, $pKey, OPENSSL_ALGO_SHA1);
//        if ($isSigned) {
//            return $signature;
//        }
//        return false;
//    }
//
//}


namespace Sniper\EfrisLib;

use Exception;
use http\Exception\RuntimeException;
use Illuminate\Http\Response;

class Crypto2
{
    private const CIPHER_ALGORITHM = 'aes-128-ecb';
    public static string $privateKeyPath;
    public static string $privateKeyPassword;

      public static function setPrivateKeyPath(string $path): void
    {
        self::$privateKeyPath = $path;
    }

    public static function setPrivateKeyPassword(string $password): void
    {
        self::$privateKeyPassword = $password;
    }

    private static function getPrivateKey(): Response
    {
        $certStore = file_get_contents(self::$privateKeyPath);
        if (!$certStore) {
            throw new \Exception('Failed to read private key file.');
        }

//        dd(self::$privateKeyPassword);

        $certInfo = [];
        $isRead = openssl_pkcs12_read($certStore, $certInfo, 'efris12345');

        if (!$isRead) {
            throw new Exception('Failed to parse private key from certificate store.');
        }

        return $certInfo['pkey'];
    }

    public static function rsaDecrypt(string $encryptedData): string
    {
        $privateKey = self::getPrivateKey();
        $result = openssl_private_decrypt($encryptedData, $decryptedData, $privateKey, OPENSSL_PKCS1_PADDING);

        if ($result !== true) {
            throw new Exception('Failed to decrypt data with private key.');
        }

        return $decryptedData;
    }

    public static function aesEncrypt(string $data, string $aesKey): string
    {
        if (empty($data)) {
            return $data;
        }

        $encryptedData = openssl_encrypt($data, self::CIPHER_ALGORITHM, $aesKey);
        if (!$encryptedData) {
            throw new Exception('Failed to encrypt data with AES.');
        }

        return $encryptedData;
    }

    public static function aesDecrypt(string $encryptedData, string $aesKey): string
    {
        $decryptedData = openssl_decrypt($encryptedData, self::CIPHER_ALGORITHM, $aesKey);
        if (!$decryptedData) {
            throw new Exception('Failed to decrypt data with AES.');
        }

        return $decryptedData;
    }

    public static function rsaSign(string $data): string
    {
        $privateKey = self::getPrivateKey();
        $result = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA1);

        if (!$result) {
            throw new Exception('Failed to sign data with private key.');
        }

        return $signature;
    }
}
