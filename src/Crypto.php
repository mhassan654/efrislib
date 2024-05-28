<?php
/**
 * Created by Muwonge Hassan Saava.
 * User: Muwonge Hassan Saava
 * Date: 28/05/2024$
 * Time: 16:57$
 * FileName: Crypto.php
 * PROJECT NAME: efrislib
 * Github: https://github.com/mhassan654
 */


namespace Sniper\EfrisLib;

use Illuminate\Http\Response;

class Crypto
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
            throw new RuntimeException('Failed to read private key file.');
        }

        $certInfo = [];
        $isRead = openssl_pkcs12_read($certStore, $certInfo, self::$privateKeyPassword);
        if (!$isRead) {
            throw new RuntimeException('Failed to parse private key from certificate store.');
        }

        return $certInfo['pkey'];
    }

    public static function rsaDecrypt(string $encryptedData): string
    {
        $privateKey = self::getPrivateKey();
        $result = openssl_private_decrypt($encryptedData, $decryptedData, $privateKey, OPENSSL_PKCS1_PADDING);

        if ($result !== true) {
            throw new RuntimeException('Failed to decrypt data with private key.');
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
            throw new RuntimeException('Failed to encrypt data with AES.');
        }

        return $encryptedData;
    }

    public static function aesDecrypt(string $encryptedData, string $aesKey): string
    {
        $decryptedData = openssl_decrypt($encryptedData, self::CIPHER_ALGORITHM, $aesKey);
        if (!$decryptedData) {
            throw new RuntimeException('Failed to decrypt data with AES.');
        }

        return $decryptedData;
    }

    public static function rsaSign(string $data): string
    {
        $privateKey = self::getPrivateKey();
        $result = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA1);

        if (!$result) {
            throw new RuntimeException('Failed to sign data with private key.');
        }

        return $signature;
    }
}
