package com.example.otameshi2

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.DelicateCryptographyApi
import kotlinx.coroutines.runBlocking

class CryptoManager {
    @OptIn(DelicateCryptographyApi::class)
    fun aesEncryptAndDecrypt() = runBlocking {
        val provider = CryptographyProvider.Default
        val aes = provider.get(AES.CBC)
        
        // キーの生成
        val key = aes.keyGenerator().generateKey()
        val cipher = key.cipher()
        
        // カスタムIVの作成（16バイト）
        val customIV = ByteArray(16) { it.toByte() }
        
        // 明示的なIVを使用した暗号化
        val plaintext = "Hello, Sunnies! 12345ABCD$&#*".encodeToByteArray()
        val encryptedData = cipher.encryptWithIv(customIV, plaintext)
        
        // 復号化時も同じIVを使用
        val decryptedData = cipher.decryptWithIv(customIV, encryptedData)
        
        println("Original: ${plaintext.decodeToString()}")
        println("Decrypted: ${decryptedData.decodeToString()}")
        println("Success: ${plaintext.contentEquals(decryptedData)}")
    }

    fun rsaOaepEncryptAndDecrypt() = runBlocking {
        val provider = CryptographyProvider.Default
        val rsaOaep = provider.get(RSA.OAEP)
        
        // RSA鍵ペアの生成（2048ビット、SHA-256ダイジェスト）
        val keyPair = rsaOaep.keyPairGenerator(
            keySize = 2048.bits,
            digest = SHA256
        ).generateKey()
        
        // 暗号化するデータ
        val plaintext = "Hello, Sunnies! 12345ABCD$&# (RSA-OAEP!)".encodeToByteArray()
        
        // 公開鍵で暗号化
        val encryptor = keyPair.publicKey.encryptor()
        val encryptedData = encryptor.encrypt(plaintext)
        
        // 秘密鍵で復号化
        val decryptor = keyPair.privateKey.decryptor()
        val decryptedData = decryptor.decrypt(encryptedData)
        
        println("RSA-OAEP Test:")
        println("Original: ${plaintext.decodeToString()}")
        println("Encrypted size: ${encryptedData.size} bytes")
        println("Decrypted: ${decryptedData.decodeToString()}")
        println("Success: ${plaintext.contentEquals(decryptedData)}")
    }
}