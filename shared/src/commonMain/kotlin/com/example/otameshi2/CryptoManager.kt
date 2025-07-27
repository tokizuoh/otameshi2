package com.example.otameshi2

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
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
}