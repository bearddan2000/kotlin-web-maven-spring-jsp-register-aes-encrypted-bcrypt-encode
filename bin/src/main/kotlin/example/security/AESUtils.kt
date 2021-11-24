package example.security

import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.BadPaddingException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.util.Base64

object AESUtils {
    @Throws (
      NoSuchPaddingException::class
      , NoSuchAlgorithmException::class
      , InvalidAlgorithmParameterException::class
      , InvalidKeyException::class
      , BadPaddingException::class
      , IllegalBlockSizeException::class
    )
    fun encrypt(algorithm :String, input :String, key :SecretKey, iv :IvParameterSpec) : String
    {
        val cipher :Cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        val cipherText :ByteArray = cipher.doFinal(input.toByteArray())
        return Base64.getEncoder().encodeToString(cipherText)
    }

    @Throws (NoSuchAlgorithmException::class)
    fun generateKey(n :Int) :SecretKey {
        val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(n)
        return keyGenerator.generateKey()
    }

    @Throws (NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun getKeyFromPassword(password :String, salt :String) : SecretKey
    {
        val factory :SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec :KeySpec = PBEKeySpec(password.toCharArray(), salt.toByteArray(), 65536, 256)
        return SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES")
    }

    fun generateIv() :IvParameterSpec {
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        return IvParameterSpec(iv)
    }

    @Throws (
      NoSuchPaddingException::class
      , NoSuchAlgorithmException::class
      , InvalidAlgorithmParameterException::class
      , InvalidKeyException::class
      , BadPaddingException::class
      , IllegalBlockSizeException::class
    )
    fun encryptPasswordBased(plainText :String, key :SecretKey, iv :IvParameterSpec) : String
    {
        val cipher :Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.toByteArray()))
    }
}
