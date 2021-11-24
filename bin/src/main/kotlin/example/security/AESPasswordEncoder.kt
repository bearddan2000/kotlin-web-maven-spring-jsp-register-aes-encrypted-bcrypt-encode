package example.security

import example.security.AESUtils

import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.BadPaddingException
import javax.crypto.spec.IvParameterSpec
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

import org.springframework.security.crypto.password.PasswordEncoder

class AESPasswordEncoder : org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 65536, 10)
, PasswordEncoder {

    val password = "@amG89>"
    val salt = "blacknoir"

    val ivParameterSpec :IvParameterSpec by lazy {
      AESUtils.generateIv()
    }

    val key :SecretKey by lazy {
      AESUtils.getKeyFromPassword(password,salt)
    }

    override fun encode(rawPassword :CharSequence) :String
    {
      try {
        val res = AESUtils.encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec)
        return super.encode(res)//BCrypt.hashpw(res, BCrypt.gensalt())
      } catch(e :Exception) {}
      return super.encode(rawPassword)
    }

    override fun matches(rawPassword :CharSequence, encodedPassword :String) :Boolean
    {
     try {
       val res = AESUtils.encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec)
       return super.matches(res, encodedPassword)
     }catch(e :Exception) {return false}
    }
}
