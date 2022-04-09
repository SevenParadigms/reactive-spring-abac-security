package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.Constants.JWT_ITERATION_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_SECRET_PROPERTY
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Component
@ConditionalOnProperty(JWT_SECRET_PROPERTY)
class PBKDF2Encoder : PasswordEncoder {
    @Value("\${$JWT_SECRET_PROPERTY}")
    lateinit var secret: String

    @Value("\${$JWT_ITERATION_PROPERTY}")
    lateinit var iteration: String

    override fun encode(cs: CharSequence) = Base64.getEncoder().encodeToString(
        SecretKeyFactory.getInstance(Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512.name)
            .generateSecret(PBEKeySpec(cs.toString().toCharArray(), "$iteration$secret".toByteArray(), iteration.toInt(), "$iteration$secret".length))
            .encoded
    )

    override fun matches(cs: CharSequence, string: String) = encode(cs) == string
}