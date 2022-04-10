package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.Constants.JWT_SECRET_PROPERTY
import io.github.sevenparadigms.abac.configuration.JwtProperties
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Component
@ConditionalOnProperty(JWT_SECRET_PROPERTY)
class PBKDF2Encoder(val jwt: JwtProperties) : PasswordEncoder {
    override fun encode(cs: CharSequence) = Base64.getEncoder().encodeToString(
        SecretKeyFactory.getInstance(Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.valueOf(jwt.passwordAlgorithm).name)
            .generateSecret(PBEKeySpec(cs.toString().toCharArray(), "${jwt.iteration}${jwt.secretKey}".toByteArray(),
                jwt.iteration, "${jwt.iteration}${jwt.secretKey}".length))
            .encoded)

    override fun matches(cs: CharSequence, string: String) = encode(cs) == string
}