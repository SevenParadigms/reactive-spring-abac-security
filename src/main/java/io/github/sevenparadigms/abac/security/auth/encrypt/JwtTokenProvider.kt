package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.AUTHORITIES_KEY
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SignatureException
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.error
import org.sevenparadigms.kotlin.common.loadResource
import org.sevenparadigms.kotlin.common.remove
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.KeyStore.PasswordProtection
import java.security.KeyStore.ProtectionParameter
import java.security.cert.CertificateFactory
import java.util.*
import javax.crypto.spec.SecretKeySpec
import kotlin.streams.toList


@Component
class JwtTokenProvider {
    @Value("\${spring.security.jwt.secret:}")
    lateinit var seckey: String

    @Value("\${spring.security.jwt.public:}")
    lateinit var pubkey: String

    @Value("\${spring.security.jwt.expiration:}")
    lateinit var expiration: String

    @Value("\${spring.security.jwt.algorithm:HS512}")
    lateinit var algorithm: String

    @Value("\${spring.security.jwt.keystore-path:}")
    lateinit var keyPath: String

    @Value("\${spring.security.jwt.keystore-alias:}")
    lateinit var keystoreAlias: String

    @Value("\${spring.security.jwt.keystore-password:}")
    lateinit var keyPassword: String

    fun getAuthToken(authentication: Authentication): String = Jwts.builder()
        .setSubject(authentication.name)
        .claim(AUTHORITIES_KEY, authentication.authorities.stream().map { it.authority }.toList())
        .signWith(
            if (ObjectUtils.isNotEmpty(keyPath) && ObjectUtils.isNotEmpty(keyPassword) && authentication.name != Constants.TEST_USER) {
                val keyStore = KeyStore.getInstance("PKCS12")
                keyStore.load(ByteArrayInputStream(keyPath.loadResource()), keyPassword.toCharArray())
                val entryPassword: ProtectionParameter = PasswordProtection(keyPassword.toCharArray())
                val privateKeyEntry = keyStore.getEntry(keystoreAlias, entryPassword) as KeyStore.PrivateKeyEntry
                privateKeyEntry.privateKey
            } else
                SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.valueOf(algorithm).jcaName)
        )
        .setExpiration(Date(Date().time + expiration.toLong() * 1000))
        .compact()

    fun getAuthentication(authorizeKey: String): Authentication {
        val claims = getClaims(authorizeKey)
        val authorities: List<GrantedAuthority> = claims.get(AUTHORITIES_KEY, List::class.java)
            .map { role -> SimpleGrantedAuthority(role.toString()) }.toList()
        val principal = User(claims.subject, StringUtils.EMPTY, authorities)
        return UsernamePasswordAuthenticationToken(principal, claims, authorities)
    }

    fun getClaims(authToken: String): Claims {
        try {
            val key = if (ObjectUtils.isEmpty(pubkey) && ObjectUtils.isNotEmpty(seckey) && ObjectUtils.isNotEmpty(expiration))
                SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.valueOf(algorithm).jcaName)
            else
                if (ObjectUtils.isNotEmpty(pubkey)) {
                    val certificate: InputStream = ByteArrayInputStream(Base64.getDecoder().decode(pubkey.remove("[\\s\\r\\n]")))
                    CertificateFactory.getInstance("X.509").generateCertificate(certificate).publicKey
                } else
                    throw RuntimeException("Property with public key[spring.security.jwt.public] not found")
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(authToken).body
        } catch (e: SignatureException) {
            error("Invalid JWT signature trace: {}", e)
        } catch (e: MalformedJwtException) {
            error("Invalid JWT token trace: {}", e)
        } catch (e: ExpiredJwtException) {
            error("Expired JWT token trace: {}", e)
        } catch (e: UnsupportedJwtException) {
            error("Unsupported JWT token trace: {}", e)
        } catch (e: IllegalArgumentException) {
            error("JWT token compact of handler are invalid trace: {}", e)
        }
        throw BadCredentialsException("Invalid token")
    }
}