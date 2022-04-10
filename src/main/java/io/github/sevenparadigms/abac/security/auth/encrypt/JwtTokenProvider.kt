package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.AUTHORITIES_KEY
import io.github.sevenparadigms.abac.Constants.JWT_ALGORITHM_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_EXPIRE_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_KEYSTORE_ALIAS_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_KEYSTORE_PASSWORD_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_KEYSTORE_PATH_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_KEYSTORE_TYPE_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_PUBLIC_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_REFRESH_EXPIRE_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_SECRET_PROPERTY
import io.github.sevenparadigms.abac.security.auth.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.support.JwtCache
import io.jsonwebtoken.*
import io.jsonwebtoken.security.SignatureException
import org.apache.commons.codec.digest.MurmurHash2
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.error
import org.sevenparadigms.kotlin.common.loadResource
import org.sevenparadigms.kotlin.common.remove
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationListener
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
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.util.*
import javax.crypto.spec.SecretKeySpec
import kotlin.streams.toList

@Component
class JwtTokenProvider : ApplicationListener<RevokeTokenEvent> {
    @Value("\${$JWT_SECRET_PROPERTY:}")
    lateinit var seckey: String

    @Value("\${$JWT_PUBLIC_PROPERTY:}")
    lateinit var pubkey: String

    @Value("\${$JWT_EXPIRE_PROPERTY:}")
    lateinit var expiration: String

    @Value("\${$JWT_REFRESH_EXPIRE_PROPERTY:3600}")
    lateinit var refreshExpiration: String

    @Value("\${$JWT_ALGORITHM_PROPERTY:HS512}")
    lateinit var algorithm: String

    @Value("\${$JWT_KEYSTORE_PATH_PROPERTY:}")
    lateinit var keyPath: String

    @Value("\${$JWT_KEYSTORE_TYPE_PROPERTY:PKCS12}")
    lateinit var keyType: String

    @Value("\${$JWT_KEYSTORE_ALIAS_PROPERTY:}")
    lateinit var keystoreAlias: String

    @Value("\${$JWT_KEYSTORE_PASSWORD_PROPERTY:}")
    lateinit var keyPassword: String

    private var privateKey: PrivateKey? = null

    private fun getPrivateKey() =
        if (privateKey == null) {
            val keyStore = KeyStore.getInstance(keyType)
            keyStore.load(ByteArrayInputStream(keyPath.loadResource()), keyPassword.toCharArray())
            val entryPassword: ProtectionParameter = PasswordProtection(keyPassword.toCharArray())
            val privateKeyEntry = keyStore.getEntry(keystoreAlias, entryPassword) as KeyStore.PrivateKeyEntry
            privateKeyEntry.privateKey
        } else
            privateKey

    fun getAuthToken(authentication: Authentication): String {
        val expireDate = Date(Date().time + expiration.toLong() * 1000)
        val authorizeKey = Jwts.builder()
            .setSubject(authentication.name)
            .claim(
                AUTHORITIES_KEY,
                authentication.authorities.stream().map { it.authority }.toList()
            )
            .signWith(
                if (ObjectUtils.isNotEmpty(keyPath) && ObjectUtils.isNotEmpty(keyPassword) && authentication.name != Constants.TEST_USER) {
                    getPrivateKey()
                } else
                    SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.valueOf(algorithm).jcaName)
            )
            .setExpiration(Date(Date().time + expiration.toLong() * 1000))
            .compact()
        JwtCache.put(authorizeKey, authentication.principal, expireDate)
        return authorizeKey
    }

    fun getRefreshToken(authorizeKey: String): String {
        val tokenHash = MurmurHash2.hash64(authorizeKey)
        val expireDate = Date(Date().time + refreshExpiration.toLong() * 1000)
        val refreshKey = Jwts.builder()
            .setSubject(tokenHash.toString())
            .signWith(
                if (ObjectUtils.isNotEmpty(keyPath) && ObjectUtils.isNotEmpty(keyPassword)) {
                    getPrivateKey()
                } else
                    SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.valueOf(algorithm).jcaName)
            )
            .setExpiration(expireDate)
            .compact()
        JwtCache.putRefresh(refreshKey, tokenHash, expireDate)
        return refreshKey
    }

    override fun onApplicationEvent(event: RevokeTokenEvent) {
        val cacheContext = if (event.token == null) JwtCache.get(event.hash!!)
        else JwtCache.get(event.token)
        if (cacheContext != null) {
            if (event.token == null) JwtCache.put(event.hash!!, cacheContext.t1, cacheContext.t2, true)
            else JwtCache.put(event.token, cacheContext.t1, cacheContext.t2, true)
        }
    }

    fun getAuthentication(authorizeKey: String): Authentication {
        val cacheContext = JwtCache.get(authorizeKey)
        if (cacheContext != null) {
            if (Date().after(cacheContext.t2)) {
                error("Expired JWT token: $authorizeKey")
                throw BadCredentialsException("Invalid token")
            }
            if (cacheContext.t3) {
                error("Revoked JWT token: $authorizeKey")
                throw BadCredentialsException("Invalid token")
            }
            return UsernamePasswordAuthenticationToken(cacheContext.t1, null, cacheContext.t1.authorities)
        }
        val claims = getJwtClaims(authorizeKey)
        val authorities: List<GrantedAuthority> = claims.get(AUTHORITIES_KEY, List::class.java)
            .map { role -> SimpleGrantedAuthority(role.toString()) }.toList()
        val principal = User(claims.subject, StringUtils.EMPTY, authorities)
        JwtCache.put(authorizeKey, principal, claims.expiration)
        return UsernamePasswordAuthenticationToken(principal, null, principal.authorities)
    }

    fun getJwtClaims(authorizeKey: String): Claims {
        try {
            val key = if (ObjectUtils.isEmpty(keyPath) && ObjectUtils.isEmpty(pubkey) && ObjectUtils.isNotEmpty(seckey))
                SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.valueOf(algorithm).jcaName)
            else
                if (ObjectUtils.isNotEmpty(pubkey)) {
                    val certificate: InputStream =
                        ByteArrayInputStream(Base64.getDecoder().decode(pubkey.remove("[\\s\\r\\n\\t]")))
                    CertificateFactory.getInstance("X.509").generateCertificate(certificate).publicKey
                } else
                    if (ObjectUtils.isNotEmpty(keyPath)) {
                        getPrivateKey()
                    } else {
                        throw RuntimeException("Property with public key[$JWT_PUBLIC_PROPERTY] not found")
                    }
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(authorizeKey).body
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