package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.Constants.AUTHORITIES_KEY
import io.jsonwebtoken.*
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import io.jsonwebtoken.security.SignatureException
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.error
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.r2dbc.repository.query.Dsl
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.stream.Collectors
import javax.crypto.spec.SecretKeySpec

@Component
class JwtTokenProvider {
    @Value("\${spring.security.secret}")
    lateinit var seckey: String

    @Value("\${spring.security.public}")
    lateinit var pubkey: String

    @Value("\${spring.security.expiration}")
    lateinit var expiration: String

    fun getToken(authentication: Authentication): String {
        val authorities = authentication.authorities.stream()
            .map { obj: GrantedAuthority -> obj.authority }
            .collect(Collectors.joining(Dsl.COMMA))

        return Jwts.builder()
            .setSubject(authentication.name)
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.HS512.jcaName))
            .setExpiration(Date(Date().time + expiration.toLong() * 1000))
            .compact()
    }

    fun getAuthentication(authorizeKey: String): Authentication {
        val claims = getClaims(authorizeKey)
        val authorities: Collection<GrantedAuthority> =
            Arrays.stream(claims[AUTHORITIES_KEY].toString().split(Dsl.COMMA.toRegex()).toTypedArray())
                .map { role -> SimpleGrantedAuthority(role) }
                .collect(Collectors.toList())
        val principal = User(claims.subject, StringUtils.EMPTY, authorities)
        return UsernamePasswordAuthenticationToken(principal, claims, authorities)
    }

    fun getClaims(authToken: String): Claims {
        try {
            val key = if (ObjectUtils.isNotEmpty(seckey) && ObjectUtils.isNotEmpty(expiration))
                SecretKeySpec("$seckey$expiration".toByteArray(), SignatureAlgorithm.HS512.jcaName)
            else
                if (ObjectUtils.isNotEmpty(pubkey)) {
                    val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(pubkey))
                    KeyFactory.getInstance("RSA").generatePublic(keySpec)
                } else throw RuntimeException("Property with public key[spring.security.public] not found")
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

    companion object {
        @JvmStatic
        fun getPrincipal(authToken: String): User =
            Jwts.parserBuilder()
                .deserializeJsonWith(JacksonDeserializer(mutableMapOf("user" to User::class.java) as Map<String, Class<User>>))
                .build().parseClaimsJwt(authToken).body.get("user", User::class.java)
    }
}