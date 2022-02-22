package io.github.sevenparadigms.abac.security.opaque.encrypt

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.util.*
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec

class OpaqueTokenValidator(
    private val expiration: String,
    private val secret: String,
) {

    // token is SUCCESS -> token must have attributes
    fun expireValidateToken(opaqueTokenPrincipal: OpaqueTokenPrincipal): TokenStatus {
        if (opaqueTokenPrincipal.status == TokenStatus.SUCCESS) {
            if ((opaqueTokenPrincipal.attributes[Claims.EXPIRATION] as Long).plus(this.expiration.toInt()) < TimeUnit.MILLISECONDS.toSeconds(
                    System.currentTimeMillis()
                )
            ) {
                return TokenStatus.EXPIRED
            }
        }
        return opaqueTokenPrincipal.status
    }

    fun getClaims(token: String): MutableMap<String, Any> {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(SecretKeySpec("$secret$expiration".toByteArray(), SignatureAlgorithm.HS512.jcaName))
                .build()
                .parseClaimsJws(token).body
        } catch (e: ExpiredJwtException) {
            Collections.singletonMap(Constants.TOKEN_INTROSPECTION_STATUS, TokenStatus.EXPIRED)
        } catch (e: Exception) {
            Collections.singletonMap(Constants.TOKEN_INTROSPECTION_STATUS, TokenStatus.INVALID)
        }
    }

}