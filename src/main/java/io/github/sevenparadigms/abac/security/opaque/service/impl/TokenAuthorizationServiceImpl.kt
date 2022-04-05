package io.github.sevenparadigms.abac.security.opaque.service.impl

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionRequest
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionSuccessResponse
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.opaque.encrypt.OpaqueTokenValidator
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.jsonwebtoken.Claims
import org.apache.commons.lang3.StringUtils
import reactor.core.publisher.Mono

class TokenAuthorizationServiceImpl(
    private val validator: OpaqueTokenValidator,
) : TokenAuthorizationService {

    override fun validateToken(request: TokenIntrospectionRequest): Mono<TokenIntrospectionSuccessResponse> {
        return Mono.just(request.token!!)
            .handle { it, sink ->
                val claims = this.validator.getClaims(it)
                if (claims is Claims) {
                    sink.next(this.createSuccessResponse(claims))
                } else sink.next(TokenIntrospectionSuccessResponse(status = claims[Constants.TOKEN_INTROSPECTION_STATUS] as TokenStatus))
            }
    }
    
    private fun createSuccessResponse(claims: Claims): TokenIntrospectionSuccessResponse {
        val response = TokenIntrospectionSuccessResponse(status = TokenStatus.SUCCESS)
        if (claims.containsKey(Claims.AUDIENCE)) {
            response.audience = claims.audience.split(StringUtils.SPACE.toRegex()).toMutableList()
        }
        if (claims.containsKey(Claims.EXPIRATION)) {
            response.expiration = claims.expiration
        }
        if (claims.containsKey(Claims.ISSUED_AT)) {
            response.issueTime = claims.issuedAt
        }
        if (claims.containsKey(Claims.ISSUER)) {
            response.issuer = claims.issuer
        }
        if (claims.containsKey(Claims.NOT_BEFORE)) {
            response.notBeforeTime = claims.notBefore
        }
        if (claims.containsKey(Claims.SUBJECT)) {
            response.subject = claims.subject
        }
        if (claims.containsKey(Constants.TOKEN_INTROSPECTION_SCOPE)) {
            response.scope = claims.get(Constants.TOKEN_INTROSPECTION_SCOPE, HashSet::class.java) as HashSet<String>
        }
        response.authorities = claims[Constants.AUTHORITIES_KEY].toString()
        return response
    }

}