package io.github.sevenparadigms.abac.security.opaque.service

import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionRequest
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionSuccessResponse
import reactor.core.publisher.Mono

interface TokenAuthorizationService {
    fun validateToken(request: TokenIntrospectionRequest): Mono<TokenIntrospectionSuccessResponse>
}