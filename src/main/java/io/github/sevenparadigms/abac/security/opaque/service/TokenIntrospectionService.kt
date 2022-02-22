package io.github.sevenparadigms.abac.security.opaque.service

import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import reactor.core.publisher.Mono

interface TokenIntrospectionService {
    fun delegateIntrospect(token: String): Mono<OpaqueTokenPrincipal>
}
