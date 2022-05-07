package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.context.ExchangeHolder
import org.springframework.data.r2dbc.repository.security.AuthenticationIdentifierResolver
import reactor.core.publisher.Mono

class CurrentUserResolver : AuthenticationIdentifierResolver {
    override fun resolve(): Mono<Any> {
        return ExchangeHolder.getUserPrincipal().map { it.id } as Mono<Any>
    }
}