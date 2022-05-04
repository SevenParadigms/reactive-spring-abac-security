package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.context.ExchangeHolder
import org.springframework.data.r2dbc.repository.security.AuthenticationIdentifierResolver

class CurrentUserResolver : AuthenticationIdentifierResolver {
    override fun resolve(): Any {
        return ExchangeHolder.getUser()
    }
}