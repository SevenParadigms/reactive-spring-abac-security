package io.github.sevenparadigms.abac.security.opaque.data

data class TokenIntrospectionRequest(
    val token: String? = null,
)