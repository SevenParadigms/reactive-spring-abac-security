package io.github.sevenparadigms.abac.security.opaque.data

data class TokenIntrospectionErrorResponse(
    val error: String? = null,
    val errorDescription: String? = null,
)