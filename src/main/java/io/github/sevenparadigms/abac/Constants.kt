package io.github.sevenparadigms.abac

object Constants {
    const val ROLE_ADMIN = "ROLE_ADMIN"
    const val ROLE_USER = "ROLE_USER"
    const val ANONYMOUS = "ROLE_ANONYMOUS"

    const val AUTHORITIES_KEY = "auth"

    const val AUTHORIZE_KEY = "X-User-Id"
    const val AUTHORIZE_LOGIN = "X-Login"
    const val AUTHORIZE_ROLES = "X-Roles"
    const val AUTHORIZE_IP = "X-Forwarded-For"

    const val AUTHORIZE_PROPERTY = "spring.security.$AUTHORIZE_KEY"

    const val BEARER = "Bearer "
    const val REQUEST = "Request"
    const val RESPONSE = "Response"

    const val PRINCIPAL = "Principal"

    const val SKIP_TOKEN_PROPERTY = "spring.security.skip-token-validation"

    const val TOKEN_CACHE = "tokens"
    const val TOKEN_INTROSPECTION_STATUS = "token_status"
    const val TOKEN_INTROSPECTION_SCOPE = "scope"
    const val TOKEN_ROLES = "roles"

    val whitelist = arrayOf(
        "/actuator/**",
        "/static/**",
        "/auth/**",
        "/favicon.ico",
        "/swagger-ui.html/**",
        "/webjars/**",
        "/v3/api-docs/**"
    )
}