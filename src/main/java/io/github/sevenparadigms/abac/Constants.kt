package io.github.sevenparadigms.abac

import org.springframework.http.HttpHeaders
import org.springframework.web.reactive.function.server.ServerRequest

object Constants {
    const val ROLE_ADMIN = "ROLE_ADMIN"
    const val ROLE_USER = "ROLE_USER"
    const val ANONYMOUS = "ROLE_ANONYMOUS"

    const val AUTHORITIES_KEY = "roles"

    const val JWT_CACHE = "jwt"
    const val JWT_CACHE_REFRESH = "refresh"

    const val AUTHORIZE_KEY = "X-User-Id"
    const val AUTHORIZE_LOGIN = "X-Login"
    const val AUTHORIZE_ROLES = "X-Roles"
    const val AUTHORIZE_IP = "X-Forwarded-For"

    const val BEARER = "Bearer "
    const val REQUEST = "Request"
    const val RESPONSE = "Response"

    const val PRINCIPAL = "Principal"

    const val ABAC_URL_PROPERTY = "spring.security.abac.url"

    const val JWT_AUTHORIZE_PROPERTY = "spring.security.jwt.header-authorize"
    const val JWT_SKIP_TOKEN_PROPERTY = "spring.security.jwt.skip-token-validation"
    const val JWT_PUBLIC_PROPERTY = "spring.security.jwt.public-key"
    const val JWT_SECRET_PROPERTY = "spring.security.jwt.secret-key"
    const val JWT_EXPIRE_PROPERTY = "spring.security.jwt.expiration"
    const val JWT_ITERATION_PROPERTY = "spring.security.jwt.iteration"
    const val JWT_REFRESH_EXPIRE_PROPERTY = "spring.security.jwt.refresh-expiration"
    const val JWT_ALGORITHM_PROPERTY = "spring.security.jwt.algorithm"
    const val JWT_KEYSTORE_PATH_PROPERTY = "spring.security.jwt.keystore-path"
    const val JWT_KEYSTORE_TYPE_PROPERTY = "spring.security.jwt.keystore-type"
    const val JWT_KEYSTORE_ALIAS_PROPERTY = "spring.security.jwt.keystore-alias"
    const val JWT_KEYSTORE_PASSWORD_PROPERTY = "spring.security.jwt.keystore-password"

    const val JWT_CACHE_WRITE = "spring.cache.jwt.expireAfterWrite"
    const val JWT_CACHE_ACCESS = "spring.cache.jwt.expireAfterAccess"

    val whitelist = arrayOf(
        "/actuator/**",
        "/static/**",
        "/token/**",
        "/favicon.ico",
        "/swagger-ui.html/**",
        "/webjars/**",
        "/v3/api-docs/**"
    )

    const val TEST_USER = "test_user"
}

fun ServerRequest.hasHeader(name: String): Boolean = this.getHeader(name) != null

fun ServerRequest.getHeader(name: String): String? = this.headers().firstHeader(name)

fun ServerRequest.getBearerToken(): String? = this.getHeader(HttpHeaders.AUTHORIZATION)?.substring(Constants.BEARER.length)
