package io.github.sevenparadigms.abac.security.support

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.ANONYMOUS
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_KEY
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_LOGIN
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_ROLES
import io.github.sevenparadigms.abac.Constants.BEARER
import io.github.sevenparadigms.abac.Constants.JWT_EXPIRE_PROPERTY
import io.github.sevenparadigms.abac.Constants.JWT_SKIP_TOKEN_PROPERTY
import io.github.sevenparadigms.abac.Constants.ROLE_USER
import io.github.sevenparadigms.abac.getBearerToken
import io.github.sevenparadigms.abac.hasHeader
import io.github.sevenparadigms.abac.security.auth.data.AuthResponse
import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.jsonwebtoken.Claims
import org.apache.commons.codec.digest.MurmurHash2
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.parseJson
import org.springframework.data.r2dbc.config.Beans
import org.springframework.data.r2dbc.repository.query.Dsl
import org.springframework.data.r2dbc.support.DslUtils
import org.springframework.data.r2dbc.support.JsonUtils
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.ok
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.util.*
import java.util.concurrent.TimeUnit
import java.util.stream.Collectors

open class ConfigHelper {
    fun unauthorizedEntryPoint() =
        ServerAuthenticationEntryPoint { exchange: ServerWebExchange, _: AuthenticationException ->
            Mono.fromRunnable { exchange.response.statusCode = HttpStatus.UNAUTHORIZED }
        }

    fun tokenAuthenticationConverter(isAuthorizeKeyEnabled: Boolean, jwtTokenProvider: JwtTokenProvider) =
        ServerAuthenticationConverter { serverWebExchange: ServerWebExchange ->
            val bearerToken = serverWebExchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
            if (ObjectUtils.isEmpty(bearerToken) || !bearerToken!!.startsWith(BEARER) || bearerToken.length <= BEARER.length) {
                if (isAuthorizeKeyEnabled) {
                    val userId = serverWebExchange.request.headers.getFirst(AUTHORIZE_KEY) as String
                    val login = if (serverWebExchange.request.headers.containsKey(AUTHORIZE_LOGIN))
                        serverWebExchange.request.headers.getFirst(AUTHORIZE_LOGIN) as String
                    else
                        StringUtils.EMPTY
                    val roles = serverWebExchange.request.headers.getFirst(AUTHORIZE_ROLES) as String
                    val authorities =
                        if (ObjectUtils.isEmpty(roles)) AuthorityUtils.createAuthorityList(ROLE_USER)
                        else AuthorityUtils.createAuthorityList(*roles.split(",").toTypedArray())
                    val principal = User(userId, login, authorities)
                    return@ServerAuthenticationConverter Mono.just(
                        UsernamePasswordAuthenticationToken(principal, UUID.fromString(userId), authorities)
                    )
                }
                return@ServerAuthenticationConverter Mono.just(
                    AnonymousAuthenticationToken(
                        "key",
                        "anonymous",
                        AuthorityUtils.createAuthorityList(ANONYMOUS)
                    )
                )
            }
            val skipTokenValidation = Beans.getProperty(JWT_SKIP_TOKEN_PROPERTY, Boolean::class.java, false)
            if (skipTokenValidation) {
                return@ServerAuthenticationConverter skipValidation(bearerToken.substring(BEARER.length))
            }
            Mono.just(jwtTokenProvider.getAuthentication(bearerToken.substring(BEARER.length)))
        }

    fun jwtHeadersExchangeMatcher(isAuthorizeKeyEnabled: Boolean) = ServerWebExchangeMatcher { serverWebExchange: ServerWebExchange ->
        val request = Mono.just(serverWebExchange).map { obj: ServerWebExchange -> obj.request }
        request.map { obj: ServerHttpRequest -> obj.headers }
            .filter {
                it.containsKey(HttpHeaders.AUTHORIZATION) || (isAuthorizeKeyEnabled && it.containsKey(AUTHORIZE_KEY))
            }
            .flatMap { ServerWebExchangeMatcher.MatchResult.match() }
            .switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch())
    }

    fun authorize(serverRequest: ServerRequest): Mono<ServerResponse> {
        val jwtTokenProvider = Beans.of(JwtTokenProvider::class.java)
        val authenticationManager = Beans.of(ReactiveAuthenticationManager::class.java)
        val expiration = Beans.getProperty(JWT_EXPIRE_PROPERTY, StringUtils.EMPTY)
        return serverRequest.bodyToMono(UserPrincipal::class.java)
            .filter { !ObjectUtils.isEmpty(it.login) && !ObjectUtils.isEmpty(it.password) }
            .switchIfEmpty(Mono.error { throw BadCredentialsException("Login and password required") })
            .flatMap { authenticationManager.authenticate(UsernamePasswordAuthenticationToken(it.login, it.password)) }
            .map { jwtTokenProvider.getAuthToken(it) }
            .flatMap { ok().bodyValue(AuthResponse(
                tokenType = BEARER.trim().lowercase(),
                accessToken = it,
                expiresIn = expiration.toInt(),
                refreshToken = jwtTokenProvider.getRefreshToken(it)
            )) }
    }

    fun refresh(serverRequest: ServerRequest): Mono<ServerResponse> {
        val error: String
        val jwtTokenProvider = Beans.of(JwtTokenProvider::class.java)
        val refreshToken = serverRequest.queryParam("refresh_token")
        if (serverRequest.hasHeader(HttpHeaders.AUTHORIZATION) && refreshToken.isPresent && ObjectUtils.isNotEmpty(refreshToken.get())) {
            val refreshTuple = JwtCache.getRefresh(refreshToken.get())
            val authorizeKey = serverRequest.getBearerToken()
            if (refreshTuple != null && MurmurHash2.hash64(authorizeKey) == refreshTuple.t1 && Date().before(refreshTuple.t2)) {
                val cacheContext = JwtCache.get(refreshTuple.t1)!!
                val authentication = jwtTokenProvider.getAuthToken(
                    UsernamePasswordAuthenticationToken(cacheContext.t1, null, cacheContext.t1.authorities)
                )
                val expiration = Beans.getProperty(JWT_EXPIRE_PROPERTY, StringUtils.EMPTY)
                JwtCache.evict(refreshTuple.t1).evictRefresh(refreshToken.get())
                return ok().bodyValue(AuthResponse(
                    tokenType = BEARER.trim().lowercase(),
                    accessToken = authentication,
                    expiresIn = expiration.toInt(),
                    refreshToken = jwtTokenProvider.getRefreshToken(authentication)
                ))
            } else {
                error = "Actual Bearer token is not found or refresh token is expired"
            }
        } else
            error = "Authorization header or query param `refresh_token` is not found"
        return ServerResponse.badRequest().bodyValue(JsonUtils.objectNode()
            .put("error", "Invalid request")
            .put("error", error))
    }

    private fun skipValidation(authToken: String): Mono<Authentication> {
        val expirationProperty = Beans.of(JwtTokenProvider::class.java).expiration.toInt()
        return Mono.just(authToken)
            .handle { token, sink ->
                val claims =
                    String(
                        Base64.getDecoder().decode(token.split(DslUtils.DOT)[1])
                    ).parseJson(LinkedHashMap::class.java)
                if ((claims[Claims.EXPIRATION] as Int).plus(expirationProperty * 1000) < TimeUnit.MILLISECONDS.toSeconds(
                        System.currentTimeMillis()
                    )
                ) {
                    error("Expired JWT token")
                } else {
                    val authorities: Collection<GrantedAuthority> =
                        Arrays.stream(
                            claims[Constants.AUTHORITIES_KEY].toString().split(Dsl.COMMA.toRegex()).toTypedArray()
                        )
                            .map { role -> SimpleGrantedAuthority(role) }
                            .collect(Collectors.toList())
                    val principal = User(claims[Claims.SUBJECT].toString(), StringUtils.EMPTY, authorities)
                    sink.next(UsernamePasswordAuthenticationToken(principal, claims, authorities))
                }
            }
    }

    fun tryAddTokenIntrospect(http: ServerHttpSecurity): ServerHttpSecurity {
        try {
            val introspect = Beans.of(ReactiveOpaqueTokenIntrospector::class.java)
            http.oauth2ResourceServer().opaqueToken().introspector(introspect)
        } catch (_: RuntimeException) {}
        return http
    }
}