package io.github.sevenparadigms.abac.security.support

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.ANONYMOUS
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_KEY
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_LOGIN
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_ROLES
import io.github.sevenparadigms.abac.Constants.BEARER
import io.github.sevenparadigms.abac.Constants.REFRESH_TOKEN
import io.github.sevenparadigms.abac.Constants.ROLE_USER
import io.github.sevenparadigms.abac.configuration.JwtProperties
import io.github.sevenparadigms.abac.getBearerToken
import io.github.sevenparadigms.abac.hasHeader
import io.github.sevenparadigms.abac.security.auth.data.AuthResponse
import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.auth.data.toUser
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.jsonwebtoken.Claims
import org.apache.commons.codec.digest.MurmurHash2
import org.apache.commons.lang3.ObjectUtils
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.parseJson
import org.springframework.data.r2dbc.support.Beans
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
import reactor.kotlin.core.util.function.component1
import reactor.kotlin.core.util.function.component2
import reactor.kotlin.core.util.function.component3
import java.util.*
import java.util.concurrent.TimeUnit

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
            if (Beans.of(JwtProperties::class.java).skipTokenValidation) {
                return@ServerAuthenticationConverter skipValidation(bearerToken.substring(BEARER.length))
            }
            Mono.just(jwtTokenProvider.getAuthentication(bearerToken.substring(BEARER.length)))
        }

    fun jwtHeadersExchangeMatcher(isAuthorizeKeyEnabled: Boolean) =
        ServerWebExchangeMatcher { serverWebExchange: ServerWebExchange ->
            Mono.just(serverWebExchange)
                .map { obj: ServerWebExchange -> obj.request }
                .map { obj: ServerHttpRequest -> obj.headers }
                .filter {
                    it.containsKey(HttpHeaders.AUTHORIZATION) || (isAuthorizeKeyEnabled && it.containsKey(AUTHORIZE_KEY))
                }
                .flatMap { ServerWebExchangeMatcher.MatchResult.match() }
                .switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch())
        }

    fun authorize(serverRequest: ServerRequest): Mono<ServerResponse> {
        val jwtTokenProvider = Beans.of(JwtTokenProvider::class.java)
        val authenticationManager = Beans.of(ReactiveAuthenticationManager::class.java)
        val expiration = Beans.of(JwtProperties::class.java).expiration
        return serverRequest.bodyToMono(UserPrincipal::class.java)
            .filter { !ObjectUtils.isEmpty(it.login) && !ObjectUtils.isEmpty(it.password) }
            .switchIfEmpty(Mono.error { throw BadCredentialsException("Login and password required") })
            .flatMap { authenticationManager.authenticate(UsernamePasswordAuthenticationToken(it.login, it.password)) }
            .map { jwtTokenProvider.getAuthenticationToken(it) }
            .flatMap { accessToken ->
                ok().bodyValue(
                    AuthResponse(
                        tokenType = BEARER.trim().lowercase(),
                        accessToken = accessToken,
                        expiresIn = expiration,
                        refreshToken = jwtTokenProvider.getRefreshToken(accessToken)
                    )
                )
            }
    }

    fun refresh(serverRequest: ServerRequest): Mono<ServerResponse> {
        val error: String
        val jwtTokenProvider = Beans.of(JwtTokenProvider::class.java)
        val refreshToken = serverRequest.queryParam(REFRESH_TOKEN)
        if (serverRequest.hasHeader(HttpHeaders.AUTHORIZATION) && refreshToken.isPresent && ObjectUtils.isNotEmpty(
                refreshToken.get()
            )
        ) {
            val (hash, expire) = JwtCache.getRefresh(refreshToken.get())!!
            val authorizeKey = serverRequest.getBearerToken()
            if (MurmurHash2.hash64(authorizeKey) == hash && Date().before(expire)) {
                val (principal, _, expired) = JwtCache.get(hash)!!
                if (!expired) {
                    val authentication = jwtTokenProvider.getAuthenticationToken(
                        UsernamePasswordAuthenticationToken(
                            principal.toUser(),
                            principal.id,
                            principal.toUser().authorities
                        )
                    )
                    val expiration = Beans.of(JwtProperties::class.java).expiration
                    JwtCache.revoke(hash).evictRefresh(refreshToken.get())
                    return ok().bodyValue(
                        AuthResponse(
                            tokenType = BEARER.trim().lowercase(),
                            accessToken = authentication,
                            expiresIn = expiration,
                            refreshToken = jwtTokenProvider.getRefreshToken(authentication)
                        )
                    )
                } else
                    error = "Bearer token is revoked"
            } else {
                error = "Actual Bearer token is not found or refresh token is expired"
            }
        } else
            error = "Authorization header or query param `refresh_token` is not found"
        return ServerResponse.badRequest().bodyValue(
            JsonUtils.objectNode()
                .put("error", "Invalid request")
                .put("error", error)
        )
    }

    private fun skipValidation(authToken: String): Mono<Authentication> {
        val expirationProperty = Beans.of(JwtProperties::class.java).expiration
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
                    val authorities: Collection<GrantedAuthority> = (claims[Constants.ROLES_KEY] as List<String>)
                            .map { role -> SimpleGrantedAuthority(role) }.toList()
                    val principal = User(claims[Claims.SUBJECT].toString(), StringUtils.EMPTY, authorities)
                    val userId = UUID.fromString(claims[Constants.USER_ID] as String)
                    sink.next(UsernamePasswordAuthenticationToken(principal, userId, authorities))
                }
            }
    }

    fun tryAddTokenIntrospect(http: ServerHttpSecurity): ServerHttpSecurity {
        try {
            val introspect = Beans.of(ReactiveOpaqueTokenIntrospector::class.java)
            http.oauth2ResourceServer().opaqueToken().introspector(introspect)
        } catch (_: RuntimeException) {
        }
        return http
    }
}