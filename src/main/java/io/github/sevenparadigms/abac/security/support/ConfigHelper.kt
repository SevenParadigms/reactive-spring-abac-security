package io.github.sevenparadigms.abac.security.support

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.ANONYMOUS
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_KEY
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_LOGIN
import io.github.sevenparadigms.abac.Constants.AUTHORIZE_ROLES
import io.github.sevenparadigms.abac.Constants.BEARER
import io.github.sevenparadigms.abac.Constants.ROLE_USER
import io.github.sevenparadigms.abac.Constants.SKIP_TOKEN_PROPERTY
import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionRequest
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionSuccessResponse
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.jsonwebtoken.Claims
import org.apache.commons.lang3.StringUtils
import org.sevenparadigms.kotlin.common.error
import org.sevenparadigms.kotlin.common.parseJson
import org.springframework.data.r2dbc.config.Beans
import org.springframework.data.r2dbc.repository.query.Dsl
import org.springframework.data.r2dbc.support.DslUtils
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
import org.springframework.util.ObjectUtils
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
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
            val skipTokenValidation = Beans.getProperty(SKIP_TOKEN_PROPERTY, Boolean::class.java, false)
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
        return serverRequest.bodyToMono(UserPrincipal::class.java)
            .filter { !ObjectUtils.isEmpty(it.login) && !ObjectUtils.isEmpty(it.password) }
            .switchIfEmpty(Mono.error { throw BadCredentialsException("Login and password required") })
            .flatMap { authenticationManager.authenticate(UsernamePasswordAuthenticationToken(it.login, it.password)) }
            .flatMap { ok().bodyValue(jwtTokenProvider.getAuthToken(it)) }
    }

    fun validateOpaqueToken(serverRequest: ServerRequest): Mono<ServerResponse> {
        val validator = Beans.of(TokenAuthorizationService::class.java)
        return serverRequest.bodyToMono(TokenIntrospectionRequest::class.java)
            .flatMap { validator.validateToken(it) }
            .flatMap {
                if (it is TokenIntrospectionSuccessResponse) ok().body(BodyInserters.fromValue(it))
                else badRequest().body(BodyInserters.fromValue(it))
            }
    }

    private fun skipValidation(authToken: String): Mono<Authentication> {
        val expirationProperty = Beans.of(JwtTokenProvider::class.java).expiration.toInt()
        return Mono.just(authToken)
            .handle { token, sink ->
                val claims =
                    String(
                        Base64.getDecoder().decode(token.split(DslUtils.DOT)[1])
                    ).parseJson(LinkedHashMap::class.java)
                if ((claims[Claims.EXPIRATION] as Int).plus(expirationProperty) < TimeUnit.MILLISECONDS.toSeconds(
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