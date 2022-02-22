package io.github.sevenparadigms.abac.security.opaque.service.impl

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionErrorResponse
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionRequest
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionSuccessResponse
import io.github.sevenparadigms.abac.security.opaque.service.TokenIntrospectionService
import io.jsonwebtoken.Claims
import org.sevenparadigms.kotlin.common.putIfNotEmpty
import org.springframework.data.r2dbc.repository.query.Dsl
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import java.net.URL
import java.util.*
import java.util.stream.Collectors

class TokenIntrospectionServiceImpl(
    private val introspectionUrl: String,
    private val introspectionClientId: String? = null,
    private val introspectionSecret: String? = null,
    private var webClient: WebClient? = null,
) : TokenIntrospectionService {

    init {
        if (this.webClient == null) {
            require(introspectionClientId != null)
            require(introspectionSecret != null)
            this.webClient = WebClient.builder().defaultHeaders { h: HttpHeaders ->
                h.setBasicAuth(
                    introspectionClientId,
                    introspectionSecret
                )
            }.build()
        }
    }

    override fun delegateIntrospect(token: String): Mono<OpaqueTokenPrincipal> {
        return Mono.just(token)
            .flatMap { this.makeRequest(it) }
            .map { this.convertClaimsSet(it) }
            .onErrorMap({ it !is OAuth2IntrospectionException }) { onError(it!!) }
    }

    private fun makeRequest(token: String): Mono<TokenIntrospectionSuccessResponse> {
        return this.webClient!!.post().uri(this.introspectionUrl)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(TokenIntrospectionRequest(token = token)))
            .exchangeToMono { this.castToIntrospectionResponse(it) }
    }

    private fun castToIntrospectionResponse(response: ClientResponse): Mono<TokenIntrospectionSuccessResponse> {
        return if (response.statusCode().is2xxSuccessful) {
            response.bodyToMono(TokenIntrospectionSuccessResponse::class.java)
        } else {
            response.bodyToMono(TokenIntrospectionErrorResponse::class.java)
                .handle { resp, sink -> sink.error(BadOpaqueTokenException(resp.errorDescription)) }
        }
    }

    // authorities must be in response
    private fun convertClaimsSet(response: TokenIntrospectionSuccessResponse): OpaqueTokenPrincipal {
        val attributes: MutableMap<String, Any> = HashMap()
        attributes.putIfNotEmpty(
            Claims.AUDIENCE, if (response.audience == null) null
            else Collections.unmodifiableList(response.audience!!)
        )
        attributes.putIfNotEmpty(Claims.SUBJECT, response.subject)
        attributes.putIfNotEmpty(Claims.EXPIRATION, response.expiration?.toInstant())
        attributes.putIfNotEmpty(Claims.ISSUED_AT, response.issueTime?.toInstant())
        attributes.putIfNotEmpty(Claims.ISSUER, response.issuer)
        attributes.putIfNotEmpty(Claims.NOT_BEFORE, response.notBeforeTime?.toInstant())
        attributes.putIfNotEmpty(Constants.TOKEN_INTROSPECTION_SCOPE, response.scope)
        val authorities =
            Arrays.stream(response.authorities!!.split(Dsl.COMMA.toRegex()).toTypedArray())
                .map { role -> SimpleGrantedAuthority(role) }
                .collect(Collectors.toList())

        return OpaqueTokenPrincipal(
            status = response.status!!,
            attributes = attributes,
            authorities = authorities
        )
    }

    private fun issuer(uri: String): URL {
        return try {
            URL(uri)
        } catch (var3: Exception) {
            throw OAuth2IntrospectionException("Invalid iss value: $uri")
        }
    }

    private fun onError(ex: Throwable): OAuth2IntrospectionException {
        return OAuth2IntrospectionException(ex.message, ex)
    }
}