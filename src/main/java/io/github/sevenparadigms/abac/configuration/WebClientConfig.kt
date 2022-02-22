package io.github.sevenparadigms.abac.configuration

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.r2dbc.support.JsonUtils
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.ClientCodecConfigurer
import org.springframework.http.codec.json.Jackson2JsonDecoder
import org.springframework.http.codec.json.Jackson2JsonEncoder
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ExchangeFunction
import org.springframework.web.reactive.function.client.ExchangeStrategies
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import reactor.netty.resources.ConnectionProvider
import reactor.util.context.ContextView
import java.time.Duration

@Configuration
class WebClientConfig {
    @Bean
    @ConditionalOnProperty("webclient.url")
    fun webClient(
        @Value("\${webclient.url}") url: String,
        builder: WebClient.Builder
    ): WebClient = builder.baseUrl(url).build()

    @Bean
    fun webClientBuilder(): WebClient.Builder = WebClient.builder()
        .clientConnector(
            ReactorClientHttpConnector(
                HttpClient.create(
                    ConnectionProvider.builder("fixed")
                        .maxConnections(500)
                        .maxIdleTime(Duration.ofSeconds(30))
                        .maxLifeTime(Duration.ofSeconds(60))
                        .pendingAcquireTimeout(Duration.ofSeconds(60))
                        .evictInBackground(Duration.ofSeconds(120)).build()
                ).keepAlive(false)
            )
        )
        .exchangeStrategies(ExchangeStrategies.builder()
            .codecs { c: ClientCodecConfigurer ->
                c.customCodecs().register(Jackson2JsonDecoder(JsonUtils.getMapper()))
                c.customCodecs().register(Jackson2JsonEncoder(JsonUtils.getMapper()))
            }
            .build())
        .filter { clientRequest: ClientRequest, next: ExchangeFunction ->
            Mono.deferContextual { ctx: ContextView ->
                val requestHeaders = ctx.get(ServerWebExchange::class.java).request.headers.toSingleValueMap()
                val request =
                    ClientRequest.from(clientRequest).headers { headers -> headers.setAll(requestHeaders) }.build()
                next.exchange(request)
            }
        }
        .codecs { it.defaultCodecs().apply { maxInMemorySize(16 * 1024 * 1024) } }
}