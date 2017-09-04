package org.angry1980.security.jwt

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.web.server.LocalServerPort
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import reactor.core.publisher.Mono

import java.util.Arrays

@RunWith(SpringRunner::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApplicationTest {

    val LOG = LoggerFactory.getLogger(ApplicationTest::class.java)

    @LocalServerPort
    private val port: Int = 0
    @Value("security.jwt.signingKey")
    private lateinit var signingKey: String

    private lateinit var client: WebTestClient

    private val requests = listOf(
            RequestInfo("test1", "TEST1"),
            RequestInfo("test2", "TEST2"),
            RequestInfo("test3", null)
    )


    @Before
    fun setup() {
        this.client = WebTestClient.bindToServer()
                .baseUrl("http://localhost:$port/$PATH_PREFIX")
                .filter { clientRequest, next ->
                    LOG.debug("Request is ready to sent {}", clientRequest.requestInfo())
                    clientRequest.headers().print()
                    next.exchange(clientRequest)
                            .doOnError { ex -> LOG.error("Error when sending request {}", clientRequest.requestInfo(), ex) }
                            .doOnSuccess { result ->
                                LOG.debug("Response for {} was recieved with status {}", clientRequest.requestInfo(), result.statusCode())
                                result.headers().asHttpHeaders().print(false)
                            }
                }.build()
    }

    @Test
    fun `requests by unauthorized user should be rejected`() {
        requests.forEach { request ->
            client.get()
                    .uri("/" + request.path)
                    .exchange()
                    .expectStatus()
                    .isUnauthorized
        }
    }

    @Test
    fun requestsByUserWithoutRoles() {
        requests.forEach { request ->
            jwtAuthClient(client, signingKey).get()
                    .uri("/" + request.path)
                    .exchange()
                    .expectStatus()
                    .isEqualTo(if (request.role != null) HttpStatus.FORBIDDEN else HttpStatus.OK)
        }
    }

    @Test
    fun requestsByUserWithRoles() {
        requests.stream()
                .filter { request -> request.role != null }
                .forEach { request ->
                    jwtAuthClient(client, signingKey, request.role).get()
                            .uri("/" + request.path)
                            .exchange()
                            .expectStatus()
                            .isEqualTo(HttpStatus.OK)
                }
    }

    @Test
    fun requestsWithWrongSignigKey() {
        requests.stream()
                .forEach { request ->
                    jwtAuthClient(client, "WrongKey", request.role).get()
                            .uri("/" + request.path)
                            .exchange()
                            .expectStatus()
                            .isUnauthorized
                }
    }

    private fun jwtAuthClient(client: WebTestClient, signingKey: String, vararg roles: String?): WebTestClient {
        return client.mutate().filter(
                ExchangeFilterFunction.ofRequestProcessor { clientRequest ->
                    val authorization = authorization(signingKey, *roles)
                    LOG.debug("Generated jwt authorization header  {}", authorization)
                    val authorizedRequest = ClientRequest.from(clientRequest)
                            .headers { headers -> headers.set(HttpHeaders.AUTHORIZATION, authorization) }
                            .build()
                    Mono.just(authorizedRequest)
                }
        ).build()
    }

    private fun authorization(signingKey: String, vararg roles: String?): String {
        val claims = Jwts.claims().setSubject("test")
        claims.put("scopes", roles)
        val token = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, signingKey)
                .compact()
        return "Bearer " + token
    }

    internal inner class RequestInfo(var path: String, var role: String?)

}
