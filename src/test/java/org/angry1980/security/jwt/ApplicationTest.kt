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

@RunWith(SpringRunner::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApplicationTest {

    val LOG = LoggerFactory.getLogger(ApplicationTest::class.java)

    /**
     * Helper class which allows to describe user who makes request
     */
    data class User(val role: String? = null,
                    val name: String = "test")

    /**
     * Helper class which allows to describe request and expected result
     */
    data class RequestInfo(val path: String,
                           val user: User? = null,
                           val signingKey: String,
                           val status: HttpStatus = HttpStatus.UNAUTHORIZED)

    /**
     * Basic description of request to resource with restricted access
     */
    val test1Request: RequestInfo by lazy {
        RequestInfo("test1", signingKey = signingKey)
    }

    /**
     * Basic description of request to resource with full access
     */
    val test3Request: RequestInfo by lazy {
        RequestInfo("test3", signingKey = signingKey)
    }

    @LocalServerPort
    private val port: Int = 0
    @Value("security.jwt.signingKey")
    private lateinit var signingKey: String

    /**
     * Spring reactive web client
     */
    private lateinit var client: WebTestClient

    @Before
    fun setup() {
        this.client = WebTestClient.bindToServer()
                .baseUrl("http://localhost:$port/$PATH_PREFIX")
                .build()
    }

    @Test
    fun `request protected resource with restricted access by user which has got necessary permissions`() =
            testTemplate(test1Request.copy(user = User("TEST1"), status = HttpStatus.OK))

    @Test
    fun `request protected resource with restricted access by user which has not got necessary permissions`() =
        testTemplate(test1Request.copy(user = User("TEST2"), status = HttpStatus.FORBIDDEN))

    @Test
    fun `request protected resource with restricted access by user without permissions`() =
        testTemplate(test1Request.copy(user = User(), status = HttpStatus.FORBIDDEN))

    @Test
    fun `request protected resource with restricted access by unauthorized user`() = testTemplate(test1Request)

    @Test
    fun `request protected resource with full access by user without permissions`() =
        testTemplate(test3Request.copy(user = User(), status = HttpStatus.OK))

    @Test
    fun `request protected resource with full access by unauthorized user`() = testTemplate(test3Request)

    @Test
    fun `request protected resource when signing key is wrong`() = testTemplate(test1Request.copy(user = User("TEST1"), signingKey = "wrongKey"))

    /**
     * Test template contains main steps which we should do while checking some case.
     * It sends http request with parameters defined in input parameter and check the result.
     * @param request - description of request and expected result
     */
    private fun testTemplate(request: RequestInfo) {
        LOG.info("Checking request: {}", request)
        // get instance of web client
        this.client.jwt(request.signingKey, request.user)
                .get()
                // set resource url
                .uri("/${request.path}")
                // send request
                .exchange()
                //check status
                .expectStatus()
                .isEqualTo(request.status)
    }

    /**
     * In case when we need to make request from authorized user ( user is not null)
     * this method adds to existed filter chain new filter which creates authorization header and set to request header.
     * @param client - existed web client
     * @param signingKey - secret key to sign authorization token
     * @param user - data about user
     * @return client which should be used to make request
     */
    private fun WebTestClient.jwt(signingKey: String, user: User?) = when(user){
        null -> this
        else -> mutate().filter(
                ExchangeFilterFunction.ofRequestProcessor {
                    val authorization = authorizationHeader(signingKey, user)
                    LOG.debug("Generated jwt authorization header  {}", authorization)
                    Mono.just(
                            ClientRequest.from(it)
                                    .headers { it.set(HttpHeaders.AUTHORIZATION, authorization) }
                                    .build()
                    )
                }
        ).build()
    }

    /**
     * This method creates the value of authorization header.
     * Firstly it encrypts name of user and the list of his roles and signed result by secret key
     * @param signingKey - secret key to sign authorization token
     * @param user - data about user
     * @return - value of authorization header
     */
    private fun authorizationHeader(signingKey: String, user: User) = Jwts.claims()
            .setSubject(user.name)
            .apply {
                put("scopes", listOf(user.role))
            }.let {
                Jwts.builder()
                    .setClaims(it)
                    .signWith(SignatureAlgorithm.HS512, signingKey)
                    .compact()
            }.let {
                "Bearer $it"
            }

}

