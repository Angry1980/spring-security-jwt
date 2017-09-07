package org.angry1980.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ApplicationTest {

    private static Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

    @LocalServerPort
    private int port;
    @Value("security.jwt.signingKey")
    private String signingKey;

    private WebTestClient client;

    @Before
    public void setup(){
        this.client = WebTestClient.bindToServer()
                        .baseUrl("http://localhost:" + port + "/" + Application.PATH_PREFIX)
                        .filter((clientRequest, next) -> {
                            LOG.debug("Request is ready to sent {}", requestInfo(clientRequest));
                            print(clientRequest.headers(), true);
                            return next.exchange(clientRequest)
                                    .doOnError(ex -> LOG.error("Error when sending request {}", requestInfo(clientRequest), ex))
                                    .doOnSuccess(result -> {
                                        LOG.debug("Response for {} was recieved with status {}", requestInfo(clientRequest), result.statusCode());
                                        print(result.headers().asHttpHeaders(), false);
                                    });
                        }).build();
    }

    @Test
    public void testRequestsPermissions(){
        Arrays.asList(
                //test1 requests
                new RequestInfo("test1", new User("TEST1"), HttpStatus.OK),
                new RequestInfo("test1", new User("TEST2"), HttpStatus.FORBIDDEN),
                new RequestInfo("test1", new User(null),    HttpStatus.FORBIDDEN),
                new RequestInfo("test1", null,              HttpStatus.UNAUTHORIZED),
                // test3 requests
                new RequestInfo("test3", new User("TEST1"), HttpStatus.OK),
                new RequestInfo("test3", new User(null),    HttpStatus.OK),
                new RequestInfo("test3", null,              HttpStatus.UNAUTHORIZED)

        ).forEach(request -> {
            LOG.info("Checking request {}", request);
            WebTestClient client = request.user == null ? this.client
                    : jwtAuthClient(this.client, signingKey, request.user.role);
            client.get()
                    .uri("/" + request.path)
                    .exchange()
                    .expectStatus()
                    .isEqualTo(request.status);
        });
    }

    @Test
    public void testWrongSignigKey(){
        jwtAuthClient(client, "WrongKey", "TEST1").get()
                .uri("/test1")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    private WebTestClient jwtAuthClient(WebTestClient client, String signingKey, String ... roles){
        return client.mutate().filter(
                ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
                    String authorization = authorization(signingKey, roles);
                    LOG.debug("Generated jwt authorization header  {}", authorization);
                    ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
                        .headers(headers -> headers.set(HttpHeaders.AUTHORIZATION, authorization) )
                        .build();
                    return Mono.just(authorizedRequest);
                })
        ).build();
    }

    private String authorization(String signingKey, String ... roles) {
        Claims claims = Jwts.claims().setSubject("test");
        claims.put("scopes", roles);
        String token = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, signingKey)
                .compact();
        return "Bearer " + token;
    }

    private String requestInfo(ClientRequest request){
        return request.method() + " " + request.url();
    }

    private void print(HttpHeaders headers, boolean request){
        headers.forEach( (name, values) ->
            values.forEach(value -> LOG.debug(request ? "Request header {}: {}" : "Response header {}: {}", name, value))
        );
    }

    class User {
        String role;

        public User(String role) {
            this.role = role;
        }

        @Override
        public String toString() {
            return "User{" +
                    "role='" + role + '\'' +
                    '}';
        }
    }

    class RequestInfo{

        String path;
        User user;
        HttpStatus status;

        public RequestInfo(String path, User user, HttpStatus status) {
            this.path = path;
            this.user = user;
            this.status = status;
        }

        @Override
        public String toString() {
            return "RequestInfo{" +
                    "path='" + path + '\'' +
                    ", user=" + user +
                    ", status=" + status +
                    '}';
        }
    }
}
