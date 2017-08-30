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
import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ApplicationTest {

    private static Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

    @LocalServerPort
    private int port;
    @Value("security.jwt.signingKey")
    private String signingKey;

    private WebTestClient client;

    private List<RequestInfo> requests = Arrays.asList(
            new RequestInfo("test1", "TEST1"),
            new RequestInfo("test2", "TEST2"),
            new RequestInfo("test3", null)
    );


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
    public void requestsByUnauthorizedUser(){
        requests.forEach(request ->
                client.get()
                        .uri("/" + request.path)
                        .exchange()
                        .expectStatus()
                        .isUnauthorized()
        );
    }

    @Test
    public void requestsByUserWithoutRoles(){
        requests.forEach(request ->
                jwtAuthClient(client).get()
                        .uri("/" + request.path)
                        .exchange()
                        .expectStatus()
                        .isEqualTo(request.role != null ? HttpStatus.FORBIDDEN : HttpStatus.OK)
        );
    }

    @Test
    public void requestsByUserWithRoles(){
        requests.stream()
                .filter(request -> request.role != null)
                .forEach(request ->
                    jwtAuthClient(client, request.role).get()
                        .uri("/" + request.path)
                        .exchange()
                        .expectStatus()
                        .isEqualTo(HttpStatus.OK)
                );
    }

    private WebTestClient jwtAuthClient(WebTestClient client, String ... roles){
        return client.mutate().filter(
                ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
                    String authorization = authorization(client, roles);
                    LOG.debug("Generated jwt authorization header  {}", authorization);
                    ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
                        .headers(headers -> headers.set(HttpHeaders.AUTHORIZATION, authorization) )
                        .build();
                    return Mono.just(authorizedRequest);
                })
        ).build();
    }

    private String authorization(WebTestClient client, String ... roles) {
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

    class RequestInfo{

        String path;
        String role;

        public RequestInfo(String path, String role) {
            this.path = path;
            this.role = role;
        }
    }
}
