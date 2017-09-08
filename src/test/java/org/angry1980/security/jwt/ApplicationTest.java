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

import static java.util.Objects.requireNonNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ApplicationTest {

    private static Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

    /**
     *  Helper class which allows to describe user who makes request
     */
    static class User {
        final String name;
        final String role;

        User(String role){
            this("test", role);
        }

        User(String name, String role) {
            this.name = requireNonNull(name);
            this.role = role;
        }

        @Override
        public String toString() {
            return "User{" +
                    "name='" + name + '\'' +
                    "role='" + role + '\'' +
                    '}';
        }
    }

    /**
     * Helper class which allows to describe request and expected result
     */
    static class RequestInfo{

        final String path;
        final User user;
        final HttpStatus status;
        final String signingKey;

        RequestInfo(String path, User user, String signingKey, HttpStatus status) {
            this.path = requireNonNull(path);
            this.user = user;
            this.status = requireNonNull(status);
            this.signingKey = requireNonNull(signingKey);
        }

        @Override
        public String toString() {
            return "RequestInfo{" +
                    "path='" + path + '\'' +
                    ", user=" + user +
                    ", status=" + status +
                    ", signingKey=" + signingKey +
                    '}';
        }
    }

    @LocalServerPort
    private int port;
    @Value("security.jwt.signingKey")
    private String signingKey;

    /**
     * Spring reactive web client
     */
    private WebTestClient client;

    @Before
    public void setup(){
        this.client = WebTestClient.bindToServer()
                        .baseUrl("http://localhost:" + port + "/" + Application.PATH_PREFIX)
                        .build();
    }

    @Test
    public void requestProtectedResourceWithRestrictedAccessByUserWhichHasNecessaryPermissions(){
        testTemplate(new RequestInfo("test1", new User("TEST1"), signingKey, HttpStatus.OK));
    }

    @Test
    public void requestProtectedResourceWithRestrictedAccessByUserWhichHasNotNecessaryPermissions(){
        testTemplate(new RequestInfo("test1", new User("TEST2"), signingKey, HttpStatus.FORBIDDEN));
    }

    @Test
    public void requestProtectedResourceWithRestrictedAccessByUserWithoutPermissions(){
        testTemplate(new RequestInfo("test1", new User(null), signingKey, HttpStatus.FORBIDDEN));
    }

    @Test
    public void requestProtectedResourceWithRestrictedAccessByUnauthorizedUser(){
        testTemplate(new RequestInfo("test1", null, signingKey, HttpStatus.UNAUTHORIZED));
    }

    @Test
    public void requestProtectedResourceWithFullAccessByUserWithoutPermissions(){
        testTemplate(new RequestInfo("test3", new User(null), signingKey, HttpStatus.OK));
    }

    @Test
    public void requestProtectedResourceWithFullAccessByUnauthorizedUser(){
        testTemplate(new RequestInfo("test3", null, signingKey, HttpStatus.UNAUTHORIZED));
    }

    @Test
    public void requestProtectedResourceWhenSigningKeyIsWrong(){
        testTemplate(new RequestInfo("test1", new User("TEST1"), "wrongKey", HttpStatus.UNAUTHORIZED));
    }

    /**
     * Test template contains main steps which we should do while checking some case.
     * It sends http request with parameters defined in input parameter and check the result.
     * @param request - description of request and expected result
     */
    private void testTemplate(RequestInfo request){
        LOG.info("Checking request: {}", request);
        // get instance of web client
        jwtAuthClient(this.client, request.signingKey, request.user)
                .get()
                // set resource url
                .uri("/" + request.path)
                // send request
                .exchange()
                //check status
                .expectStatus()
                .isEqualTo(request.status);
    }

    /**
     * In case when we need to make request from authorized user ( user is not null)
     * this method adds to existed filter chain new filter which creates authorization header and set to request header.
     * @param client - existed web client
     * @param signingKey - secret key to sign authorization token
     * @param user - data about user
     * @return client which should be used to make request
     */
    private WebTestClient jwtAuthClient(WebTestClient client, String signingKey, User user){
        if(user == null){
            return client;
        }
        return client.mutate().filter(
                ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
                    String authorization = authorizationHeader(signingKey, user);
                    LOG.debug("Generated jwt authorization header  {}", authorization);
                    return Mono.just(
                            ClientRequest.from(clientRequest)
                                .headers(headers -> headers.set(HttpHeaders.AUTHORIZATION, authorization) )
                                .build()
                    );
                })
        ).build();
    }

    /**
     * This method creates the value of authorization header.
     * Firstly it encrypts name of user and the list of his roles and signed result by secret key
     * @param signingKey - secret key to sign authorization token
     * @param user - data about user
     * @return - value of authorization header
     */
    private String authorizationHeader(String signingKey, User user) {
        Claims claims = Jwts.claims().setSubject(user.name);
        claims.put("scopes", Arrays.asList(user.role));
        String token = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, signingKey)
                .compact();
        return "Bearer " + token;
    }

}

