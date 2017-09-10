package org.angry1980.security.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.HttpJwtSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.BodyInserters.fromObject;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

/**
 *  Application which is created for test purpose.
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class Application {

    /**
     * Path prefix which allows to group requests and define common rules
     */
    public static final String PATH_PREFIX = "api";

    public static void main(String[] args){
        SpringApplication.run(Application.class, args);
    }

    /**
     * Definition of request mapping
     * @return spring {@linkplain RouterFunction router function}
     * which is used to route requests to {@linkplain HandlerFunction handler function}
     */
    @Bean
    public RouterFunction<ServerResponse> router(){
        return nest(
                path("/" + PATH_PREFIX),
                route(
                    path("/test1"), request -> ok().body(fromObject("test1"))
                ).andRoute(
                    path("/test2"), request -> ok().body(fromObject("test2"))
                ).andRoute(
                    path("/test3"), request -> ok().body(fromObject("test3"))
                )
        );
    }

    /**
     * Definition of security permissions
     * @param prototype - builder which has been already linked with all components common for different resources
     * @return {@linkplain SecurityWebFilterChain web filter chain} for our application
     */
    @Bean
    public SecurityWebFilterChain security(HttpJwtSecurity prototype){
        return prototype
                // rules are actual only for requests with our prefix in path
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/" + PATH_PREFIX + "/**"))
                .authorizeExchange()
                    // test1 is acceptable for users with role TEST1 only
                    .pathMatchers("/*/test1").hasRole("TEST1")
                    // test2 is acceptable for users with role TEST2 only
                    .pathMatchers("/*/test2").hasRole("TEST2")
                    // test3 is acceptable for any authenticated user
                    .anyExchange().authenticated()
                .and()
                .build();
    }
}
