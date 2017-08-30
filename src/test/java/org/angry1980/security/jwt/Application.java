package org.angry1980.security.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.HttpJwtSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.BodyInserters.fromObject;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

@SpringBootApplication
@EnableWebFluxSecurity
public class Application {

    public static final String PATH_PREFIX = "api";

    public static void main(String[] args){
        SpringApplication.run(Application.class, args);
    }

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

    @Bean
    public SecurityWebFilterChain security(HttpJwtSecurity prototype){
        return prototype
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/" + PATH_PREFIX + "/**"))
                .authorizeExchange()
                    //todo: has Role
                    .pathMatchers("/*/test1").hasRole("TEST1")
                    .pathMatchers("/*/test2").hasRole("TEST2")
                    .anyExchange().authenticated()
                .and()
                .build();
    }
}
