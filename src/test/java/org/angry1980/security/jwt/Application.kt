package org.angry1980.security.jwt

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.HttpJwtSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse

import org.springframework.web.reactive.function.BodyInserters.fromObject
import org.springframework.web.reactive.function.server.HandlerFunction
import org.springframework.web.reactive.function.server.RequestPredicates.path
import org.springframework.web.reactive.function.server.RouterFunctions.nest
import org.springframework.web.reactive.function.server.RouterFunctions.route
import org.springframework.web.reactive.function.server.ServerResponse.ok

val PATH_PREFIX = "api"

fun main(args: Array<String>) {
    SpringApplication.run(Application::class.java, *args)
}

/**
 *  Application which is created for test purpose.
 *  It has handlers for three different request paths.
 *  Two of them require special permission.
 *  Last one should be acceptable for all authenticated users.
 */
@SpringBootApplication
@EnableWebFluxSecurity
class Application {

    @Bean
    fun router(): RouterFunction<ServerResponse> {
        return nest(
                path("/$PATH_PREFIX"),
                route<ServerResponse>(
                        path("/test1"), HandlerFunction { ok().body(fromObject("test1")) }
                ).andRoute(
                        path("/test2"), HandlerFunction { ok().body(fromObject("test2")) }
                ).andRoute(
                        path("/test3"), HandlerFunction { ok().body(fromObject("test3")) }
                )
        )
    }

    @Bean
    fun security(prototype: HttpJwtSecurity): SecurityWebFilterChain {
        return prototype
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/$PATH_PREFIX/**"))
                .authorizeExchange()
                .pathMatchers("/*/test1").hasRole("TEST1")
                .pathMatchers("/*/test2").hasRole("TEST2")
                .anyExchange().authenticated()
                .and()
                .build()
    }

}
