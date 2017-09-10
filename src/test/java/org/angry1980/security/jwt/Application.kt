package org.angry1980.security.jwt

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.HttpJwtSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.reactive.function.server.HandlerFunction
import org.springframework.web.reactive.function.server.RouterFunction

import org.springframework.web.reactive.function.BodyInserters.fromObject
import org.springframework.web.reactive.function.server.ServerResponse.ok
import org.springframework.web.reactive.function.server.router

/**
 * Path prefix which allows to group requests and define common rules
 */
val PATH_PREFIX = "api"

fun main(args: Array<String>) {
    SpringApplication.run(Application::class.java, *args)
}

/**
 * Application which is created for test purpose.
 */
@SpringBootApplication
@EnableWebFluxSecurity
class Application {

    /**
     * Definition of request mapping
     * @return spring [router function][RouterFunction]
     * which is used to route requests to [handler function][HandlerFunction]
     */
    @Bean
    fun applicationRouter() = router {
        path("/$PATH_PREFIX").nest {
            GET("/test1") { ok().body(fromObject("test1")) }
            GET("/test2") { ok().body(fromObject("test2")) }
            GET("/test3") { ok().body(fromObject("test3")) }
        }
    }

    /**
     * Definition of security permissions
     * @param prototype - builder which has been already linked with all components common for different resources
     * @return [web filter chain][SecurityWebFilterChain] for our application
     */
    @Bean
    fun security(prototype: HttpJwtSecurity) = prototype
            .apply {
                // rules are actual only for requests with our prefix in path
                securityMatcher = ServerWebExchangeMatchers.pathMatchers("/$PATH_PREFIX/**")
                authorizeExchangeBuilder
                        // test1 is acceptable for users with role TEST1 only
                        .pathMatchers("/*/test1").hasRole("TEST1")
                        // test2 is acceptable for users with role TEST2 only
                        .pathMatchers("/*/test2").hasRole("TEST2")
                        // test3 is acceptable for any authenticated user
                        .anyExchange().authenticated()
            }.build()

}
