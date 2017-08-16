package org.angry1980.security.jwt;

import org.springframework.web.server.ServerWebExchange;

public class JwtUtils {

    private JwtUtils(){}

    public static String getRequestInfo(ServerWebExchange exchange){
        return exchange.getRequest().getMethod() + " " + exchange.getRequest().getURI();
    }
}
