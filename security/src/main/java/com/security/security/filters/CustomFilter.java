package com.security.security.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class CustomFilter extends GenericFilterBean {

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain filterChain
    ) throws IOException, ServletException {
        System.out.println("Custom Filter Called");
        System.out.println("request attributes: ");
        System.out.println(servletRequest.getRequestId());
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
