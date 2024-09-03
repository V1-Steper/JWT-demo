/*
 * Custom filter u aplikaciji koji presjeca dolazeći HTTP zahtjev 
 * kako bi provjerio prisutnost validnog JWT u Authorizacijskom headeru
 * 
 * Ako je JWT pronađen, filter izvlaci username
 * loada user details i postavlja usera kao autenticiranog u kontekstu securitija
*/


package com.auth_demo.auth_api.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import com.auth_demo.auth_api.services.JwtService;

import java.io.IOException;

//OncePerRequestFilter garantira samo jedno izvršenje po requestu
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	//interface za resolvanje exceptiona
    private final HandlerExceptionResolver handlerExceptionResolver;

    //za metode poput generiranja tokena, validacije itd.
    private final JwtService jwtService;
    
    //za loadanje podataka pomocu username
    private final UserDetailsService userDetailsService;

    //za dohvacanje potrebnih stvari za filter
    public JwtAuthenticationFilter(
        JwtService jwtService,
        UserDetailsService userDetailsService,
        HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
    	
    	//izvlaci JWT iz Requesta
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
        	
        	//miće Bearer prefiks i hvata samo token
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);

            //Provjerava jel ima vec authenticiran user
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (userEmail != null && authentication == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                //provjerava jel token istekao ili je poremecen
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    }
}