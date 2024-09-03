package com.auth_demo.auth_api.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
	
	//string koji predstavlja secret key koji se nalazi u application.prop
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    //predstavlja vrijeme trajanja JWT
    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    //izvlaci user name iz tokena
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    //za izvlacenje claima iz tokena
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //generiranje tokena za usera sa default claimom
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }
    
    //generira token sa ekstra claimovima 
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    	
    	// poziva buildera za token
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }
    
    //vraca vrijeme isteka tokena
    public long getExpirationTime() {
        return jwtExpiration;
    }
    
    //logika za stvaranje tokena
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder() //koristi za konstruiranje tokena
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //validira ispravnost tokena
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    //validira jel token aktualan
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //ekstrakta vrijeme isteka tokena iz tokena
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //izvlaci sve claimove iz tokena
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //vraca signing key za signanje JWT tokena
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
