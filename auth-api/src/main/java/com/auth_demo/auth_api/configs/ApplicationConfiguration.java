package com.auth_demo.auth_api.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.auth_demo.auth_api.repositories.UserRepository;

@Configuration
public class ApplicationConfiguration {

	//potreban je i dostupan kada configuration klasa bude instancirana, takoder koristi se pristupanje podataka User entitija
	private final UserRepository userRepository;
	
	public ApplicationConfiguration(UserRepository userRepository) {
		this.userRepository=userRepository;
	}
	
	//za loadanje podataka usera prilikom procesa autentikacije
	@Bean
	UserDetailsService userDetailsService() {
		return username -> userRepository.findByEmail(username)
				.orElseThrow(()-> new UsernameNotFoundException("User not found!"));
	}
	
	//za encodanje sifre
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		
		return config.getAuthenticationManager();
	}
	
	//za usporedbu usera i usera unutar nase baze
	@Bean
	AuthenticationProvider authenticationProvider() {
		
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		
		return authProvider;
		
	}
	
}
