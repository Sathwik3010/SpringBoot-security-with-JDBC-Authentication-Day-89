package com.codegnan.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfigure {
	// JDBC authentication(Default Queries)
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}
	// Password Encoder
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	//Authorization Rules.
	@Bean
	public SecurityFilterChain securityFilter(HttpSecurity http) throws Exception{
		http
		.csrf(csrf->csrf.disable())
		.authorizeHttpRequests(req->req
			// public
			.requestMatchers("/").permitAll()
			// ROLE Based
			.requestMatchers("/admin").hasRole("ADMIN")
			.requestMatchers("/user").hasAnyRole("ADMIN","USER")
			.anyRequest().authenticated()
			).httpBasic(Customizer.withDefaults());
		return http.build();
	}
}

