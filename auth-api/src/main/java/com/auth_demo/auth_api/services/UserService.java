package com.auth_demo.auth_api.services;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth_demo.auth_api.dtos.RegisterUserDto;
import com.auth_demo.auth_api.entities.Role;
import com.auth_demo.auth_api.entities.RoleEnum;
import com.auth_demo.auth_api.entities.User;
import com.auth_demo.auth_api.repositories.RoleRepository;
import com.auth_demo.auth_api.repositories.UserRepository;

@Service
public class UserService {

	private final UserRepository userRepository;
	
	private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;
	
	public UserService(UserRepository userRepository ,RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
		this.userRepository=userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
		
	}
	
	public List<User> allUsers(){
		List<User> users= new ArrayList<>();
		
		userRepository.findAll().forEach(users::add);
		
		return users;
	}
	
	
	public User createAdministrator(RegisterUserDto input) {
		
		Optional<Role>  optionalRole = roleRepository.findByName(RoleEnum.ADMIN);
		
		if(optionalRole.isEmpty()) {
			return null;
		}
		
		var user = new User()
				.setFullName(input.getFullName())
				.setEmail(input.getEmail())
				.setPassword(passwordEncoder.encode(input.getPassword()))
				.setRole(optionalRole.get());
		
		return userRepository.save(user);
		
		
		
		
	}
	
	
}
