package com.auth_demo.auth_api.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth_demo.auth_api.entities.User;
import com.auth_demo.auth_api.services.UserService;

@RequestMapping("/users")
@RestController
public class UserController {

	private final UserService userService;
	
	public UserController(UserService userService) {
		this.userService=userService;
	}
	
	@GetMapping("/me")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<User> authenticatedUser(){
		
		Authentication authentication= SecurityContextHolder.getContext().getAuthentication();
		
		User currentUser = (User)authentication.getPrincipal();
		
		return ResponseEntity.ok(currentUser);
		
	}
	
	@GetMapping("/")
	@PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
	public ResponseEntity<List<User>> allUsers(){
		
		
		List<User> users = userService.allUsers();
		
		return ResponseEntity.ok(users);
		
	}
	
	@DeleteMapping("/user/{userId}")
	@PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
	public ResponseEntity<Void> deleteUser(@PathVariable Integer userId){
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
        User currentUser = (User) authentication.getPrincipal();
		
        if (currentUser.getId().equals(userId)) {
            return ResponseEntity.status(403).build();
        }
        
		userService.deleteUserById(userId);
		
		return ResponseEntity.noContent().build();
		
		
	}
	
}
