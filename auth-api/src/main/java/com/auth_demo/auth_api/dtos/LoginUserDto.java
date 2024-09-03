package com.auth_demo.auth_api.dtos;

public class LoginUserDto {

	private String email;
	
	private String password;
	
	public LoginUserDto() {
		super();
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	
	
}
