package com.auth_demo.auth_api.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.auth_demo.auth_api.entities.Role;
import com.auth_demo.auth_api.entities.RoleEnum;

@Repository
public interface RoleRepository extends CrudRepository<Role, Integer> {

	Optional<Role> findByName(RoleEnum name);
	
}
