package fr.fb.Api_Authentication.dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import fr.fb.Api_Authentication.persistence.User;

@Component
public interface UserDao extends JpaRepository<User, Long>{
	
	public Optional<User> findByEmail(String email);
	UserDetails findUserByEmail(String email);

}
