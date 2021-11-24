package example.controller;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class UserRestController
{
	@Autowired
	private lateinit var inMemoryUserDetailsManager :InMemoryUserDetailsManager;

	@Autowired
	private lateinit var passwordEncoder :PasswordEncoder;

	@GetMapping("/person/{username}")
	fun checkIfUserExists(@PathVariable("username") username :String) : String
	{
		val flag :Boolean = inMemoryUserDetailsManager.userExists(username);
		if (flag)
			return "\""+username + "\" exist in InMemoryUserDetailsManager";
		else
			return "redirect:/";
	}

	@GetMapping("/person/create/{username}/{password}/{role}")
	fun createUser(@PathVariable("username") username :String, @PathVariable("password") password :String,
			@PathVariable("role") role :String) :String
	{

		var grantedAuthoritiesList = listOf<GrantedAuthority>();
		grantedAuthoritiesList += SimpleGrantedAuthority(role);

		inMemoryUserDetailsManager.createUser(User(username, passwordEncoder.encode(password), grantedAuthoritiesList));

		return checkIfUserExists(username);
	}

}
