package example.repository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;

@Repository
class UserRepositoryImpl() : UserRepository {

    @Autowired
    private lateinit var inMemoryUserDetailsManager :InMemoryUserDetailsManager;


    @Autowired
    private lateinit var passwordEncoder :PasswordEncoder;

    override fun findUserByName(name :String) :UserDetails {
        return inMemoryUserDetailsManager.loadUserByUsername(name);
    }

    override fun save(user :example.model.User) {
      val name :String = user.username;
      val password :String = user.password;

      var grantedAuthoritiesList = listOf<GrantedAuthority>();
      grantedAuthoritiesList += SimpleGrantedAuthority("ROLE_USER");

      inMemoryUserDetailsManager
      .createUser(org.springframework.security.core.userdetails.User(name, passwordEncoder.encode(password), grantedAuthoritiesList));

    }
}
