package example.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
class SecurityServiceImpl() : SecurityService{

    @Autowired
    private lateinit var authenticationManager :AuthenticationManager;

    @Autowired
    private lateinit var userDetailsService :UserDetailsService;

    override fun isAuthenticated() :Boolean {
      var value :Boolean = true
        val authentication :Authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            value = false;
        }
        else {
          value = authentication.isAuthenticated();
        }
        return value;
    }

    override fun autoLogin(username :String, password :String) {

        val userDetails :UserDetails = userDetailsService.loadUserByUsername(username);

        val usernamePasswordAuthenticationToken =  UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

        val auth :Authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(auth);
            println("[LOG] Auto login successfully!");
        }
    }
}
