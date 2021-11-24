package example.config

import example.config.MySimpleUrlAuthenticationSuccessHandler
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.context.annotation.Bean

import java.util.ArrayList
import java.util.List

@Configuration
@EnableWebSecurity
class Security : WebSecurityConfigurerAdapter() {

    @Autowired
    lateinit var accessDeniedHandler :AccessDeniedHandler

    // roles admin allow to access /admin/**
    // roles user allow to access /user/**
    // custom 403 access denied handler
    @Throws(Exception::class)
    override fun configure(http :HttpSecurity) {
  		http
  			.authorizeRequests()
        .antMatchers("/user").access("hasRole('USER') or hasRole('SUPER')")
        .antMatchers("/admin").access("hasRole('ADMIN') or hasRole('SUPER')")
        .antMatchers("/super").access("hasRole('SUPER')")
  				.antMatchers("/login", "/register").permitAll()
  				.anyRequest().authenticated()
  				.and()
  			.formLogin()
  				.loginPage("/login")
          .loginProcessingUrl("/login")
          .successHandler(myAuthenticationSuccessHandler())
  				.permitAll()
    }

    @Bean
    fun myAuthenticationSuccessHandler() :AuthenticationSuccessHandler {
        return MySimpleUrlAuthenticationSuccessHandler()
    }

  	@Bean
  	fun passwordEncoder() :PasswordEncoder
  	{
  		try {
  			return example.security.AESPasswordEncoder()
  		} catch(e :Exception) {}
  		println("Using default.")
  		return org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()
  	}

    @Bean
    fun inMemoryUserDetailsManager() :InMemoryUserDetailsManager {
      return userDetailsService() as InMemoryUserDetailsManager
    }

  	override fun userDetailsService() :UserDetailsService {

      var userDetailsList = ArrayList<UserDetails>()

      userDetailsList.add(
        User.withUsername("admin")
 				  .password(passwordEncoder().encode("pass"))
          .roles("ADMIN")
          .build()
      )

      userDetailsList.add(
        User.withUsername("user")
 				  .password(passwordEncoder().encode("pass"))
          .roles("USER")
          .build()
      )

      userDetailsList.add(
        User.withUsername("super")
 				  .password(passwordEncoder().encode("pass"))
          .roles("SUPER")
          .build()
      )

      return InMemoryUserDetailsManager(userDetailsList)
  	}

    @Throws(Exception::class)
    @Bean
    override fun authenticationManagerBean() : AuthenticationManager  {
        return super.authenticationManagerBean();
    }

}
