package example.repository;

import example.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository("userRepository")
interface UserRepository {
    fun findUserByName(name :String) :UserDetails;
    fun save(user :User);
}
