package example.service;

import example.model.User;
import example.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
class UserServiceImpl : UserService {

    @Autowired
    private lateinit var userRepository :UserRepository;

    override fun save(user :User) {
        user.role = "ROLE_USER";
        userRepository.save(user);
        println("[LOG] user saved");
    }

    override fun findByUsername(username :String) : UserDetails {
        return userRepository.findUserByName(username);
    }
}
