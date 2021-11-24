package example.service;
import org.springframework.stereotype.Service;

@Service
interface SecurityService {
    fun isAuthenticated() :Boolean;
    fun autoLogin(username :String, password :String);
}
