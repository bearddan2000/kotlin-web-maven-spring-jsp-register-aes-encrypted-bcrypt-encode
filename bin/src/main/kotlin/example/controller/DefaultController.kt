package example.controller

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.stereotype.Controller

@Controller
class DefaultController {

  @GetMapping("/")
  fun home1(): String {
      return "/home"
  }

  @GetMapping("/home")
  fun home(): String {
      return "/home"
  }

  @GetMapping("/admin")
  fun admin(): String {
      return "/admin"
  }

  @GetMapping("/super")
  fun super1(): String {
      return "/super"
  }

  @GetMapping("/user")
  fun user(): String {
      return "/user"
  }

  @GetMapping("/about")
  fun about(): String {
      return "/about"
  }

  @GetMapping("/login")
  fun login(): String {
      return "/login"
  }

  @GetMapping("/logout")
  fun logout(): String {
    SecurityContextHolder.getContext().setAuthentication(null);
    return "/login"
  }

  @GetMapping("/403")
  fun error403(): String {
      return "/error/403"
  }
}
