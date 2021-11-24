package example.controller;

import example.model.User;
import example.service.UserService;
import example.service.SecurityService;

import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.stereotype.Controller;

@Controller
class RegisterController
{

  @Autowired
  private lateinit var securityService :SecurityService;

  @Autowired
  private lateinit var userService :UserService;

	@GetMapping("/register")
	fun register(model :Model) :String
	{
		model.addAttribute("userForm", User());
		return "register";
	}

  @PostMapping("/register")
  fun register(@ModelAttribute("userForm") userForm :User) :String {

      var value :String = "redirect:/user";

      userService.save(userForm);

      securityService.autoLogin(userForm.username, userForm.password);

      return value;
  }
}
