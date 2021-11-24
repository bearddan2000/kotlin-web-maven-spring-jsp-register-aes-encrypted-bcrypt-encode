package example.config

import java.io.IOException
import java.util.Collection
import java.util.HashMap
import java.util.Map

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.WebAttributes
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

open class MySimpleUrlAuthenticationSuccessHandler : AuthenticationSuccessHandler {

  @Throws(IOException::class)
  override fun onAuthenticationSuccess(request :HttpServletRequest, response :HttpServletResponse, authentication :Authentication) {
      // run custom logics upon successful login

      handle(request, response, authentication)
      clearAuthenticationAttributes(request)
  }

  @Throws(IOException::class)
  fun handle(request :HttpServletRequest, response :HttpServletResponse, authentication :Authentication) {
      val targetUrl = determineTargetUrl(authentication)

      if (request == null) {
        return
      } else if (response == null) {
        return
      }

      val redirectStrategy :RedirectStrategy = DefaultRedirectStrategy()

      if (response.isCommitted()) {
          println("Response has already been committed. Unable to redirect to ${targetUrl}")
          return
      }

      redirectStrategy.sendRedirect(request, response, targetUrl)
  }

  fun determineTargetUrl(authentication :Authentication) :String? {
    if (authentication == null) {
      return "/"
    }
      var roleTargetUrlMap = HashMap<String, String>()
      roleTargetUrlMap.put("ROLE_USER", "/user")
      roleTargetUrlMap.put("ROLE_ADMIN", "/admin")
      roleTargetUrlMap.put("ROLE_SUPER", "/super")

      authentication.getAuthorities().forEach {
          grantedAuthority :GrantedAuthority? ->
          if(grantedAuthority != null)
          {
            val authorityName :String? = grantedAuthority.getAuthority()
            if(authorityName != null)
            {
              if(roleTargetUrlMap.containsKey(authorityName)) {
                    return roleTargetUrlMap.get(authorityName)
              }
            }
          }
      }

      return "/"
  }

  /**
   * Removes temporary authentication-related data which may have been stored in the session
   * during the authentication process.
   */
  fun clearAuthenticationAttributes(request :HttpServletRequest) {

      val session = request.getSession(false)

      if (session == null) {
          return
      }

      session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
  }
}
