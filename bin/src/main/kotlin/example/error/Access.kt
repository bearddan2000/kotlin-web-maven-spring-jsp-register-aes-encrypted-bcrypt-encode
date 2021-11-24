package example.error

import org.apache.logging.log4j.kotlin.Logging
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.IOException

// handle 403 page
@Component
class Access : AccessDeniedHandler, Logging {

    @Throws (IOException::class, ServletException::class)
    override fun handle(httpServletRequest :HttpServletRequest,
                      httpServletResponse :HttpServletResponse,
                      _e :AccessDeniedException) {

        val auth :Authentication = SecurityContextHolder.getContext().getAuthentication()

        if (auth != null) {
            logger.info("User '" + auth.getName()
                    + "' attempted to access the protected URL: "
                    + httpServletRequest.getRequestURI())
        }

        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/403")

    }
}
