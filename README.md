# kotlin-web-maven-spring-jsp-register-aes-encrypted-bcrypt-encode

## Description
A springboot secure web app with jsp support.
Three roles are defined; USER, ADMIN, and SUPER. All roles
can access pages `/home`, `/login`, and `/about`. Only USER
can access `/user` and ADMIN only `/admin` whereas SUPER can
navigate to either and have its own `/super`. Each role
has an action USER=VIEW ONLY, ADMIN=READ/WRITE, SUPER=CREATE.
All password are encrypted with AES and encoded with bcrypt
to insure strong passwords.

Presents a register form to create an inMemoryUser.
Once the user is created it is given the `USER` role
by default and auto logged in.

## Tech stack
- kotlin
- maven

## Docker stack
- maven:3-openjdk-17

## To run
`sudo ./install.sh -u`
Available at http://localhost
- Login with id: user and password: pass
- Login with id: admin and password: pass
- Login with id: super and password: pass

## To stop (optional)
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`

## Credits
- https://hellokoding.com/spring-security-login-logout-jsp/
- https://www.javainterviewpoint.com/spring-security-inmemoryuserdetailsmanager/
