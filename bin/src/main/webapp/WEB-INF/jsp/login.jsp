<!DOCTYPE HTML>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <title>Spring Boot Thymeleaf Security Example</title>


    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css"/>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.10.23/css/jquery.dataTables.min.css"/>
</head>

<body>
  <nav class="navbar navbar-inverse">
      <div class="container">
          <div class="navbar-header">
              <a class="navbar-brand" href="/">Spring Boot</a>
          </div>
          <div id="navbar" class="collapse navbar-collapse">
              <ul class="nav navbar-nav">
                  <li class="active"><a href="/">Index</a></li>
                  <li><a href="/home">Home</a></li>
                  <li><a href="/admin">Admin</a></li>
                  <li><a href="/user">User</a></li>
                  <li><a href="/super">Super</a></li>
                  <li><a href="/about">About</a></li>
              </ul>
          </div>
      </div>
  </nav>

<div class="container">
  <div class="row" style="margin-top:20px">
          <div class="col-xs-12 col-sm-8 col-md-6 col-sm-offset-2 col-md-offset-3">
              <form:form action="/login" method="post">
                  <fieldset>
                      <h1>Please Sign In</h1>

                      <c:if test="${param.error ne null}">
                          <div class="alert alert-danger">
                              Invalid username and password.
                          </div>
                      </c:if>
                      <c:if test="${param.logout ne null}">
                          <div class="alert alert-info">
                              You have been logged out.
                          </div>
                      </c:if>

                      <div class="form-group">
                          <input type="text" name="username" id="username" class="form-control input-lg"
                                 placeholder="UserName" required="true" autofocus="true"/>
                      </div>
                      <div class="form-group">
                          <input type="password" name="password" id="password" class="form-control input-lg"
                                 placeholder="Password" required="true"/>
                      </div>
                      <div class="row">
                          <div class="col-xs-6 col-sm-6 col-md-6">
                              <input type="submit" class="btn btn-lg btn-primary btn-block" value="Sign In"/>
                          </div>
                          <div class="col-xs-6 col-sm-6 col-md-6">
                              <a href="/register" class="btn btn-lg btn-primary btn-block">Register</a>
                          </div>
                     </div>
                  </fieldset>
              </form:form>
          </div>
      </div>
</div>
<!-- /.container -->
<div class="container">
  <footer>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
  </footer>
</div>
</body>
</html>
