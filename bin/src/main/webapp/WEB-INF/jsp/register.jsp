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

  <form:form method="POST" class="form-signin" modelAttribute="userForm" action="/register">
    <h2 class="form-signin-heading">Create your account</h2>
    <div class="form-group">
        <input type="text" name="username" class="form-control" placeholder="Username" autofocus="true"/>
    </div>

    <div class="form-group">
        <input type="password" name="password" class="form-control" placeholder="Password"/>
    </div>

    <button class="btn btn-lg btn-primary btn-block" type="submit">Submit</button>
  </form:form>
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
