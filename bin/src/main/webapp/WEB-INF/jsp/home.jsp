<!DOCTYPE HTML>
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
                    <li><a href="/">Index</a></li>
                    <li class="active"><a href="/home">Home</a></li>
                    <li><a href="/admin">Admin</a></li>
                    <li><a href="/user">User</a></li>
                    <li><a href="/super">Super</a></li>
                    <li><a href="/about">About</a></li>
                </ul>
            </div>
        </div>
    </nav>
<div class="container">

    <div class="starter-template">
        <h1>Spring Boot Web Thymeleaf + Spring Security</h1>
        <h2>1. Visit <a href="/admin">Admin page (Spring Security protected, Need Admin Role)</a></h2>
        <h2>2. Visit <a href="/user">User page (Spring Security protected, Need User Role)</a></h2>
        <h2>3. Visit <a href="/about">Normal page</a></h2>
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
