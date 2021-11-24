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
                  <li><a href="/home">Home</a></li>
                  <li class="active"><a href="/admin">Admin</a></li>
                  <li><a href="/user">User</a></li>
                  <li><a href="/super">Super</a></li>
                  <li><a href="/about">About</a></li>
              </ul>
          </div>
      </div>
  </nav>

<div class="container">

    <table id="example" class="display" width="100%">
    <thead>
      <th>Id</th>
      <th>Name</th>
      <th>Action</th>
    </thead>
    </table>
  <!-- Modal -->
  <div id="myModal" class="modal fade" role="dialog">
    <div class="modal-dialog">

      <!-- Modal content-->
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal">&times;</button>
          <h4 class="modal-title">Modal Header</h4>
        </div>
        <div class="modal-body">
          <label for="userName">Name</label>
          <input type="text" name="userName" id="userName" value="" placeholder="">
        </div>
        <div class="modal-footer">
          <button id="userCreate" type="button" class="btn btn-primary" data-dismiss="modal">Create</button>
          <button id="userUpdate" type="button" class="btn btn-primary" data-dismiss="modal">Update</button>
            <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>

    </div>
  </div>

</div>
<!-- /.container -->
<div class="container">
  <footer>
    <form action="/logout" method="get">
        <input type="submit" value="Sign Out"/>
    </form>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
    <script src="https://cdn.datatables.net/1.10.23/js/jquery.dataTables.min.js" charset="utf-8"></script>
  </footer>
</div>
<script src="js/admin.js" charset="utf-8"></script>
</body>
</html>
