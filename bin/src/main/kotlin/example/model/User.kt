package example.model;

data class User (
  var id :Long = 0
  , var username :String = ""
  , var password :String = ""
  , var role :String = "ROLE_USER"
)
