$(document).ready(function() {
  var dataSet = {
    "data":
    [
      {"id": "1", "name": "Adam", "action": ""},
      {"id": "2", "name": "Bary", "action": ""},
      {"id": "3", "name": "Cody", "action": ""},
      {"id": "4", "name": "David", "action": ""},
      {"id": "5", "name": "Eric", "action": ""}
    ]
  };


var data = jQuery.map(dataSet.data, function(el, i) {
  return [[el.id, el.name, el.action]];
});

    var table = $('#example').DataTable( {
        aaData: data,
        aoColumns: [
            { "sTitle": "id" },
            { "sTitle": "name" }
        ]
    } );
} );
