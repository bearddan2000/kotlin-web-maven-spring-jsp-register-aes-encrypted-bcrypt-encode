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
var update = "<button type='button' class='btn btn-success upd'>UPDATE</button>";

    var table = $('#example').DataTable( {
        aaData: data,
        aoColumns: [
            { "sTitle": "id" },
            { "sTitle": "name" },
            { "sTitle": "action" }
        ],
        columnDefs: [ {
            "targets": -1,
            "data": null,
            "defaultContent": update
          }]
    } );

    // reg update buttons
    actionClick(table);
} );

function actionClick(table) {

  // finds row index based on id column
  function getIndex(data) {
    return table
      .rows()
      .indexes()
      .filter( function ( value, index ) {
        var cmp = "" + data[0];
        return cmp === table.row(value).data()[0];
      } );
  }


  $('.upd').click( function () {
   var data = table.row( $(this).parents('tr') ).data();
   modalInit('Update User', data[1], '#userUpdate', '#userCreate');
   $('#userUpdate').click( function () {
     const mData = modalData();
     var indexes = getIndex(data);

     var newData = [data[0], mData, ""];
     table.row(indexes).data(newData).draw();

     // call b/c when table data redraws it replaces old row
     actionClick(table);
   } );
  } );
}
