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
var len = data.length+1;
var update = "<button type='button' class='btn btn-success upd'>UPDATE</button>";
var del = "<button type='button' class='btn btn-danger del'>DELETE</button>";

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
            "defaultContent": update+del
          }]
    } );
    $('#create').click( function () {
      modalInit('Create New User', 'new', '#userCreate', '#userUpdate')
      $('#userCreate').click( function () {
        const mData = modalData();

        var text= {"data": [{"id": "" + len, "name": mData, "action":""}]};
        data = jQuery.map(text.data, function(el, i) {
          return [[el.id, el.name, el.action]];
        });
        table.rows.add(data).draw();

        // call b/c when table adds rows button clicks aren't reg
        actionClick(table);
        len++;
      } );
    } );

    // reg delete and update buttons
    actionClick(table);
} );

function modalInit(title, oldData, show, hide) {
  $(".modal-title").text(title);

  $("#userName").val('');
  $("#userName").attr("placeholder", oldData);

  $(show).show();
  $(hide).hide();

  $("#myModal").modal('show');
}

function modalData() {
  // insure we never have blanks
  var mData = $("#userName").val();
  mData = (mData === '') ? $("#userName").attr("placeholder") : mData;
  return mData;
}

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

  $('.del').click( function () {
    var data = table.row( $(this).parents('tr') ).data();

    var indexes = getIndex(data);

   table.rows(indexes).remove().draw();
  } );

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
