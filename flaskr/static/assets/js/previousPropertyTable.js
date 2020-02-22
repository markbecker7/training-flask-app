
displayTable();

// This dynamically populates the previously owned table
function displayTable(){
    var url = "table1/previousProperties";

     $.getJSON(url, null, function (jsonResult) {
     	if (jsonResult.length > 0){
     		for (var i = 0; i < jsonResult.length; i++ ){
            var totalBaths = jsonResult[i].bath + (jsonResult[i].half_bath * 0.5);
            $("#previousPropertyTable tbody:last").append('<tr><td style="display:none;">' + jsonResult[i].ID + '</td><td>' +
                jsonResult[i].address + '</td><td>' +
                jsonResult[i].total_beds + '</td><td>' +
                totalBaths + '</td><td>' +
                jsonResult[i].living_sq_ft.toLocaleString() + '</td><td>' +
                jsonResult[i].year_built + '</td><td>' +
                "$" + jsonResult[i].total_value.toLocaleString() + '</td><td>' +   
                jsonResult[i].zip_code + '</td><td style="display:none;">' +

                //Hidden columns
                jsonResult[i].class + '</td><td style="display:none;">' +
                jsonResult[i].land_value + '</td><td style="display:none;">' +
                jsonResult[i].bldg_value + '</td><td style="display:none;">' +
                jsonResult[i].address_city + '</td><td style="display:none;">' +
                jsonResult[i].owner + '</td><td style="display:none;">' +
                jsonResult[i].school_dist + '</td><td style="display:none;">' +
                jsonResult[i].land_sq_ft + '</td><td style="display:none;">' +
                jsonResult[i].condition + '</td><td style="display:none;">' +
                jsonResult[i].residence_type + '</td><td style="display:none;">' +
                jsonResult[i].building_style + '</td><td style="display:none;">' +
                jsonResult[i].bath + '</td><td style="display:none;">' +
                jsonResult[i].half_bath + '</td><td style="display:none;">' +
                jsonResult[i].bedrooms + '</td><td style="display:none;">' +
                jsonResult[i].basement_beds + '</td><td style="display:none;">' +
                jsonResult[i].attached_gar + '</td><td style="display:none;">' +
                jsonResult[i].price + '</td><td style="display:none;">' +
                jsonResult[i].grade + '</td><td style="display:none;">' +
                jsonResult[i].like_dislike + '</td><td>' +
                '<button type="button" data-toggle="modal" data-target=".bd-map-modal-lg" name="delete" class="mapButton btn" value="' + jsonResult[i].ID +'">Map</button' + '</td><td>' +
                '<button type="button" name="delete" class="deleteButton btn" value="' + jsonResult[i].ID +'">Delete</button' + '</td><tr>'
         		);
        	} 
            //Buttons
        	$(".mapButton").on("click", showMap);
			$(".deleteButton").on("click", deleteItem);
        } else {
        	$("#previousPropertyTable tbody:last").append('<tr><td>There are no known previous properties.</td></tr>');
        }
    });
}

// Deletes and repopulates all rows
function refreshTable() {
    $("#previousPropertyTable tbody tr").remove();
    displayTable();
}

// Displays Google Map with selected property
function showMap(e) {
    var address = e.target.parentNode.parentNode.childNodes[1].innerHTML;
    var zip_code = e.target.parentNode.parentNode.childNodes[7].innerHTML;
    var geocoder;
    var map;
    geocoder = new google.maps.Geocoder();
    var latlng = new google.maps.LatLng(-34.397, 150.644);
    var mapOptions = {
      zoom: 12,
      center: latlng
    }
    map = new google.maps.Map(document.getElementById('map'), mapOptions);
    var mapSearch = address + zip_code
    console.log(mapSearch)
    geocoder.geocode( { 'address': mapSearch}, function(results, status) {
      if (status == 'OK') {
        map.setCenter(results[0].geometry.location);
        var marker = new google.maps.Marker({
            map: map,
            position: results[0].geometry.location
        });
      } else {
        alert('Geocode was not successful for the following reason: ' + status);
      }
    });
}

// Deletes selected property from previously owned table
function deleteItem(e) {
    var address = e.target.parentNode.parentNode.childNodes[1].innerHTML;
    var zip_code = e.target.parentNode.parentNode.childNodes[7].innerHTML;
    var jsonData = {
      "address":address,
      "zip_code":zip_code,
   }

    var url = "table1/delete";

    var confirm = window.confirm("Are you sure you want to delete?");
    if(confirm){
        $.ajax({
            type: 'POST',
            url: url,
            data: JSON.stringify(jsonData),
            success: function(dataFromServer) {
                refreshTable();
            },
            contentType: "application/json",
            dataType: 'text'
        });
    }

}







