
updateTable();

// This dynamically populates the recommended properties table
function updateTable(){
    var url = "table2/recommended";

     $.getJSON(url, null, function (jsonResult) {
        for (var i = 0; i < 3; i++ ){
            var totalBaths = jsonResult[i].bath + (jsonResult[i].half_bath * 0.5);
            $("#dataTable tbody:last").append('<tr><td style="display:none;">' + jsonResult[i].ID + '</td><td>' +
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

                //Buttons
                '<button type="button" data-toggle="modal" data-target=".bd-map-modal-lg" name="mapButton" class="mapButton btn" value="' + jsonResult[i].ID +'">Map</button>' + '</td><td>' +
                '<button type="button" id="' + jsonResult[i].ID +'" name="favorite" class="favButton btn" value="' + jsonResult[i].ID +'">Add</button>' + '</td><td>' +
                '<button type="button" name="delete" class="deleteButton btn" value="' + jsonResult[i].ID +'">Delete</button' + '</td></tr>'
                );
        }
        $(".deleteButton").on("click", deleteItem);
        $(".favButton").on("click", addProperty);
        $(".mapButton").on("click", showMap);
        
    });
}

// This adds a property to the Previously owned property
function addProperty(e) {
    var ID = e.target.value;
    var target = e.target, count = +target.dataset.count;
    // toggle change the color on click from default grey to yellow based on series of 0 and 1 clicks
    target.style.backgroundColor = count === 1 ? "#999999" : '#ffeb3b';
    target.dataset.count = count === 1 ? 0 : 1;
    var address = e.target.parentNode.parentNode.childNodes[1].innerHTML;
    var total_beds = e.target.parentNode.parentNode.childNodes[2].innerHTML;
    var total_baths = e.target.parentNode.parentNode.childNodes[3].innerHTML;
    var living_sq_ft = parseInt(e.target.parentNode.parentNode.childNodes[4].innerHTML.replace(',',''));
    var year_built = e.target.parentNode.parentNode.childNodes[5].innerHTML;
    var total_value = parseInt(e.target.parentNode.parentNode.childNodes[6].innerHTML.replace(',','').replace('$',''));
    var zip_code = e.target.parentNode.parentNode.childNodes[7].innerHTML;
    var class1 = e.target.parentNode.parentNode.childNodes[8].innerHTML;
    var land_value = e.target.parentNode.parentNode.childNodes[9].innerHTML;
    var bldg_value = e.target.parentNode.parentNode.childNodes[10].innerHTML;
    var address_city = e.target.parentNode.parentNode.childNodes[11].innerHTML;
    var owner = e.target.parentNode.parentNode.childNodes[12].innerHTML;
    var school_dist = e.target.parentNode.parentNode.childNodes[13].innerHTML;
    var land_sq_ft = e.target.parentNode.parentNode.childNodes[14].innerHTML;
    var condition = e.target.parentNode.parentNode.childNodes[15].innerHTML;
    var residence_type = e.target.parentNode.parentNode.childNodes[16].innerHTML;
    var building_style = e.target.parentNode.parentNode.childNodes[17].innerHTML;

    var bath = e.target.parentNode.parentNode.childNodes[18].innerHTML;
    var half_bath = e.target.parentNode.parentNode.childNodes[19].innerHTML;
    var bedrooms = e.target.parentNode.parentNode.childNodes[20].innerHTML;
    var basement_beds = e.target.parentNode.parentNode.childNodes[21].innerHTML;
    var attached_gar = e.target.parentNode.parentNode.childNodes[22].innerHTML;
    var price = e.target.parentNode.parentNode.childNodes[23].innerHTML;
    var grade = e.target.parentNode.parentNode.childNodes[24].innerHTML;
    var like_dislike = e.target.parentNode.parentNode.childNodes[25].innerHTML;

    var jsonData = {
      "ID":ID,
      "class":class1,
      "land_value":land_value,
      "bldg_value":bldg_value,
      "total_value":total_value,
      "address":address,
      "address_city":address_city,
      "zip_code":zip_code,
      "owner":owner,
      "school_dist":school_dist,
      "land_sq_ft":land_sq_ft,
      "year_built":year_built,
      "living_sq_ft":living_sq_ft,
      "condition":condition,
      "residence_type":residence_type,
      "building_style":building_style,
      "bath":bath,
      "half_bath":half_bath,
      "bedrooms":bedrooms,
      "basement_beds":basement_beds,
      "total_beds":total_beds,
      "attached_gar":attached_gar,
      "price":price,
      "grade":grade,
      "like_dislike":like_dislike
   }

    var url = "table1/add";
    $.ajax({
        type: 'POST',
        url: url,
        data: JSON.stringify(jsonData),
        success: function(dataFromServer) {
        },
        contentType: "application/json",
        dataType: 'text'
    });
}

// Clears the recommended table and repopulates
function refreshTable() {
    $("#dataTable tbody tr").remove();
    updateTable();
}

//This is called when a delete button is pushed, adds property to model as a "disliked" property
function deleteItem(e) {
    var ID = e.target.value;
    var address = e.target.parentNode.parentNode.childNodes[1].innerHTML;
    var total_beds = e.target.parentNode.parentNode.childNodes[2].innerHTML;
    var total_baths = e.target.parentNode.parentNode.childNodes[3].innerHTML;
    var living_sq_ft = parseInt(e.target.parentNode.parentNode.childNodes[4].innerHTML.replace(',',''));
    var year_built = e.target.parentNode.parentNode.childNodes[5].innerHTML;
    var total_value = parseInt(e.target.parentNode.parentNode.childNodes[6].innerHTML.replace(',','').replace('$',''));
    var zip_code = e.target.parentNode.parentNode.childNodes[7].innerHTML;
    var class1 = e.target.parentNode.parentNode.childNodes[8].innerHTML;
    var land_value = e.target.parentNode.parentNode.childNodes[9].innerHTML;
    var bldg_value = e.target.parentNode.parentNode.childNodes[10].innerHTML;
    var address_city = e.target.parentNode.parentNode.childNodes[11].innerHTML;
    var owner = e.target.parentNode.parentNode.childNodes[12].innerHTML;
    var school_dist = e.target.parentNode.parentNode.childNodes[13].innerHTML;
    var land_sq_ft = e.target.parentNode.parentNode.childNodes[14].innerHTML;
    var condition = e.target.parentNode.parentNode.childNodes[15].innerHTML;
    var residence_type = e.target.parentNode.parentNode.childNodes[16].innerHTML;
    var building_style = e.target.parentNode.parentNode.childNodes[17].innerHTML;

    var bath = e.target.parentNode.parentNode.childNodes[18].innerHTML;
    var half_bath = e.target.parentNode.parentNode.childNodes[19].innerHTML;
    var bedrooms = e.target.parentNode.parentNode.childNodes[20].innerHTML;
    var basement_beds = e.target.parentNode.parentNode.childNodes[21].innerHTML;
    var attached_gar = e.target.parentNode.parentNode.childNodes[22].innerHTML;
    var price = e.target.parentNode.parentNode.childNodes[23].innerHTML;
    var grade = e.target.parentNode.parentNode.childNodes[24].innerHTML;
    var like_dislike = e.target.parentNode.parentNode.childNodes[25].innerHTML;

    var jsonData = {  
      "ID":ID,
      "class":class1,
      "land_value":land_value,
      "bldg_value":bldg_value,
      "total_value":total_value,
      "address":address,
      "address_city":address_city,
      "zip_code":zip_code,
      "owner":owner,
      "school_dist":school_dist,
      "land_sq_ft":land_sq_ft,
      "year_built":year_built,
      "living_sq_ft":living_sq_ft,
      "condition":condition,
      "residence_type":residence_type,
      "building_style":building_style,
      "bath":bath,
      "half_bath":half_bath,
      "bedrooms":bedrooms,
      "basement_beds":basement_beds,
      "total_beds":total_beds,
      "attached_gar":attached_gar,
      "price":price,
      "grade":grade,
      "like_dislike":like_dislike
   }

    var url = "table2/delete";

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

// This displays a Google map when the user presses the map button
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


