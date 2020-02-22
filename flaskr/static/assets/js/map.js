// Put your zillow.com API key here
var zwsid = "X1-ZWz17w5odsr5l7_2rqd6";

// Initializing variables
var request = new XMLHttpRequest();
var new_request = new XMLHttpRequest();
var geocoder;
var map;
var postal;
var for_Zilla;
var estimate;
var infowindow;
var infowindow2;
var new_content;
var marker;
var lat_lon;
var reverse_address;
var zilla_reverse;
var for_Zilla2;
var new_content2;



// Send data from index to property-single
function sendData(){
  var bedrooms = document.getElementById("bedrooms").value;
  var bathrooms = document.getElementById("bathrooms").value;
  var squareFeet = document.getElementById("sqft").value;
  var yearBuilt = document.getElementById("yearBuilt").value;
  var zip = document.getElementById("zipName").value;

  localStorage["bedrooms"] = bedrooms;
  localStorage["bathrooms"] = bathrooms;
  localStorage["squareFeet"] = squareFeet;
  localStorage["yearBuilt"] = yearBuilt;
  localStorage["zip"] = zip;
}

// Retrieve data from index to property-single, connecting APIS, and updating UI
function sendRequest() {
  // Retrieve data from index to property-single
     var bedrooms = localStorage["bedrooms"];
     var bathrooms = localStorage["bathrooms"];
     var squareFeet = localStorage["squareFeet"];
     var yearBuilt = localStorage["yearBuilt"];
     var zip = localStorage["zip"];
  
     document.getElementById("bedsSummary").innerHTML = bedrooms;
     document.getElementById("bathsSummary").innerHTML = bathrooms;
     document.getElementById("yearBuiltSummary").innerHTML = yearBuilt;
     document.getElementById("zipSummary").innerHTML = zip;
     document.getElementById("areaSummary").innerHTML = squareFeet + "sqft";

    // Populate address fields 
    // var addr = address + " " + city + " " + state + " " + zip;
    var addr = zip 
    // document.getElementById("addressHeader").innerHTML = addr;
    // document.getElementById("addressContent").innerHTML = addr;


    // Google map initialization 
    geocoder = new google.maps.Geocoder();
    var latlng = new google.maps.LatLng(41.589830, -93.786110);
    var mapOptions = {
    zoom: 11,
    center: latlng
    }
    map = new google.maps.Map(document.getElementById("map"), mapOptions);
    geocoder.geocode( { 'address': addr}, function(results, status) {
        if (status == google.maps.GeocoderStatus.OK) {

            postal = results[0].formatted_address
            map.setCenter(results[0].geometry.location);
            // if marker is a google address, make a marker based on location
            if (marker) {
                marker.setPosition(results[0].geometry.location);
            }
            else {
                marker = new google.maps.Marker({
                map: map,
                position: results[0].geometry.location
                });}
            // info used by Zillow API 
            // seperate the address into components used by zilla (address, city, state, zip)
            for_Zilla = postal.split(",")
            // make PHP zillow API request
            request.open("GET","proxy2.php?zws-id="+zwsid+"&address="+for_Zilla[0]+"&citystatezip="+for_Zilla[1]+"+"+for_Zilla[2]+"+"+for_Zilla[3]);
            request.onreadystatechange = function(){
                // parse Zillow response XML
                var xml = request.responseXML.documentElement;
                var value = xml.getElementsByTagName("zestimate")[0].getElementsByTagName("amount")[0].innerHTML;

                value = parseFloat(value).toLocaleString('en');
                document.getElementById("zillowEstimateHeader").innerHTML=value;

                var type = xml.getElementsByTagName("useCode")[0].innerHTML;
                var area = xml.getElementsByTagName("finishedSqFt")[0].innerHTML;
                var bath = xml.getElementsByTagName("bathrooms")[0].innerHTML;
                var bed = xml.getElementsByTagName("bedrooms")[0].innerHTML;

                //Populate Zillow Fields
                document.getElementById("zillowEstimateType").innerHTML = type;
                document.getElementById("zillowEstimateArea").innerHTML = area + "sqft";
                document.getElementById("zillowEstimateBed").innerHTML = bed;
                document.getElementById("zillowEstimateBath").innerHTML = bath;
                document.getElementById("zilla").innerHTML += postal+" "+value+"<br>";
                new_content = infowindow.getContent();
                infowindow.setContent(new_content+value);
            }
            // validate that the URL request has the paramaters of zwsid and addr
            request.withCredentials = "true";
            request.send(null);

            infowindow = new google.maps.InfoWindow({
                content:postal
            });
            // put marker on map
            infowindow.open(map, marker);
            google.maps.event.addListener(map, 'click', function(event) {
                oneMarker(event.latLng);
                lat_lon = event.latLng
            });
        } else {
            alert("Geocode was not successful for the following reason: " + status);
        }
    });
}


// JSON Data
var data = [{
  "ID": 1,
  "district_parcel": "120/04472-147-001",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=12004472147001&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 29300,
  "bldg_value": 153800,
  "total_value": 183100,
  "address": "1 E EMMA AVE",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "DANG, THANH THI T",
  "school_dist": 1,
  "land_sq_ft": 13320,
  "year_built": 1969,
  "living _sq_ft": 1891,
  "condition": "Normal",
  "residence_type": "Split Foyer",
  "building _style": "Split Foyer",
  "bath": 2,
  "half_bath": 0,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 0,
  "last_sale_date": "7/26/99",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=12004472147001&amp;yymm=9907&amp;book=8285&amp;pg=446&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$65,000 ",
  "grade": "04-05",
  "prediction": 205962
},
{
  "ID": 2,
  "district_parcel": "010/01574-000-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=01001574000000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 16000,
  "bldg_value": 99200,
  "total_value": 115200,
  "address": "1 E PLEASANT VIEW DR ",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "RAMOS, AMARILDO",
  "school_dist": 1,
  "land_sq_ft": 9000,
  "year_built": 1955,
  "living _sq_ft": 1291,
  "condition": "Above Normal",
  "residence_type": "1s Fin Attic",
  "building _style": "Conventional",
  "bath": 1,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 0,
  "last_sale_date": "3/31/98",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=01001574000000&amp;yymm=9803&amp;book=7868&amp;pg=612&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$80,000 ",
  "grade": "4+05",
  "prediction": 129584
},
{
  "ID": 3,
  "district_parcel": "090/03803-002-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09003803002000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 124900,
  "bldg_value": 415200,
  "total_value": 540100,
  "address": "1 SW 51ST ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "BRANSTAD, ERIC",
  "school_dist": 1,
  "land_sq_ft": 58165,
  "year_built": 1961,
  "living _sq_ft": 2099,
  "condition": "Very Good",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 4,
  "half_bath": 1,
  "bedrooms": 5,
  "basement_beds": null,
  "total_beds": 5,
  "attached_gar": 456,
  "last_sale_date": "2/11/15",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09003803002000&amp;yymm=1502&amp;book=15475&amp;pg=429&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$447,500 ",
  "grade": "03-05",
  "prediction": 607539
},
{
  "ID": 4,
  "district_parcel": "090/07117-009-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09007117009000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 233800,
  "bldg_value": 801100,
  "total_value": 1034900,
  "address": "1 SW 56TH ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "THOMPSON, JEFFREY S",
  "school_dist": 1,
  "land_sq_ft": 128937,
  "year_built": 1965,
  "living _sq_ft": 4437,
  "condition": "Very Good",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 5,
  "half_bath": 2,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 784,
  "last_sale_date": "9/25/08",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09007117009000&amp;yymm=809&amp;book=12788&amp;pg=855&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$950,000 ",
  "grade": "03-05",
  "prediction": 1086645
},
{
  "ID": 5,
  "district_parcel": "090/07117-028-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09007117028000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 174700,
  "bldg_value": 529900,
  "total_value": 704600,
  "address": "10 52ND ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "OSWALD, TIMOTHY J",
  "school_dist": 1,
  "land_sq_ft": 31150,
  "year_built": 1996,
  "living _sq_ft": 3342,
  "condition": "Above Normal",
  "residence_type": "2 Story Plus",
  "building _style": "Conventional",
  "bath": 3,
  "half_bath": 1,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 787,
  "last_sale_date": "5/16/95",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09007117028000&amp;yymm=9505&amp;book=7194&amp;pg=175&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$102,000 ",
  "grade": "05-10",
  "prediction": 792579
},
{
  "ID": 6,
  "district_parcel": "010/01431-001-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=01001431001000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 17500,
  "bldg_value": 88100,
  "total_value": 105600,
  "address": "10 E BELL AVE ",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "KIRKMAN, JULIA",
  "school_dist": 1,
  "land_sq_ft": 10575,
  "year_built": 1952,
  "living _sq_ft": 768,
  "condition": "Above Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 1,
  "half_bath": 0,
  "bedrooms": 2,
  "basement_beds": null,
  "total_beds": 2,
  "attached_gar": 0,
  "last_sale_date": "11/11/16",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=01001431001000&amp;yymm=1611&amp;book=16280&amp;pg=876&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$115,000 ",
  "grade": "06-10",
  "prediction": 110880
},
{
  "ID": 7,
  "district_parcel": "010/04100-003-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=01004100003000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 16900,
  "bldg_value": 91100,
  "total_value": 108000,
  "address": "10 E CRESTON AVE ",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "SEREG, CHARLES E",
  "school_dist": 1,
  "land_sq_ft": 9000,
  "year_built": 1959,
  "living _sq_ft": 876,
  "condition": "Above Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 1,
  "half_bath": 0,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 0,
  "last_sale_date": "11/1/07",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=01004100003000&amp;yymm=711&amp;book=12436&amp;pg=440&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$75,000 ",
  "grade": "5+00",
  "prediction": 113400
},
{
  "ID": 8,
  "district_parcel": "120/04472-035-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=12004472035000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 26800,
  "bldg_value": 121200,
  "total_value": 148000,
  "address": "10 E MAXWELTON DR ",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "KALINA, TYLER J",
  "school_dist": 1,
  "land_sq_ft": 7680,
  "year_built": 1968,
  "living _sq_ft": 1192,
  "condition": "Above Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 1,
  "half_bath": 0,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 0,
  "last_sale_date": "12/22/16",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=12004472035000&amp;yymm=1612&amp;book=16336&amp;pg=373&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$115,000 ",
  "grade": "5+00",
  "prediction": 155400
},
{
  "ID": 9,
  "district_parcel": "010/01576-000-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=01001576000000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 21700,
  "bldg_value": 126900,
  "total_value": 148600,
  "address": "10 E PARK AVE ",
  "address_city": "DES MOINES",
  "zip_code": 50315,
  "owner": "ASW SOLUTIONS LLC",
  "school_dist": 1,
  "land_sq_ft": 23175,
  "year_built": 1980,
  "living _sq_ft": 922,
  "condition": "Normal",
  "residence_type": "Split Foyer",
  "building _style": "Split Foyer",
  "bath": 2,
  "half_bath": 0,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 0,
  "last_sale_date": "10/27/17",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=01001576000000&amp;yymm=1710&amp;book=16706&amp;pg=206&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$135,000 ",
  "grade": "6+00",
  "prediction": 156030
},
{
  "ID": 10,
  "district_parcel": "180/01000-010-001",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=18001000010001&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 67600,
  "bldg_value": 158100,
  "total_value": 225700,
  "address": "10 NE 70TH PL ",
  "address_city": "ANKENY",
  "zip_code": 50023,
  "owner": "JELSMA, GWEN K",
  "school_dist": 6,
  "land_sq_ft": 51700,
  "year_built": 1976,
  "living _sq_ft": 1392,
  "condition": "Normal",
  "residence_type": "Split Level",
  "building _style": "4 Split",
  "bath": 2,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 576,
  "last_sale_date": "5/7/15",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=18001000010001&amp;yymm=1505&amp;book=15569&amp;pg=778&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$195,000 ",
  "grade": "4+05",
  "prediction": 236985
},
{
  "ID": 11,
  "district_parcel": "231/00221-422-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=23100221422000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 35800,
  "bldg_value": 109000,
  "total_value": 144800,
  "address": "100 10TH ST SE ",
  "address_city": "BONDURANT",
  "zip_code": 50035,
  "owner": "ROBERTS, ANGELA L",
  "school_dist": 4,
  "land_sq_ft": 14157,
  "year_built": 1988,
  "living _sq_ft": 857,
  "condition": "Above Normal",
  "residence_type": "Split Level",
  "building _style": "3 Split",
  "bath": 1,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 460,
  "last_sale_date": "8/30/10",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=23100221422000&amp;yymm=1008&amp;book=13562&amp;pg=525&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$97,000 ",
  "grade": "4+05",
  "prediction": 152040
},
{
  "ID": 12,
  "district_parcel": "171/00360-932-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=17100360932000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 58200,
  "bldg_value": 149800,
  "total_value": 208000,
  "address": "100 21ST ST SW ",
  "address_city": "ALTOONA",
  "zip_code": 50009,
  "owner": "MCNICHOLS, COLBY A",
  "school_dist": 3,
  "land_sq_ft": 15008,
  "year_built": 2009,
  "living _sq_ft": 1262,
  "condition": "Normal",
  "residence_type": "Split Foyer",
  "building _style": "Split Foyer",
  "bath": 2,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 594,
  "last_sale_date": "4/29/10",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=17100360932000&amp;yymm=1004&amp;book=13451&amp;pg=70&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$170,000 ",
  "grade": "4+05",
  "prediction": 218400
},
{
  "ID": 13,
  "district_parcel": "090/04190-004-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09004190004000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 95300,
  "bldg_value": 285600,
  "total_value": 380900,
  "address": "100 30TH ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "MCKELFRESH, BENJAMIN D",
  "school_dist": 1,
  "land_sq_ft": 22690,
  "year_built": 1972,
  "living _sq_ft": 1964,
  "condition": "Normal",
  "residence_type": "Split Level",
  "building _style": "4 Split",
  "bath": 3,
  "half_bath": 0,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 480,
  "last_sale_date": "7/13/15",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09004190004000&amp;yymm=1507&amp;book=15663&amp;pg=544&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$310,000 ",
  "grade": "4+05",
  "prediction": 399945
},
{
  "ID": 14,
  "district_parcel": "090/03797-000-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09003797000000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 79700,
  "bldg_value": 333700,
  "total_value": 413400,
  "address": "100 35TH ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "LAKSHMINARAYANAN, SRIRAM",
  "school_dist": 1,
  "land_sq_ft": 17900,
  "year_built": 1954,
  "living _sq_ft": 1782,
  "condition": "Above Normal",
  "residence_type": "2 Story Plus",
  "building _style": "Contemporary",
  "bath": 3,
  "half_bath": 1,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 624,
  "last_sale_date": "9/24/14",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09003797000000&amp;yymm=1409&amp;book=15336&amp;pg=578&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$404,500 ",
  "grade": "4+05",
  "prediction": 434070
},
{
  "ID": 15,
  "district_parcel": "231/00225-015-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=23100225015000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 37400,
  "bldg_value": 188500,
  "total_value": 225900,
  "address": "100 3RD ST NE ",
  "address_city": "BONDURANT",
  "zip_code": 50035,
  "owner": "BROWN, NEDD R",
  "school_dist": 4,
  "land_sq_ft": 12356,
  "year_built": 1970,
  "living _sq_ft": 1326,
  "condition": "Above Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 1,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 528,
  "last_sale_date": "10/3/18",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=23100225015000&amp;yymm=1810&amp;book=17103&amp;pg=697&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$200,000 ",
  "grade": "5+05",
  "prediction": 237195
},
{
  "ID": 16,
  "district_parcel": "171/00202-000-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=17100202000000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 32200,
  "bldg_value": 120200,
  "total_value": 152400,
  "address": "100 4TH AVE SE ",
  "address_city": "ALTOONA",
  "zip_code": 50009,
  "owner": "PENMAN, MELISSA",
  "school_dist": 3,
  "land_sq_ft": 8712,
  "year_built": 1983,
  "living _sq_ft": 1247,
  "condition": "Normal",
  "residence_type": "1s Fin Attic",
  "building _style": "Conventional",
  "bath": 1,
  "half_bath": 2,
  "bedrooms": 1,
  "basement_beds": null,
  "total_beds": 1,
  "attached_gar": 0,
  "last_sale_date": "6/8/18",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=17100202000000&amp;yymm=1806&amp;book=16959&amp;pg=906&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$150,000 ",
  "grade": "06-10",
  "prediction": 160020
},
{
  "ID": 17,
  "district_parcel": "231/00226-014-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=23100226014000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 38900,
  "bldg_value": 130700,
  "total_value": 169600,
  "address": "100 4TH ST NE ",
  "address_city": "BONDURANT",
  "zip_code": 50035,
  "owner": "DOOLEY, DELL A",
  "school_dist": 4,
  "land_sq_ft": 14331,
  "year_built": 1972,
  "living _sq_ft": 1040,
  "condition": "Above Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 1,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 0,
  "last_sale_date": "3/26/05",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=23100226014000&amp;yymm=503&amp;book=10999&amp;pg=951&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$135,000 ",
  "grade": "6+00",
  "prediction": 190776
},
{
  "ID": 18,
  "district_parcel": "231/00224-155-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=23100224155000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 75300,
  "bldg_value": 204500,
  "total_value": 279800,
  "address": "100 4TH ST NW ",
  "address_city": "BONDURANT",
  "zip_code": 50035,
  "owner": "KAVEN, EMILY R",
  "school_dist": 4,
  "land_sq_ft": 18591,
  "year_built": 2016,
  "living _sq_ft": 1490,
  "condition": "Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 2,
  "half_bath": 1,
  "bedrooms": 3,
  "basement_beds": null,
  "total_beds": 3,
  "attached_gar": 770,
  "last_sale_date": "8/24/16",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=23100224155000&amp;yymm=1608&amp;book=16157&amp;pg=368&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$264,760 ",
  "grade": "4+05",
  "prediction": 293790
},
{
  "ID": 19,
  "district_parcel": "090/02927-003-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=09002927003000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 38200,
  "bldg_value": 159100,
  "total_value": 197300,
  "address": "100 56TH ST ",
  "address_city": "DES MOINES",
  "zip_code": 50312,
  "owner": "SHEHAN, BRENDA",
  "school_dist": 1,
  "land_sq_ft": 10000,
  "year_built": 1966,
  "living _sq_ft": 1335,
  "condition": "Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 3,
  "half_bath": 0,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 0,
  "last_sale_date": "6/22/07",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=09002927003000&amp;yymm=706&amp;book=12262&amp;pg=254&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$165,470 ",
  "grade": "4+05",
  "prediction": 207165
},
{
  "ID": 20,
  "district_parcel": "231/00220-318-000",
  "district_parcel_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card/card&dp=23100220318000&amp;format=codeDescrOnly&amp;level=1&amp;",
  "class": "Res",
  "land_value": 59700,
  "bldg_value": 221600,
  "total_value": 281300,
  "address": "100 5TH ST NE ",
  "address_city": "BONDURANT",
  "zip_code": 50035,
  "owner": "LAPPE, JIM",
  "school_dist": 4,
  "land_sq_ft": 16339,
  "year_built": 2003,
  "living _sq_ft": 1603,
  "condition": "Normal",
  "residence_type": "1 Story",
  "building _style": "Ranch",
  "bath": 3,
  "half_bath": 0,
  "bedrooms": 4,
  "basement_beds": null,
  "total_beds": 4,
  "attached_gar": 810,
  "last_sale_date": "4/17/12",
  "date_url": "http://web.assess.co.polk.ia.us/cgi-bin/web/tt/infoqry.cgi?tt=card_sale/cardS&amp;dp=23100220318000&amp;yymm=1204&amp;book=14244&amp;pg=256&amp;table=rsale&amp;report=WebSales&amp;fixed=N&amp;sketch=Y&amp;photo=N&amp;",
  "price": "$229,000 ",
  "grade": "4+05",
  "prediction": 295365
}
];


