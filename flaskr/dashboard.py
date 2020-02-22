from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, jsonify, session, Flask
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.auth import login_required
from flaskr.db import get_db
from flaskr.__init__ import create_app
import sqlite3
import json
from flask_uploads import UploadSet, configure_uploads, IMAGES

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import mpl_toolkits
import re
import time
import uuid
import os


bp = Blueprint('dashboard', __name__)


# Method that renders index.html and handles all POST requests from index.html
@bp.route('/', methods=('GET', 'POST'))
@login_required
def index():
    if request.method == 'POST':
        email = request.form['email']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        description = request.form['description']
        photoUploaded = False
        try:
            file = request.files['photo']
            extension = os.path.splitext(file.filename)[1]
            ALLOWED_EXTENSIONS = set(['.jpe', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.bmp'])
            if extension not in ALLOWED_EXTENSIONS:
                flash('Please Enter A Valid Photo Type')
            else:
                f_name = str(uuid.uuid4()) + extension
                app = create_app(None)
                file.save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], f_name))
                location = "uploads/" + f_name
                photoUploaded = True
        except:
            photoUploaded = False

        error = None
        db = get_db()

        if re.search(".+@.+", email) is None:
            error = "Please Enter a Valid Email Address"
        elif re.search("[a-zA-Z ]+", firstName) is None:
            error = "Please Enter a Valid First Name"
        elif re.search("[a-zA-Z ]+", lastName) is None:
            error = "Please Enter a Valid Last Name"

        #SQL statements when Photo is uploaded
        if error is None and photoUploaded:

            destination = db.execute(
                'SELECT profilePicture FROM user WHERE firstName = ? AND email = ? AND userId = ?',
                (firstName, email, session.get('user_id'))
            ).fetchone()
            if str(destination[0]) != "uploads/stickfigure.png":
                print(str(destination[0]))
                os.remove('flaskr/static/' + str(destination[0]))

            db.execute(
            'UPDATE user SET email = ?, firstName = ? , lastName = ?, description = ?, profilePicture = ? WHERE userId =? ', (email, firstName, lastName, description, location, session.get('user_id'))
            )
            db.commit()
            print("successfully updated user")
        
        #SQL statements when Photo is not uploaded
        elif error is None and not photoUploaded:
            db.execute(
            'UPDATE user SET email = ?, firstName = ? , lastName = ?, description = ? WHERE userId =? ', (email, firstName, lastName, description, session.get('user_id'))
            )
            db.commit()
            print("successfully updated user")
        else:
            print(error)

        return redirect(url_for('dashboard.index'))


    return render_template('dashboard/index.html')


#Method that is called when users want to change their password on index.html page
@bp.route('/changepassword', methods=('GET', 'POST'))
@login_required
def changePassword():
    if request.method == "POST":
        password = request.form['password']
        passwordConfirmation = request.form['password2']
        error = None
        db = get_db()

        if password != passwordConfirmation:
            error = "Passwords do not match"
        elif not re.search("((?=.*\d)(?=.*[a-zA-Z])(?=.*\W).{8,})", password):
            error = "Please enter a password at of least 8 characters containing an uppercase letter, lowercase letter, number, and special character."
        else:
            db.execute(
            'UPDATE user SET password = ? WHERE userId = ?', (generate_password_hash(password), session.get('user_id'))
            )
            db.commit()
            return redirect(url_for('dashboard.index'))

        flash(error)

    return render_template('dashboard/index.html')


# Adds properties to previously owned through a form (manually) and renders tables.html
@bp.route('/table1', methods=('GET', 'POST'))
@login_required
def table1():
    if request.method == 'POST':
        address = request.form['address']
        beds = request.form['beds']
        baths = request.form['baths']
        halfBaths = request.form['halfBathrooms']
        sqft = request.form['sqft']
        zip = request.form['zip']
        yearBuilt = request.form['yearBuilt']
        landValue = request.form['landValue']
        buildingValue = request.form['buildingValue']
        totalValue = int(landValue) + int(buildingValue)
        yearPurchased = request.form['yearPurchased']
        error = None
        db = get_db()

        if re.search("\d+\s.+", address) is None:
            error = "Please Enter a Valid Address"
        elif re.search("[0-9]+", beds) is None:
            error = "Please Enter a Valid Integer of Bedrooms"
        elif re.search("[0-9]+", baths) is None:
            error = "Please Enter a Valid Integer of Bathrooms"
        elif re.search("[0-9]+", halfBaths) is None:
            error = "Please Enter a Valid Integer of Half Bathrooms"
        elif re.search("[0-9]+", sqft) is None:
            error = "Please Enter a Valid Integer of Square Feet"
        elif re.search("[0-9]+", zip) is None:
            error = "Please Enter a Valid Zip Code"
        elif re.search("[0-9]+", yearBuilt) is None:
            error = "Please Enter a Valid Year Built"
        elif re.search("[0-9]+", landValue) is None:
            error = "Please Enter a Valid Integer of Land Value"
        elif re.search("[0-9]+", buildingValue) is None:
            error = "Please Enter a Valid Integer of Building Value"
        elif re.search("[0-9]+", yearPurchased) is None:
            error = "Please Enter a Valid Year Purchased"
        elif db.execute(
            'SELECT address, zip_code FROM formerProperties WHERE address = ? AND zip_code = ? AND userId = ?', 
            (address, zip, session.get('user_id'))
        ).fetchone() is not None:
            error = "This property is already in the Previously Owned table."

        #SQL to run if there is no error and the property doesn't already exist
        if error is None:
            db.execute(
                'INSERT INTO formerProperties (address, total_beds, bath, half_bath, living_sq_ft, zip_code, year_built, land_value, bldg_value, total_value, year_purchased, userId, like_dislike) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (address, beds, baths, halfBaths, sqft, zip, yearBuilt, landValue, buildingValue, totalValue, yearPurchased, session.get('user_id'), 1)
            )
            db.commit()
            print("successfully inserted into database")

        print(error)

    return render_template('dashboard/tables.html')


#Renders tables_2.html
@bp.route('/table2')
@login_required
def table2():
    return render_template('dashboard/tables_2.html')

# Adds property to previously owned through the "Add" button on tables_2.html
@bp.route('/table1/add', methods=('GET', 'POST'))
def addRow():
    db = get_db()
    if request.method == 'POST':
        jsonData = request.get_json()
        propertyId = jsonData['ID']
        class1 = jsonData['class']
        land_value = jsonData['land_value']
        bldg_value = jsonData['bldg_value']
        total_value = jsonData['total_value']
        address = jsonData['address']
        address_city = jsonData['address_city']
        zip_code = jsonData['zip_code']
        owner = jsonData['owner']
        school_dist = jsonData['school_dist']
        land_sq_ft = jsonData['land_sq_ft']
        year_built = jsonData['year_built']

        living_sq_ft = jsonData['living_sq_ft']
        condition = jsonData['condition']
        residence_type = jsonData['residence_type']
        building_style = jsonData['building_style']
        bath = jsonData['bath']
        half_bath = jsonData['half_bath']
        bedrooms = jsonData['bedrooms']
        basement_beds = jsonData['basement_beds']
        total_beds = jsonData['total_beds']
        attached_gar = jsonData['attached_gar']
        price = jsonData['price']
        grade = jsonData['grade']


        if db.execute(
            'SELECT * FROM formerProperties WHERE address = ? AND zip_code = ? AND userId = ?', (address, zip_code, session.get('user_id'))
        ).fetchone() is not None:
            db.execute(
                'UPDATE formerProperties SET like_dislike = 1 WHERE address = ? AND zip_code = ? AND userId = ?', (address, zip_code, session.get('user_id'))
            )
            db.commit()
            print("Updated Successfully")
        else:
            db.execute(
                'INSERT INTO formerProperties(class,land_value,bldg_value,total_value,address,address_city,zip_code,owner,school_dist,land_sq_ft,year_built,living_sq_ft,condition,residence_type,building_style,bath,half_bath,bedrooms,basement_beds,total_beds,attached_gar,price,grade,like_dislike,userID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);',
                (class1, land_value, bldg_value, total_value, address, address_city, zip_code, owner, school_dist, land_sq_ft, year_built, living_sq_ft, condition, residence_type, building_style, bath, half_bath, bedrooms, basement_beds, total_beds, attached_gar, price, grade, 1, session.get('user_id'))
            )
            db.commit()
            print("Inserted Successfully")

    return "Made it here in addRow()"


# Deletes a property from previously owned when user presses delete button in tables.html
@bp.route('/table1/delete', methods=('GET', 'POST'))
def delete_table1_row():
    db = get_db()
    if request.method == 'POST':
        jsonData = request.get_json()
        address = jsonData['address']
        zip_code = jsonData['zip_code']
        db.execute('DELETE FROM formerProperties WHERE address = ? AND zip_code = ? AND userId = ?', (address, zip_code, session.get('user_id')))
        db.commit()
        print("Deleted Successfully")

    return "Made it here in delete_table1_row()"


# Sends all Previously owned properties to tables.html
@bp.route('/table1/previousProperties', methods=('GET', 'POST'))
def sendProperties():
    db = get_db()
    query = "SELECT * FROM FormerProperties WHERE userId = %s" % (session.get('user_id'))
    data = pd.read_sql_query(query, db)
    data.sort_values(by=["year_purchased"])
    jsonData = data.to_json(orient = "records")
    return jsonData


# This method is called when users press the "delete" button in tables_2.html. This 
# adds the deleted property to the user's model as a "disliked" property. NOTE: THIS DOES NOT GUARENTEE
# THE DELETED PROPERTY WILL BE WIPED FROM THE RECOMMENDED PROPERTIES TABLE
@bp.route('/table2/delete', methods=('GET', 'POST'))
def deleteRow():
    db = get_db()
    if request.method == 'POST':
        jsonData = request.get_json()
        propertyId = jsonData['ID']
        class1 = jsonData['class']
        land_value = jsonData['land_value']
        bldg_value = jsonData['bldg_value']
        total_value = jsonData['total_value']
        address = jsonData['address']
        address_city = jsonData['address_city']
        zip_code = jsonData['zip_code']
        owner = jsonData['owner']
        school_dist = jsonData['school_dist']
        land_sq_ft = jsonData['land_sq_ft']
        year_built = jsonData['year_built']

        living_sq_ft = jsonData['living_sq_ft']
        condition = jsonData['condition']
        residence_type = jsonData['residence_type']
        building_style = jsonData['building_style']
        bath = jsonData['bath']
        half_bath = jsonData['half_bath']
        bedrooms = jsonData['bedrooms']
        basement_beds = jsonData['basement_beds']
        total_beds = jsonData['total_beds']
        attached_gar = jsonData['attached_gar']
        price = jsonData['price']
        grade = jsonData['grade']

        # If property is already in model, set it to "disliked"
        if db.execute(
            'SELECT * FROM properties WHERE address = ? AND zip_code = ? AND userId = ?', (address, zip_code, session.get('user_id'))
        ).fetchone() is not None:
            db.execute(
                'UPDATE properties SET like_dislike = 0 WHERE address = ? AND zip_code = ? AND userId = ?', (address, zip_code, session.get('user_id'))
            )
            db.commit()
            return "Updated Successfully"

        # If property is not in model, add it to model as a "disliked" property
        else:
            db.execute(
                'INSERT INTO properties(class,land_value,bldg_value,total_value,address,address_city,zip_code,owner,school_dist,land_sq_ft,year_built,living_sq_ft,condition,residence_type,building_style,bath,half_bath,bedrooms,basement_beds,total_beds,attached_gar,price,grade,like_dislike,userID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);', 
                (class1, land_value, bldg_value, total_value, address, address_city, zip_code, owner, school_dist, land_sq_ft, year_built, living_sq_ft, condition, residence_type, building_style, bath, half_bath, bedrooms, basement_beds, total_beds, attached_gar, price, grade, 0, session.get('user_id'))
            )
            db.commit()
            return "Inserted Successfully"

    return "Made it here in deleteRow()"



# AI Function that sends Recommended Properties to tables_2.html
@bp.route('/table2/recommended', methods=('GET', 'POST'))
def sendRecommended():


    db = get_db()
    query = "SELECT * FROM properties WHERE userId = %s" % (session.get('user_id'))
    # import the training data- houses that have previously been liked or disliked by the user in properties tables
    train_data = pd.read_sql_query(query, db)

    train_data.head()

    # set up the data to train the system
    labels = train_data['like_dislike']
    train1 = train_data.drop(['ID', 'class', 'address', 'address_city', 'zip_code', 'owner', 'school_dist', 'land_sq_ft', 'residence_type', 'building_style', 'condition', 'bedrooms', 'basement_beds', 'attached_gar', 'grade', 'like_dislike', 'price', 'userId'],axis=1)
    train1.head()
    from sklearn.model_selection import train_test_split


    #Configuring the machine to learn
    x_train , x_test , y_train , y_test = train_test_split(train1 , labels , test_size = 0.10,random_state =1)

    from sklearn import ensemble
    clf = ensemble.GradientBoostingClassifier(n_estimators = 1000, max_depth = 10, min_samples_split = 2,
              learning_rate = 0.2)


    # train the model
    clf.fit(x_train, y_train)


    # test how well the model learned
    clf.score(x_test,y_test)


    # read in the dataset of houses
    data = pd.read_csv("flaskr/house_data.csv")
    x_predict = data.drop(['ID', 'class', 'address', 'address_city', 'zip_code', 'owner', 'school_dist', 'land_sq_ft', 'residence_type', 'building_style', 'condition', 'bedrooms', 'basement_beds', 'attached_gar', 'grade', 'like_dislike', 'price'],axis=1)


    # predict if dataset houses should be liked or disliked
    prediction = clf.predict(x_predict)


    # put predictions into the dataset
    prediction.tolist()
    data['like_dislike'] = prediction


    # create new dataset with only liked houses
    output_data = data[data.like_dislike != 0]


    # Sort the output data
    output_data.sort_values(by=["ID"])


    # convert new dataset to json
    json_file = output_data.to_json(orient = "records")

    return json_file










