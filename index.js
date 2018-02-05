require('dotenv').config()
var fs = require('fs')
var bodyParser = require('body-parser')
var https = require('https')
// var sqlite3 = require('sqlite3').verbose(); 
var mysql = require('mysql'); 
var express = require('express')
var helmet = require('helmet')
var winston = require('winston')
var morgan = require('morgan')

var app = express()

app.use(helmet())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

const port = process.env.PORT || 3000;

var authenticationCache = []

if (!fs.existsSync("log")){
    fs.mkdirSync("log")
}

var logger = new winston.Logger({
    transports: [
        new winston.transports.File({
            level: 'info',
            filename: 'log/log.log',
            handleExceptions: true,
            json: true,
            maxsize: 5242880,
            maxFiles: 5,
            colorize: false,
            timestamp:function() {
              var date = new Date()
              return date.toLocaleString()
            }
        }),
        new winston.transports.Console({
            level: 'debug',
            handleExceptions: true,
            json: false,
            colorize: true,
            timestamp:function() {
              var date = new Date()
              return date.toLocaleString()
            }
        })
    ],
    exitOnError: false
})

logger.stream = {
    write: function(message, encoding){
        logger.info(message.trim())
    }
};

// var sqliteFile = "tigerdatabase.sqlite3";
// var db = new sqlite3.Database(sqliteFile); 

var db = mysql.createConnection(process.env.JAWSDB_URL)

db.connect(function(err) {
  if (err) throw err;
  logger.info("Connected to the database!");
})

app.use(require("morgan")("tiny", { "stream": logger.stream }))

/*

This function authenticates a token id using Google's backend in an async manner. If a user has already been authenticated and the token is still valid, it will use a cache in order to reduce the hits to Google's server. 

Arguments:

token: String that contains the token id as reported by Google's OAuth token. 
callback: A function that is called when this function returns. It needs to have a single argument, which is the return dictionary.

Returns:
{
  ["authenticated"], //A boolean that is true if the user is authenticated
  ["data"]           //The data returned by Google's server. It contains the email, the name, and a few parameters such as expiry time. The token id is added for convenience.
}

*/

function authenticate(token, callback) {
  // for (cache in authenticationCache) {
  for (var cache = 0; cache < authenticationCache.length; i++) {
    if (token == authenticationCache[cache]["id"]) {
      logger.info("Using cached data for " + authenticationCache[cache]["email"])
      callback({
        authenticated: true,
        data: authenticationCache[cache]
      })
      return
    }
  }
  https.get('https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=' + token, (res) => {
      const { statusCode } = res;
      const contentType = res.headers['content-type'];

      let error;
      if (statusCode == 400) {
        logger.info("Unauthorized user, with token: " + token)
        callback({
            authenticated: false,
            data: undefined
          })
        return
      } else if (statusCode != 200) {
        error = new Error('Request Failed.\n' +
                          `Status Code: ${statusCode}`);
      }
      if (error) {
        res.resume();
        log(error)
        return;
      }

      res.setEncoding('utf8');
      let rawData = '';
      res.on('data', (chunk) => { rawData += chunk; });
      res.on('end', () => {
        try {
          const parsedData = JSON.parse(rawData);
          if (parsedData["hd"] == "depauw.edu") {
            parsedData["id"] = token
            authenticationCache.push(parsedData)
            callback({
              authenticated: true,
              data: parsedData
            })
          }
        } catch (e) {
          console.error(e.message);
        }
      });
    }).on('error', (e) => {
      console.error(`Got error: ${e.message}`);
    });
}

//BEGINNING OF SERVER PAGES

/*

It is important to mention that all the pages have the following code at the beginning:

try {
  data = JSON.parse(Object.keys(req.body))
} catch(err) {
  data = req.body
}

This code acts as a work-around for the iOS version, as it embedded the JSON as a key in the body, and not as a dictionary. It should also work if the JSON data is properly embedded in the body.


The server will ALWAYS return a 401 http status if the token id is invalid. The app should act accordingly if the status is 401. Maybe a blacklist should be implemented if an IP accumulates too many 401s?


The way to know if a user is part of the security team is by using its email. It is necessary to add its email to the security table in the database, else it won't be recognized as a security user and instead it will be registered as a regular user.


All the documentation for the server requests will assume that the arguments are the keys and the values in JSON format that needs to be sent from the client to the server, and the response will be a JSON table sent from the server to the client. 

---------IMPORTANT---------
All the requests need to include the token id, as a security measure. It always needs to be added to the JSON request with the following key: ["id"]

*/

/*

This page checks if the user has already registered, and whether it is security or it isn't. If the user is part of security, it won't be asked to register. In order to avoid spoofing, it uses the email associated to the token id as reported by Google. 

Arguments:

{
  ["id"] //The user's token id as reported by Google.
}

Returns:

{
  ["userRegistered"], //A boolean that is true if the user is registered, false otherwise.
  ["securityAccess"]  //A boolean that is true if the user has security clearance, false otherwise.
}

The app should redirect the user to the register form if it isn't registered. If the user has security clearance, ["userRegistered"] will always be true.

*/

app.post('/login', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
  }
  token = data.token
  res.set("Connection", "close");
  authenticate(token, function (user) {
    if (user.authenticated) {
      db.query("SELECT * FROM user WHERE email == ?", [user.data["email"]], function(err, row, _fields) {
        db.query("SELECT * FROM security WHERE email == ?", [user.data["email"]], function(securityErr, securityRow, _securityFields) {
          if (row.length == 0 && securityRow.length == 0) {
            log("Registering as " + user.data["email"])
            res.json({"userRegistered": false});
          } else if (row.email == user.data["email"] || securityRow.email == user.data["email"]){
            if (securityRow.length == 0) {
              security = false
            } else {
              security = true
            }
            logger.info("Logged in as " + user.data["email"] + " , with security clearance: " + security)
            res.json({"userRegistered": true, "securityAccess": security});
          }
        })
      })
    } else {
      res.sendStatus(401);
    }
  })
})

/*

This page registers a user in the database. 

Arguments:

{
  ["email"],       //String that contains the user's email. This should not be able to be edited by the user. Maybe we should not use this argument and rely instead on the information given by the token id?
  ["name"],        //String that contains the user's name. This should not be able to be edited by the user. Maybe we should not use this argument and rely instead on the information given by the token id?
  ["height"],      //OPTIONAL, String that contains the user's height.
  ["weight"],      //OPTIONAL, Float that contains the user's weight.
  ["hair"],        //OPTIONAL, String that contains the user's hair color.
  ["eye"],         //OPTIONAL, String that contains the user's eye color.
  ["house"],       //OPTIONAL, String that contains the user's current house.
  ["room"],        //OPTIONAL, Integer that contains the user's room.
  ["allergies"],   //OPTIONAL, String that contains the user's allergies.
  ["medications"], //OPTIONAL, String that contains the user's medications.
  ["contact"]      //OPTIONAL, String that contains the user's contact information.
}

Returns:

{
  ["userRegistered"] = true //This boolean will always be true if the registration was sucesful. TODO: Add a false statement if the registration wasn't sucesful.
}

*/

app.post('/register', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      names = ["height", "weight", "hair", "eye", "house", "room", "allergies", "medications", "contact"]
      for (name in names) {
        if (!data[names[name]]) {
          //This check is to change the integers to 0, and the strings to "".
          if (names[name] == "weight") {
            data[names[name]] = 0
          } else {
            data[names[name]] = ""
          }
        }
      }
      db.query("INSERT INTO user VALUES (?,?,?,?,?,?,?,?,?,?,?)", [data["email"], data["name"], data["height"], data["weight"], data["hair"], data["eye"], data["house"], data["room"], data["allergies"], data["medications"], data["contact"]], function (err, _row, _fields) {
        logger.info("Registered email " + user.data["email"])
        res.json({"userRegistered": true});
      }) 
    } else {
      res.sendStatus(401);
    }
  })
})

/*

This page logs an emergency to the queue. If an emergency has been logged already, it won't log it again.

TODO: Add a geographical check as to limit the locations to DePauw's campus.

Arguments: 

{
  ["email"],    //The user's email. It is purposively being taken from the request.
  ["name"],     //The user's name. It is purposively being taken from the request.
  ["latitude"], //The user's latitude, as reported by the OS.
  ["longitude"] //The user's longitude, as reported by the OS.
}

Returns:

Nothing

*/

app.post('/emergency', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      if (data["latitude"] && data ["longitude"]) {
        db.query("SELECT * FROM queue WHERE email == ?", [data["email"]], function(err, row, _fields) {
          if (row.length == 0) {
            db.query("INSERT INTO queue VALUES (?,?,?,?,?)", [data["email"], data["name"], data["latitude"], data["longitude"], Date.now()], function (_err, _row, _fields) {
              logger.info("Emergency reported at lat:" + data["latitude"] + " lon:" + data["longitude"] + " by " + user.data["email"], req.ip, hrstart)
            }) 
          } else {
            logger.info("Attempted to report emmergency by " + user.data["email"] + " but an emergency has already been logged", req.ip, hrstart)
          }
        })
      }
    }
  })
})

/*
  
This page returns all the information from a user in the database. It doesn't check if the user exists, so if it doesn't exist, it will return "undefined".

Arguments:

{
  ["email"] //The email from which the information is requested
}

Returns:

{
  ["email"],       //String that contains the user's email.
  ["name"],        //String that contains the user's name.
  ["height"],      //OPTIONAL, String that contains the user's height.
  ["weight"],      //OPTIONAL, Float that contains the user's weight.
  ["hair"],        //OPTIONAL, String that contains the user's hair color.
  ["eye"],         //OPTIONAL, String that contains the user's eye color.
  ["house"],       //OPTIONAL, String that contains the user's current house.
  ["room"],        //OPTIONAL, Integer that contains the user's room.
  ["allergies"],   //OPTIONAL, String that contains the user's allergies.
  ["medications"], //OPTIONAL, String that contains the user's medications.
  ["contact"]      //OPTIONAL, String that contains the user's contact information.
}

*/

app.post('/request', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      db.query("SELECT * FROM user WHERE email == ?", [data["email"]], function(err, row, _fields) {
        logger.info("Requested data from " + data["email"] + " by " + user.data["email"])
        res.json(row[0])
      })
    }
  })
})

/*

This page updates the information of an user in the database. 

Arguments:

{
  ["email"],       //String that contains the user's email.
  ["name"],        //String that contains the user's name.
  ["height"],      //OPTIONAL, String that contains the user's height.
  ["weight"],      //OPTIONAL, Float that contains the user's weight.
  ["hair"],        //OPTIONAL, String that contains the user's hair color.
  ["eye"],         //OPTIONAL, String that contains the user's eye color.
  ["house"],       //OPTIONAL, String that contains the user's current house.
  ["room"],        //OPTIONAL, Integer that contains the user's room.
  ["allergies"],   //OPTIONAL, String that contains the user's allergies.
  ["medications"], //OPTIONAL, String that contains the user's medications.
  ["contact"]      //OPTIONAL, String that contains the user's contact information.
}

Returns:

Nothing

*/

app.post('/update', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated && user.data["email"] == data["email"]) {
      db.run("DELETE FROM user WHERE email == ?", [data["email"]], function (_err, _row, _fields) {
        names = ["height", "weight", "hair", "eye", "house", "room", "allergies", "medications", "contact"]
        for (name in names) {
          if (!data[names[name]]) {
            if (names[name] == "weight") {
              data[names[name]] = 0
            } else {
              data[names[name]] = ""
            }
          }
        }
        db.run("INSERT INTO user VALUES (?,?,?,?,?,?,?,?,?,?,?)", [data["email"], data["name"], data["height"], data["weight"], data["hair"], data["eye"], data["house"], data["room"], data["allergies"], data["medications"], data["contact"]], function (_err, _row, _fields) {
          logger.info("Updated information of " + data["email"]);
          res.end();
        })
      })
    }
  })
})

/*

This page cancels and deletes an element in the queue, identified by the email associated to the request. It doesn't verify if the email is the same as the token, as to allow security members to cancel queue items.

Arguments:

{
  ["email"] //The email of the queue item to delete.
}

Returns:

Nothing

*/

app.post('/cancel', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body))
  } catch(err) {
    data = req.body
    log(err)
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      db.query("DELETE FROM queue WHERE email = ?", [data["email"]], function (_err, _row, _fields) {
        logger.info("Canceled emergency from " + data["email"]);
        res.end();
      })
    }
  })
})

/*

This page returns all the elements in the queue. TODO: check if the email that is requesting the data has security clearance.

Arguments:

None. (Except for the token id)

Returns:

{
  ["data"] //Array with all the queue items. If there is none, then this table will be empty.
}

*/

app.post('/get-queue', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body));
  } catch(err) {
    data = req.body;
    logger.error(err);
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      var jsonTable = {"data":[]};
      db.query("SELECT * FROM queue", function (err, rows, _fields) {
        for (var i = 0; i < rows.length; i++) {
          jsonTable["data"].push({"email":rows[i].email,
            "name":rows[i].name,
            "latitude":rows[i].latitude,
            "longitude":rows[i].longitude
          })
        };
        res.json(jsonTable);
        logger.info("Updated queue of " + user.data["email"] + " with a total of " + rows + " items");
      })
    }
  })
})

/*
  
This page returns all the information from a user in the database, including the coordinates of an emergency submitted by the user. It doesn't check if the user exists, so if it doesn't exist, it will return "undefined".

Arguments:

{
  ["email"] //The email from which the information is requested
}

Returns:

{
  ["email"],       //String that contains the user's email.
  ["name"],        //String that contains the user's name.
  ["height"],      //OPTIONAL, String that contains the user's height.
  ["weight"],      //OPTIONAL, Float that contains the user's weight.
  ["hair"],        //OPTIONAL, String that contains the user's hair color.
  ["eye"],         //OPTIONAL, String that contains the user's eye color.
  ["house"],       //OPTIONAL, String that contains the user's current house.
  ["room"],        //OPTIONAL, Integer that contains the user's room.
  ["allergies"],   //OPTIONAL, String that contains the user's allergies.
  ["medications"], //OPTIONAL, String that contains the user's medications.
  ["contact"],     //OPTIONAL, String that contains the user's contact information.
  ["latitude"],    //String that contain's the user's latitude.
  ["longitude"]    //String that contain's the user's longitude.
}

*/


app.post('/request-emergency', function (req, res) {
  var hrstart = process.hrtime();
  try {
    data = JSON.parse(Object.keys(req.body));
  } catch(err) {
    data = req.body
    logger.error(err)
  }
  res.set("Connection", "close");
  authenticate(data["id"], function (user) {
    if (user.authenticated) {
      db.query("SELECT * FROM user WHERE email == ?", data["email"], function(err, row, _fields) {
        db.query("SELECT * FROM queue WHERE email == ?", data["email"], function(queueErr, queueRow, _fields) {
          row[0].latitude = queueRow[0].latitude;
          row[0].longitude = queueRow[0].longitude;
          res.json(row[0]);
        })
      })
      logger.info("Requested emergency data from " + data["email"] + " by " + user.data["email"]);
    }
  })
})

//If a user requests the root directory, it will send a string to the client saying that the user should not be here.

app.get('/', function (req, res) {
    res.send("Hallo, you shouldn't be here");
})

/*

This function clears the queue. It will remove items that are over 60 minutes old. It will also clear the authentication cache from all the tokens that already expired. It runs every 5 minutes.

*/

function cleanQueue() {
  var count = 0
  db.query("SELECT * FROM queue", function(err, rows, _fields) {
    for (var i = 0; i < rows.length; i++) {
      if (Date.now() - rows[i].time >= 3600000) {
        db.query("DELETE FROM queue WHERE email = ?", rows[i].email, function (_err, _rows, _fields) {});
        count++;
      }
    }
  })
  logger.info("Cleaned " + count + " elements on the queue!")
  count = 0
  date = new Date()
  for (cache in authenticationCache) {
    cacheDate = new Date(authenticationCache[cache]["exp"]*1000)
    if (date.getTime() >= cacheDate.getTime()) {
      authenticationCache.splice(cache)
      count++
    }
  }
  logger.info("Cleaned cache, removing " + count + " entries")
}

//This method should be user to create a server with SSL, so all the requests would have to be done using SSL. 
/*
https.createServer({
      key: fs.readFileSync('certificates/key.pem'),
      cert: fs.readFileSync('certificates/cert.pem')
    }, app).listen(port);*/

logger.info("Sucessfully started the server, with the port " + port)


//Creates a server that serves http requests on port 3000.
app.listen(port)

setInterval(cleanQueue, 300000)