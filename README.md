Answers Cloud Services API Client Library - PHP
===================
Helper library for connecting to the Answers Cloud Services (ForeSee in particular) web API in a headless manner. You can use this to simplify connecting to the ACS api without requiring a browser or user interaction to grant access to a particular account.
###Version Support
Supports PHP v5.2 and above 

###Installation 
+ Download client library
+ Install extracted library to a sub-path of your codebase

###Simple Usage
```php
require_once realpath('path/to/library/AcsClient.php');

$opts = array(
  consumerKey: "[CONSUMER KEY PROVIDED BY FORESEE]",
  consumerSecret: "[CONSUMER SECRET PROVIDED BY FORESEE]",
  consumerType: "[CONSUMER TYPE PROVIDED BY FORESEE]",
  username: "[USERNAME]",
  password: "[PASSWORD]"
);

/**
 * Set up the client
 */
$client = new AcsClient($opts);

// Call resource endpoint
$client->callResource(
    "currentUser", // Resource endpoint 
    "GET", // HTTP method
    [], // Extra Parameters necessary for some end points 
    function($result) { // callback function to be executed on error and success
        if ($result->isError()) {
            // Preform actions when errors occur
        } else {
            // Preform actions for a successful execution
            $last = $result->getLastResponse();
        }
    }
);
```
Note: Native anonymous function implementation above requires PHP5.3, see http://php.net/manual/en/functions.anonymous.php

###Errors
The ACS Client class throws InvalidArgumentException, see http://php.net/manual/en/class.invalidargumentexception.php, when creating instances or executing methods with missing or invalid argumnets.

Otherwise, ACS Client returns a FALSE when errors occur after setting internal error variables. If not monitoring the return result, errors can be checked by executing isError() and retrieving the errors by calling getErrors().  

If there is a problem authenticating or reaching an endpoint, or if a request is malformed, an error will be generated and stored internally within the ACS Client instance. Possible error codes:
* `INVALIDREQUESTTOKEN` - Could not get a request token. There may be something wrong with your consumer key or consumer secret.
* `COULDNOTLOGIN` - There was a problem with the login process. Probably not due to invalid credentials.
* `INVALIDCREDENTIALS` - Could not log in with the provided credentials.
* `COULDNOTAUTHTOKEN` - Could not authorize the auth token.
* `COULDNOTFINDVERIFIER` - There was a problem with the authentication flow. Might be due to an invalid `consumer_type`, `consumer_key` or `consumer_secret`.
* `COULDNOTGETACCESSTOKEN` - There was a problem with the authentication flow. Might be due to an invalid `consumer_type`, `consumer_key` or `consumer_secret`.
* `COULDNOTGETACCESSTOKENNULL` - There was a problem with the authentication flow. Might be due to an invalid `consumer_type`, `consumer_key` or `consumer_secret`.
* `403` - You do not have access to that endpoint with that criteria.

Errors are provided as a simple array with keys 'code' and 'msg'. Example:
```php
[
  "code": "COULDNOTGETACCESSTOKENNULL",
  "msg": "Error getting the access token since they were null."
]
```
###Authentication
Authentication will occur automatically, when necessary, as you make service calls. Therefor, if you have not authenticated already and not yet been granted an access token nor an access token secret, the first call to an endpoint will take longer than the rest since it has to go through the authentication flow first.

If you want to check your credentials or just ensure you're actually able to contact an endpoint using the information provided, you can call the `authenticate()` method:
 
```php
require_once realpath('path/to/library/AcsClient.php');

$opts = array(
  consumerKey: "[CONSUMER KEY PROVIDED BY FORESEE]",
  consumerSecret: "[CONSUMER SECRET PROVIDED BY FORESEE]",
  consumerType: "[CONSUMER TYPE PROVIDED BY FORESEE]",
  username: "[USERNAME]",
  password: "[PASSWORD]"
);

/**
 * Set up the client
 */
$client = new AcsClient($opts);
if ($client->authenticate()) {
    // Authenticated
} else {
    // Error state
}
```

###Accessing without Credentials
ACS uses an oAuth authentication scheme so you may want to take advantage of the fact that once you have an access token and an access token secret, you should not need to keep user credentials around to continue using the service layer. ACS can issue you a long-lived token if you request it so you can just set the following attributes on the `options` object rather than the u/p combo:
```php
// Authenticating without usernames or passwords
require_once realpath('path/to/library/AcsClient.php');

$opts = array(
  consumerKey: "[CONSUMER KEY PROVIDED BY FORESEE]",
  consumerSecret: "[CONSUMER SECRET PROVIDED BY FORESEE]",
  consumerType: "[CONSUMER TYPE PROVIDED BY FORESEE]",
  accessToken: "[AUTHENTICATED ACCESS TOKEN]",
  accessTokenSecret: "[AUTHENTICATED ACCESS TOKEN SECRET]"
);

/**
 * Set up the client
 */
$client = new AcsClient($opts);

$client->callResource(
    "currentUser", // Resource endpoint 
    "GET", // HTTP method
    [], // Extra Parameters necessary for some end points 
    function($result) { // callback function to be executed on error and success
        if ($result->isError()) {
            // Preform actions when errors occur
        } else {
            // Preform actions for a successful execution
            $last = $result->getLastResponse();
        }
    }
);
```
Using this technique can result in performance improvements since it eliminates the need to move through the authentication flow. The only downside is, if your token has expired, then you will need to authenticate again with your username and password.

Getting your access token and secret is easy: just look for them on the `client.opts` object:
```php
/**
 * @var array $accessToken ['accessToken' => '..', 'accessTokenSecret' => '..']
 */
$accessToken = $client->getAccessToken();
print_r($accessToken);
```
###Date Criteria
Many of the endpoints accept dates or date ranges as filtering criteria. The full documentaton for how to format these can be found at the ACS developer portal (http://bit.ly/15uYi0k). We've provided a convenience method to help generate these terse date objects:
```php
$clientID = "[ASSIGNED CLIENTID]";

$client->callResource(
    "endPointUri", // Resource endpoint 
    "GET", // HTTP method
    [
        "criteria" => [
            "dateRange" => $client->getDateObject($clientId, "WEEKTODATE")
        ]
    ],  
    function($result) { // callback function to be executed on error and success
        if ($result->isError()) {
            // Preform actions when errors occur
        } else {
            // Preform actions for a successful execution
            $last = $result->getLastResponse();
        }
    }
);
```
The first argument to `getDateObject()` is always the client id (Number). This is used to handle some custom calendaring functions like fiscal calendar. The rest of the arguments depend on what you want. The second argument can be one of the following constants, for example:
* `WEEKTODATE` - The current week of data.
* `LASTWEEK` - Last week's data.
* `YESTERDAY` - Yesterday's data. Note there is no "today" currently.
* `MONTHTODATE` - The current month of data.
* `LASTMONTH` - Last month
* `QUARTERTODATE` - The current fiscal quarter of data
* `LASTQUARTER` - The last fiscal quarter of data
* `YEARTODATE` - The current year of data.
* `LASTYEAR` - Last year

You can also construct more complex ranges that involve several arguments. Here are come examples to get you started:
```php
$client->getDateObject($clientId, "LAST", 3, "DAYS");
$client->getDateObject($clientId, "LAST", 6, "MONTHS");
$client->getDateObject($clientId, "LAST", 2, "YEARS");
```
Of course you can also get date objects for specific dates and date ranges:
```php
$client->getDateObject($clientId, "2013-03-04");  // Get for April 4, 2013 by string
$client->getDateObject($clientId, new \DateTime("2013-03-04");  // Get for April 4, 2013 by object

// Get for a range between April 4, 2013 and January 1, 2014:
$client->getDateObject($clientId, "2014-03-04", "2015-01-01");  
```
###Fiscal Calendars
Normally, relative and general dates are calculated using normal calendar (Gregorian) dates. If your account is set up with fiscal calendars, you can switch to this instead by passing `FISCAL` as the last argument:
```php
$client->getDateObject($clientId, "LAST", 2, "YEARS", "FISCAL");
```
###Date Comparisons
To perform a date comparison on a period period, which is possible on some endpoints, make the last argument in your `getDateObject()` call equal to `PRIORPERIOD`. Then, assign this to the `dateRangeCompare` attribute of the criteria object:
```php
$client->callResource(
    "endPointUri", // Resource endpoint 
    "GET", // HTTP method
    [
        "criteria" => [
            "dateRange" => $client->getDateObject($clientId, "WEEKTODATE"),
            "dateRangeCompare" => $client->getDateObject($clientId, "WEEKTODATE", "PRIORPERIOD")
        ]
    ],  
    function($result) { // callback function to be executed on error and success
        if ($result->isError()) {
            // Preform actions when errors occur
        } else {
            // Preform actions for a successful execution
            $last = $result->getLastResponse();
        }
    }
);
```