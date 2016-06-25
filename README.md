# wikk_web_auth

* http://wikarekare.github.com/wikk_web_auth/
* Source https://github.com/wikarekare/wikk_web_auth
* Gem https://rubygems.org/gems/wikk_web_auth

## DESCRIPTION:

Gem provides common authentication framework for Wikarekare's Ruby CGIs. 

## FEATURES/PROBLEMS:

* In process of conversion from a library to a gem, and refactored to be more generic. Needs some real world testing. 

## SYNOPSIS:

### Redirect to login scenario
* Logic flows from clients to the cgi; 
* generating a login html page; 
* client logs in, sending the form to the login.rbx Ruby cgi;
* If successful, the login.rbx cgi sends back a redirect to the original cgi.

### Javascript Scenario, with separation of function.
* A separate login button is included on the HTML page, which uses the wikk_auth_js library
```
  <html>
  <head>
    <script src="wikk_web_auth.js"></script>
    ...
    <script>
      init() {
        //Check if we are authenticated, and fill in login span appropriately. 
        logged_in(true, '/admin/sites.html'); //(display lock/unlock image, return url after login page)
        ...
      }
      ...
    </script>
  </head>
  <body onload="init();">
    ...
    <span id="login_span"></span>
    ...
```
* The cgi simple calls the class level WIKK::Web_Auth.authenticate? call, for a true/false response.
```
  require 'wikk_web_auth'
  @authenticated = Authenticated.authenticated?(@cgi)
```

## REQUIREMENTS:

* Used in conjunction with Ruby cgi login.rbx 
* relies on gems wikk_password
* Could make use of wikk_configuration and wikk_aes_256

## INSTALL:

* sudo gem install wikk_web_auth

## LICENSE:

(The MIT License)

Derived from Wikarekare authentication.rb library.

Copyright (c) 2004-2016

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
